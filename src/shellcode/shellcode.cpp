#include "pch.h"
#include "shellcode.h"
#include "ConstantToStackEmitter.h"

namespace
{
class FunctionReferenceIndex
{
public:
    explicit FunctionReferenceIndex(
        const SmallPtrSetImpl<Function*>& unreachable_functions
    )
        : _unreachable_functions(unreachable_functions)
    {
    }

    bool contains_unreachable(Value* root)
    {
        SmallPtrSet<Value*, 32> visiting;
        return contains_unreachable(root, visiting);
    }

    bool has_live_use(Value* value)
    {
        SmallPtrSet<User*, 32> visiting;
        return has_live_use(value, visiting);
    }

    void clear_live_use_cache()
    {
        _live_use_cache.clear();
    }

private:
    bool contains_unreachable(
        Value* value,
        SmallPtrSetImpl<Value*>& visiting
    )
    {
        if (value == nullptr)
        {
            return false;
        }

        auto cache_it = _unreachable_cache.find(value);
        if (cache_it != _unreachable_cache.end())
        {
            return cache_it->second;
        }

        if (!visiting.insert(value).second)
        {
            return false;
        }

        bool result = false;
        if (auto* function = dyn_cast<Function>(
            value->stripPointerCastsAndAliases()
        ))
        {
            result = _unreachable_functions.contains(function);
        }
        else if (auto* constant = dyn_cast<Constant>(value))
        {
            for (Value* operand : constant->operands())
            {
                if (contains_unreachable(operand, visiting))
                {
                    result = true;
                    break;
                }
            }
        }

        visiting.erase(value);
        _unreachable_cache[value] = result;
        return result;
    }

    bool has_live_use(
        Value* value,
        SmallPtrSetImpl<User*>& visiting
    )
    {
        if (value == nullptr)
        {
            return false;
        }

        for (User* user : value->users())
        {
            if (is_live_user(user, visiting))
            {
                return true;
            }
        }

        return false;
    }

    bool is_live_user(
        User* user,
        SmallPtrSetImpl<User*>& visiting
    )
    {
        if (isa<Instruction>(user) ||
            isa<GlobalVariable>(user) ||
            isa<GlobalAlias>(user) ||
            isa<Function>(user))
        {
            return true;
        }

        auto cache_it = _live_use_cache.find(user);
        if (cache_it != _live_use_cache.end())
        {
            return cache_it->second;
        }

        auto* constant = dyn_cast<Constant>(user);
        if (constant == nullptr || !visiting.insert(user).second)
        {
            return false;
        }

        bool result = false;
        for (User* parent : constant->users())
        {
            if (is_live_user(parent, visiting))
            {
                result = true;
                break;
            }
        }

        visiting.erase(user);
        _live_use_cache[user] = result;
        return result;
    }

    const SmallPtrSetImpl<Function*>& _unreachable_functions;
    DenseMap<Value*, bool> _unreachable_cache;
    DenseMap<User*, bool> _live_use_cache;
};
}

PreservedAnalyses ToShellCodePass::run(Module& M, ModuleAnalysisManager& MAM)
{
    reset_state();

    LOG("Running on module: {}", M.getName().str());

    // Collect entry functions
    collect_entry_function(M);

    if (_entry_functions.empty())
    {
        return PreservedAnalyses::all();
    }
    
    // Collect chain functions
    for (auto* func : _entry_functions)
    {
        LOG("Found entry function: {}", func->getName().str());

        collect_chain_function(func);
    }

    for (auto* func : _chain_functions)
    {
        LOG("Found chain function: {}", func->getName().str());
    }
    
    // Collect declare call
    collect_declare_call();
    for (auto& [name, func_type] : _declare_call_functions)
    {
        LOG("Found declare call function: {}", name.str());
    }

    if (auto error = validate_api_resolver(M); !error.empty())
    {
        report_fatal_error(StringRef(error));
    }


    // Collect global variables and build global variable info
    collect_global_variables();
    for (auto* gv : _global_variables)
    {
        LOG("Found global variable: {}", gv->getName().str());
    }
    build_global_variable_info(M);
    
    // Add global variable info alloca to entry functions
    for (auto* func : _entry_functions)
    {
        add_global_variable_alloca(func);
    }

    // Add global variable info parameter to chain functions
    for (auto* func : _chain_functions) 
    {
        if (_entry_functions.contains(func)) 
        {
            _function_ctx_ptr[func] = _global_variable_info_alloc[func];
        }
        else
        {
            auto* new_func = add_function_parameter(func, PointerType::getUnqual(_global_variable_info.type));
            _chain_with_ctx_functions[func] = new_func;
            _function_ctx_ptr[new_func] = &*std::prev(new_func->arg_end());
        }
    }

    // Remap call sites
    remap_call_sites();

    // Replace global variable accesses
    replace_global_variable_accesses();

    // replace declare call
    replace_declare_call();

    // Replace store vector
    replace_store_vector();

    prune_unreachable_functions(M);

    for (auto* gv : _global_variables)
    {
        gv->eraseFromParent();
    }

    for (auto* func : _entry_functions)
    {
        func->setLinkage(Function::ExternalLinkage);
        func->setDLLStorageClass(llvm::GlobalValue::DLLExportStorageClass);
    }

    return PreservedAnalyses::none();
}

void ToShellCodePass::reset_state()
{
    _entry_functions.clear();
    _chain_functions.clear();
    _declare_call_functions.clear();
    _declare_call_functions_index.clear();
    _global_variables.clear();
    _global_variable_info.type = nullptr;
    _global_variable_info.field_index.clear();
    _global_variable_info_alloc.clear();
    _chain_with_ctx_functions.clear();
    _function_ctx_ptr.clear();
    _api_resolver = nullptr;
}

void ToShellCodePass::prune_unreachable_functions(Module& module)
{
    SmallSetVector<Function*, 32> reachable_functions;
    SmallVector<Function*, 32> worklist(
        _entry_functions.begin(),
        _entry_functions.end()
    );

    while (!worklist.empty())
    {
        Function* function = worklist.pop_back_val();

        if (function == nullptr || !reachable_functions.insert(function))
        {
            continue;
        }

        for (auto& block : *function)
        {
            for (auto& instruction : block)
            {
                auto* call = dyn_cast<CallBase>(&instruction);
                if (call == nullptr)
                {
                    continue;
                }

                Function* callee = get_direct_callee(call);
                if (callee != nullptr)
                {
                    worklist.push_back(callee);
                }
            }
        }

        if (function->hasPersonalityFn())
        {
            auto* personality = dyn_cast<Function>(
                function->getPersonalityFn()->stripPointerCastsAndAliases()
            );
            if (personality != nullptr)
            {
                worklist.push_back(personality);
            }
        }
    }

    SmallVector<Function*, 32> unreachable_functions;
    SmallPtrSet<Function*, 32> unreachable_function_set;

    for (auto& function : module)
    {
        if (!reachable_functions.contains(&function))
        {
            unreachable_functions.push_back(&function);
            unreachable_function_set.insert(&function);
        }
    }

    auto is_special_global = [](StringRef name)
    {
        return name == "llvm.global.ctors" ||
            name == "llvm.global.dtors" ||
            name == "llvm.used" ||
            name == "llvm.compiler.used" ||
            name == "llvm.global.annotations";
    };

    FunctionReferenceIndex references(unreachable_function_set);

    SmallVector<GlobalVariable*, 8> special_globals;
    for (auto& global : module.globals())
    {
        if (is_special_global(global.getName()))
        {
            special_globals.push_back(&global);
        }
    }

    for (auto* global : special_globals)
    {
        auto* array = dyn_cast<ConstantArray>(global->getInitializer());
        if (array == nullptr)
        {
            continue;
        }

        SmallVector<Constant*, 32> retained;
        retained.reserve(array->getNumOperands());
        bool changed = false;

        for (Value* operand : array->operands())
        {
            auto* element = cast<Constant>(operand);
            if (references.contains_unreachable(element))
            {
                changed = true;
                continue;
            }

            retained.push_back(element);
        }

        if (!changed)
        {
            continue;
        }

        auto* new_array_type = ArrayType::get(
            array->getType()->getElementType(),
            retained.size()
        );
        auto* new_initializer = ConstantArray::get(new_array_type, retained);
        auto* replacement = new GlobalVariable(
            module,
            new_array_type,
            global->isConstant(),
            global->getLinkage(),
            new_initializer,
            "",
            global,
            global->getThreadLocalMode(),
            global->getAddressSpace(),
            global->isExternallyInitialized()
        );
        replacement->copyAttributesFrom(global);
        replacement->takeName(global);
        global->replaceAllUsesWith(replacement);
        global->eraseFromParent();
    }

    for (auto* function : unreachable_functions)
    {
        function->dropAllReferences();
    }

    bool erased_alias = false;
    do
    {
        erased_alias = false;
        SmallVector<GlobalAlias*, 8> dead_aliases;

        for (auto& alias : module.aliases())
        {
            auto* aliasee = dyn_cast<Function>(
                alias.getAliasee()->stripPointerCastsAndAliases()
            );

            if (aliasee != nullptr &&
                unreachable_function_set.contains(aliasee) &&
                !references.has_live_use(&alias))
            {
                dead_aliases.push_back(&alias);
            }
        }

        for (auto* alias : dead_aliases)
        {
            alias->eraseFromParent();
            erased_alias = true;
        }

        if (erased_alias)
        {
            references.clear_live_use_cache();
        }
    } while (erased_alias);

    for (auto& alias : module.aliases())
    {
        auto* aliasee = dyn_cast<Function>(
            alias.getAliasee()->stripPointerCastsAndAliases()
        );

        if (aliasee == nullptr || !unreachable_function_set.contains(aliasee))
        {
            continue;
        }

        if (!references.has_live_use(&alias))
        {
            continue;
        }

        std::string message;
        raw_string_ostream stream(message);
        stream << "Unreachable function still has an alias reference\n";
        stream << "Function: " << aliasee->getName() << "\n";
        stream << "Alias: ";
        alias.print(stream);
        stream << "\n";
        report_fatal_error(stream.str().c_str());
    }

    for (auto* function : unreachable_functions)
    {
        if (references.has_live_use(function))
        {
            std::string message;
            raw_string_ostream stream(message);
            stream << "Unreachable function still has a reference\n";
            stream << "Function: " << function->getName() << "\n";
            stream << "Use: ";
            for (User* user : function->users())
            {
                if (isa<Instruction>(user) ||
                    isa<GlobalVariable>(user) ||
                    isa<GlobalAlias>(user) ||
                    isa<Function>(user))
                {
                    user->print(stream);
                    break;
                }
            }
            stream << "\n";
            report_fatal_error(stream.str().c_str());
        }

        if (!function->use_empty())
        {
            function->replaceAllUsesWith(UndefValue::get(function->getType()));
        }

        function->eraseFromParent();
    }
}


void ToShellCodePass::collect_entry_function(Module& M)
{
    auto* annotations = M.getGlobalVariable("llvm.global.annotations");

    if (!annotations) 
    {
        LOG("No annotations found");
        return;
    }

    auto* arr = dyn_cast<ConstantArray>(annotations->getInitializer());
    if (!arr) 
    {
        LOG("No annotations found");
        return;
    }

    for (size_t i = 0; i < arr->getNumOperands(); i++) 
    {
        auto* annotation = dyn_cast<ConstantStruct>(arr->getOperand(i));

        if (!annotation) 
        {
            continue;
        }
        
        auto* str = dyn_cast<GlobalVariable>( annotation->getOperand(1)->stripPointerCastsAndAliases());
        auto* target_func = dyn_cast<Function>(annotation->getOperand(0)->stripPointerCastsAndAliases());
        
        if (!str || !target_func) 
        {
            continue;
        }

        if (!str->hasInitializer()) 
        {
            continue;
        }

        auto* seq = dyn_cast<ConstantDataSequential>(str->getInitializer());
        if (!seq || !seq->isString()) 
        {
            continue;
        }

        if (seq->getAsString().starts_with("shellcode")) 
        {
            _entry_functions.insert(target_func);
        }
    }
}

void ToShellCodePass::collect_chain_function(Function* func)
{
    if (func == nullptr || func->isDeclaration()) 
    {
        return;
    }

    if (_chain_functions.contains(func)) 
    {
        return;
    }

    _chain_functions.insert(func);

    check_function_escaped(func);

    for (auto& BB : *func)
    {
        for (auto& inst : BB) 
        {
            if (auto* call = dyn_cast<CallBase>(&inst))
            {
                if (isa<CallBrInst>(call))
                {
                    report_unsupported_call(call);
                }

                if (Function* callee = get_direct_callee(call))
                {
                    collect_chain_function(callee);
                }
            }
        }
    }
}

void ToShellCodePass::check_function_escaped(Function* func)
{
    if (func == nullptr || func->isDeclaration()) 
    {
        return;
    }

    SmallPtrSet<User*, 16> visited;

    for (Use& use : func->uses())
    {
        if (is_supported_function_use(func, use, visited))
        {
            continue;
        }

        report_function_escape(func, use.getUser());
    }
}

Function* ToShellCodePass::get_direct_callee(CallBase* call)
{
    if (call == nullptr || call->isInlineAsm())
    {
        return nullptr;
    }

    return dyn_cast<Function>(
        call->getCalledOperand()->stripPointerCastsAndAliases()
    );
}

bool ToShellCodePass::is_supported_function_use(
    Function* func,
    Use& use,
    SmallPtrSetImpl<User*>& visited
)
{
    User* user = use.getUser();

    if (auto* call = dyn_cast<CallBase>(user))
    {
        if (!call->isCallee(&use) || get_direct_callee(call) != func)
        {
            return false;
        }

        if (isa<CallBrInst>(call))
        {
            report_unsupported_call(call);
        }

        return true;
    }

    if (is_allowed_metadata_use(user))
    {
        return true;
    }

    auto* value = dyn_cast<Value>(user);
    if (value == nullptr || value->stripPointerCastsAndAliases() != func)
    {
        return false;
    }

    if (!visited.insert(user).second)
    {
        return true;
    }

    for (Use& nested_use : user->uses())
    {
        if (!is_supported_function_use(func, nested_use, visited))
        {
            return false;
        }
    }

    return true;

}

bool ToShellCodePass::is_allowed_metadata_use(User* user)
{
    if (auto* gv = dyn_cast<GlobalVariable>(user)) 
    {
        StringRef name = gv->getName();

        if (name == "llvm.global.annotations" ||
            name == "llvm.global.ctors" ||
            name == "llvm.global.dtors" ||
            name == "llvm.used" ||
            name == "llvm.compiler.used")
        {
            return true;
        }
    }

    if (auto* constant = dyn_cast<Constant>(user)) 
    {
        for (auto& u : constant->uses()) 
        {
            if (is_allowed_metadata_use(u.getUser()))
            {
                return true;
            }
        }
    }

    return false;
}

void ToShellCodePass::report_function_escape(Function* func, User* user)
{
    std::string Message;
    raw_string_ostream OS(Message);

    OS << "Function pointer escape detected\n";
    OS << "Function: " << func->getName() << "\n";
    OS << "Use: ";

    if (auto* I = dyn_cast<Instruction>(user))
    {
        OS << "\n";
        I->print(OS);
        OS << "\n";
    }
    else
    {
        user->print(OS);
        OS << "\n";
    }

    report_fatal_error(OS.str().c_str());
}

void ToShellCodePass::report_unsupported_call(CallBase* call)
{
    std::string message;
    raw_string_ostream stream(message);

    stream << "Unsupported call instruction detected\n";
    stream << "Instruction: ";
    call->print(stream);
    stream << "\n";

    report_fatal_error(stream.str().c_str());
}

void ToShellCodePass::report_unsupported_global_variable(GlobalVariable* gv)
{
     std::string Message;
    raw_string_ostream OS(Message);

    OS << "Unsupported global variable detected\n";
    OS << "Global variable: " << gv->getName() << "\n";

    report_fatal_error(OS.str().c_str());
}


void ToShellCodePass::collect_global_variables()
{
    for (auto* func : _chain_functions)
    {
        for (auto& BB : *func) 
        {
            for (auto& inst : BB) 
            {
                for (auto& use : inst.operands()) 
                {
                    auto value = use.get();

                    if (auto* c = dyn_cast<ConstantExpr>(value)) 
                    {
                        for (auto* gv : expand_constant_expr_to_global_variables(c))
                        {
                            if (is_valid_global_variable(gv))
                            {
                                _global_variables.insert(gv);
                            }
                        }
                        continue;
                    }

                    value = value->stripPointerCastsAndAliases();
                    if (auto* gv = dyn_cast<GlobalVariable>(value)) 
                    {
                        if (is_valid_global_variable(gv)) 
                        {
                            _global_variables.insert(gv);
                        }
                    }
                }
            }
        }
    }
}

bool ToShellCodePass::is_valid_global_variable(GlobalVariable* gv)
{
    if (gv == nullptr) 
    {
        return false;
    }

    if (gv->isThreadLocal())  
    {
        return false;
    }

    if (!gv->hasInitializer()) 
    {
        return false;
    }

    auto Name = gv->getName();
    if (Name.starts_with("llvm.")) 
    {
        return false;
    }

    return true;
}

void ToShellCodePass::build_global_variable_info(Module& M)
{
    SmallVector<Type*, 64> field_types;

    field_types.reserve(_global_variables.size());

    for (auto* gv : _global_variables) 
    {
        Type* type = gv->getValueType();
        _global_variable_info.field_index[gv] = field_types.size();
        field_types.push_back(type);
    }

    for (auto& [name, func_type] : _declare_call_functions)
    {
        _declare_call_functions_index[name] = field_types.size();
        field_types.push_back(PointerType::get(func_type, 0));
    }

    auto type = StructType::create(
        M.getContext(),
        field_types,
        "global_variable_info"
    );

    _global_variable_info.type = type;
}

void ToShellCodePass::add_global_variable_alloca(Function* func)
{
    auto& entry = func->getEntryBlock();

    IRBuilder<> builder(&*entry.getFirstInsertionPt());

    auto alloc = builder.CreateAlloca(_global_variable_info.type, nullptr, "global_variable_info");
    
    alloc->setAlignment(Align(8));

    _global_variable_info_alloc[func] = alloc;



    add_declare_call_ctx_initializer(func);
    add_global_variable_ctx_initializer(func);
}

void ToShellCodePass::add_global_variable_ctx_initializer(Function* func)
{
    auto it = _global_variable_info_alloc.find(func);
    if (it == _global_variable_info_alloc.end())
    {
        return;
    }

    auto* alloc = it->second;
    
    IRBuilder<> builder(alloc->getNextNode());

    ConstantToStackEmitter emitter(builder, func->getParent()->getDataLayout());

    for (auto* gv : _global_variables)
    {
        auto it = _global_variable_info.field_index.find(gv);
        if (it == _global_variable_info.field_index.end())
        {
            continue;
        }

        auto field_index = it->second;

        Type* type = gv->getValueType();

        Value* value = builder.CreateStructGEP(
            _global_variable_info.type, 
            alloc, 
            field_index,
            gv->getName() + ".ptr"
        );

        auto* constant = gv->getInitializer();
        if (constant == nullptr)
        {
            continue;
        }

        if (!emitter.emit_constant_initializer(constant, value))
        {
            report_unsupported_global_variable(gv);
            return;
        }
    }

}

void ToShellCodePass::add_declare_call_ctx_initializer(Function* func)
{
    auto it = _global_variable_info_alloc.find(func);
    if (it == _global_variable_info_alloc.end())
    {
        return;
    }

    auto* resolve_api = _api_resolver;

    auto* alloc = it->second;
    IRBuilder<> builder(alloc->getNextNode());

    for (auto& [name, func_type] : _declare_call_functions) 
    {
        auto field_index = _declare_call_functions_index[name];
        auto* resolver_type = resolve_api->getFunctionType();
        auto* hash_type = cast<IntegerType>(resolver_type->getParamType(0));
        Value* hash = builder.getIntN(
            hash_type->getBitWidth(),
            gvr_djb2(name)
        );
        Value* resolved_address = builder.CreateCall(resolve_api, {hash});
        Value* func_ptr = builder.CreateIntToPtr(
            resolved_address,
            PointerType::get(func_type, 0),
            name + ".resolved"
        );
        Value* ctx_ptr = builder.CreateStructGEP(
            _global_variable_info.type, 
            alloc, 
            field_index,
            name + ".ptr"
        );
        builder.CreateStore(func_ptr, ctx_ptr);
    }
}

std::string ToShellCodePass::validate_api_resolver(Module& module)
{
    _api_resolver = nullptr;

    if (_declare_call_functions.empty())
    {
        return {};
    }

    constexpr StringLiteral resolver_name("?resolve_api@@YA_K_K@Z");
    const unsigned pointer_bits = module.getDataLayout().getPointerSizeInBits(0);
    if (pointer_bits == 0)
    {
        return (Twine("external declaration calls require resolver ") +
            resolver_name + ": target DataLayout has no pointer width").str();
    }

    const std::string expected_signature =
        (Twine("i") + Twine(pointer_bits) + " (i" +
         Twine(pointer_bits) + ")").str();

    auto* resolver = module.getFunction(resolver_name);
    if (resolver == nullptr)
    {
        return (Twine("missing required resolver ") + resolver_name +
            "; expected signature " + expected_signature).str();
    }

    std::string actual_signature;
    raw_string_ostream actual_stream(actual_signature);
    resolver->getFunctionType()->print(actual_stream);
    actual_stream.flush();

    auto fail = [&](StringRef reason)
    {
        return (Twine("invalid resolver ") + resolver_name +
            "; expected signature " + expected_signature +
            "; actual signature " + actual_signature +
            "; reason: " + reason).str();
    };

    auto* resolver_type = resolver->getFunctionType();
    if (resolver->isDeclaration())
    {
        return fail("resolver must have a function body");
    }
    if (resolver_type->isVarArg())
    {
        return fail("resolver must not be variadic");
    }
    if (resolver_type->getNumParams() != 1)
    {
        return fail("resolver must take exactly one integer parameter");
    }
    if (!resolver_type->getParamType(0)->isIntegerTy(pointer_bits))
    {
        return fail("resolver parameter width must match the target pointer width");
    }
    if (!resolver_type->getReturnType()->isIntegerTy(pointer_bits))
    {
        return fail("resolver return width must match the target pointer width");
    }

    _api_resolver = resolver;
    return {};
}


Function* ToShellCodePass::add_function_parameter(Function* func, Type* type)
{
    if (func == nullptr || type == nullptr) 
    {
        return nullptr;
    }

    auto* func_type = func->getFunctionType();

    SmallVector<Type*, 8> new_params(func_type->param_begin(), func_type->param_end());
    new_params.push_back(type);

    auto* new_func_type = FunctionType::get(
        func_type->getReturnType(),
        new_params,
        func_type->isVarArg()
    );

    auto* new_func = Function::Create(
        new_func_type,
        func->getLinkage(),
        func->getName() + ".ctx",
        func->getParent()
    );

    new_func->copyAttributesFrom(func);
    new_func->setCallingConv(func->getCallingConv());

    if (func->hasPersonalityFn())
    {
        new_func->setPersonalityFn(func->getPersonalityFn());
    }

    ValueToValueMapTy value_map;
    auto new_arg_it = new_func->arg_begin();
    for (auto& arg : func->args())
    {
        new_arg_it->setName(arg.getName());
        value_map[&arg] = &*new_arg_it;
        new_arg_it++;
    }

    new_arg_it->setName("ctx");

    SmallVector<ReturnInst*, 8> returns;

    CloneFunctionInto(
        new_func, func, value_map, CloneFunctionChangeType::LocalChangesOnly, returns
    );

    return new_func;
}

void ToShellCodePass::remap_call_sites()
{
    SmallVector<CallBase*, 64> calls;

    SmallVector<Function*, 64> funcs;

    funcs.append(_entry_functions.begin(), _entry_functions.end());
    funcs.append(_chain_with_ctx_functions.values().begin(), _chain_with_ctx_functions.values().end());

    for (auto* func : funcs)
    {
        if (func->isDeclaration()) 
        {
            continue;
        }

        for (auto& BB : *func) 
        {
            for (auto& inst : BB) 
            {
                if (auto* call = dyn_cast<CallBase>(&inst))
                {
                    if (isa<CallBrInst>(call))
                    {
                        report_unsupported_call(call);
                    }

                    Function* callee = get_direct_callee(call);
                    if (callee == nullptr) 
                    {
                        continue;
                    }

                    if (!_chain_with_ctx_functions.contains(callee))
                    {
                        continue;
                    }

                    calls.push_back(call);
                }
            }
        }
    }

    for (auto* old_call : calls) 
    {
        if (old_call == nullptr) 
        {
            continue;
        }

        Function* caller = old_call->getFunction();
        Function* old_callee = get_direct_callee(old_call);

        if (caller == nullptr || old_callee == nullptr)
        {
            continue;
        }

        if (!_function_ctx_ptr.contains(caller)) 
        {
            continue;
        }

        auto* new_callee = _chain_with_ctx_functions[old_callee];
        auto* ctx = _function_ctx_ptr[caller];

        if (new_callee == nullptr || ctx == nullptr) 
        {
            continue;
        }

        SmallVector<Value*, 16> args(old_call->arg_begin(), old_call->arg_end());
        args.push_back(ctx);

        SmallVector<OperandBundleDef, 4> operand_bundles;
        old_call->getOperandBundlesAsDefs(operand_bundles);

        IRBuilder<> builder(old_call);
        CallBase* new_call = nullptr;

        if (auto* old_invoke = dyn_cast<InvokeInst>(old_call))
        {
            new_call = builder.CreateInvoke(
                new_callee->getFunctionType(),
                new_callee,
                old_invoke->getNormalDest(),
                old_invoke->getUnwindDest(),
                args,
                operand_bundles
            );
        }
        else if (auto* old_plain_call = dyn_cast<CallInst>(old_call))
        {
            auto* new_plain_call = builder.CreateCall(
                new_callee->getFunctionType(),
                new_callee,
                args,
                operand_bundles
            );
            new_plain_call->setTailCallKind(old_plain_call->getTailCallKind());
            new_call = new_plain_call;
        }
        else
        {
            report_unsupported_call(old_call);
        }

        new_call->setCallingConv(old_call->getCallingConv());
        new_call->setAttributes(old_call->getAttributes());
        new_call->setDebugLoc(old_call->getDebugLoc());
        new_call->copyMetadata(*old_call);
        new_call->takeName(old_call);

        if (!old_call->getType()->isVoidTy())
        {
            old_call->replaceAllUsesWith(new_call);
        }

        old_call->eraseFromParent();
    }

    return;
}

void ToShellCodePass::replace_global_variable_accesses() 
{
    SmallVector<Function*, 64> funcs;

    funcs.append(_entry_functions.begin(), _entry_functions.end());
    funcs.append(_chain_with_ctx_functions.values().begin(), _chain_with_ctx_functions.values().end());

    for (auto* func : funcs)
    {
        if (func->isDeclaration()) 
        {
            continue;
        }

        for (auto& BB : *func) 
        {
            for (auto& inst : BB) 
            {
                for (size_t i = 0; i < inst.getNumOperands(); i++) 
                {
                    if (auto* gv = dyn_cast<GlobalVariable>(inst.getOperand(i))) 
                    {
                        Value* replacement = get_global_variable_ctx_ptr(func, gv, &inst);
                        if (replacement) 
                        {
                            inst.setOperand(i, replacement);
                        }
                        continue;
                    }

                    if (auto* c = dyn_cast<Constant>(inst.getOperand(i))) 
                    {
                        Value* replacement = materialize_value(c, func, &inst);
                        if (replacement) 
                        {
                            inst.setOperand(i, replacement);
                        }
                        continue;
                    }
                }
            }
        }
    }
}

void ToShellCodePass::replace_declare_call()
{
    SmallVector<Function*, 64> funcs;

    funcs.append(_entry_functions.begin(), _entry_functions.end());
    funcs.append(_chain_with_ctx_functions.values().begin(), _chain_with_ctx_functions.values().end());

    for (auto* func : funcs)
    {
        for (auto& BB : *func) 
        {
            for (auto& inst : BB) 
            {
                if (auto* call = dyn_cast<CallBase>(&inst))
                {
                    if (isa<CallBrInst>(call))
                    {
                        report_unsupported_call(call);
                    }

                    Function* callee = get_direct_callee(call);

                    if (callee == nullptr) 
                    {
                        continue;
                    }

                    if (callee->isIntrinsic()) 
                    {
                        continue;
                    }

                    if (!callee->isDeclaration()) 
                    {
                        continue;
                    }

                    Value* func_ptr = get_declare_call_ctx_ptr(func, callee->getName().str(), &inst);
                    call->setCalledFunction(callee->getFunctionType(), func_ptr);
                }
            }
        }
    }
}

void ToShellCodePass::replace_store_vector()
{
    SmallVector<Function*, 64> funcs;

    funcs.append(_entry_functions.begin(), _entry_functions.end());
    funcs.append(_chain_with_ctx_functions.values().begin(), _chain_with_ctx_functions.values().end());

    SmallVector<Instruction*, 64> stores;

    for (auto* func : funcs)
    {
        for (auto& BB : *func) 
        {
            for (auto& inst : BB) 
            {
                if (auto* store = dyn_cast<StoreInst>(&inst)) 
                {
                    if (auto* c = dyn_cast<ConstantDataSequential>(store->getValueOperand()))
                    {
                        IRBuilder<> builder(store->getNextNode());
                        ConstantToStackEmitter emitter(builder, func->getParent()->getDataLayout());

                        emitter.emit_constant_initializer(c, store->getPointerOperand());

                        stores.push_back(store);
                    }
                }
            }
        }
    }

    for (auto* s : stores) 
    {
        s->eraseFromParent();
    }
}

Value* ToShellCodePass::get_global_variable_ctx_ptr(Function* func, GlobalVariable* gv, Instruction* insert_before)
{
    if (func == nullptr || gv == nullptr || insert_before == nullptr) 
    {
        return nullptr;
    }

    if (!_global_variable_info.field_index.contains(gv) || !_function_ctx_ptr.contains(func)) 
    {
        return nullptr;
    }

    auto field_index = _global_variable_info.field_index[gv];
    auto ctx = _function_ctx_ptr[func];

    IRBuilder<> builder(insert_before);

    return builder.CreateStructGEP(
        _global_variable_info.type,
        ctx,
        field_index,
        gv->getName() + ".ctx.ptr"
    );
}

Value* ToShellCodePass::get_declare_call_ctx_ptr(Function* func, std::string name, Instruction* insert_before)
{
    if (func == nullptr || insert_before == nullptr) 
    {
        return nullptr;
    }

    if (!_declare_call_functions_index.contains(name) || !_function_ctx_ptr.contains(func)) 
    {
        return nullptr;
    }

    auto field_index = _declare_call_functions_index[name];
    auto ctx = _function_ctx_ptr[func];

    IRBuilder<> builder(insert_before);

    Value* func_ptr = builder.CreateStructGEP(
        _global_variable_info.type,
        ctx,
        field_index,
        name + ".ctx.ptr"
    );

    return builder.CreateLoad(
        _global_variable_info.type->getTypeAtIndex(field_index),
        func_ptr
    );
}

SmallSetVector<GlobalVariable*, 32> ToShellCodePass::expand_constant_expr_to_global_variables(ConstantExpr* c)
{
    if (c == nullptr)
    {
        return {};
    }

    SmallSetVector<GlobalVariable*, 32> result;

    SmallVector<Value*, 16> worklist;

    worklist.push_back(c);

    while (!worklist.empty())
    {
        Value* v = worklist.pop_back_val();

        if (auto* gv = dyn_cast<GlobalVariable>(v)) 
        {
            result.insert(gv);
            continue;
        }

        if (auto* c = dyn_cast<Constant>(v)) 
        {
            for (size_t i = 0; i < c->getNumOperands(); ++i)
            {
                worklist.push_back(c->getOperand(i));
            }
        }
    }

    return result;
}

Value* ToShellCodePass::materialize_value(Value* c, Function* func, Instruction* insert_before)
{
    if (c == nullptr || func == nullptr || insert_before == nullptr) 
    {
        return nullptr;
    }

    if (auto* gv = dyn_cast<GlobalVariable>(c)) 
    {
        return get_global_variable_ctx_ptr(func, gv, insert_before);
    }

    if (auto* ce = dyn_cast<ConstantExpr>(c)) 
    {
        Instruction* inst = ce->getAsInstruction();
        
        for (unsigned i = 0; i < inst->getNumOperands(); ++i)
        {
            Value* operand = inst->getOperand(i);
            Value* new_op = materialize_value(operand, func, insert_before);
            if (new_op != nullptr) 
            {
                inst->setOperand(i, new_op);
            }
        }

        inst->insertBefore(insert_before);
        return inst;
    }

    return c;
}

void ToShellCodePass::collect_declare_call()
{
    SmallVector<Function*, 64> funcs;

    funcs.append(_entry_functions.begin(), _entry_functions.end());
    funcs.append(_chain_functions.begin(), _chain_functions.end());

    for (auto* func : funcs)
    {
        for (auto& BB : *func) 
        {
            for (auto& inst : BB) 
            {
                if (auto* call = dyn_cast<CallBase>(&inst))
                {
                    if (isa<CallBrInst>(call))
                    {
                        report_unsupported_call(call);
                    }

                    Function* callee = get_direct_callee(call);

                    if (callee == nullptr) 
                    {
                        continue;
                    }

                    if (callee->isIntrinsic()) 
                    {
                        continue;
                    }

                    if (!callee->isDeclaration()) 
                    {
                        continue;
                    }

                    _declare_call_functions[callee->getName()] = callee->getFunctionType();
                }
            }
        }
    }
}

uint64_t ToShellCodePass::gvr_djb2(StringRef name)
{
    uint64_t h = 5381;
    for (unsigned char c : name.bytes())
    {
        h = ((h << 5) + h) + c;
    }
    return h;
}
