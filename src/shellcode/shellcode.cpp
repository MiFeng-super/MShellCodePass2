#include "pch.h"
#include "shellcode.h"
#include "ConstantToStackEmitter.h"

PreservedAnalyses ToShellCodePass::run(Module& M, ModuleAnalysisManager& MAM)
{
    LOG("Running on module: {}", M.getName().str());

    // Collect entry functions
    collect_entry_function(M);
    
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

    for (auto* func : _chain_with_ctx_functions.keys()) 
    {
        func->eraseFromParent();
    }

    for (auto& func : llvm::make_early_inc_range(M.getFunctionList())) 
    {
        if (func.isIntrinsic()) 
        {
            continue;
        }

        if (func.isDeclaration()) 
        {
            continue;
        }

        if (func.use_empty() && !func.getName().contains("main")) 
        {
            func.eraseFromParent();
        }
    }

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

    check_function_escaped(func);

    for (auto& BB : *func)
    {
        for (auto& inst : BB) 
        {
            if (auto* call = dyn_cast<CallInst>(&inst)) 
            {
                // 直接调用
                if (Function* callee = call->getCalledFunction()) 
                {
                    collect_chain_function(callee);
                    continue;
                }
            }
        }
    }

    _chain_functions.insert(func);
}

void ToShellCodePass::check_function_escaped(Function* func)
{
    if (func == nullptr || func->isDeclaration()) 
    {
        return;
    }

    for (Use& use : func->uses()) 
    {
        User* user = use.getUser();

        if (auto* call = dyn_cast<CallInst>(user)) 
        {
            if (call->getCalledFunction() == func) 
            {
                continue;
            }
        }

        if (is_allowed_metadata_use(user))
        {
            continue;
        }

        report_function_escape(func, user);
    }

}

bool ToShellCodePass::is_allowed_metadata_use(User* user)
{
    if (auto* gv = dyn_cast<GlobalVariable>(user)) 
    {
        StringRef name = gv->getName();

        if (name == "llvm.global.annotations" || name == "llvm.used")
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

    auto* resolve_api = func->getParent()->getFunction("?resolve_api@@YA_K_K@Z");
    if (resolve_api == nullptr)
    {
        return;
    }

    auto* alloc = it->second;
    IRBuilder<> builder(alloc->getNextNode());

    for (auto& [name, func_type] : _declare_call_functions) 
    {
        auto field_index = _declare_call_functions_index[name];
        Value* func_ptr = builder.CreateCall(resolve_api, { builder.getInt64(gvr_djb2(name.data())) });
        Value* ctx_ptr = builder.CreateStructGEP(
            _global_variable_info.type, 
            alloc, 
            field_index,
            name + ".ptr"
        );
        builder.CreateStore(func_ptr, ctx_ptr);
    }
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
    SmallVector<CallInst*, 64> calls;

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
                if (auto* call = dyn_cast<CallInst>(&inst)) 
                {
                    Function* callee = call->getCalledFunction();
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
        Function* old_callee = old_call->getCalledFunction();

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

        IRBuilder<> builder(old_call);
        CallInst* new_call = builder.CreateCall(
            new_callee,
            args
        );

        if (old_call->hasName())
        {
            new_call->setName(old_call->getName());
        }

        new_call->setCallingConv(old_call->getCallingConv());
        new_call->setTailCallKind(old_call->getTailCallKind());

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
                if (auto* call = dyn_cast<CallInst>(&inst)) 
                {
                    Function* callee = call->getCalledFunction();

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
                if (auto* call = dyn_cast<CallInst>(&inst)) 
                {
                    Function* callee = call->getCalledFunction();

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

uint64_t ToShellCodePass::gvr_djb2(const char *s)
{
    uint64_t h = 5381;
    while (*s) h = ((h << 5) + h) + (unsigned char)(*s++);
    return h;
}
