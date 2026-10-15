#pragma once

#include "pch.h"

struct GlobalVariableInfo
{
    StructType* type;
    DenseMap<llvm::GlobalVariable*, unsigned> field_index;
};

class ToShellCodePass : public PassInfoMixin<ToShellCodePass>
{
public:
    PreservedAnalyses run(Module& M, ModuleAnalysisManager& MAM);

    static bool isRequired() { return true; }

    void collect_entry_function(Module& M);
    void collect_chain_function(Function* func);
    void check_function_escaped(Function* func);
    bool is_allowed_metadata_use(User* user);
    void report_function_escape(Function* func, User* user);
    void report_unsupported_global_variable(GlobalVariable* gv);
    void collect_global_variables();
    bool is_valid_global_variable(GlobalVariable* gv);

    void build_global_variable_info(Module& M);
    void add_global_variable_alloca(Function* func);
    void add_global_variable_ctx_initializer(Function* func);
    void add_declare_call_ctx_initializer(Function* func);
    void remap_call_sites();
    void replace_global_variable_accesses();
    void replace_declare_call();
    void replace_store_vector();

    Value* get_global_variable_ctx_ptr(Function* func, GlobalVariable* gv, Instruction* insert_before);
    Value* get_declare_call_ctx_ptr(Function* func, std::string name, Instruction* insert_before);

    SmallSetVector<GlobalVariable*, 32> expand_constant_expr_to_global_variables(ConstantExpr* c);

    Value* materialize_value(Value* c, Function* func, Instruction* insert_before);
    void collect_declare_call();

    Function* add_function_parameter(Function* func, Type* type);

    uint64_t gvr_djb2(const char *s);
    

public:
    SmallSetVector<Function*, 8>   _entry_functions;
    SmallSetVector<Function*, 32>  _chain_functions;

    DenseMap<StringRef, FunctionType*>  _declare_call_functions;
    DenseMap<StringRef, unsigned>  _declare_call_functions_index;

    SmallSetVector<GlobalVariable*, 32> _global_variables;

    GlobalVariableInfo _global_variable_info;
    DenseMap<Function*, AllocaInst*> _global_variable_info_alloc;
    DenseMap<Function*, Function*> _chain_with_ctx_functions;
    DenseMap<Function*, Value*> _function_ctx_ptr;
};
