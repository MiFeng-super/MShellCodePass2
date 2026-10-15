#pragma once

#include "pch.h"


class ConstantToStackEmitter
{
public:
    ConstantToStackEmitter(IRBuilder<>& builder, const DataLayout& layout) 
        : _builder(builder), _layout(layout) {}

    ~ConstantToStackEmitter() = default;

public:
    bool emit_constant_initializer(Constant* constant, Value* dst);

private:
    bool emit_constant(Constant* constant, Value* dst, Type* type);

    bool emit_zero(Type* type, Value* dst);
    bool emit_zero_bytes(Value* dst, size_t size);
    bool emit_data_sequential(ConstantDataSequential* constant, Value* dst, Type* type);
    bool emit_store_int_form_buffer(Value* dst, size_t offset, ArrayRef<uint8_t> bytes, size_t width);
    bool emit_store_int(Value* dst, size_t offset, uint64_t value, size_t width = 1);
    bool emit_struct(ConstantStruct* constant, Value* dst, StructType* type);
    bool emit_array(ConstantArray* constant, Value* dst, ArrayType* type);
    bool emit_vector(ConstantVector* constant, Value* dst, VectorType* type);
    bool emit_expr(ConstantExpr* constant, Value* dst, Type* type);

    size_t choose_store_width(size_t remaining);

private:
    IRBuilder<>& _builder;
    const DataLayout& _layout;
};
