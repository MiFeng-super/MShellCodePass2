#include "pch.h"
#include "ConstantToStackEmitter.h"

bool ConstantToStackEmitter::emit_constant_initializer(Constant* constant, Value* dst)
{
    if (constant == nullptr || dst == nullptr) 
    {
        return false;
    }

    Type* type = constant->getType();
    if (type == nullptr) 
    {
        return false;
    }

    return emit_constant(constant, dst, type);
}

bool ConstantToStackEmitter::emit_constant(Constant* constant, Value* dst, Type* type)
{
    if (constant == nullptr || dst == nullptr || type == nullptr) 
    {
        return false;
    }

    if (isa<UndefValue>(constant) || isa<PoisonValue>(constant)) 
    {
        return emit_zero(type, dst);
    }

    if (isa<ConstantAggregateZero>(constant)) 
    {
        return emit_zero(type, dst);
    }

    if (auto* c = dyn_cast<ConstantInt>(constant)) 
    {
        _builder.CreateStore(c, dst);
        return true;
    }

    if (auto* c = dyn_cast<ConstantFP>(constant)) 
    {
        _builder.CreateStore(c, dst);
        return true;
    }

    if (auto* c = dyn_cast<ConstantPointerNull>(constant)) 
    {
        _builder.CreateStore(c, dst);
        return true;
    }

    if (auto* c = dyn_cast<ConstantDataSequential>(constant)) 
    {
        return emit_data_sequential(c, dst, type);
    }

    if (auto* c = dyn_cast<ConstantStruct>(constant))
    {
        return emit_struct(c, dst, cast<StructType>(type));
    }

    if (auto* c = dyn_cast<ConstantArray>(constant))
    {
        return emit_array(c, dst, cast<ArrayType>(type));
    }

    if (auto* c = dyn_cast<ConstantVector>(constant))
    {
        return emit_vector(c, dst, cast<VectorType>(type));
    }

    if (auto* c = dyn_cast<ConstantExpr>(constant))
    {
        return emit_expr(c, dst, type);
    }

    return false;
}

bool ConstantToStackEmitter::emit_zero(Type* type, Value* dst)
{
    if (type == nullptr || dst == nullptr) 
    {
        return false;
    }

    auto size = _layout.getTypeAllocSize(type);
    return emit_zero_bytes(dst, size);
}   

bool ConstantToStackEmitter::emit_zero_bytes(Value* dst, size_t size)
{
    if (dst == nullptr)
    {
        return false;
    }

    if (size == 0)
    {
        return true;
    }

    size_t offset = 0; 

    while (offset < size) 
    {
        size_t remaining = size - offset;
        size_t width = choose_store_width(remaining);

        emit_store_int(dst, offset, 0, width);

        offset += width;
    }

    return true;
}

bool ConstantToStackEmitter::emit_data_sequential(ConstantDataSequential* constant, Value* dst, Type* type)
{
    if (constant == nullptr || dst == nullptr || type == nullptr) 
    {
        return false;
    }

    const size_t element_count = constant->getNumElements();
    const size_t element_size = constant->getElementByteSize();
    const size_t size = element_count * element_size;

    SmallVector<uint8_t, 64> buffer;
    buffer.reserve(size);

    Type* element_type = constant->getElementType();

    for (size_t i = 0; i < element_count; i++)
    {
        APInt bits(1, 0);

        if (element_type->isIntegerTy())
        {
            bits = constant->getElementAsAPInt(i);
        }
        else if (element_type->isFloatingPointTy())
        {
            bits = constant->getElementAsAPFloat(i).bitcastToAPInt();
        }
        else
        {
            return false;
        }

        if (bits.getBitWidth() != element_size * 8)
        {
            return false;
        }

        for (size_t byte_index = 0; byte_index < element_size; byte_index++)
        {
            const size_t bit_offset = _layout.isLittleEndian()
                ? byte_index * 8
                : (element_size - byte_index - 1) * 8;
            buffer.push_back(static_cast<uint8_t>(bits.extractBitsAsZExtValue(8, bit_offset)));
        }
    }

    size_t offset = 0;

    while (offset < size) 
    {
        size_t remaining = size - offset;
        size_t width = choose_store_width(remaining);

        if (!emit_store_int_form_buffer(dst, offset, buffer, width)) 
        {
            return false;
        }
        
        offset += width;
    }

    return true;
}

bool ConstantToStackEmitter::emit_store_int_form_buffer(Value* dst, size_t offset, ArrayRef<uint8_t> bytes, size_t width)
{
    if (dst == nullptr || bytes.empty() || width == 0 || offset + width > bytes.size())
    {
        return false;
    }

    uint64_t value = 0;

    if (_layout.isLittleEndian())
    {
        for (size_t i = 0; i < width; i++)
        {
            value |= static_cast<uint64_t>(bytes[offset + i]) << (i * 8);
        }
    }
    else
    {
        for (size_t i = 0; i < width; i++)
        {
            value = (value << 8) | bytes[offset + i];
        }
    }
    
    return emit_store_int(dst, offset, value, width);
}

bool ConstantToStackEmitter::emit_store_int(Value* dst, size_t offset, uint64_t value, size_t width)
{
    if (dst == nullptr) 
    {
        return false;
    }

    IntegerType* int_type = IntegerType::get(_builder.getContext(), width * 8);
    ConstantInt* c = ConstantInt::get(int_type, value);

    Value* ptr = dst;

    if (offset != 0) 
    {
        ptr = _builder.CreateGEP(
            Type::getInt8Ty(_builder.getContext()),
            ptr,
            _builder.getInt64(offset),
            "init.int.offset"
        );
    }

    auto store = _builder.CreateStore(c, ptr);
    store->setAlignment(Align(1));
    return true;
}

bool ConstantToStackEmitter::emit_struct(ConstantStruct* constant, Value* dst, StructType* type)
{
    if (constant == nullptr || dst == nullptr || type == nullptr) 
    {
        return false;
    }

    auto fields_number = type->getNumElements();

    for (size_t i = 0; i < fields_number; i++) 
    {
        auto field_constant = constant->getAggregateElement(i);

        if (field_constant == nullptr) 
        {
            return false;
        }

        Type* field_type = field_constant->getType();
        if (field_type == nullptr) 
        {
            return false;
        }

        Value* field_value = _builder.CreateStructGEP(type, dst, i, "init.field");

        if (!emit_constant(field_constant, field_value, field_type)) 
        {
            return false;
        }
    }

    return true;
}

bool ConstantToStackEmitter::emit_array(ConstantArray* constant, Value* dst, ArrayType* type)
{
    if (constant == nullptr || dst == nullptr || type == nullptr) 
    {
        return false;
    }

    auto size = type->getNumElements();
    auto element_type = type->getElementType();

    for (size_t i = 0; i < size; i++) 
    {
        auto element = constant->getAggregateElement(i);
        if (element == nullptr) 
        {
            return false;
        }

        Value* ptr = _builder.CreateGEP(
            element_type, 
            dst, 
            {
                _builder.getInt32(0),
                _builder.getInt32(i)
            }, 
            "init.elem");
            
        if (!emit_constant(element, ptr, element_type)) 
        {
            return false;
        }
    }

    return true;
}

bool ConstantToStackEmitter::emit_vector(ConstantVector* constant, Value* dst, VectorType* type)
{
    if (constant == nullptr || dst == nullptr || type == nullptr) 
    {
        return false;
    }

    Value* vector_value = PoisonValue::get(type);

    auto size = type->getElementCount().getKnownMinValue();
    auto element_type = type->getElementType();

    for (size_t i = 0; i < size; i++) 
    {
        auto element = constant->getAggregateElement(i);
        if (element == nullptr) 
        {
            return false;
        }   

        vector_value = _builder.CreateInsertElement(vector_value, element, _builder.getInt32(i), "init.vec");
        
    }

    _builder.CreateStore(vector_value, dst);

    return true;
}

bool ConstantToStackEmitter::emit_expr(ConstantExpr* constant, Value* dst, Type* type)
{
    report_fatal_error("ConstantExpr is not supported");
    return false;
}

size_t ConstantToStackEmitter::choose_store_width(size_t remaining)
{
    if (remaining >= 8) 
    {
        return 8;
    }
    else if (remaining >= 4) 
    {
        return 4;
    }
    else if (remaining >= 2) 
    {
        return 2;
    }
    return 1;
}

