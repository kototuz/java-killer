#include <stdio.h>

#define NOB_IMPLEMENTATION
#include "jvm_class.h"

#define write_bytes(file, ptr, size) (assert(fwrite(ptr, 1, size, file) == size))

#define CODE_ATTR_NAME_IDX            1
#define STACK_MAP_TABLE_ATTR_NAME_IDX 2



JcClass jc_new(String_View class_name)
{
    JcClass c = {0};

    // Push attribute names now to reuse it later
    jc_cp_push_utf8(&c, SV_STATIC("Code"));
    jc_cp_push_utf8(&c, SV_STATIC("StackMapTable"));

    c.this_class = jc_cp_push_class(&c, class_name);

    // Default parameters for convenience
    c.super_class = jc_cp_push_class(&c, SV_STATIC("java/lang/Object"));
    c.minor_version = 0;
    c.major_version = 64;
    c.access_flags = JC_ACCESS_FLAG_SUPER;

    return c;
}

JcMethod *jc_method_new(
        JcClass *c,
        String_View name,
        String_View descriptor,
        JcLocalDef *local_defs,
        uint16_t local_def_count,
        uint16_t arg_count)
{
    JcMethod m = {0};
    m.name_index = jc_cp_push_utf8(c, name);
    m.descriptor_index = jc_cp_push_utf8(c, descriptor);
    m.max_locals = local_def_count;

    { // Create the method frame
        m.stack_map_frames.count = 1;

        da_append(&m.stack_map_frames.bytes, 255); // full frame type

        // integer:
        //   0: iconst_0
        //   1: istore <n>
        //   3: ...
        // object:
        //   0: astore_null
        //   1: astore <n>
        //   3: ...
        // ...
        // ...

        // Push offset
        uint16_t offset = 3 * (local_def_count - arg_count);
        da_append(&m.stack_map_frames.bytes, ((uint8_t*)&offset)[1]);
        da_append(&m.stack_map_frames.bytes, ((uint8_t*)&offset)[0]);

        m.stack_map_frames.last_frame_loc = offset;

        // Push definition count
        da_append(&m.stack_map_frames.bytes, ((uint8_t*)&local_def_count)[1]);
        da_append(&m.stack_map_frames.bytes, ((uint8_t*)&local_def_count)[0]);

        // Define local variable types for the method
        for (uint16_t i = 0; i < local_def_count; i++) {
            switch (local_defs[i].type) {
            case JC_LOCAL_TYPE_INT:
            case JC_LOCAL_TYPE_FLOAT:
                da_append(&m.stack_map_frames.bytes, local_defs[i].type);
                break;

            case JC_LOCAL_TYPE_DOUBLE:
            case JC_LOCAL_TYPE_LONG:
                da_append(&m.stack_map_frames.bytes, local_defs[i].type);
                m.max_locals += 1;
                break;

            case JC_LOCAL_TYPE_OBJECT:
                da_append(&m.stack_map_frames.bytes, 7); // push object type
                uint16_t class_idx = jc_cp_push_class(c, local_defs[i].as_object);
                da_append(&m.stack_map_frames.bytes, ((uint8_t*)&class_idx)[1]);
                da_append(&m.stack_map_frames.bytes, ((uint8_t*)&class_idx)[0]);
                break;

            default:
                UNREACHABLE("Unknown local type");
            }
        }

        // Push number of stack items
        da_append(&m.stack_map_frames.bytes, 0);
        da_append(&m.stack_map_frames.bytes, 0);

        // Initialize all local variables but arguments
        uint8_t local_index = arg_count;
        for (uint16_t i = arg_count; i < local_def_count; i++) {
            switch (local_defs[i].type) {
            case JC_LOCAL_TYPE_INT:
                jc_method_push_inst(&m, JC_INST_OPCODE_ICONST_0);
                jc_method_push_inst(&m, JC_INST_OPCODE_ISTORE, JC_OPERAND_U8(local_index));
                local_index += 1;
                break;

            case JC_LOCAL_TYPE_FLOAT:
                jc_method_push_inst(&m, JC_INST_OPCODE_FCONST_0);
                jc_method_push_inst(&m, JC_INST_OPCODE_FSTORE, JC_OPERAND_U8(local_index));
                local_index += 1;
                break;

            case JC_LOCAL_TYPE_DOUBLE:
                jc_method_push_inst(&m, JC_INST_OPCODE_DCONST_0);
                jc_method_push_inst(&m, JC_INST_OPCODE_DSTORE, JC_OPERAND_U8(local_index));
                local_index += 2;
                break;

            case JC_LOCAL_TYPE_LONG:
                jc_method_push_inst(&m, JC_INST_OPCODE_LCONST_0);
                jc_method_push_inst(&m, JC_INST_OPCODE_LSTORE, JC_OPERAND_U8(local_index));
                local_index += 2;
                break;

            case JC_LOCAL_TYPE_OBJECT:
                jc_method_push_inst(&m, JC_INST_OPCODE_ACONST_NULL);
                jc_method_push_inst(&m, JC_INST_OPCODE_ASTORE, JC_OPERAND_U8(local_index));
                local_index += 1;
                break;

            default:
                UNREACHABLE("Unknown local type");
            }
        }

        // Frames must not have offset as of the initialization frame.
        // If 'full_frame' has offset 3 and 'same_frame_extended' offset 3 then
        // following the formula 'frame_loc = prev_frame_loc + offset + 1' we got -1
        jc_method_push_inst(&m, JC_INST_OPCODE_NOP);
    }

    da_append(&c->methods, m);
    return &c->methods.items[c->methods.count-1];
}

void jc_method_push_inst_(JcMethod *m, JcInstOpcode opcode, JcInstOperand *operands, size_t operand_count)
{
    da_append(&m->code, (uint8_t)opcode);
    for (size_t i = 0; i < operand_count; i++) {
        switch (operands[i].tag) { 
        case JC_INST_OPERAND_TAG_U8:
            da_append(&m->code, operands[i].as_u8);
            break;

        case JC_INST_OPERAND_TAG_U16:
            da_append(&m->code, ((uint8_t*)&operands[i].as_u16)[1]);
            da_append(&m->code, ((uint8_t*)&operands[i].as_u16)[0]);
            break;

        case JC_INST_OPERAND_TAG_U32:
            da_append(&m->code, ((uint8_t*)&operands[i].as_u32)[3]);
            da_append(&m->code, ((uint8_t*)&operands[i].as_u32)[2]);
            da_append(&m->code, ((uint8_t*)&operands[i].as_u32)[1]);
            da_append(&m->code, ((uint8_t*)&operands[i].as_u32)[0]);
            break;

        default:
            UNREACHABLE("Unknown operand tag");
        }
    }
}

void jc_method_push_inst2_(JcMethod *m, JcInstOpcode opcode, JcInstOperand *operands, size_t operand_count)
{
    da_append(&m->code, (uint8_t)opcode);

    { // Push new frame if it is branching instruction
        assert(opcode < JC_INST_OPCODE_COUNT);

        // Calculate offset
        uint16_t offset;
        switch (opcode) { // offset = loc - prev_frame_loc -1
        case JC_INST_OPCODE_IF_ICMPNE:
        case JC_INST_OPCODE_GOTO: {
            assert(operand_count == 1 && operands[0].tag == JC_INST_OPERAND_TAG_U16);
            offset = (m->code.count + operands[0].as_u16 - 1) - m->stack_map_frames.last_frame_loc - 1;
            m->stack_map_frames.last_frame_loc = m->code.count + operands[0].as_u16;

            m->stack_map_frames.count += 1;
            da_append(&m->stack_map_frames.bytes, 251); // same frame extended
            da_append(&m->stack_map_frames.bytes, ((uint8_t*)&offset)[1]);
            da_append(&m->stack_map_frames.bytes, ((uint8_t*)&offset)[0]);
        } break;

        default:
        }
    }

    for (size_t i = 0; i < operand_count; i++) {
        switch (operands[i].tag) { 
        case JC_INST_OPERAND_TAG_U8:
            da_append(&m->code, operands[i].as_u8);
            break;

        case JC_INST_OPERAND_TAG_U16:
            da_append(&m->code, ((uint8_t*)&operands[i].as_u16)[1]);
            da_append(&m->code, ((uint8_t*)&operands[i].as_u16)[0]);
            break;

        case JC_INST_OPERAND_TAG_U32:
            da_append(&m->code, ((uint8_t*)&operands[i].as_u32)[3]);
            da_append(&m->code, ((uint8_t*)&operands[i].as_u32)[2]);
            da_append(&m->code, ((uint8_t*)&operands[i].as_u32)[1]);
            da_append(&m->code, ((uint8_t*)&operands[i].as_u32)[0]);
            break;

        default:
            UNREACHABLE("Unknown operand tag");
        }
    }
}

void jc_method_push_frame(JcMethod *m, uint32_t offset)
{
    assert(offset < m->code.count);
    uint16_t offset_from_prev = offset - m->stack_map_frames.last_frame_loc - 1;
    m->stack_map_frames.last_frame_loc = offset;
    m->stack_map_frames.count += 1;
    da_append(&m->stack_map_frames.bytes, 251); // same frame extended
    da_append(&m->stack_map_frames.bytes, ((uint8_t*)&offset_from_prev)[1]);
    da_append(&m->stack_map_frames.bytes, ((uint8_t*)&offset_from_prev)[0]);
}

uint16_t jc_cp_push_ref(
        JcClass *jc,
        JcConstantTag ref_kind,
        String_View class_name,
        String_View method_name,
        String_View descriptor)
{
    JcConstant c = {
        .tag = ref_kind,
        .as_ref = (JcConstantReference){
            .class_index = jc_cp_push_class(jc, class_name),
            .name_and_type_index = jc_cp_push_name_and_type(jc, method_name, descriptor)
        }
    };

    assert(jc->constant_pool.count < UINT16_MAX);
    da_append(&jc->constant_pool, c);

    jc->constant_pool.strange_count += 1;
    return jc->constant_pool.strange_count;
}

uint16_t jc_cp_push_name_and_type(JcClass *jc, String_View name, String_View descriptor)
{
    JcConstant c = {
        .tag = JC_CONSTANT_TAG_NAME_AND_TYPE,
        .as_name_and_type = (JcConstantNameAndType){
            .name_index = jc_cp_push_utf8(jc, name),
            .descriptor_index = jc_cp_push_utf8(jc, descriptor),
        }
    };

    assert(jc->constant_pool.count < UINT16_MAX);
    da_append(&jc->constant_pool, c);
    jc->constant_pool.strange_count += 1;
    return jc->constant_pool.strange_count;
}

uint16_t jc_cp_push_class(JcClass *jc, String_View class_name)
{
    JcConstant c = {
        .tag = JC_CONSTANT_TAG_CLASS,
        .as_class = (JcConstantClass){
            .name_index = jc_cp_push_utf8(jc, class_name)
        }
    };

    assert(jc->constant_pool.count < UINT16_MAX);
    da_append(&jc->constant_pool, c);
    jc->constant_pool.strange_count += 1;
    return jc->constant_pool.strange_count;
}

uint16_t jc_cp_push_utf8(JcClass *jc, String_View bytes)
{
    JcConstant c = {
        .tag = JC_CONSTANT_TAG_UTF8,
        .as_utf8 = (JcConstantUtf8){
            .length = bytes.count,
            .bytes = (uint8_t*)bytes.data,
        }
    };

    assert(jc->constant_pool.count < UINT16_MAX);
    da_append(&jc->constant_pool, c);
    jc->constant_pool.strange_count += 1;
    return jc->constant_pool.strange_count;
}

uint16_t jc_cp_push_string(JcClass *jc, String_View bytes)
{
    JcConstant c = {
        .tag = JC_CONSTANT_TAG_STRING,
        .as_string.string_index = jc_cp_push_utf8(jc, bytes)
    };

    assert(jc->constant_pool.count < UINT16_MAX);
    da_append(&jc->constant_pool, c);
    jc->constant_pool.strange_count += 1;
    return jc->constant_pool.strange_count;
}

uint16_t jc_cp_push_integer(JcClass *jc, int32_t n)
{
    JcConstant c = {
        .tag = JC_CONSTANT_TAG_INTEGER,
        .as_u32 = n,
    };

    assert(jc->constant_pool.count < UINT16_MAX);
    da_append(&jc->constant_pool, c);
    jc->constant_pool.strange_count += 1;
    return jc->constant_pool.strange_count;
}

uint16_t jc_cp_push_float(JcClass *jc, float n)
{
    JcConstant c = { .tag = JC_CONSTANT_TAG_FLOAT };
    memcpy(&c.as_u32, &n, sizeof(float));
    assert(jc->constant_pool.count < UINT16_MAX);
    da_append(&jc->constant_pool, c);
    jc->constant_pool.strange_count += 1;
    return jc->constant_pool.strange_count;
}

uint16_t jc_cp_push_long(JcClass *jc, int64_t n)
{
    JcConstant c = {
        .tag = JC_CONSTANT_TAG_LONG,
        .as_u64 = n,
    };

    assert(jc->constant_pool.count < UINT16_MAX);
    da_append(&jc->constant_pool, c);
    jc->constant_pool.strange_count += 2;
    return jc->constant_pool.strange_count - 1;
}

uint16_t jc_cp_push_double(JcClass *jc, double n)
{
    JcConstant c = { .tag = JC_CONSTANT_TAG_DOUBLE };
    memcpy(&c.as_u64, &n, sizeof(double));
    assert(jc->constant_pool.count < UINT16_MAX);
    da_append(&jc->constant_pool, c);
    jc->constant_pool.strange_count += 2;
    return jc->constant_pool.strange_count - 1;
}

void jc_cp_dump(JcClass jc)
{
    for (uint16_t i = 0; i < jc.constant_pool.count; i++) {
        JcConstant c = jc.constant_pool.items[i];
        switch (c.tag) {
        case JC_CONSTANT_TAG_INTERFACE_METHOD_REF:
            printf("#%-3d INTERFACE_METHOD_REF : class_index=%d, name_and_type_index=%d\n",
                   i+1, c.as_ref.class_index,
                   c.as_ref.name_and_type_index);
            break;
        case JC_CONSTANT_TAG_FIELD_REF:
            printf("#%-3d FIELD_REF            : class_index=%d, name_and_type_index=%d\n",
                   i+1, c.as_ref.class_index,
                   c.as_ref.name_and_type_index);
            break;
        case JC_CONSTANT_TAG_METHOD_REF:
            printf("#%-3d METHOD_REF           : class_index=%d, name_and_type_index=%d\n",
                   i+1, c.as_ref.class_index,
                   c.as_ref.name_and_type_index);
            break;

        case JC_CONSTANT_TAG_CLASS:
            printf("#%-3d CLASS                : name_index=%d\n", i+1, c.as_class.name_index);
            break;

        case JC_CONSTANT_TAG_NAME_AND_TYPE:
            printf("#%-3d NAME_AND_TYPE        : name_index=%d, descriptor_index=%d\n",
                   i+1, c.as_name_and_type.name_index,
                   c.as_name_and_type.descriptor_index);
            break;

        case JC_CONSTANT_TAG_UTF8:
            printf("#%-3d UTF8                 : bytes=\"%s\"\n", i+1, c.as_utf8.bytes);
            break;

        case JC_CONSTANT_TAG_STRING:
            printf("#%-3d STRING               : string_index=%d\n", i+1, c.as_string.string_index);
            break;

        case JC_CONSTANT_TAG_INTEGER:
            printf("#%-3d INTEGER              : bytes=%d\n", i+1, c.as_u32);
            break;

        case JC_CONSTANT_TAG_FLOAT:
            printf("#%-3d FLOAT                : bytes=%f\n", i+1, *(float*)&c.as_u32);
            break;

        case JC_CONSTANT_TAG_LONG:
            printf("#%-3d LONG                 : bytes=%ld\n", i+1, (long)c.as_u64);
            break;

        case JC_CONSTANT_TAG_DOUBLE:
            printf("#%-3d DOUBLE               : bytes=%f\n", i+1, *(double*)&c.as_u64);
            break;

        default:
            printf("%-3d\n", c.tag);
            UNREACHABLE("Unknown constant tag");
        }
    }
}

// Write big endian number as little endian. Yes C numbers are big endian
static void write_u16(FILE *f, uint16_t n)
{
    write_bytes(f, &((uint8_t*)&n)[1], 1);
    write_bytes(f, &((uint8_t*)&n)[0], 1);
}
static void write_u32(FILE *f, uint32_t n)
{
    write_bytes(f, &((uint8_t*)&n)[3], 1);
    write_bytes(f, &((uint8_t*)&n)[2], 1);
    write_bytes(f, &((uint8_t*)&n)[1], 1);
    write_bytes(f, &((uint8_t*)&n)[0], 1);
}
static void write_u64(FILE *f, uint64_t n)
{
    write_bytes(f, &((uint8_t*)&n)[7], 1);
    write_bytes(f, &((uint8_t*)&n)[6], 1);
    write_bytes(f, &((uint8_t*)&n)[5], 1);
    write_bytes(f, &((uint8_t*)&n)[4], 1);
    write_bytes(f, &((uint8_t*)&n)[3], 1);
    write_bytes(f, &((uint8_t*)&n)[2], 1);
    write_bytes(f, &((uint8_t*)&n)[1], 1);
    write_bytes(f, &((uint8_t*)&n)[0], 1);
}

bool jc_serialize(JcClass jc, const char *path)
{
    FILE *output = fopen(path, "w");
    if (output == NULL) {
        nob_log(ERROR, "Could not open '%s'", path);
        return false;
    }

    // Something like a header i can say
    write_u32(output, 0xcafebabe);
    write_u16(output, jc.minor_version);
    write_u16(output, jc.major_version);

    // Constant pool
    write_u16(output, jc.constant_pool.strange_count + 1);
    da_foreach(JcConstant, c, &jc.constant_pool) {
        write_bytes(output, &c->tag, 1);
        switch (c->tag) {
        case JC_CONSTANT_TAG_INTERFACE_METHOD_REF:
        case JC_CONSTANT_TAG_FIELD_REF:
        case JC_CONSTANT_TAG_METHOD_REF:
            write_u16(output, c->as_ref.class_index);
            write_u16(output, c->as_ref.name_and_type_index);
            break;

        case JC_CONSTANT_TAG_CLASS:
            write_u16(output, c->as_class.name_index);
            break;

        case JC_CONSTANT_TAG_NAME_AND_TYPE:
            write_u16(output, c->as_name_and_type.name_index);
            write_u16(output, c->as_name_and_type.descriptor_index);
            break;

        case JC_CONSTANT_TAG_UTF8:
            write_u16(output, c->as_utf8.length);
            write_bytes(output, c->as_utf8.bytes, c->as_utf8.length);
            break;

        case JC_CONSTANT_TAG_STRING:
            write_u16(output, c->as_string.string_index);
            break;

        case JC_CONSTANT_TAG_INTEGER:
        case JC_CONSTANT_TAG_FLOAT:
            write_u32(output, c->as_u32);
            break;

        case JC_CONSTANT_TAG_DOUBLE:
        case JC_CONSTANT_TAG_LONG:
            write_u64(output, c->as_u64);
            break;

        default:
            UNREACHABLE("Unknown constant tag");
        }
    }

    write_u16(output, jc.access_flags);
    write_u16(output, jc.this_class);
    write_u16(output, jc.super_class);

    // Interfaces
    write_u16(output, jc.interfaces.count);
    da_foreach(uint16_t, iface, &jc.interfaces) {
        write_u16(output, *iface);
    }

    // TODO: Implement fields
    write_u16(output, 0);

    // Method
    write_u16(output, jc.methods.count);
    da_foreach(JcMethod, m, &jc.methods) {
        write_u16(output, m->access_flags);
        write_u16(output, m->name_index);
        write_u16(output, m->descriptor_index);
        write_u16(output, 1); // Attributes count

        uint32_t code_attr_size = 18 + m->code.count;
        uint32_t stack_map_frames_attr_size = 2 + m->stack_map_frames.bytes.count;

        // 'Code' attribute
        write_u16(output, CODE_ATTR_NAME_IDX);
        write_u32(output, code_attr_size + stack_map_frames_attr_size); // Attribute length
        write_u16(output, m->max_stack);
        write_u16(output, m->max_locals);
        write_u32(output, m->code.count);
        write_bytes(output, m->code.items, m->code.count);
        write_u16(output, 0); // TODO: Exception table length
        write_u16(output, 1); // `StackMapFrame` attribute

        // 'StackMapTable' attribute of 'Code'
        write_u16(output, STACK_MAP_TABLE_ATTR_NAME_IDX);
        write_u32(output, stack_map_frames_attr_size);
        write_u16(output, m->stack_map_frames.count);
        write_bytes(output, m->stack_map_frames.bytes.items, m->stack_map_frames.bytes.count);
    }

    // Class file attributes
    write_u16(output, 0);

    fclose(output);
    return true;
}
