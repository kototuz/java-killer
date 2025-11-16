#include <stdio.h>
#include <float.h>

#define STB_C_LEXER_IMPLEMENTATION
#include <stb_c_lexer.h>

#include "jvm_class.h"

#define LOC_Fmt      "%d:%d"
#define LOC_Arg(loc) (loc).line_number, (loc).line_offset+1

typedef struct {
    JcLocalDef *items;
    uint16_t count;
    uint16_t capacity;
} LocalDefs;

typedef enum {
    OPERAND_TYPE_FIELD_REF,
    OPERAND_TYPE_METHOD_REF,
    OPERAND_TYPE_U8,
    OPERAND_TYPE_I8,
    OPERAND_TYPE_I16,
    OPERAND_TYPE_CLASS,
    OPERAND_TYPE_JMP_LABEL_U16,
    OPERAND_TYPE_JMP_LABEL_U32,
    OPERAND_TYPE_CONSTANT_INT_FLOAT_STRING_U8,  // int|float|string
    OPERAND_TYPE_CONSTANT_INT_FLOAT_STRING_U16, // int|float|string
    OPERAND_TYPE_CONSTANT_LONG_DOUBLE,          // long|double
} OperandType;

typedef struct {
    JcInstOpcode opcode;
    String_View opcode_name;
    OperandType *operand_types;
    size_t operand_type_count;
} Instruction;

typedef struct {
    JcInstOperand *items;
    size_t count;
    size_t capacity;
} Operands;

typedef struct {
    String_View name;
    uint32_t bytecode_offset;
} JmpLabel;

typedef struct {
    JmpLabel *items;
    size_t count;
    size_t capacity;
} JmpLabels;

typedef struct {
    String_View name;
    uint32_t bytecode_offset;
    char *where_firstchar;
    bool is_u32;
} JmpLabelRef;

typedef struct {
    JmpLabelRef *items;
    size_t count;
    size_t capacity;
} JmpLabelRefs;

#define OPERAND_TYPES(...) .operand_types = (OperandType[]){__VA_ARGS__}, .operand_type_count = sizeof((OperandType[]){__VA_ARGS__})/sizeof(OperandType)
static const Instruction instructions[] = {
    { .opcode = JC_INST_OPCODE_AALOAD,          .opcode_name = SV_STATIC("aaload") },
    { .opcode = JC_INST_OPCODE_AASTORE,         .opcode_name = SV_STATIC("aastore") },
    { .opcode = JC_INST_OPCODE_ACONST_NULL,     .opcode_name = SV_STATIC("aconst_null") },
    { .opcode = JC_INST_OPCODE_ALOAD,           .opcode_name = SV_STATIC("aload"), OPERAND_TYPES(OPERAND_TYPE_U8) },
    { .opcode = JC_INST_OPCODE_ALOAD_0,         .opcode_name = SV_STATIC("aload_0") },
    { .opcode = JC_INST_OPCODE_ALOAD_1,         .opcode_name = SV_STATIC("aload_1") },
    { .opcode = JC_INST_OPCODE_ALOAD_2,         .opcode_name = SV_STATIC("aload_2") },
    { .opcode = JC_INST_OPCODE_ALOAD_3,         .opcode_name = SV_STATIC("aload_3") },
    { .opcode = JC_INST_OPCODE_ANEWARRAY,       .opcode_name = SV_STATIC("anewarray"), OPERAND_TYPES(OPERAND_TYPE_CLASS) },
    { .opcode = JC_INST_OPCODE_ARETURN,         .opcode_name = SV_STATIC("areturn") },
    { .opcode = JC_INST_OPCODE_ARRAYLENGTH,     .opcode_name = SV_STATIC("arraylength") },
    { .opcode = JC_INST_OPCODE_ASTORE,          .opcode_name = SV_STATIC("astore"), OPERAND_TYPES(OPERAND_TYPE_U8) },
    { .opcode = JC_INST_OPCODE_ASTORE_0,        .opcode_name = SV_STATIC("astore_0") },
    { .opcode = JC_INST_OPCODE_ASTORE_1,        .opcode_name = SV_STATIC("astore_1") },
    { .opcode = JC_INST_OPCODE_ASTORE_2,        .opcode_name = SV_STATIC("astore_2") },
    { .opcode = JC_INST_OPCODE_ASTORE_3,        .opcode_name = SV_STATIC("astore_3") },
    { .opcode = JC_INST_OPCODE_ATHROW,          .opcode_name = SV_STATIC("athrow") },
    { .opcode = JC_INST_OPCODE_BALOAD,          .opcode_name = SV_STATIC("baload") },
    { .opcode = JC_INST_OPCODE_BASTORE,         .opcode_name = SV_STATIC("bastore") },
    { .opcode = JC_INST_OPCODE_BIPUSH,          .opcode_name = SV_STATIC("bipush"), OPERAND_TYPES(OPERAND_TYPE_I8) },
    { .opcode = JC_INST_OPCODE_CALOAD,          .opcode_name = SV_STATIC("caload") },
    { .opcode = JC_INST_OPCODE_CASTORE,         .opcode_name = SV_STATIC("castore") },
    { .opcode = JC_INST_OPCODE_CHECKCAST,       .opcode_name = SV_STATIC("checkcast"), OPERAND_TYPES(OPERAND_TYPE_CLASS) },
    { .opcode = JC_INST_OPCODE_D2F,             .opcode_name = SV_STATIC("d2f") },
    { .opcode = JC_INST_OPCODE_D2I,             .opcode_name = SV_STATIC("d2i") },
    { .opcode = JC_INST_OPCODE_D2L,             .opcode_name = SV_STATIC("d2l") },
    { .opcode = JC_INST_OPCODE_DADD,            .opcode_name = SV_STATIC("dadd") },
    { .opcode = JC_INST_OPCODE_DALOAD,          .opcode_name = SV_STATIC("daload") },
    { .opcode = JC_INST_OPCODE_DASTORE,         .opcode_name = SV_STATIC("dastore") },
    { .opcode = JC_INST_OPCODE_DCMPG,           .opcode_name = SV_STATIC("dcmpg") },
    { .opcode = JC_INST_OPCODE_DCMPL,           .opcode_name = SV_STATIC("dcmpl") },
    { .opcode = JC_INST_OPCODE_DCONST_0,        .opcode_name = SV_STATIC("dconst_0") },
    { .opcode = JC_INST_OPCODE_DCONST_1,        .opcode_name = SV_STATIC("dconst_1") },
    { .opcode = JC_INST_OPCODE_DDIV,            .opcode_name = SV_STATIC("ddiv") },
    { .opcode = JC_INST_OPCODE_DLOAD,           .opcode_name = SV_STATIC("dload"), OPERAND_TYPES(OPERAND_TYPE_U8) },
    { .opcode = JC_INST_OPCODE_DLOAD_0,         .opcode_name = SV_STATIC("dload_0") },
    { .opcode = JC_INST_OPCODE_DLOAD_1,         .opcode_name = SV_STATIC("dload_1") },
    { .opcode = JC_INST_OPCODE_DLOAD_2,         .opcode_name = SV_STATIC("dload_2") },
    { .opcode = JC_INST_OPCODE_DLOAD_3,         .opcode_name = SV_STATIC("dload_3") },
    { .opcode = JC_INST_OPCODE_DMUL,            .opcode_name = SV_STATIC("dmul") },
    { .opcode = JC_INST_OPCODE_DNEG,            .opcode_name = SV_STATIC("dneg") },
    { .opcode = JC_INST_OPCODE_DREM,            .opcode_name = SV_STATIC("drem") },
    { .opcode = JC_INST_OPCODE_DRETURN,         .opcode_name = SV_STATIC("dreturn") },
    { .opcode = JC_INST_OPCODE_DSTORE,          .opcode_name = SV_STATIC("dstore"), OPERAND_TYPES(OPERAND_TYPE_U8) },
    { .opcode = JC_INST_OPCODE_DSTORE_0,        .opcode_name = SV_STATIC("dstore_0") },
    { .opcode = JC_INST_OPCODE_DSTORE_1,        .opcode_name = SV_STATIC("dstore_1") },
    { .opcode = JC_INST_OPCODE_DSTORE_2,        .opcode_name = SV_STATIC("dstore_2") },
    { .opcode = JC_INST_OPCODE_DSTORE_3,        .opcode_name = SV_STATIC("dstore_3") },
    { .opcode = JC_INST_OPCODE_DSUB,            .opcode_name = SV_STATIC("dsub") },
    { .opcode = JC_INST_OPCODE_DUP2,            .opcode_name = SV_STATIC("dup2") },
    { .opcode = JC_INST_OPCODE_DUP2_X1,         .opcode_name = SV_STATIC("dup2_x1") },
    { .opcode = JC_INST_OPCODE_DUP2_X2,         .opcode_name = SV_STATIC("dup2_x2") },
    { .opcode = JC_INST_OPCODE_DUP,             .opcode_name = SV_STATIC("dup") },
    { .opcode = JC_INST_OPCODE_DUP_X1,          .opcode_name = SV_STATIC("dup_x1") },
    { .opcode = JC_INST_OPCODE_DUP_X2,          .opcode_name = SV_STATIC("dup_x2") },
    { .opcode = JC_INST_OPCODE_F2D,             .opcode_name = SV_STATIC("f2d") },
    { .opcode = JC_INST_OPCODE_F2I,             .opcode_name = SV_STATIC("f2i") },
    { .opcode = JC_INST_OPCODE_F2L,             .opcode_name = SV_STATIC("f2l") },
    { .opcode = JC_INST_OPCODE_FADD,            .opcode_name = SV_STATIC("fadd") },
    { .opcode = JC_INST_OPCODE_FALOAD,          .opcode_name = SV_STATIC("faload") },
    { .opcode = JC_INST_OPCODE_FASTORE,         .opcode_name = SV_STATIC("fastore") },
    { .opcode = JC_INST_OPCODE_FCMPG,           .opcode_name = SV_STATIC("fcmpg") },
    { .opcode = JC_INST_OPCODE_FCMPL,           .opcode_name = SV_STATIC("fcmpl") },
    { .opcode = JC_INST_OPCODE_FCONST_0,        .opcode_name = SV_STATIC("fconst_0") },
    { .opcode = JC_INST_OPCODE_FCONST_1,        .opcode_name = SV_STATIC("fconst_1") },
    { .opcode = JC_INST_OPCODE_FCONST_2,        .opcode_name = SV_STATIC("fconst_2") },
    { .opcode = JC_INST_OPCODE_FDIV,            .opcode_name = SV_STATIC("fdiv") },
    { .opcode = JC_INST_OPCODE_FLOAD,           .opcode_name = SV_STATIC("fload"), OPERAND_TYPES(OPERAND_TYPE_U8) },
    { .opcode = JC_INST_OPCODE_FLOAD_0,         .opcode_name = SV_STATIC("fload_0") },
    { .opcode = JC_INST_OPCODE_FLOAD_1,         .opcode_name = SV_STATIC("fload_1") },
    { .opcode = JC_INST_OPCODE_FLOAD_2,         .opcode_name = SV_STATIC("fload_2") },
    { .opcode = JC_INST_OPCODE_FLOAD_3,         .opcode_name = SV_STATIC("fload_3") },
    { .opcode = JC_INST_OPCODE_FMUL,            .opcode_name = SV_STATIC("fmul") },
    { .opcode = JC_INST_OPCODE_FNEG,            .opcode_name = SV_STATIC("fneg") },
    { .opcode = JC_INST_OPCODE_FREM,            .opcode_name = SV_STATIC("frem") },
    { .opcode = JC_INST_OPCODE_FRETURN,         .opcode_name = SV_STATIC("freturn") },
    { .opcode = JC_INST_OPCODE_FSTORE,          .opcode_name = SV_STATIC("fstore"), OPERAND_TYPES(OPERAND_TYPE_U8) },
    { .opcode = JC_INST_OPCODE_FSTORE_0,        .opcode_name = SV_STATIC("fstore_0") },
    { .opcode = JC_INST_OPCODE_FSTORE_1,        .opcode_name = SV_STATIC("fstore_1") },
    { .opcode = JC_INST_OPCODE_FSTORE_2,        .opcode_name = SV_STATIC("fstore_2") },
    { .opcode = JC_INST_OPCODE_FSTORE_3,        .opcode_name = SV_STATIC("fstore_3") },
    { .opcode = JC_INST_OPCODE_FSUB,            .opcode_name = SV_STATIC("fsub") },
    { .opcode = JC_INST_OPCODE_GETFIELD,        .opcode_name = SV_STATIC("getfield"), OPERAND_TYPES(OPERAND_TYPE_FIELD_REF) },
    { .opcode = JC_INST_OPCODE_GETSTATIC,       .opcode_name = SV_STATIC("getstatic"), OPERAND_TYPES(OPERAND_TYPE_FIELD_REF) },
    { .opcode = JC_INST_OPCODE_I2B,             .opcode_name = SV_STATIC("i2b") },
    { .opcode = JC_INST_OPCODE_I2C,             .opcode_name = SV_STATIC("i2c") },
    { .opcode = JC_INST_OPCODE_I2D,             .opcode_name = SV_STATIC("i2d") },
    { .opcode = JC_INST_OPCODE_I2F,             .opcode_name = SV_STATIC("i2f") },
    { .opcode = JC_INST_OPCODE_I2L,             .opcode_name = SV_STATIC("i2l") },
    { .opcode = JC_INST_OPCODE_I2S,             .opcode_name = SV_STATIC("i2s") },
    { .opcode = JC_INST_OPCODE_IADD,            .opcode_name = SV_STATIC("iadd") },
    { .opcode = JC_INST_OPCODE_IALOAD,          .opcode_name = SV_STATIC("iaload") },
    { .opcode = JC_INST_OPCODE_IAND,            .opcode_name = SV_STATIC("iand") },
    { .opcode = JC_INST_OPCODE_IASTORE,         .opcode_name = SV_STATIC("iastore") },
    { .opcode = JC_INST_OPCODE_ICONST_0,        .opcode_name = SV_STATIC("iconst_0") },
    { .opcode = JC_INST_OPCODE_ICONST_1,        .opcode_name = SV_STATIC("iconst_1") },
    { .opcode = JC_INST_OPCODE_ICONST_2,        .opcode_name = SV_STATIC("iconst_2") },
    { .opcode = JC_INST_OPCODE_ICONST_3,        .opcode_name = SV_STATIC("iconst_3") },
    { .opcode = JC_INST_OPCODE_ICONST_4,        .opcode_name = SV_STATIC("iconst_4") },
    { .opcode = JC_INST_OPCODE_ICONST_5,        .opcode_name = SV_STATIC("iconst_5") },
    { .opcode = JC_INST_OPCODE_ICONST_M1,       .opcode_name = SV_STATIC("iconst_m1") },
    { .opcode = JC_INST_OPCODE_IDIV,            .opcode_name = SV_STATIC("idiv") },
    { .opcode = JC_INST_OPCODE_IINC,            .opcode_name = SV_STATIC("iinc"), OPERAND_TYPES(OPERAND_TYPE_U8, OPERAND_TYPE_I8) },
    { .opcode = JC_INST_OPCODE_ILOAD,           .opcode_name = SV_STATIC("iload"), OPERAND_TYPES(OPERAND_TYPE_U8) },
    { .opcode = JC_INST_OPCODE_ILOAD_0,         .opcode_name = SV_STATIC("iload_0") },
    { .opcode = JC_INST_OPCODE_ILOAD_1,         .opcode_name = SV_STATIC("iload_1") },
    { .opcode = JC_INST_OPCODE_ILOAD_2,         .opcode_name = SV_STATIC("iload_2") },
    { .opcode = JC_INST_OPCODE_ILOAD_3,         .opcode_name = SV_STATIC("iload_3") },
    { .opcode = JC_INST_OPCODE_IMUL,            .opcode_name = SV_STATIC("imul") },
    { .opcode = JC_INST_OPCODE_INEG,            .opcode_name = SV_STATIC("ineg") },
    { .opcode = JC_INST_OPCODE_INSTANCEOF,      .opcode_name = SV_STATIC("instanceof"), OPERAND_TYPES(OPERAND_TYPE_CLASS) },
    { .opcode = JC_INST_OPCODE_INVOKESTATIC,    .opcode_name = SV_STATIC("invokestatic"), OPERAND_TYPES(OPERAND_TYPE_METHOD_REF) },
    { .opcode = JC_INST_OPCODE_INVOKEVIRTUAL,   .opcode_name = SV_STATIC("invokevirtual"), OPERAND_TYPES(OPERAND_TYPE_METHOD_REF) },
    { .opcode = JC_INST_OPCODE_IOR,             .opcode_name = SV_STATIC("ior") },
    { .opcode = JC_INST_OPCODE_IREM,            .opcode_name = SV_STATIC("irem") },
    { .opcode = JC_INST_OPCODE_IRETURN,         .opcode_name = SV_STATIC("ireturn") },
    { .opcode = JC_INST_OPCODE_ISHL,            .opcode_name = SV_STATIC("ishl") },
    { .opcode = JC_INST_OPCODE_ISHR,            .opcode_name = SV_STATIC("ishr") },
    { .opcode = JC_INST_OPCODE_ISTORE,          .opcode_name = SV_STATIC("istore"), OPERAND_TYPES(OPERAND_TYPE_U8) },
    { .opcode = JC_INST_OPCODE_ISTORE_0,        .opcode_name = SV_STATIC("istore_0") },
    { .opcode = JC_INST_OPCODE_ISTORE_1,        .opcode_name = SV_STATIC("istore_1") },
    { .opcode = JC_INST_OPCODE_ISTORE_2,        .opcode_name = SV_STATIC("istore_2") },
    { .opcode = JC_INST_OPCODE_ISTORE_3,        .opcode_name = SV_STATIC("istore_3") },
    { .opcode = JC_INST_OPCODE_ISUB,            .opcode_name = SV_STATIC("isub") },
    { .opcode = JC_INST_OPCODE_IUSHR,           .opcode_name = SV_STATIC("iushr") },
    { .opcode = JC_INST_OPCODE_IXOR,            .opcode_name = SV_STATIC("ixor") },
    { .opcode = JC_INST_OPCODE_L2D,             .opcode_name = SV_STATIC("l2d") },
    { .opcode = JC_INST_OPCODE_L2F,             .opcode_name = SV_STATIC("l2f") },
    { .opcode = JC_INST_OPCODE_L2I,             .opcode_name = SV_STATIC("l2i") },
    { .opcode = JC_INST_OPCODE_LADD,            .opcode_name = SV_STATIC("ladd") },
    { .opcode = JC_INST_OPCODE_LALOAD,          .opcode_name = SV_STATIC("laload") },
    { .opcode = JC_INST_OPCODE_LAND,            .opcode_name = SV_STATIC("land") },
    { .opcode = JC_INST_OPCODE_LASTORE,         .opcode_name = SV_STATIC("lastore") },
    { .opcode = JC_INST_OPCODE_LCMP,            .opcode_name = SV_STATIC("lcmp") },
    { .opcode = JC_INST_OPCODE_LCONST_0,        .opcode_name = SV_STATIC("lconst_0") },
    { .opcode = JC_INST_OPCODE_LCONST_1,        .opcode_name = SV_STATIC("lconst_1") },
    { .opcode = JC_INST_OPCODE_LDIV,            .opcode_name = SV_STATIC("ldiv") },
    { .opcode = JC_INST_OPCODE_LLOAD,           .opcode_name = SV_STATIC("lload"), OPERAND_TYPES(OPERAND_TYPE_U8) },
    { .opcode = JC_INST_OPCODE_LLOAD_0,         .opcode_name = SV_STATIC("lload_0") },
    { .opcode = JC_INST_OPCODE_LLOAD_1,         .opcode_name = SV_STATIC("lload_1") },
    { .opcode = JC_INST_OPCODE_LLOAD_2,         .opcode_name = SV_STATIC("lload_2") },
    { .opcode = JC_INST_OPCODE_LLOAD_3,         .opcode_name = SV_STATIC("lload_3") },
    { .opcode = JC_INST_OPCODE_LMUL,            .opcode_name = SV_STATIC("lmul") },
    { .opcode = JC_INST_OPCODE_LNEG,            .opcode_name = SV_STATIC("lneg") },
    { .opcode = JC_INST_OPCODE_LOR,             .opcode_name = SV_STATIC("lor") },
    { .opcode = JC_INST_OPCODE_LREM,            .opcode_name = SV_STATIC("lrem") },
    { .opcode = JC_INST_OPCODE_LRETURN,         .opcode_name = SV_STATIC("lreturn") },
    { .opcode = JC_INST_OPCODE_LSHL,            .opcode_name = SV_STATIC("lshl") },
    { .opcode = JC_INST_OPCODE_LSHR,            .opcode_name = SV_STATIC("lshr") },
    { .opcode = JC_INST_OPCODE_LSTORE,          .opcode_name = SV_STATIC("lstore"), OPERAND_TYPES(OPERAND_TYPE_U8) },
    { .opcode = JC_INST_OPCODE_LSTORE_0,        .opcode_name = SV_STATIC("lstore_0") },
    { .opcode = JC_INST_OPCODE_LSTORE_1,        .opcode_name = SV_STATIC("lstore_1") },
    { .opcode = JC_INST_OPCODE_LSTORE_2,        .opcode_name = SV_STATIC("lstore_2") },
    { .opcode = JC_INST_OPCODE_LSTORE_3,        .opcode_name = SV_STATIC("lstore_3") },
    { .opcode = JC_INST_OPCODE_LSUB,            .opcode_name = SV_STATIC("lsub") },
    { .opcode = JC_INST_OPCODE_LUSHR,           .opcode_name = SV_STATIC("lushr") },
    { .opcode = JC_INST_OPCODE_LXOR,            .opcode_name = SV_STATIC("lxor") },
    { .opcode = JC_INST_OPCODE_MONITORENTER,    .opcode_name = SV_STATIC("monitorenter") },
    { .opcode = JC_INST_OPCODE_MONITOREXIT,     .opcode_name = SV_STATIC("monitorexit") },
    { .opcode = JC_INST_OPCODE_MULTIANEWARRAY,  .opcode_name = SV_STATIC("multianewarray"), OPERAND_TYPES(OPERAND_TYPE_CLASS, OPERAND_TYPE_U8) },
    { .opcode = JC_INST_OPCODE_NEW,             .opcode_name = SV_STATIC("new"), OPERAND_TYPES(OPERAND_TYPE_CLASS) },
    { .opcode = JC_INST_OPCODE_NOP,             .opcode_name = SV_STATIC("nop") },
    { .opcode = JC_INST_OPCODE_POP2,            .opcode_name = SV_STATIC("pop2") },
    { .opcode = JC_INST_OPCODE_POP,             .opcode_name = SV_STATIC("pop") },
    { .opcode = JC_INST_OPCODE_PUTFIELD,        .opcode_name = SV_STATIC("putfield"), OPERAND_TYPES(OPERAND_TYPE_FIELD_REF) },
    { .opcode = JC_INST_OPCODE_PUTSTATIC,       .opcode_name = SV_STATIC("putstatic"), OPERAND_TYPES(OPERAND_TYPE_FIELD_REF) },
    { .opcode = JC_INST_OPCODE_RETURN,          .opcode_name = SV_STATIC("return") },
    { .opcode = JC_INST_OPCODE_SALOAD,          .opcode_name = SV_STATIC("saload") },
    { .opcode = JC_INST_OPCODE_SASTORE,         .opcode_name = SV_STATIC("sastore") },
    { .opcode = JC_INST_OPCODE_SIPUSH,          .opcode_name = SV_STATIC("sipush"), OPERAND_TYPES(OPERAND_TYPE_I16) },
    { .opcode = JC_INST_OPCODE_SWAP,            .opcode_name = SV_STATIC("swap") },
    { .opcode = JC_INST_OPCODE_GOTO,            .opcode_name = SV_STATIC("goto"), OPERAND_TYPES(OPERAND_TYPE_JMP_LABEL_U16) },
    { .opcode = JC_INST_OPCODE_GOTO_W,          .opcode_name = SV_STATIC("goto_w"), OPERAND_TYPES(OPERAND_TYPE_JMP_LABEL_U32) },
    { .opcode = JC_INST_OPCODE_IFEQ,            .opcode_name = SV_STATIC("ifeq"), OPERAND_TYPES(OPERAND_TYPE_JMP_LABEL_U16) },
    { .opcode = JC_INST_OPCODE_IFNE,            .opcode_name = SV_STATIC("ifne"), OPERAND_TYPES(OPERAND_TYPE_JMP_LABEL_U16) },
    { .opcode = JC_INST_OPCODE_IFLT,            .opcode_name = SV_STATIC("iflt"), OPERAND_TYPES(OPERAND_TYPE_JMP_LABEL_U16) },
    { .opcode = JC_INST_OPCODE_IFGE,            .opcode_name = SV_STATIC("ifge"), OPERAND_TYPES(OPERAND_TYPE_JMP_LABEL_U16) },
    { .opcode = JC_INST_OPCODE_IFGT,            .opcode_name = SV_STATIC("ifgt"), OPERAND_TYPES(OPERAND_TYPE_JMP_LABEL_U16) },
    { .opcode = JC_INST_OPCODE_IFLE,            .opcode_name = SV_STATIC("ifle"), OPERAND_TYPES(OPERAND_TYPE_JMP_LABEL_U16) },
    { .opcode = JC_INST_OPCODE_IF_ICMPEQ,       .opcode_name = SV_STATIC("if_icmpeq"), OPERAND_TYPES(OPERAND_TYPE_JMP_LABEL_U16) },
    { .opcode = JC_INST_OPCODE_IF_ICMPNE,       .opcode_name = SV_STATIC("if_icmpne"), OPERAND_TYPES(OPERAND_TYPE_JMP_LABEL_U16) },
    { .opcode = JC_INST_OPCODE_IF_ICMPLT,       .opcode_name = SV_STATIC("if_icmplt"), OPERAND_TYPES(OPERAND_TYPE_JMP_LABEL_U16) },
    { .opcode = JC_INST_OPCODE_IF_ICMPGE,       .opcode_name = SV_STATIC("if_icmpge"), OPERAND_TYPES(OPERAND_TYPE_JMP_LABEL_U16) },
    { .opcode = JC_INST_OPCODE_IF_ICMPGT,       .opcode_name = SV_STATIC("if_icmpgt"), OPERAND_TYPES(OPERAND_TYPE_JMP_LABEL_U16) },
    { .opcode = JC_INST_OPCODE_IF_ICMPLE,       .opcode_name = SV_STATIC("if_icmple"), OPERAND_TYPES(OPERAND_TYPE_JMP_LABEL_U16) },
    { .opcode = JC_INST_OPCODE_IF_ACMPEQ,       .opcode_name = SV_STATIC("if_acmpeq"), OPERAND_TYPES(OPERAND_TYPE_JMP_LABEL_U16) },
    { .opcode = JC_INST_OPCODE_IF_ACMPNE,       .opcode_name = SV_STATIC("if_acmpne"), OPERAND_TYPES(OPERAND_TYPE_JMP_LABEL_U16) },
    { .opcode = JC_INST_OPCODE_IFNULL,          .opcode_name = SV_STATIC("ifnull"), OPERAND_TYPES(OPERAND_TYPE_JMP_LABEL_U16) },
    { .opcode = JC_INST_OPCODE_IFNONNULL,       .opcode_name = SV_STATIC("ifnonnull"), OPERAND_TYPES(OPERAND_TYPE_JMP_LABEL_U16) },
    { .opcode = JC_INST_OPCODE_LDC,             .opcode_name = SV_STATIC("ldc"), OPERAND_TYPES(OPERAND_TYPE_CONSTANT_INT_FLOAT_STRING_U8) },
    { .opcode = JC_INST_OPCODE_LDC_W,           .opcode_name = SV_STATIC("ldc_w"), OPERAND_TYPES(OPERAND_TYPE_CONSTANT_INT_FLOAT_STRING_U16) },
    { .opcode = JC_INST_OPCODE_LDC2_W,          .opcode_name = SV_STATIC("ldc2_w"), OPERAND_TYPES(OPERAND_TYPE_CONSTANT_LONG_DOUBLE) },
};

static char lexer_storage[1024] = {0};

const char *lexer_token_id_string(long token_id)
{
    static char single_char_token_buf[2] = {0};
    switch (token_id) {
    case CLEX_eof:                return "EOF";
    case CLEX_parse_error:        return "Parse Error";
    case CLEX_intlit:             return "integer";
    case CLEX_floatlit:           return "float";
    case CLEX_id:                 return "identifier";
    case CLEX_dqstring:           return "string";
    case CLEX_sqstring:           return "NOT USED";
    case CLEX_charlit:            return "NOT USED";
    case CLEX_eq:                 return "NOT USED";
    case CLEX_noteq:              return "NOT USED";
    case CLEX_lesseq:             return "NOT USED";
    case CLEX_greatereq:          return "NOT USED";
    case CLEX_andand:             return "NOT USED";
    case CLEX_oror:               return "NOT USED";
    case CLEX_shl:                return "NOT USED";
    case CLEX_shr:                return "NOT USED";
    case CLEX_plusplus:           return "NOT USED";
    case CLEX_minusminus:         return "NOT USED";
    case CLEX_pluseq:             return "NOT USED";
    case CLEX_minuseq:            return "NOT USED";
    case CLEX_muleq:              return "NOT USED";
    case CLEX_diveq:              return "NOT USED";
    case CLEX_modeq:              return "NOT USED";
    case CLEX_andeq:              return "NOT USED";
    case CLEX_oreq:               return "NOT USED";
    case CLEX_xoreq:              return "NOT USED";
    case CLEX_arrow:              return "NOT USED";
    case CLEX_eqarrow:            return "NOT USED";
    case CLEX_shleq:              return "NOT USED";
    case CLEX_shreq:              return "NOT USED";
    case CLEX_first_unused_token: return "NOT USED";
    default:
        single_char_token_buf[0] = token_id;
        return single_char_token_buf;
    }
}

bool lexer_expect_token(stb_lexer *lexer, long token_id)
{
    stb_c_lexer_get_token(lexer);
    if (lexer->token != token_id) {
        stb_lex_location loc;
        stb_c_lexer_get_location(lexer, lexer->where_firstchar, &loc);
        fprintf(stderr,
                "ERROR:"LOC_Fmt": Token '%s' was expected but found '%s'\n",
                LOC_Arg(loc),
                lexer_token_id_string(token_id),
                lexer_token_id_string(lexer->token));

        return false;
    }

    return true;
}

bool lexer_expect_keyword(stb_lexer *lexer, const char *keyword)
{
    if (!lexer_expect_token(lexer, CLEX_id)) return false;
    if (strcmp(lexer->string, keyword) != 0) {
        stb_lex_location loc;
        stb_c_lexer_get_location(lexer, lexer->where_firstchar, &loc);
        fprintf(
            stderr,
            "ERROR:"LOC_Fmt": Keyword '%s' was expected buf found '%s'\n",
            LOC_Arg(loc),
            keyword,
            lexer_token_id_string(lexer->token)
        );

        return false;
    }

    return true;
}

String_View lexer_token_sv(stb_lexer lexer)
{
    switch (lexer.token) {
    case CLEX_id:       return sv_from_parts(lexer.parse_point - lexer.string_len, lexer.string_len);
    case CLEX_dqstring: return sv_from_parts(lexer.parse_point - lexer.string_len - 1, lexer.string_len);
    default:
        UNREACHABLE("lexer_token_sv");
    }
}

bool parse_field_descriptors(stb_lexer *lexer, String_View descriptors, LocalDefs *result)
{
    stb_lex_location loc;
    String_View class_name;
    while (descriptors.count > 0) {
        switch (descriptors.data[0]) {
        case 'V': {
            sv_chop_left(&descriptors, 1);
        } break;

        case 'I': {
            da_append(result, ((JcLocalDef){ .type = JC_LOCAL_TYPE_INT }));
            sv_chop_left(&descriptors, 1);
        } break;

        case '[': {
            class_name = sv_chop_by_delim(&descriptors, ';');
            if (class_name.data[class_name.count] != ';') {
                stb_c_lexer_get_location(lexer, &class_name.data[class_name.count], &loc);
                fprintf(stderr, "ERROR:"LOC_Fmt": Object descriptor must end with ';'\n", LOC_Arg(loc));
                return false;
            }
            
            class_name.count += 1;
            da_append(result, ((JcLocalDef){ .type = JC_LOCAL_TYPE_OBJECT, .as_object = class_name }));
        } break;

        case 'L': {
            class_name = sv_chop_by_delim(&descriptors, ';');
            if (class_name.data[class_name.count] != ';') {
                stb_c_lexer_get_location(lexer, &class_name.data[class_name.count], &loc);
                fprintf(stderr, "ERROR:"LOC_Fmt": Object descriptor must end with ';'\n", LOC_Arg(loc));
                return false;
            }

            sv_chop_left(&class_name, 1);
            da_append(result, ((JcLocalDef){ .type = JC_LOCAL_TYPE_OBJECT, .as_object = class_name }));
        } break;

        default:
            stb_c_lexer_get_location(lexer, descriptors.data, &loc);
            fprintf(stderr, "ERROR:"LOC_Fmt": Unknown field descriptor\n", LOC_Arg(loc));
            return false;
        }
    }

    return true;
}

bool lexer_expect_method_descriptor(stb_lexer *lexer, LocalDefs *result)
{
    stb_lex_location loc;

    if (!lexer_expect_token(lexer, CLEX_dqstring)) return false;

    String_View descriptor = lexer_token_sv(*lexer);
    if (!sv_starts_with(descriptor, SV_STATIC("("))) {
        stb_c_lexer_get_location(lexer, descriptor.data, &loc);
        fprintf(stderr, "ERROR:"LOC_Fmt": Method descriptor parameters must start with '('\n", LOC_Arg(loc));
        return false;
    }

    String_View params = sv_chop_by_delim(&descriptor, ')');
    sv_chop_left(&params, 1);
    if (params.data[params.count] != ')') {
        stb_c_lexer_get_location(lexer, params.data + params.count, &loc);
        fprintf(stderr, "ERROR:"LOC_Fmt": Method descriptor parameters must end with ')'\n", LOC_Arg(loc));
        return false;
    }

    // Parse parameters
    if (!parse_field_descriptors(lexer, params, result)) return false;
    uint16_t param_count = result->count;

    // Parse return value
    if (!parse_field_descriptors(lexer, descriptor, result)) return false;
    result->count = param_count; // We need just check that return value is in correct form

    return true;
}

void report_unexpected_token(stb_lexer lexer)
{
    stb_lex_location loc;
    stb_c_lexer_get_location(&lexer, lexer.where_firstchar, &loc);
    fprintf(stderr, "ERROR:"LOC_Fmt": Unexpected token '%s'\n", LOC_Arg(loc), lexer_token_id_string(lexer.token));
}

bool lexer_expect_ref(
        stb_lexer *lexer,
        String_View *res_class,
        String_View *res_name,
        String_View *res_descriptor)
{
    if (!lexer_expect_token(lexer, CLEX_dqstring)) return false;

    stb_lex_location loc;
    String_View ref = lexer_token_sv(*lexer);

    // Class
    String_View class = sv_chop_by_delim(&ref, '.');
    if (class.count == 0) {
        stb_c_lexer_get_location(lexer, class.data, &loc);
        fprintf(stderr, "ERROR:"LOC_Fmt": Reference class name must not be empty\n", LOC_Arg(loc));
        return false;
    }
    if (class.data[class.count] != '.') {
        stb_c_lexer_get_location(lexer, class.data + class.count, &loc);
        fprintf(stderr, "ERROR:"LOC_Fmt": Reference class name must end with '.'\n", LOC_Arg(loc));
        return false;
    }

    // Reference name
    String_View name = sv_chop_by_delim(&ref, ':');
    if (name.count == 0) {
        stb_c_lexer_get_location(lexer, name.data, &loc);
        fprintf(stderr, "ERROR:"LOC_Fmt": Reference name must not be empty\n", LOC_Arg(loc));
        return false;
    }
    if (name.data[name.count] != ':') {
        stb_c_lexer_get_location(lexer, name.data + name.count, &loc);
        fprintf(stderr, "ERROR:"LOC_Fmt": Reference name must end with ':'\n", LOC_Arg(loc));
        return false;
    }

    // Descriptor
    if (ref.count == 0) {
        stb_c_lexer_get_location(lexer, ref.data, &loc);
        fprintf(stderr, "ERROR:"LOC_Fmt": Reference descriptor must not be empty\n", LOC_Arg(loc));
        return false;
    }

    *res_class = class;
    *res_name = name;
    *res_descriptor = ref;

    return true;
}

bool lexer_expect_int(stb_lexer *lexer)
{
    stb_c_lexer_get_token(lexer);
    switch (lexer->token) {
        case '-':
            lexer_expect_token(lexer, CLEX_intlit);
            lexer->int_number = -lexer->int_number;
            return true;

        case CLEX_intlit:
            return true;

        default:
            report_unexpected_token(*lexer);
            return false;
    }
}

bool find_label(JmpLabels jmp_labels, String_View label_name, JmpLabel *result)
{
    da_foreach(JmpLabel, l, &jmp_labels) {
        if (sv_eq(l->name, label_name)) {
            *result = *l;
            return true;
        }
    }

    return false;
}

bool parse_and_compile_inst(
        stb_lexer *lexer,
        String_View opcode,
        JcMethod *method,
        JcClass *jc,
        JmpLabelRefs *jmp_label_refs)
{
    static Operands operand_buf = {0};

    operand_buf.count = 0;

    stb_lex_location loc;
    JcInstOperand operand;
    String_View ref_class, ref_name, ref_descriptor;
    for (size_t i = 0; i < ARRAY_LEN(instructions); i++) {
        Instruction inst = instructions[i];
        if (sv_eq(opcode, inst.opcode_name)) {
            for (size_t j = 0; j < inst.operand_type_count; j++) {
                switch (inst.operand_types[j]) {
                case OPERAND_TYPE_FIELD_REF: {
                    if (!lexer_expect_ref(lexer, &ref_class, &ref_name, &ref_descriptor)) return false;
                    operand.tag = JC_INST_OPERAND_TAG_U16;
                    operand.as_u16 = jc_cp_push_ref(jc, JC_CONSTANT_TAG_FIELD_REF, ref_class, ref_name, ref_descriptor);
                } break;

                case OPERAND_TYPE_METHOD_REF: {
                    if (!lexer_expect_ref(lexer, &ref_class, &ref_name, &ref_descriptor)) return false;
                    operand.tag = JC_INST_OPERAND_TAG_U16;
                    operand.as_u16 = jc_cp_push_ref(jc, JC_CONSTANT_TAG_METHOD_REF, ref_class, ref_name, ref_descriptor);
                } break;

                case OPERAND_TYPE_U8: {
                    if (!lexer_expect_int(lexer)) return false;
                    if (!(0 <= lexer->int_number && lexer->int_number <= UINT8_MAX)) {
                        stb_c_lexer_get_location(lexer, lexer->where_firstchar, &loc);
                        fprintf(stderr, "ERROR:"LOC_Fmt": Unsigned byte was expected, but found '%ld'\n", LOC_Arg(loc), lexer->int_number);
                        return false;
                    }

                    operand.tag = JC_INST_OPERAND_TAG_U8;
                    operand.as_u8 = lexer->int_number;
                } break;

                case OPERAND_TYPE_I8: {
                    if (!lexer_expect_int(lexer)) return false;
                    if (!(INT8_MIN <= lexer->int_number && lexer->int_number <= INT8_MAX)) {
                        stb_c_lexer_get_location(lexer, lexer->where_firstchar, &loc);
                        fprintf(stderr, "ERROR:"LOC_Fmt": Signed byte was expected, but found '%ld'\n", LOC_Arg(loc), lexer->int_number);
                        return false;
                    }

                    operand.tag = JC_INST_OPERAND_TAG_U8;
                    operand.as_u8 = lexer->int_number;
                } break;

                case OPERAND_TYPE_I16: {
                    if (!lexer_expect_int(lexer)) return false;
                    if (!(INT16_MIN <= lexer->int_number && lexer->int_number <= INT16_MAX)) {
                        stb_c_lexer_get_location(lexer, lexer->where_firstchar, &loc);
                        fprintf(stderr, "ERROR:"LOC_Fmt": Signed short was expected, but found '%ld'\n", LOC_Arg(loc), lexer->int_number);
                        return false;
                    }

                    operand.tag = JC_INST_OPERAND_TAG_U16;
                    operand.as_u16 = lexer->int_number;
                } break;

                case OPERAND_TYPE_CLASS: {
                    if (!lexer_expect_token(lexer, CLEX_dqstring)) return false;
                    operand.tag = JC_INST_OPERAND_TAG_U16;
                    operand.as_u16 = jc_cp_push_class(jc, lexer_token_sv(*lexer));
                } break;

                case OPERAND_TYPE_JMP_LABEL_U16: {
                    if (!lexer_expect_token(lexer, CLEX_id)) return false;
                    operand.tag = JC_INST_OPERAND_TAG_U16;
                    operand.as_u16 = 0;
                    da_append(jmp_label_refs, ((JmpLabelRef){
                        .name = lexer_token_sv(*lexer),
                        .bytecode_offset = method->code.count,
                        .where_firstchar = lexer->where_firstchar,
                    }));
                } break;

                case OPERAND_TYPE_JMP_LABEL_U32: {
                    if (!lexer_expect_token(lexer, CLEX_id)) return false;
                    operand.tag = JC_INST_OPERAND_TAG_U32;
                    operand.as_u32 = 0;
                    da_append(jmp_label_refs, ((JmpLabelRef){
                        .name = lexer_token_sv(*lexer),
                        .bytecode_offset = method->code.count,
                        .where_firstchar = lexer->where_firstchar,
                        .is_u32 = true,
                    }));
                } break;

                case OPERAND_TYPE_CONSTANT_INT_FLOAT_STRING_U8: {
                    stb_c_lexer_get_token(lexer);
                    operand.tag = JC_INST_OPERAND_TAG_U8;
                    if (lexer->token == CLEX_intlit) {
                        if (!(INT32_MIN <= lexer->int_number && lexer->int_number <= INT32_MAX)) {
                            stb_c_lexer_get_location(lexer, lexer->where_firstchar, &loc);
                            fprintf(stderr, "ERROR:"LOC_Fmt": Number must be 32-bit integer\n", LOC_Arg(loc));
                            return false;
                        }

                        operand.as_u8 = jc_cp_push_integer(jc, lexer->int_number);
                    } else if (lexer->token == CLEX_floatlit) {
                        if (!(FLT_MIN <= lexer->real_number && lexer->real_number <= FLT_MAX)) {
                            stb_c_lexer_get_location(lexer, lexer->where_firstchar, &loc);
                            fprintf(stderr, "ERROR:"LOC_Fmt": Number must be 32-bit float\n", LOC_Arg(loc));
                            return false;
                        }

                        operand.as_u8 = jc_cp_push_float(jc, lexer->real_number);
                    } else if (lexer->token == CLEX_dqstring) {
                        operand.as_u8 = jc_cp_push_string(jc, lexer_token_sv(*lexer));
                    } else {
                        report_unexpected_token(*lexer);
                        return false;
                    }
                } break;

                case OPERAND_TYPE_CONSTANT_INT_FLOAT_STRING_U16: {
                    stb_c_lexer_get_token(lexer);
                    operand.tag = JC_INST_OPERAND_TAG_U16;
                    if (lexer->token == CLEX_intlit) {
                        if (!(INT32_MIN <= lexer->int_number && lexer->int_number <= INT32_MAX)) {
                            stb_c_lexer_get_location(lexer, lexer->where_firstchar, &loc);
                            fprintf(stderr, "ERROR:"LOC_Fmt": Number must be 32-bit integer\n", LOC_Arg(loc));
                            return false;
                        }

                        operand.as_u16 = jc_cp_push_integer(jc, lexer->int_number);
                    } else if (lexer->token == CLEX_floatlit) {
                        if (!(FLT_MIN <= lexer->real_number && lexer->real_number <= FLT_MAX)) {
                            stb_c_lexer_get_location(lexer, lexer->where_firstchar, &loc);
                            fprintf(stderr, "ERROR:"LOC_Fmt": Number must be 32-bit float\n", LOC_Arg(loc));
                            return false;
                        }

                        operand.as_u16 = jc_cp_push_float(jc, lexer->real_number);
                    } else if (lexer->token == CLEX_dqstring) {
                        operand.as_u16 = jc_cp_push_string(jc, lexer_token_sv(*lexer));
                    } else {
                        report_unexpected_token(*lexer);
                        return false;
                    }
                } break;

                case OPERAND_TYPE_CONSTANT_LONG_DOUBLE: {
                    stb_c_lexer_get_token(lexer);
                    operand.tag = JC_INST_OPERAND_TAG_U16;
                    if (lexer->token == CLEX_intlit) {
                        if (!(INT64_MIN <= lexer->int_number && lexer->int_number <= INT64_MAX)) {
                            stb_c_lexer_get_location(lexer, lexer->where_firstchar, &loc);
                            fprintf(stderr, "ERROR:"LOC_Fmt": Number must be 64-bit integer\n", LOC_Arg(loc));
                            return false;
                        }

                        operand.as_u16 = jc_cp_push_long(jc, lexer->int_number);
                    } else if (lexer->token == CLEX_floatlit) {
                        if (!(DBL_MIN <= lexer->real_number && lexer->real_number <= DBL_MAX)) {
                            stb_c_lexer_get_location(lexer, lexer->where_firstchar, &loc);
                            fprintf(stderr, "ERROR:"LOC_Fmt": Number must be 64-bit double\n", LOC_Arg(loc));
                            return false;
                        }

                        operand.as_u16 = jc_cp_push_double(jc, lexer->real_number);
                    } else {
                        report_unexpected_token(*lexer);
                        return false;
                    }
                } break;

                default:
                    UNREACHABLE("parse_and_compile_inst");
                }

                da_append(&operand_buf, operand);
            }

            // nob_log(INFO, "pushing '"SV_Fmt"', %zu operands", SV_Arg(opcode), operand_buf.count);
            jc_method_push_inst_(method, inst.opcode, operand_buf.items, operand_buf.count);

            return true;
        }
    }

    stb_c_lexer_get_location(lexer, lexer->where_firstchar, &loc);
    fprintf(stderr, "ERROR:"LOC_Fmt": Unknown instruction opcode '"SV_Fmt"'\n", LOC_Arg(loc), SV_Arg(opcode));
    return false;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <source_file.jasm>\n", argv[0]);
        return 1;
    }

    const char *file_path = argv[1];

    String_Builder sb = {0};
    if (!read_entire_file(file_path, &sb)) return 1;

    stb_lexer lexer = {0};
    stb_c_lexer_init(&lexer, sb.items, sb.items + sb.count, lexer_storage, sizeof(lexer_storage));

    if (!lexer_expect_keyword(&lexer, "class")) return 1;
    if (!lexer_expect_token(&lexer, CLEX_dqstring)) return 1;
    JcClass jc = jc_new(lexer_token_sv(lexer));

    // Parsing method
    stb_lex_location loc;
    LocalDefs local_defs = {0};
    JmpLabels jmp_labels = {0};
    JmpLabelRefs jmp_label_refs = {0};
    while (stb_c_lexer_get_token(&lexer)) {
        local_defs.count = 0;
        jmp_labels.count = 0;
        jmp_label_refs.count = 0;

        if (strcmp(lexer.string, "method") != 0) {
            report_unexpected_token(lexer);
            return 1;
        }

        if (!lexer_expect_token(&lexer, CLEX_id)) return 1;
        String_View name = lexer_token_sv(lexer);
        if (!lexer_expect_method_descriptor(&lexer, &local_defs)) return 1;
        String_View descriptor = lexer_token_sv(lexer);

        uint16_t param_count = local_defs.count;

        // Parse local variable definitions
        if (!lexer_expect_token(&lexer, '[')) return 1;
        for (;;) {
            stb_c_lexer_get_token(&lexer);
            if (lexer.token == ']') {
                break;
            } else if (lexer.token == CLEX_id && strcmp(lexer.string, "int") == 0) {
                da_append(&local_defs, ((JcLocalDef){ .type = JC_LOCAL_TYPE_INT }));
            } else if (lexer.token == CLEX_dqstring) {
                // TODO: Check format
                da_append(&local_defs, ((JcLocalDef){ .type = JC_LOCAL_TYPE_OBJECT, .as_object = lexer_token_sv(lexer) }));
            } else {
                report_unexpected_token(lexer);
                return 1;
            }
        }

        if (!lexer_expect_token(&lexer, CLEX_intlit)) return false;
        if (!(0 <= lexer.int_number && lexer.int_number <= UINT16_MAX)) {
            stb_c_lexer_get_location(&lexer, lexer.where_firstchar, &loc);
            fprintf(stderr, "ERROR:"LOC_Fmt": Stack size must be u16\n", LOC_Arg(loc));
            return 1;
        }

        JcMethod *method = jc_method_new(&jc, name, descriptor, local_defs.items, local_defs.count, param_count);
        method->max_stack = lexer.int_number;
        method->access_flags = JC_ACCESS_FLAG_PUBLIC | JC_ACCESS_FLAG_STATIC;

        // Parse code
        if (!lexer_expect_token(&lexer, '{')) return 1;
        for (;;) {
            stb_c_lexer_get_token(&lexer);
            if (lexer.token == '}') {
                break;
            } else if (lexer.token == CLEX_id) {
                String_View opcode = lexer_token_sv(lexer);
                if (!parse_and_compile_inst(&lexer, opcode, method, &jc, &jmp_label_refs)) return 1;
            } else if (lexer.token == '.') {
                if (!lexer_expect_token(&lexer, CLEX_id)) return 1;
                da_append(&jmp_labels, ((JmpLabel){
                    .name = lexer_token_sv(lexer),
                    .bytecode_offset = method->code.count,
                }));
            } else {
                report_unexpected_token(lexer);
                return 1;
            }
        }

        // Substite label offsets
        da_foreach(JmpLabelRef, label_ref, &jmp_label_refs) {
            JmpLabel label;
            if (!find_label(jmp_labels, label_ref->name,  &label)) {
                stb_c_lexer_get_location(&lexer, label_ref->where_firstchar, &loc);
                fprintf(stderr, "ERROR:"LOC_Fmt" Label '"SV_Fmt"' is undefined\n", LOC_Arg(loc), SV_Arg(label_ref->name));
                return 1;
            }

            union {
                uint32_t as_u32;
                uint8_t as_bytes[4];
            } offset;

            offset.as_u32 = label.bytecode_offset - label_ref->bytecode_offset;
            uint8_t *code_ptr = &method->code.items[label_ref->bytecode_offset + 1];
            if (label_ref->is_u32) {
                // Write as little endian
                code_ptr[0] = offset.as_bytes[3];
                code_ptr[1] = offset.as_bytes[2];
                code_ptr[2] = offset.as_bytes[1];
                code_ptr[3] = offset.as_bytes[0];
            } else {
                // Write as little endian
                code_ptr[0] = offset.as_bytes[1];
                code_ptr[1] = offset.as_bytes[0];
            }
        }

        da_foreach(JmpLabel, label, &jmp_labels) {
            jc_method_push_frame(method, label->bytecode_offset);
        }
    }

    jc_serialize(jc, "./test.class");
    return 0;
}
