#include <stdio.h>

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
    OPERAND_TYPE_U16,
    OPERAND_TYPE_CLASS,
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
    { .opcode = JC_INST_OPCODE_SIPUSH,          .opcode_name = SV_STATIC("sipush"), OPERAND_TYPES(OPERAND_TYPE_U16) },
    { .opcode = JC_INST_OPCODE_SWAP,            .opcode_name = SV_STATIC("swap") },
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
        fprintf(stderr, "ERROR: Keyword '%s' was expected buf found '%s'\n", keyword, lexer_token_id_string(lexer->token));
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

bool parse_instruction(stb_lexer *lexer, String_View opcode, JcClass *jc, JcInstOpcode *res_opcode, Operands *res_operands)
{
    stb_lex_location loc;
    JcInstOperand operand;
    String_View ref_class, ref_name, ref_descriptor;
    for (size_t i = 0; i < ARRAY_LEN(instructions); i++) {
        Instruction inst = instructions[i];
        if (sv_eq(opcode, inst.opcode_name)) {
            *res_opcode = inst.opcode;
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
                    if (!(0 <= lexer->int_number && lexer->int_number <= 255)) {
                        stb_c_lexer_get_location(lexer, lexer->where_firstchar, &loc);
                        fprintf(stderr, "ERROR:"LOC_Fmt": Unsigned byte was expected, but found '%ld'\n", LOC_Arg(loc), lexer->int_number);
                        return false;
                    }

                    operand.tag = JC_INST_OPERAND_TAG_U8;
                    operand.as_u8 = lexer->int_number;
                } break;

                case OPERAND_TYPE_I8: {
                    if (!lexer_expect_int(lexer)) return false;
                    if (!(-128 <= lexer->int_number && lexer->int_number <= 127)) {
                        stb_c_lexer_get_location(lexer, lexer->where_firstchar, &loc);
                        fprintf(stderr, "ERROR:"LOC_Fmt": Signed byte was expected, but found '%ld'\n", LOC_Arg(loc), lexer->int_number);
                        return false;
                    }

                    operand.tag = JC_INST_OPERAND_TAG_U8;
                    operand.as_u8 = lexer->int_number;
                } break;

                case OPERAND_TYPE_U16: {
                    if (!lexer_expect_int(lexer)) return false;
                    if (!(-32768 <= lexer->int_number && lexer->int_number <= 32767)) {
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

                default:
                    UNREACHABLE("parse_instruction");
                }

                da_append(res_operands, operand);
            }

            return true;
        }
    }

    stb_c_lexer_get_location(lexer, lexer->where_firstchar, &loc);
    fprintf(stderr, "ERROR:"LOC_Fmt": Unknown instruction opcode '"SV_Fmt"'\n", LOC_Arg(loc), SV_Arg(opcode));
    return false;
}

#define STACK_SIZE 10
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

    JcClass jc = jc_new("Test");
    jc.sourcefile_index = jc_cp_push_utf8(&jc, sv_from_cstr(file_path));

    // Parsing method
    LocalDefs local_defs = {0};
    while (stb_c_lexer_get_token(&lexer))
    {
        local_defs.count = 0;

        if (lexer.token != '.') {
            report_unexpected_token(lexer);
            return 1;
        }

        lexer_expect_keyword(&lexer, "method");

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

        JcMethod *method = jc_method_new(&jc, name, descriptor, local_defs.items, local_defs.count, param_count);
        method->max_stack = STACK_SIZE;
        method->access_flags = JC_ACCESS_FLAG_PUBLIC | JC_ACCESS_FLAG_STATIC;

        // Parse code
        Operands inst_operands = {0};
        JcInstOpcode inst_opcode;
        if (!lexer_expect_token(&lexer, '{')) return 1;
        for (;;) {
            stb_c_lexer_get_token(&lexer);
            if (lexer.token == '}') {
                break;
            } else if (lexer.token == CLEX_id) {
                inst_operands.count = 0;
                String_View opcode = lexer_token_sv(lexer);
                if (!parse_instruction(&lexer, opcode, &jc, &inst_opcode, &inst_operands)) return 1;
                nob_log(INFO, "pushing '"SV_Fmt"', %zu operands", SV_Arg(opcode), inst_operands.count);
                jc_method_push_inst_(method, inst_opcode, inst_operands.items, inst_operands.count);
            } else {
                report_unexpected_token(lexer);
                return 1;
            }
        }
    }

    jc_serialize(jc, "./Test.class");
    return 0;
}

// TODO: At the moment 'jasm' supports only opcodes without operands
// TODO: Ability to define stack size
