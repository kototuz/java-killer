#include <stdio.h>

#define STB_C_LEXER_IMPLEMENTATION
#include <stb_c_lexer.h>

#include "jvm_class.h"

typedef struct {
    JcLocalDef *items;
    uint16_t count;
    uint16_t capacity;
} LocalDefs;

static char lexer_storage[1024] = {0};

const char *lexer_token_id_string(long token_id)
{
    static char single_char_token_buf[2] = {0};
    switch (token_id) {
    case CLEX_eof: return "CLEX_eof";
    case CLEX_parse_error: return "CLEX_parse_error";
    case CLEX_intlit: return "CLEX_intlit";
    case CLEX_floatlit: return "CLEX_floatlit";
    case CLEX_id: return "CLEX_id";
    case CLEX_dqstring: return "CLEX_dqstring";
    case CLEX_sqstring: return "CLEX_sqstring";
    case CLEX_charlit: return "CLEX_charlit";
    case CLEX_eq: return "CLEX_eq";
    case CLEX_noteq: return "CLEX_noteq";
    case CLEX_lesseq: return "CLEX_lesseq";
    case CLEX_greatereq: return "CLEX_greatereq";
    case CLEX_andand: return "CLEX_andand";
    case CLEX_oror: return "CLEX_oror";
    case CLEX_shl: return "CLEX_shl";
    case CLEX_shr: return "CLEX_shr";
    case CLEX_plusplus: return "CLEX_plusplus";
    case CLEX_minusminus: return "CLEX_minusminus";
    case CLEX_pluseq: return "CLEX_pluseq";
    case CLEX_minuseq: return "CLEX_minuseq";
    case CLEX_muleq: return "CLEX_muleq";
    case CLEX_diveq: return "CLEX_diveq";
    case CLEX_modeq: return "CLEX_modeq";
    case CLEX_andeq: return "CLEX_andeq";
    case CLEX_oreq: return "CLEX_oreq";
    case CLEX_xoreq: return "CLEX_xoreq";
    case CLEX_arrow: return "CLEX_arrow";
    case CLEX_eqarrow: return "CLEX_eqarrow";
    case CLEX_shleq: return "CLEX_shleq";
    case CLEX_shreq: return "CLEX_shreq";
    case CLEX_first_unused_token: return "CLEX_first_unused_token";
    default:
        single_char_token_buf[0] = token_id;
        return single_char_token_buf;
    }
}

bool lexer_expect_token(stb_lexer *lexer, long token_id)
{
    if (!stb_c_lexer_get_token(lexer)) {
        fprintf(stderr, "ERROR: Token '%s' was expected but found EOF\n", lexer_token_id_string(token_id));
        return false;
    }

    if (lexer->token != token_id) {
        fprintf(stderr, "ERROR: Token '%s' was expected but found '%s'\n", lexer_token_id_string(token_id), lexer_token_id_string(lexer->token));
        return false;
    }

    return true;
}

bool lexer_check_token_id(stb_lexer lexer, long token_id)
{
    if (lexer.token != token_id) {
        fprintf(stderr, "ERROR: Token '%s' was expected but found '%s'\n", lexer_token_id_string(token_id), lexer_token_id_string(lexer.token));
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

// Parses sequence of types e.g. 'IBLjava/lang/String;' -> [int, byte, class 'java/lang/String']
bool descriptor_to_local_defs(String_View descriptor, LocalDefs *local_defs)
{
    while (descriptor.count > 0) {
        String_View class_name;
        switch (descriptor.data[0]) {
        case 'I':
            da_append(local_defs, ((JcLocalDef){ .type = JC_LOCAL_TYPE_INT }));
            sv_chop_left(&descriptor, 1);
            break;

        case '[':
            class_name = sv_chop_by_delim(&descriptor, ';');
            class_name.count += 1;
            da_append(local_defs, ((JcLocalDef){ .type = JC_LOCAL_TYPE_OBJECT, .as_object = strndup(class_name.data, class_name.count) }));
            break;

        case 'L':
            class_name = sv_chop_by_delim(&descriptor, ';');
            da_append(local_defs, ((JcLocalDef){ .type = JC_LOCAL_TYPE_OBJECT, .as_object = strndup(class_name.data, class_name.count) }));
            break;

        default:
            fprintf(stderr, "ERROR: Unknown type declaration '%c'\n", descriptor.data[0]);
            return false;
        }
    }

    return true;
}

bool opcode_from_name(const char *name, JcInstOpcode *result)
{
    if (strcmp(name, "nop") == 0)                  *result = JC_INST_OPCODE_NOP;
    else if (strcmp(name, "aconst_null") == 0)     *result = JC_INST_OPCODE_ACONST_NULL;
    else if (strcmp(name, "iconst_m1") == 0)       *result = JC_INST_OPCODE_ICONST_M1;
    else if (strcmp(name, "iconst_0") == 0)        *result = JC_INST_OPCODE_ICONST_0;
    else if (strcmp(name, "iconst_1") == 0)        *result = JC_INST_OPCODE_ICONST_1;
    else if (strcmp(name, "iconst_2") == 0)        *result = JC_INST_OPCODE_ICONST_2;
    else if (strcmp(name, "iconst_3") == 0)        *result = JC_INST_OPCODE_ICONST_3;
    else if (strcmp(name, "iconst_4") == 0)        *result = JC_INST_OPCODE_ICONST_4;
    else if (strcmp(name, "iconst_5") == 0)        *result = JC_INST_OPCODE_ICONST_5;
    else if (strcmp(name, "lconst_0") == 0)        *result = JC_INST_OPCODE_LCONST_0;
    else if (strcmp(name, "lconst_1") == 0)        *result = JC_INST_OPCODE_LCONST_1;
    else if (strcmp(name, "fconst_0") == 0)        *result = JC_INST_OPCODE_FCONST_0;
    else if (strcmp(name, "fconst_1") == 0)        *result = JC_INST_OPCODE_FCONST_1;
    else if (strcmp(name, "fconst_2") == 0)        *result = JC_INST_OPCODE_FCONST_2;
    else if (strcmp(name, "dconst_0") == 0)        *result = JC_INST_OPCODE_DCONST_0;
    else if (strcmp(name, "dconst_1") == 0)        *result = JC_INST_OPCODE_DCONST_1;
    else if (strcmp(name, "bipush") == 0)          *result = JC_INST_OPCODE_BIPUSH;
    else if (strcmp(name, "sipush") == 0)          *result = JC_INST_OPCODE_SIPUSH;
    else if (strcmp(name, "ldc") == 0)             *result = JC_INST_OPCODE_LDC;
    else if (strcmp(name, "ldc_w") == 0)           *result = JC_INST_OPCODE_LDC_W;
    else if (strcmp(name, "ldc2_w") == 0)          *result = JC_INST_OPCODE_LDC2_W;
    else if (strcmp(name, "iload") == 0)           *result = JC_INST_OPCODE_ILOAD;
    else if (strcmp(name, "lload") == 0)           *result = JC_INST_OPCODE_LLOAD;
    else if (strcmp(name, "fload") == 0)           *result = JC_INST_OPCODE_FLOAD;
    else if (strcmp(name, "dload") == 0)           *result = JC_INST_OPCODE_DLOAD;
    else if (strcmp(name, "aload") == 0)           *result = JC_INST_OPCODE_ALOAD;
    else if (strcmp(name, "iload_0") == 0)         *result = JC_INST_OPCODE_ILOAD_0;
    else if (strcmp(name, "iload_1") == 0)         *result = JC_INST_OPCODE_ILOAD_1;
    else if (strcmp(name, "iload_2") == 0)         *result = JC_INST_OPCODE_ILOAD_2;
    else if (strcmp(name, "iload_3") == 0)         *result = JC_INST_OPCODE_ILOAD_3;
    else if (strcmp(name, "lload_0") == 0)         *result = JC_INST_OPCODE_LLOAD_0;
    else if (strcmp(name, "lload_1") == 0)         *result = JC_INST_OPCODE_LLOAD_1;
    else if (strcmp(name, "lload_2") == 0)         *result = JC_INST_OPCODE_LLOAD_2;
    else if (strcmp(name, "lload_3") == 0)         *result = JC_INST_OPCODE_LLOAD_3;
    else if (strcmp(name, "fload_0") == 0)         *result = JC_INST_OPCODE_FLOAD_0;
    else if (strcmp(name, "fload_1") == 0)         *result = JC_INST_OPCODE_FLOAD_1;
    else if (strcmp(name, "fload_2") == 0)         *result = JC_INST_OPCODE_FLOAD_2;
    else if (strcmp(name, "fload_3") == 0)         *result = JC_INST_OPCODE_FLOAD_3;
    else if (strcmp(name, "dload_0") == 0)         *result = JC_INST_OPCODE_DLOAD_0;
    else if (strcmp(name, "dload_1") == 0)         *result = JC_INST_OPCODE_DLOAD_1;
    else if (strcmp(name, "dload_2") == 0)         *result = JC_INST_OPCODE_DLOAD_2;
    else if (strcmp(name, "dload_3") == 0)         *result = JC_INST_OPCODE_DLOAD_3;
    else if (strcmp(name, "aload_0") == 0)         *result = JC_INST_OPCODE_ALOAD_0;
    else if (strcmp(name, "aload_1") == 0)         *result = JC_INST_OPCODE_ALOAD_1;
    else if (strcmp(name, "aload_2") == 0)         *result = JC_INST_OPCODE_ALOAD_2;
    else if (strcmp(name, "aload_3") == 0)         *result = JC_INST_OPCODE_ALOAD_3;
    else if (strcmp(name, "iaload") == 0)          *result = JC_INST_OPCODE_IALOAD;
    else if (strcmp(name, "laload") == 0)          *result = JC_INST_OPCODE_LALOAD;
    else if (strcmp(name, "faload") == 0)          *result = JC_INST_OPCODE_FALOAD;
    else if (strcmp(name, "daload") == 0)          *result = JC_INST_OPCODE_DALOAD;
    else if (strcmp(name, "aaload") == 0)          *result = JC_INST_OPCODE_AALOAD;
    else if (strcmp(name, "baload") == 0)          *result = JC_INST_OPCODE_BALOAD;
    else if (strcmp(name, "caload") == 0)          *result = JC_INST_OPCODE_CALOAD;
    else if (strcmp(name, "saload") == 0)          *result = JC_INST_OPCODE_SALOAD;
    else if (strcmp(name, "istore") == 0)          *result = JC_INST_OPCODE_ISTORE;
    else if (strcmp(name, "lstore") == 0)          *result = JC_INST_OPCODE_LSTORE;
    else if (strcmp(name, "fstore") == 0)          *result = JC_INST_OPCODE_FSTORE;
    else if (strcmp(name, "dstore") == 0)          *result = JC_INST_OPCODE_DSTORE;
    else if (strcmp(name, "astore") == 0)          *result = JC_INST_OPCODE_ASTORE;
    else if (strcmp(name, "istore_0") == 0)        *result = JC_INST_OPCODE_ISTORE_0;
    else if (strcmp(name, "istore_1") == 0)        *result = JC_INST_OPCODE_ISTORE_1;
    else if (strcmp(name, "istore_2") == 0)        *result = JC_INST_OPCODE_ISTORE_2;
    else if (strcmp(name, "istore_3") == 0)        *result = JC_INST_OPCODE_ISTORE_3;
    else if (strcmp(name, "lstore_0") == 0)        *result = JC_INST_OPCODE_LSTORE_0;
    else if (strcmp(name, "lstore_1") == 0)        *result = JC_INST_OPCODE_LSTORE_1;
    else if (strcmp(name, "lstore_2") == 0)        *result = JC_INST_OPCODE_LSTORE_2;
    else if (strcmp(name, "lstore_3") == 0)        *result = JC_INST_OPCODE_LSTORE_3;
    else if (strcmp(name, "fstore_0") == 0)        *result = JC_INST_OPCODE_FSTORE_0;
    else if (strcmp(name, "fstore_1") == 0)        *result = JC_INST_OPCODE_FSTORE_1;
    else if (strcmp(name, "fstore_2") == 0)        *result = JC_INST_OPCODE_FSTORE_2;
    else if (strcmp(name, "fstore_3") == 0)        *result = JC_INST_OPCODE_FSTORE_3;
    else if (strcmp(name, "dstore_0") == 0)        *result = JC_INST_OPCODE_DSTORE_0;
    else if (strcmp(name, "dstore_1") == 0)        *result = JC_INST_OPCODE_DSTORE_1;
    else if (strcmp(name, "dstore_2") == 0)        *result = JC_INST_OPCODE_DSTORE_2;
    else if (strcmp(name, "dstore_3") == 0)        *result = JC_INST_OPCODE_DSTORE_3;
    else if (strcmp(name, "astore_0") == 0)        *result = JC_INST_OPCODE_ASTORE_0;
    else if (strcmp(name, "astore_1") == 0)        *result = JC_INST_OPCODE_ASTORE_1;
    else if (strcmp(name, "astore_2") == 0)        *result = JC_INST_OPCODE_ASTORE_2;
    else if (strcmp(name, "astore_3") == 0)        *result = JC_INST_OPCODE_ASTORE_3;
    else if (strcmp(name, "iastore") == 0)         *result = JC_INST_OPCODE_IASTORE;
    else if (strcmp(name, "lastore") == 0)         *result = JC_INST_OPCODE_LASTORE;
    else if (strcmp(name, "fastore") == 0)         *result = JC_INST_OPCODE_FASTORE;
    else if (strcmp(name, "dastore") == 0)         *result = JC_INST_OPCODE_DASTORE;
    else if (strcmp(name, "aastore") == 0)         *result = JC_INST_OPCODE_AASTORE;
    else if (strcmp(name, "bastore") == 0)         *result = JC_INST_OPCODE_BASTORE;
    else if (strcmp(name, "castore") == 0)         *result = JC_INST_OPCODE_CASTORE;
    else if (strcmp(name, "sastore") == 0)         *result = JC_INST_OPCODE_SASTORE;
    else if (strcmp(name, "pop") == 0)             *result = JC_INST_OPCODE_POP;
    else if (strcmp(name, "pop2") == 0)            *result = JC_INST_OPCODE_POP2;
    else if (strcmp(name, "dup") == 0)             *result = JC_INST_OPCODE_DUP;
    else if (strcmp(name, "dup_x1") == 0)          *result = JC_INST_OPCODE_DUP_X1;
    else if (strcmp(name, "dup_x2") == 0)          *result = JC_INST_OPCODE_DUP_X2;
    else if (strcmp(name, "dup2") == 0)            *result = JC_INST_OPCODE_DUP2;
    else if (strcmp(name, "dup2_x1") == 0)         *result = JC_INST_OPCODE_DUP2_X1;
    else if (strcmp(name, "dup2_x2") == 0)         *result = JC_INST_OPCODE_DUP2_X2;
    else if (strcmp(name, "swap") == 0)            *result = JC_INST_OPCODE_SWAP;
    else if (strcmp(name, "iadd") == 0)            *result = JC_INST_OPCODE_IADD;
    else if (strcmp(name, "ladd") == 0)            *result = JC_INST_OPCODE_LADD;
    else if (strcmp(name, "fadd") == 0)            *result = JC_INST_OPCODE_FADD;
    else if (strcmp(name, "dadd") == 0)            *result = JC_INST_OPCODE_DADD;
    else if (strcmp(name, "isub") == 0)            *result = JC_INST_OPCODE_ISUB;
    else if (strcmp(name, "lsub") == 0)            *result = JC_INST_OPCODE_LSUB;
    else if (strcmp(name, "fsub") == 0)            *result = JC_INST_OPCODE_FSUB;
    else if (strcmp(name, "dsub") == 0)            *result = JC_INST_OPCODE_DSUB;
    else if (strcmp(name, "imul") == 0)            *result = JC_INST_OPCODE_IMUL;
    else if (strcmp(name, "lmul") == 0)            *result = JC_INST_OPCODE_LMUL;
    else if (strcmp(name, "fmul") == 0)            *result = JC_INST_OPCODE_FMUL;
    else if (strcmp(name, "dmul") == 0)            *result = JC_INST_OPCODE_DMUL;
    else if (strcmp(name, "idiv") == 0)            *result = JC_INST_OPCODE_IDIV;
    else if (strcmp(name, "ldiv") == 0)            *result = JC_INST_OPCODE_LDIV;
    else if (strcmp(name, "fdiv") == 0)            *result = JC_INST_OPCODE_FDIV;
    else if (strcmp(name, "ddiv") == 0)            *result = JC_INST_OPCODE_DDIV;
    else if (strcmp(name, "irem") == 0)            *result = JC_INST_OPCODE_IREM;
    else if (strcmp(name, "lrem") == 0)            *result = JC_INST_OPCODE_LREM;
    else if (strcmp(name, "frem") == 0)            *result = JC_INST_OPCODE_FREM;
    else if (strcmp(name, "drem") == 0)            *result = JC_INST_OPCODE_DREM;
    else if (strcmp(name, "ineg") == 0)            *result = JC_INST_OPCODE_INEG;
    else if (strcmp(name, "lneg") == 0)            *result = JC_INST_OPCODE_LNEG;
    else if (strcmp(name, "fneg") == 0)            *result = JC_INST_OPCODE_FNEG;
    else if (strcmp(name, "dneg") == 0)            *result = JC_INST_OPCODE_DNEG;
    else if (strcmp(name, "ishl") == 0)            *result = JC_INST_OPCODE_ISHL;
    else if (strcmp(name, "lshl") == 0)            *result = JC_INST_OPCODE_LSHL;
    else if (strcmp(name, "ishr") == 0)            *result = JC_INST_OPCODE_ISHR;
    else if (strcmp(name, "lshr") == 0)            *result = JC_INST_OPCODE_LSHR;
    else if (strcmp(name, "iushr") == 0)           *result = JC_INST_OPCODE_IUSHR;
    else if (strcmp(name, "lushr") == 0)           *result = JC_INST_OPCODE_LUSHR;
    else if (strcmp(name, "iand") == 0)            *result = JC_INST_OPCODE_IAND;
    else if (strcmp(name, "land") == 0)            *result = JC_INST_OPCODE_LAND;
    else if (strcmp(name, "ior") == 0)             *result = JC_INST_OPCODE_IOR;
    else if (strcmp(name, "lor") == 0)             *result = JC_INST_OPCODE_LOR;
    else if (strcmp(name, "ixor") == 0)            *result = JC_INST_OPCODE_IXOR;
    else if (strcmp(name, "lxor") == 0)            *result = JC_INST_OPCODE_LXOR;
    else if (strcmp(name, "iinc") == 0)            *result = JC_INST_OPCODE_IINC;
    else if (strcmp(name, "i2l") == 0)             *result = JC_INST_OPCODE_I2L;
    else if (strcmp(name, "i2f") == 0)             *result = JC_INST_OPCODE_I2F;
    else if (strcmp(name, "i2d") == 0)             *result = JC_INST_OPCODE_I2D;
    else if (strcmp(name, "l2i") == 0)             *result = JC_INST_OPCODE_L2I;
    else if (strcmp(name, "l2f") == 0)             *result = JC_INST_OPCODE_L2F;
    else if (strcmp(name, "l2d") == 0)             *result = JC_INST_OPCODE_L2D;
    else if (strcmp(name, "f2i") == 0)             *result = JC_INST_OPCODE_F2I;
    else if (strcmp(name, "f2l") == 0)             *result = JC_INST_OPCODE_F2L;
    else if (strcmp(name, "f2d") == 0)             *result = JC_INST_OPCODE_F2D;
    else if (strcmp(name, "d2i") == 0)             *result = JC_INST_OPCODE_D2I;
    else if (strcmp(name, "d2l") == 0)             *result = JC_INST_OPCODE_D2L;
    else if (strcmp(name, "d2f") == 0)             *result = JC_INST_OPCODE_D2F;
    else if (strcmp(name, "i2b") == 0)             *result = JC_INST_OPCODE_I2B;
    else if (strcmp(name, "i2c") == 0)             *result = JC_INST_OPCODE_I2C;
    else if (strcmp(name, "i2s") == 0)             *result = JC_INST_OPCODE_I2S;
    else if (strcmp(name, "lcmp") == 0)            *result = JC_INST_OPCODE_LCMP;
    else if (strcmp(name, "fcmpl") == 0)           *result = JC_INST_OPCODE_FCMPL;
    else if (strcmp(name, "fcmpg") == 0)           *result = JC_INST_OPCODE_FCMPG;
    else if (strcmp(name, "dcmpl") == 0)           *result = JC_INST_OPCODE_DCMPL;
    else if (strcmp(name, "dcmpg") == 0)           *result = JC_INST_OPCODE_DCMPG;
    else if (strcmp(name, "ifeq") == 0)            *result = JC_INST_OPCODE_IFEQ;
    else if (strcmp(name, "ifne") == 0)            *result = JC_INST_OPCODE_IFNE;
    else if (strcmp(name, "iflt") == 0)            *result = JC_INST_OPCODE_IFLT;
    else if (strcmp(name, "ifge") == 0)            *result = JC_INST_OPCODE_IFGE;
    else if (strcmp(name, "ifgt") == 0)            *result = JC_INST_OPCODE_IFGT;
    else if (strcmp(name, "ifle") == 0)            *result = JC_INST_OPCODE_IFLE;
    else if (strcmp(name, "if_icmpeq") == 0)       *result = JC_INST_OPCODE_IF_ICMPEQ;
    else if (strcmp(name, "if_icmpne") == 0)       *result = JC_INST_OPCODE_IF_ICMPNE;
    else if (strcmp(name, "if_icmplt") == 0)       *result = JC_INST_OPCODE_IF_ICMPLT;
    else if (strcmp(name, "if_icmpge") == 0)       *result = JC_INST_OPCODE_IF_ICMPGE;
    else if (strcmp(name, "if_icmpgt") == 0)       *result = JC_INST_OPCODE_IF_ICMPGT;
    else if (strcmp(name, "if_icmple") == 0)       *result = JC_INST_OPCODE_IF_ICMPLE;
    else if (strcmp(name, "if_acmpeq") == 0)       *result = JC_INST_OPCODE_IF_ACMPEQ;
    else if (strcmp(name, "if_acmpne") == 0)       *result = JC_INST_OPCODE_IF_ACMPNE;
    else if (strcmp(name, "goto") == 0)            *result = JC_INST_OPCODE_GOTO;
    else if (strcmp(name, "jsr") == 0)             *result = JC_INST_OPCODE_JSR;
    else if (strcmp(name, "ret") == 0)             *result = JC_INST_OPCODE_RET;
    else if (strcmp(name, "tableswitch") == 0)     *result = JC_INST_OPCODE_TABLESWITCH;
    else if (strcmp(name, "lookupswitch") == 0)    *result = JC_INST_OPCODE_LOOKUPSWITCH;
    else if (strcmp(name, "ireturn") == 0)         *result = JC_INST_OPCODE_IRETURN;
    else if (strcmp(name, "lreturn") == 0)         *result = JC_INST_OPCODE_LRETURN;
    else if (strcmp(name, "freturn") == 0)         *result = JC_INST_OPCODE_FRETURN;
    else if (strcmp(name, "dreturn") == 0)         *result = JC_INST_OPCODE_DRETURN;
    else if (strcmp(name, "areturn") == 0)         *result = JC_INST_OPCODE_ARETURN;
    else if (strcmp(name, "return") == 0)          *result = JC_INST_OPCODE_RETURN;
    else if (strcmp(name, "getstatic") == 0)       *result = JC_INST_OPCODE_GETSTATIC;
    else if (strcmp(name, "putstatic") == 0)       *result = JC_INST_OPCODE_PUTSTATIC;
    else if (strcmp(name, "getfield") == 0)        *result = JC_INST_OPCODE_GETFIELD;
    else if (strcmp(name, "putfield") == 0)        *result = JC_INST_OPCODE_PUTFIELD;
    else if (strcmp(name, "invokevirtual") == 0)   *result = JC_INST_OPCODE_INVOKEVIRTUAL;
    else if (strcmp(name, "invokespecial") == 0)   *result = JC_INST_OPCODE_INVOKESPECIAL;
    else if (strcmp(name, "invokestatic") == 0)    *result = JC_INST_OPCODE_INVOKESTATIC;
    else if (strcmp(name, "invokeinterface") == 0) *result = JC_INST_OPCODE_INVOKEINTERFACE;
    else if (strcmp(name, "invokedynamic") == 0)   *result = JC_INST_OPCODE_INVOKEDYNAMIC;
    else if (strcmp(name, "new") == 0)             *result = JC_INST_OPCODE_NEW;
    else if (strcmp(name, "newarray") == 0)        *result = JC_INST_OPCODE_NEWARRAY;
    else if (strcmp(name, "anewarray") == 0)       *result = JC_INST_OPCODE_ANEWARRAY;
    else if (strcmp(name, "arraylength") == 0)     *result = JC_INST_OPCODE_ARRAYLENGTH;
    else if (strcmp(name, "athrow") == 0)          *result = JC_INST_OPCODE_ATHROW;
    else if (strcmp(name, "checkcast") == 0)       *result = JC_INST_OPCODE_CHECKCAST;
    else if (strcmp(name, "instanceof") == 0)      *result = JC_INST_OPCODE_INSTANCEOF;
    else if (strcmp(name, "monitorenter") == 0)    *result = JC_INST_OPCODE_MONITORENTER;
    else if (strcmp(name, "monitorexit") == 0)     *result = JC_INST_OPCODE_MONITOREXIT;
    else if (strcmp(name, "wide") == 0)            *result = JC_INST_OPCODE_WIDE;
    else if (strcmp(name, "multianewarray") == 0)  *result = JC_INST_OPCODE_MULTIANEWARRAY;
    else if (strcmp(name, "ifnull") == 0)          *result = JC_INST_OPCODE_IFNULL;
    else if (strcmp(name, "ifnonnull") == 0)       *result = JC_INST_OPCODE_IFNONNULL;
    else if (strcmp(name, "goto_w") == 0)          *result = JC_INST_OPCODE_GOTO_W;
    else if (strcmp(name, "jsr_w") == 0)           *result = JC_INST_OPCODE_JSR_W;
    else {
        fprintf(stderr, "ERROR: Unknown instruction '%s'\n", name);
        return false;
    }

    return true;
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
    jc.sourcefile_index = jc_cp_push_utf8(&jc, file_path);

    // Parsing method
    LocalDefs local_defs = {0};
    while (stb_c_lexer_get_token(&lexer))
    {
        local_defs.count = 0;

        if (!lexer_check_token_id(lexer, '.')) return 1;
        lexer_expect_keyword(&lexer, "method");

        lexer_expect_token(&lexer, CLEX_id);
        char *name = strdup(lexer.string);
        lexer_expect_token(&lexer, CLEX_dqstring);
        char *descriptor = strdup(lexer.string);

        // Extract argument definitions from descriptor
        String_View args = sv_from_cstr(descriptor);
        sv_chop_left(&args, 1);
        args = sv_chop_by_delim(&args, ')');
        if (!descriptor_to_local_defs(args, &local_defs)) return 1;

        uint16_t arg_count = local_defs.count;

        // Parse local variable definitions
        lexer_expect_token(&lexer, '[');
        for (;;) {
            if (!stb_c_lexer_get_token(&lexer)) {
                fprintf(stderr, "ERROR: Unexpected EOF\n");
                return 1;
            }

            if (lexer.token == ']') break;
            if (lexer.token == CLEX_id && strcmp(lexer.string, "int") == 0) {
                da_append(&local_defs, ((JcLocalDef){ .type = JC_LOCAL_TYPE_INT }));
            } else if (lexer.token == CLEX_dqstring) {
                da_append(&local_defs, ((JcLocalDef){ .type = JC_LOCAL_TYPE_OBJECT, .as_object = strdup(lexer.string) }));
            }
        }

        JcMethod *method = jc_method_new(&jc, name, descriptor, local_defs.items, local_defs.count, arg_count);
        method->max_stack = STACK_SIZE;
        method->access_flags = JC_ACCESS_FLAG_PUBLIC | JC_ACCESS_FLAG_STATIC;

        // Parse code
        lexer_expect_token(&lexer, '{');
        for (;;) {
            if (!stb_c_lexer_get_token(&lexer)) {
                fprintf(stderr, "ERROR: Unexpected EOF while parsing code\n");
                return 1;
            }
            
            if (lexer.token == '}') break;
            lexer_check_token_id(lexer, CLEX_id); // TODO: Operands
            JcInstOpcode opcode;
            if (!opcode_from_name(lexer.string, &opcode)) return 1;
            jc_method_push_inst(method, opcode);
        }
    }


    jc_serialize(jc, "./Test.class");
    return 0;
}

// TODO: Memory leaks. Maybe 'jvm_class' library should copy strings by itself.
//       On the other hand it may accept 'String_View' (i think it's better)
// TODO: At the moment 'jasm' supports only opcodes without operands
