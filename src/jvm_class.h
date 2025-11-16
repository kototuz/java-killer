#ifndef _JVM_CLASS_H
#define _JVM_CLASS_H

#include <stdint.h>
#include <stdbool.h>

#define NOB_STRIP_PREFIX
#include <nob.h>

#define SV_STATIC(lit) ((String_View){ sizeof(lit) - 1, (lit) })

typedef enum {
    JC_CONSTANT_TAG_CLASS                = 7,
    JC_CONSTANT_TAG_FIELD_REF            = 9,
    JC_CONSTANT_TAG_METHOD_REF           = 10,
    JC_CONSTANT_TAG_INTERFACE_METHOD_REF = 11,
    JC_CONSTANT_TAG_STRING               = 8,
    JC_CONSTANT_TAG_INTEGER              = 3,
    JC_CONSTANT_TAG_FLOAT                = 4,
    JC_CONSTANT_TAG_LONG                 = 5,
    JC_CONSTANT_TAG_DOUBLE               = 6,
    JC_CONSTANT_TAG_NAME_AND_TYPE        = 12,
    JC_CONSTANT_TAG_UTF8                 = 1,
    JC_CONSTANT_TAG_METHOD_HANDLE        = 15,
    JC_CONSTANT_TAG_METHOD_TYPE          = 16,
    JC_CONSTANT_TAG_INVOKE_DYNAMIC       = 18,
} JcConstantTag;

typedef struct {
    uint16_t name_index;
} JcConstantClass;

typedef struct {
    uint16_t       length;
    const uint8_t  *bytes;
} JcConstantUtf8;

typedef struct {
    uint16_t class_index;
    uint16_t name_and_type_index;
} JcConstantReference;

typedef struct {
    uint16_t name_index;
    uint16_t descriptor_index;
} JcConstantNameAndType;

typedef struct {
    uint16_t string_index;
} JcConstantString;

typedef struct {
    JcConstantTag tag;
    union {
        JcConstantClass       as_class;
        JcConstantUtf8        as_utf8;
        JcConstantString      as_string;
        JcConstantReference   as_ref;
        JcConstantNameAndType as_name_and_type;
        uint32_t              as_u32;
        uint64_t              as_u64;
    };
} JcConstant;

typedef struct {
    JcConstant *items;
    uint16_t count;
    uint16_t capacity;
    uint16_t strange_count; // 'long' and 'double' constants take
                            // 2 entries, so we track the amount
                            // considering this
} JcConstantPool;

typedef struct {
    uint16_t *items;
    uint16_t count;
    uint16_t capacity;
} JcInterfaces;

typedef enum {
    JC_INST_OPCODE_NOP                 = 0,
    JC_INST_OPCODE_ACONST_NULL         = 1,
    JC_INST_OPCODE_ICONST_M1           = 2,
    JC_INST_OPCODE_ICONST_0            = 3,
    JC_INST_OPCODE_ICONST_1            = 4,
    JC_INST_OPCODE_ICONST_2            = 5,
    JC_INST_OPCODE_ICONST_3            = 6,
    JC_INST_OPCODE_ICONST_4            = 7,
    JC_INST_OPCODE_ICONST_5            = 8,
    JC_INST_OPCODE_LCONST_0            = 9,
    JC_INST_OPCODE_LCONST_1            = 10,
    JC_INST_OPCODE_FCONST_0            = 11,
    JC_INST_OPCODE_FCONST_1            = 12,
    JC_INST_OPCODE_FCONST_2            = 13,
    JC_INST_OPCODE_DCONST_0            = 14,
    JC_INST_OPCODE_DCONST_1            = 15,
    JC_INST_OPCODE_BIPUSH              = 16,
    JC_INST_OPCODE_SIPUSH              = 17,
    JC_INST_OPCODE_LDC                 = 18,
    JC_INST_OPCODE_LDC_W               = 19,
    JC_INST_OPCODE_LDC2_W              = 20,
    JC_INST_OPCODE_ILOAD               = 21,
    JC_INST_OPCODE_LLOAD               = 22,
    JC_INST_OPCODE_FLOAD               = 23,
    JC_INST_OPCODE_DLOAD               = 24,
    JC_INST_OPCODE_ALOAD               = 25,
    JC_INST_OPCODE_ILOAD_0             = 26,
    JC_INST_OPCODE_ILOAD_1             = 27,
    JC_INST_OPCODE_ILOAD_2             = 28,
    JC_INST_OPCODE_ILOAD_3             = 29,
    JC_INST_OPCODE_LLOAD_0             = 30,
    JC_INST_OPCODE_LLOAD_1             = 31,
    JC_INST_OPCODE_LLOAD_2             = 32,
    JC_INST_OPCODE_LLOAD_3             = 33,
    JC_INST_OPCODE_FLOAD_0             = 34,
    JC_INST_OPCODE_FLOAD_1             = 35,
    JC_INST_OPCODE_FLOAD_2             = 36,
    JC_INST_OPCODE_FLOAD_3             = 37,
    JC_INST_OPCODE_DLOAD_0             = 38,
    JC_INST_OPCODE_DLOAD_1             = 39,
    JC_INST_OPCODE_DLOAD_2             = 40,
    JC_INST_OPCODE_DLOAD_3             = 41,
    JC_INST_OPCODE_ALOAD_0             = 42,
    JC_INST_OPCODE_ALOAD_1             = 43,
    JC_INST_OPCODE_ALOAD_2             = 44,
    JC_INST_OPCODE_ALOAD_3             = 45,
    JC_INST_OPCODE_IALOAD              = 46,
    JC_INST_OPCODE_LALOAD              = 47,
    JC_INST_OPCODE_FALOAD              = 48,
    JC_INST_OPCODE_DALOAD              = 49,
    JC_INST_OPCODE_AALOAD              = 50,
    JC_INST_OPCODE_BALOAD              = 51,
    JC_INST_OPCODE_CALOAD              = 52,
    JC_INST_OPCODE_SALOAD              = 53,
    JC_INST_OPCODE_ISTORE              = 54,
    JC_INST_OPCODE_LSTORE              = 55,
    JC_INST_OPCODE_FSTORE              = 56,
    JC_INST_OPCODE_DSTORE              = 57,
    JC_INST_OPCODE_ASTORE              = 58,
    JC_INST_OPCODE_ISTORE_0            = 59,
    JC_INST_OPCODE_ISTORE_1            = 60,
    JC_INST_OPCODE_ISTORE_2            = 61,
    JC_INST_OPCODE_ISTORE_3            = 62,
    JC_INST_OPCODE_LSTORE_0            = 63,
    JC_INST_OPCODE_LSTORE_1            = 64,
    JC_INST_OPCODE_LSTORE_2            = 65,
    JC_INST_OPCODE_LSTORE_3            = 66,
    JC_INST_OPCODE_FSTORE_0            = 67,
    JC_INST_OPCODE_FSTORE_1            = 68,
    JC_INST_OPCODE_FSTORE_2            = 69,
    JC_INST_OPCODE_FSTORE_3            = 70,
    JC_INST_OPCODE_DSTORE_0            = 71,
    JC_INST_OPCODE_DSTORE_1            = 72,
    JC_INST_OPCODE_DSTORE_2            = 73,
    JC_INST_OPCODE_DSTORE_3            = 74,
    JC_INST_OPCODE_ASTORE_0            = 75,
    JC_INST_OPCODE_ASTORE_1            = 76,
    JC_INST_OPCODE_ASTORE_2            = 77,
    JC_INST_OPCODE_ASTORE_3            = 78,
    JC_INST_OPCODE_IASTORE             = 79,
    JC_INST_OPCODE_LASTORE             = 80,
    JC_INST_OPCODE_FASTORE             = 81,
    JC_INST_OPCODE_DASTORE             = 82,
    JC_INST_OPCODE_AASTORE             = 83,
    JC_INST_OPCODE_BASTORE             = 84,
    JC_INST_OPCODE_CASTORE             = 85,
    JC_INST_OPCODE_SASTORE             = 86,
    JC_INST_OPCODE_POP                 = 87,
    JC_INST_OPCODE_POP2                = 88,
    JC_INST_OPCODE_DUP                 = 89,
    JC_INST_OPCODE_DUP_X1              = 90,
    JC_INST_OPCODE_DUP_X2              = 91,
    JC_INST_OPCODE_DUP2                = 92,
    JC_INST_OPCODE_DUP2_X1             = 93,
    JC_INST_OPCODE_DUP2_X2             = 94,
    JC_INST_OPCODE_SWAP                = 95,
    JC_INST_OPCODE_IADD                = 96,
    JC_INST_OPCODE_LADD                = 97,
    JC_INST_OPCODE_FADD                = 98,
    JC_INST_OPCODE_DADD                = 99,
    JC_INST_OPCODE_ISUB                = 100,
    JC_INST_OPCODE_LSUB                = 101,
    JC_INST_OPCODE_FSUB                = 102,
    JC_INST_OPCODE_DSUB                = 103,
    JC_INST_OPCODE_IMUL                = 104,
    JC_INST_OPCODE_LMUL                = 105,
    JC_INST_OPCODE_FMUL                = 106,
    JC_INST_OPCODE_DMUL                = 107,
    JC_INST_OPCODE_IDIV                = 108,
    JC_INST_OPCODE_LDIV                = 109,
    JC_INST_OPCODE_FDIV                = 110,
    JC_INST_OPCODE_DDIV                = 111,
    JC_INST_OPCODE_IREM                = 112,
    JC_INST_OPCODE_LREM                = 113,
    JC_INST_OPCODE_FREM                = 114,
    JC_INST_OPCODE_DREM                = 115,
    JC_INST_OPCODE_INEG                = 116,
    JC_INST_OPCODE_LNEG                = 117,
    JC_INST_OPCODE_FNEG                = 118,
    JC_INST_OPCODE_DNEG                = 119,
    JC_INST_OPCODE_ISHL                = 120,
    JC_INST_OPCODE_LSHL                = 121,
    JC_INST_OPCODE_ISHR                = 122,
    JC_INST_OPCODE_LSHR                = 123,
    JC_INST_OPCODE_IUSHR               = 124,
    JC_INST_OPCODE_LUSHR               = 125,
    JC_INST_OPCODE_IAND                = 126,
    JC_INST_OPCODE_LAND                = 127,
    JC_INST_OPCODE_IOR                 = 128,
    JC_INST_OPCODE_LOR                 = 129,
    JC_INST_OPCODE_IXOR                = 130,
    JC_INST_OPCODE_LXOR                = 131,
    JC_INST_OPCODE_IINC                = 132,
    JC_INST_OPCODE_I2L                 = 133,
    JC_INST_OPCODE_I2F                 = 134,
    JC_INST_OPCODE_I2D                 = 135,
    JC_INST_OPCODE_L2I                 = 136,
    JC_INST_OPCODE_L2F                 = 137,
    JC_INST_OPCODE_L2D                 = 138,
    JC_INST_OPCODE_F2I                 = 139,
    JC_INST_OPCODE_F2L                 = 140,
    JC_INST_OPCODE_F2D                 = 141,
    JC_INST_OPCODE_D2I                 = 142,
    JC_INST_OPCODE_D2L                 = 143,
    JC_INST_OPCODE_D2F                 = 144,
    JC_INST_OPCODE_I2B                 = 145,
    JC_INST_OPCODE_I2C                 = 146,
    JC_INST_OPCODE_I2S                 = 147,
    JC_INST_OPCODE_LCMP                = 148,
    JC_INST_OPCODE_FCMPL               = 149,
    JC_INST_OPCODE_FCMPG               = 150,
    JC_INST_OPCODE_DCMPL               = 151,
    JC_INST_OPCODE_DCMPG               = 152,
    JC_INST_OPCODE_IFEQ                = 153,
    JC_INST_OPCODE_IFNE                = 154,
    JC_INST_OPCODE_IFLT                = 155,
    JC_INST_OPCODE_IFGE                = 156,
    JC_INST_OPCODE_IFGT                = 157,
    JC_INST_OPCODE_IFLE                = 158,
    JC_INST_OPCODE_IF_ICMPEQ           = 159,
    JC_INST_OPCODE_IF_ICMPNE           = 160,
    JC_INST_OPCODE_IF_ICMPLT           = 161,
    JC_INST_OPCODE_IF_ICMPGE           = 162,
    JC_INST_OPCODE_IF_ICMPGT           = 163,
    JC_INST_OPCODE_IF_ICMPLE           = 164,
    JC_INST_OPCODE_IF_ACMPEQ           = 165,
    JC_INST_OPCODE_IF_ACMPNE           = 166,
    JC_INST_OPCODE_GOTO                = 167,
    JC_INST_OPCODE_JSR                 = 168,
    JC_INST_OPCODE_RET                 = 169,
    JC_INST_OPCODE_TABLESWITCH         = 170,
    JC_INST_OPCODE_LOOKUPSWITCH        = 171,
    JC_INST_OPCODE_IRETURN             = 172,
    JC_INST_OPCODE_LRETURN             = 173,
    JC_INST_OPCODE_FRETURN             = 174,
    JC_INST_OPCODE_DRETURN             = 175,
    JC_INST_OPCODE_ARETURN             = 176,
    JC_INST_OPCODE_RETURN              = 177,
    JC_INST_OPCODE_GETSTATIC           = 178,
    JC_INST_OPCODE_PUTSTATIC           = 179,
    JC_INST_OPCODE_GETFIELD            = 180,
    JC_INST_OPCODE_PUTFIELD            = 181,
    JC_INST_OPCODE_INVOKEVIRTUAL       = 182,
    JC_INST_OPCODE_INVOKESPECIAL       = 183,
    JC_INST_OPCODE_INVOKESTATIC        = 184,
    JC_INST_OPCODE_INVOKEINTERFACE     = 185,
    JC_INST_OPCODE_INVOKEDYNAMIC       = 186,
    JC_INST_OPCODE_NEW                 = 187,
    JC_INST_OPCODE_NEWARRAY            = 188,
    JC_INST_OPCODE_ANEWARRAY           = 189,
    JC_INST_OPCODE_ARRAYLENGTH         = 190,
    JC_INST_OPCODE_ATHROW              = 191,
    JC_INST_OPCODE_CHECKCAST           = 192,
    JC_INST_OPCODE_INSTANCEOF          = 193,
    JC_INST_OPCODE_MONITORENTER        = 194,
    JC_INST_OPCODE_MONITOREXIT         = 195,
    JC_INST_OPCODE_WIDE                = 196,
    JC_INST_OPCODE_MULTIANEWARRAY      = 197,
    JC_INST_OPCODE_IFNULL              = 198,
    JC_INST_OPCODE_IFNONNULL           = 199,
    JC_INST_OPCODE_GOTO_W              = 200,
    JC_INST_OPCODE_JSR_W               = 201,
    JC_INST_OPCODE_COUNT
} JcInstOpcode;

typedef enum {
    JC_INST_OPERAND_TAG_U8,
    JC_INST_OPERAND_TAG_U16,
    JC_INST_OPERAND_TAG_U32,
} JcInstOperandTag;

// This struct used in `code_inst_push_`
// It makes pushing instructions more easier
typedef struct {
    JcInstOperandTag tag;
    union {
        uint8_t  as_u8;
        uint16_t as_u16;
        uint32_t as_u32;
    };
} JcInstOperand;

typedef struct {
    uint8_t  *items;
    uint32_t count;
    uint32_t capacity;
} JcBytes;

typedef struct {
    JcBytes  bytes;
    uint16_t count;
    uint32_t last_frame_loc;
} JcStackMapFrames;

typedef enum {
    JC_LOCAL_TYPE_INT,
    JC_LOCAL_TYPE_OBJECT,
    // TODO: Implement remaining
} JcLocalDefType;

typedef struct {
    JcLocalDefType type;
    String_View as_object;
} JcLocalDef;

typedef struct {
    uint16_t         access_flags;
    uint16_t         name_index;
    uint16_t         descriptor_index;
    uint16_t         max_stack;
    uint16_t         max_locals;
    JcBytes          code;
    JcStackMapFrames stack_map_frames;
} JcMethod;

typedef struct {
    JcMethod *items;
    uint16_t count;
    uint16_t capacity;
} JcMethods;

// #define MAX_OPERANDS_CAP 16
// typedef struct {
//     InstOpcode opcode;
//     uint8_t    operand_count;
//     uint8_t    operands[MAX_OPERANDS_CAP];
// } Inst;
//
// typedef struct {
//     Inst     *items;
//     uint32_t count;
//     uint16_t capacity;
// } Code;
//
// typedef struct {
//     uint16_t start_pc;
//     uint16_t end_pc;
//     uint16_t handler_pc;
//     uint16_t catch_type;
// } ExceptionHandler;
//
// typedef struct {
//     ExceptionHandler *items;
//     uint16_t         count;
//     uint16_t         capacity;
// } ExceptionTable;
//
// typedef union {
//     CodeAttribute       as_code;
//     SourceFileAttribute as_sourcefile;
// } AttributeInfo;
//
// typedef struct {
//     AttributeInfo *items;
//     uint16_t      count;
//     uint16_t      capacity;
// } Attributes;
//
// typedef struct {
//     uint16_t   access_flags;
//     uint16_t   name_index;
//     uint16_t   descriptor_index;
//     Attributes attributes;
// } FieldInfo;
//
// typedef struct {
//     FieldInfo *items;
//     uint16_t  count;
//     uint16_t  capacity;
// } Fields;
//
// typedef FieldInfo MethodInfo;
// typedef Fields    Methods;

// Access flags
enum {
    JC_ACCESS_FLAG_PUBLIC        = 0x0001,
    JC_ACCESS_FLAG_PRIVATE       = 0x0002,
    JC_ACCESS_FLAG_PROTECTED     = 0x0004,
    JC_ACCESS_FLAG_STATIC        = 0x0008,
    JC_ACCESS_FLAG_FINAL         = 0x0010,
    JC_ACCESS_FLAG_SYNCHRONIZED  = 0x0020,
    JC_ACCESS_FLAG_SUPER         = 0x0020,
    JC_ACCESS_FLAG_VOLATILE      = 0x0040,
    JC_ACCESS_FLAG_BRIDGE        = 0x0040,
    JC_ACCESS_FLAG_TRANSIENT     = 0x0080,
    JC_ACCESS_FLAG_VARARGS       = 0x0080,
    JC_ACCESS_FLAG_NATIVE        = 0x0100,
    JC_ACCESS_FLAG_INTERFACE     = 0x0200,
    JC_ACCESS_FLAG_ABSTRACT      = 0x0400,
    JC_ACCESS_FLAG_STRICT        = 0x0800,
    JC_ACCESS_FLAG_SYNTHETIC     = 0x1000,
    JC_ACCESS_FLAG_ANNOTATION    = 0x2000,
    JC_ACCESS_FLAG_ENUM          = 0x4000,
    JC_ACCESS_FLAG_MODULE        = 0x8000
};

// TODO: Maybe we should use arena allocator to manage all this stuff.
// Arena allocator will be useful if we need to deallocate this at one moment.
// Also we can reuse the same structure just reset it before
//
// TODO: Maybe we don't need tagged unions.
// For example, make `Constant`:
// typedef struct {
//     uint8_t tag;
//     uint8_t info_len;
//     uint8_t info[8];
// } Constant;
//
// *Advantages*: structures take less space + simple serialization
// *Disadvantages*: debugging is less informative + we could not use
// this structures for deserialization (maybe we don't need deserialization)
typedef struct {
    uint16_t       minor_version;
    uint16_t       major_version;
    JcConstantPool constant_pool;
    uint16_t       access_flags;
    uint16_t       this_class;
    uint16_t       super_class;
    JcInterfaces   interfaces;
    JcMethods      methods;
} JcClass;



JcClass  jc_new(const char *name);

JcMethod *jc_method_new(JcClass *jc, String_View name, String_View descriptor, JcLocalDef *local_defs, uint16_t local_def_count, uint16_t arg_count);

#define JC_OPERAND_U8(n)  ((JcInstOperand){ .tag = JC_INST_OPERAND_TAG_U8,  .as_u8  = (n) })
#define JC_OPERAND_U16(n) ((JcInstOperand){ .tag = JC_INST_OPERAND_TAG_U16, .as_u16 = (n) })
#define JC_OPERAND_U32(n) ((JcInstOperand){ .tag = JC_INST_OPERAND_TAG_U32, .as_u32 = (n) })

#define jc_method_push_inst(method, opcode, ...) (jc_method_push_inst_(method, opcode, (JcInstOperand[]){__VA_ARGS__}, sizeof((JcInstOperand[]){__VA_ARGS__})/sizeof(JcInstOperand)))
void jc_method_push_inst_(JcMethod *m, JcInstOpcode opcode, JcInstOperand *operands, size_t operand_count);

// NOTE: The difference is that the function also detects branching
// instruction and then creates new frame in 'StackMapTable'
#define jc_method_push_inst2(method, opcode, ...) (jc_method_push_inst_(method, opcode, (JcInstOperand[]){__VA_ARGS__}, sizeof((JcInstOperand[]){__VA_ARGS__})/sizeof(JcInstOperand)))
void jc_method_push_inst2_(JcMethod *m, JcInstOpcode opcode, JcInstOperand *operands, size_t operand_count);

void jc_method_push_frame(JcMethod *m, uint32_t offset);

// NOTE: Javac before pushing constant to the pool checks whether the pool has that constant.
// I think pushing duplicates it's fine
uint16_t jc_cp_push_ref(JcClass *jc, JcConstantTag ref_kind, String_View class_name, String_View method_name, String_View descriptor);
uint16_t jc_cp_push_name_and_type(JcClass *jc, String_View name, String_View descriptor);
uint16_t jc_cp_push_class(JcClass *jc, String_View class_name);
uint16_t jc_cp_push_utf8(JcClass *jc, String_View bytes);
uint16_t jc_cp_push_string(JcClass *jc, String_View bytes);
uint16_t jc_cp_push_integer(JcClass *jc, int32_t n);
uint16_t jc_cp_push_float(JcClass *jc, float n);
uint16_t jc_cp_push_long(JcClass *jc, int64_t n);
uint16_t jc_cp_push_double(JcClass *jc, double n);
void     jc_cp_dump(JcClass jc);

bool     jc_serialize(JcClass jc, const char *path);

#endif //_JVM_CLASS_H
