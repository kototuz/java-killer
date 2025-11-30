#include <stdio.h>
#include <errno.h>
#include <assert.h>

#include "arena.h"
#include "bang_lexer.h"
#include "bang_parser.h"

#include <jvm_class.h>

#define SCOPE_VARS_CAPACITY 1024
#define PROCS_CAPACITY 1024

typedef enum {
    VAR_STATIC_STORAGE = 0,
    VAR_STACK_STORAGE,
} Var_Storage;

typedef enum {
    TYPE_VOID = 0,
    TYPE_I32,
    COUNT_TYPES,
} Type;

typedef struct {
    String_View name;
    Bang_Loc loc;
    Type type;
    Var_Storage storage;
    size_t index; // only matters if storage == VAR_STACK_STORAGE
} Compiled_Var;

typedef struct {
    String_View name;
    Bang_Loc loc;
    Dynarray_Of_Bang_Proc_Param params;
} Compiled_Proc;

typedef struct {
    Bang_Expr ast;
    Type type;
} Compiled_Expr;

typedef struct Scope Scope;
struct Scope {
    Scope *parent;
    Compiled_Var vars[SCOPE_VARS_CAPACITY];
    size_t vars_count;
};

typedef struct {
    Arena arena;
    Scope *scope;
    JcClass main_class;
    JcMethod *method;
    Compiled_Proc procs[PROCS_CAPACITY];
    size_t procs_count;
    Bang_Loc entry_loc;
    bool warnings_as_errors;
} Compiler;

typedef struct {
    bool exists;
    JcInstOpcode inst;
    Type ret;
} Binary_Op_Of_Type;



static const Binary_Op_Of_Type binary_op_of_type_table[COUNT_TYPES][COUNT_BANG_BINARY_OP_KINDS] = {
    [TYPE_VOID] = {
        [BANG_BINARY_OP_KIND_PLUS]  = {.exists = false},
        [BANG_BINARY_OP_KIND_MINUS] = {.exists = false},
        [BANG_BINARY_OP_KIND_MULT]  = {.exists = false},
        [BANG_BINARY_OP_KIND_LT]    = {.exists = false},
        [BANG_BINARY_OP_KIND_GE]    = {.exists = false},
        [BANG_BINARY_OP_KIND_NE]    = {.exists = false},
        [BANG_BINARY_OP_KIND_AND]   = {.exists = false},
        [BANG_BINARY_OP_KIND_OR]    = {.exists = false},
        [BANG_BINARY_OP_KIND_EQ]    = {.exists = false},
    },
    [TYPE_I32] = {
        [BANG_BINARY_OP_KIND_PLUS]  = {.exists = true, .inst = JC_INST_OPCODE_IADD,  .ret = TYPE_I32},
        [BANG_BINARY_OP_KIND_MINUS] = {.exists = true, .inst = JC_INST_OPCODE_ISUB, .ret = TYPE_I32},
        [BANG_BINARY_OP_KIND_MULT]  = {.exists = true, .inst = JC_INST_OPCODE_IMUL,  .ret = TYPE_I32},
        [BANG_BINARY_OP_KIND_LT]    = {.exists = false},
        [BANG_BINARY_OP_KIND_GE]    = {.exists = false},
        [BANG_BINARY_OP_KIND_NE]    = {.exists = false},
        [BANG_BINARY_OP_KIND_AND]   = {.exists = false},
        [BANG_BINARY_OP_KIND_OR]    = {.exists = false},
        [BANG_BINARY_OP_KIND_EQ]    = {.exists = false},
    },
};

static const String_View type_names[COUNT_TYPES] = {
    [TYPE_VOID] = SV_STATIC("void"),
    [TYPE_I32]  = SV_STATIC("i32"),
};


Binary_Op_Of_Type binary_op_of_type(Type type, Bang_Binary_Op_Kind op_kind)
{
    assert(type >= 0);
    assert(type < COUNT_TYPES);
    assert(op_kind >= 0);
    assert(op_kind < COUNT_BANG_BINARY_OP_KINDS);
    return binary_op_of_type_table[type][op_kind];
}

String_View type_name(Type t)
{
    assert(0 <= t && t < COUNT_TYPES);
    return type_names[t];
}

Type type_by_name(Bang_Loc loc, String_View name)
{
    for (Type type = 0; type < COUNT_TYPES; type++) {
        if (sv_eq(name, type_name(type))) {
            return type;
        }
    }

    bang_diag_msg(
        loc, BANG_DIAG_ERROR,
        "`"SV_Fmt"` is not a valid type", SV_Arg(name)
    );

    exit(1);
}

void comp_push_new_scope(Compiler *c)
{
    Scope *scope = arena_alloc(&c->arena, sizeof(Scope));
    scope->parent = c->scope;
    c->scope = scope;
}

void comp_pop_scope(Compiler *c)
{
    assert(c->scope != NULL);
    c->scope = c->scope->parent;
}

Compiled_Proc *comp_get_compiled_proc_by_name(Compiler *c, String_View name)
{
    for (size_t i = 0; i < c->procs_count; ++i) {
        if (sv_eq(c->procs[i].name, name)) {
            return &c->procs[i];
        }
    }
    return NULL;
}

Compiled_Var *scope_get_compiled_var_by_name(Scope *scope, String_View name)
{
    assert(scope);
    for (size_t i = 0; i < scope->vars_count; ++i) {
        if (sv_eq(scope->vars[i].name, name)) {
            return &scope->vars[i];
        }
    }

    return NULL;
}

void scope_push_var(Scope *scope, Compiled_Var var)
{
    assert(scope);
    assert(scope->vars_count < SCOPE_VARS_CAPACITY);
    scope->vars[scope->vars_count++] = var;
}

Compiled_Var compile_var(Compiler *c, Bang_Loc loc, String_View name, Type type)
{
    if (type == TYPE_VOID) {
        bang_diag_msg(
            loc, BANG_DIAG_ERROR,
            "defining variables with type "SV_Fmt" is not allowed",
            SV_Arg(type_name(type))
        );
        exit(1);
    }

    Compiled_Var *existing_var = scope_get_compiled_var_by_name(c->scope, name);
    if (existing_var) {
        bang_diag_msg(
            loc, BANG_DIAG_ERROR,
            "variable `"SV_Fmt"` is already defined", SV_Arg(name)
        );
        bang_diag_msg(
            existing_var->loc, BANG_DIAG_ERROR,
            "the first definition is located here"
        );
        exit(1);
    }

    // TODO: Check for variable shadowing

    Compiled_Var new_var = (Compiled_Var){
        .name = name,
        .loc = loc,
        .type = type,
        .storage = VAR_STACK_STORAGE,
        .index = c->method->max_locals
    };

    c->method->max_locals += 1; // TODO: Doubles and longs take 2 indices

    scope_push_var(c->scope, new_var);

    return new_var;
}

void compile_typed_read(Compiler *c, Type type, uint16_t index)
{
    switch (type) {
    case TYPE_I32:
        jc_method_push_inst(c->method, JC_INST_OPCODE_ILOAD, JC_OPERAND_U8(index));
        break;

    case TYPE_VOID:
    case COUNT_TYPES:
        UNREACHABLE("compile_typed_write");
    }
}

void compile_typed_write(Compiler *c, Type type, uint16_t index)
{
    switch (type) {
    case TYPE_I32:
        jc_method_push_inst(c->method, JC_INST_OPCODE_ISTORE, JC_OPERAND_U8(index));
        break;

    case TYPE_VOID:
    case COUNT_TYPES:
        UNREACHABLE("compile_typed_write");
    }
}

Compiled_Expr compile_expr(Compiler *c, Bang_Expr expr);
Type compile_binary_op(Compiler *c, Bang_Binary_Op binary_op)
{
    const Compiled_Expr compiled_lhs = compile_expr(c, binary_op.lhs);
    const Compiled_Expr compiled_rhs = compile_expr(c, binary_op.rhs);

    if (compiled_lhs.type != compiled_rhs.type) {
        bang_diag_msg(
            binary_op.loc, BANG_DIAG_ERROR,
            "LHS of `%s` has type `"SV_Fmt"` but RHS has type `"SV_Fmt"`",
            bang_token_kind_name(bang_binary_op_def(binary_op.kind).token_kind),
            SV_Arg(type_name(compiled_lhs.type)),
            SV_Arg(type_name(compiled_rhs.type))
        );
        exit(1);
    }

    const Type type = compiled_lhs.type;
    Binary_Op_Of_Type boot = binary_op_of_type(type, binary_op.kind);
    if (!boot.exists) {
        bang_diag_msg(
            binary_op.loc, BANG_DIAG_ERROR,
            "binary operation `%s` does not exist for type `"SV_Fmt"`",
            bang_token_kind_name(bang_binary_op_def(binary_op.kind).token_kind),
            SV_Arg(type_name(type))
        );
        exit(1);
    }

    jc_method_push_inst(c->method, boot.inst);

    return boot.ret;
}

Compiled_Expr compile_expr(Compiler *c, Bang_Expr expr)
{
    Compiled_Expr result = {0};
    switch (expr.kind) {
    case BANG_EXPR_KIND_LIT_STR: {
        uint16_t idx = jc_cp_push_string(&c->main_class, expr.as.lit_str);
        jc_method_push_inst(c->method, JC_INST_OPCODE_LDC_W, JC_OPERAND_U16(idx));
        TODO("BANG_EXPR_KIND_LIT_STR");
    } break;

    case BANG_EXPR_KIND_LIT_BOOL: {
        TODO("BANG_EXPR_KIND_LIT_BOOL");
    } break;

    // TODO: Check for number size
    case BANG_EXPR_KIND_LIT_INT: {
        uint16_t idx = jc_cp_push_integer(&c->main_class, expr.as.lit_int);
        jc_method_push_inst(c->method, JC_INST_OPCODE_LDC_W, JC_OPERAND_U16(idx));
        result.type = TYPE_I32;
    } break;

    case BANG_EXPR_KIND_VAR_READ: {
        Compiled_Var *var = scope_get_compiled_var_by_name(c->scope, expr.as.var_read.name);
        if (var == NULL) {
            bang_diag_msg(
                expr.as.var_read.loc, BANG_DIAG_ERROR,
                "could not read non-existing variable `"SV_Fmt"`",
                SV_Arg(expr.as.var_read.name)
            );
            exit(1);
        }

        compile_typed_read(c, var->type, var->index);

        result.type = var->type;
    } break;

    case BANG_EXPR_KIND_BINARY_OP: {
        result.type = compile_binary_op(c, *expr.as.binary_op);
    } break;

    case BANG_EXPR_KIND_FUNCALL:
        TODO("BANG_EXPR_KIND_FUNCALL");
    case COUNT_BANG_EXPR_KINDS:
        UNREACHABLE("compile_expr");
    }

    return result;
}

void compile_var_def(Compiler *c, Bang_Var_Def var_def)
{
    Type type = type_by_name(var_def.loc, var_def.type_name);
    Compiled_Var new_var = compile_var(c, var_def.loc, var_def.name, type);
    if (var_def.has_init) {
        Compiled_Expr expr = compile_expr(c, var_def.init);
        if (expr.type != new_var.type) {
            bang_diag_msg(
                var_def.loc, BANG_DIAG_ERROR,
                "cannot assign expression of type `"SV_Fmt"` to a variable of type `"SV_Fmt"`",
                SV_Arg(type_name(expr.type)),
                SV_Arg(type_name(type))
            );
            exit(1);
        }

        compile_typed_write(c, type, new_var.index);
    }
}

void compile_proc_def(Compiler *c, Bang_Proc_Def proc_def)
{
    Compiled_Proc *existing_proc = comp_get_compiled_proc_by_name(c, proc_def.name);
    if (existing_proc) {
        bang_diag_msg(
            proc_def.loc, BANG_DIAG_ERROR,
            "procedure `"SV_Fmt"` is already defined",
            SV_Arg(proc_def.name)
        );
        bang_diag_msg(
            existing_proc->loc, BANG_DIAG_NOTE,
            "the first definition is located here"
        );
        exit(1);
    }

    if (proc_def.params.size > 0) {
        TODO("Procedure parameters are not implemented");
    }

    assert(c->procs_count < PROCS_CAPACITY);
    c->procs[c->procs_count++] = (Compiled_Proc) {
        .name = proc_def.name,
        .loc = proc_def.loc,
        .params = proc_def.params,
    };

    if (sv_eq(proc_def.name, SV("main"))) {
        c->method = jc_method_new2(&c->main_class, SV("main"), SV("([Ljava/lang/String;)V"));
        c->method->max_locals = 1;
    } else {
        c->method = jc_method_new2(&c->main_class, proc_def.name, SV("()V"));
    }

    c->method->access_flags = JC_ACCESS_FLAG_PUBLIC | JC_ACCESS_FLAG_STATIC;
    c->method->max_stack = 64; // TODO: Maybe calculate max stack size?

    comp_push_new_scope(c);
    {
        for (size_t i = 0; i < proc_def.body.size; i++) {
            switch (proc_def.body.items[i].kind) {
            case BANG_STMT_KIND_VAR_DEF:
                compile_var_def(c, proc_def.body.items[i].as.var_def);
                break;

            case BANG_STMT_KIND_EXPR:
            case BANG_STMT_KIND_IF:
            case BANG_STMT_KIND_VAR_ASSIGN:
            case BANG_STMT_KIND_WHILE:
            case BANG_STMT_KIND_FOR:
                TODO("compile_proc_def");

            case COUNT_BANG_STMT_KINDS:
                UNREACHABLE("compile_proc_def");
            }
        }
    }
    comp_pop_scope(c);

    jc_method_push_inst(c->method, JC_INST_OPCODE_RETURN);
}



#define INPUT_PATH "./example.jlang"
int main(int argc, char **argv)
{
    const char *program_name = shift_args(&argc, &argv);
    if (argc != 1) {
        fprintf(stderr, "Usage: %s <input-file>\n", program_name);
        return 1;
    }

    Compiler comp = {0};
    comp.main_class = jc_new(sv_from_cstr(program_name));

    String_View content = {0};
    if (arena_slurp_file(&comp.arena, SV(INPUT_PATH), &content) < 0) {
        fprintf(stderr, "ERROR: could not read file `%s`: %s", INPUT_PATH, strerror(errno));
        return 1;
    }

    Bang_Lexer lexer = bang_lexer_from_sv(content, INPUT_PATH);
    Bang_Module module = parse_bang_module(&comp.arena, &lexer);

    comp_push_new_scope(&comp);
    {
        for (Bang_Top *top = module.tops_begin; top != NULL; top = top->next) {
            switch (top->kind) {
            case BANG_TOP_KIND_PROC:
                compile_proc_def(&comp, top->as.proc);
                break;

            case BANG_TOP_KIND_VAR:
                TODO("BANG_TOP_KIND_VAR");

            default:
                UNREACHABLE("main");
            }
        }
    }
    comp_pop_scope(&comp);

    jc_serialize(comp.main_class, "Main.class");
}

// TODO: 'string' type
