#define NOB_IMPLEMENTATION
#define NOB_STRIP_PREFIX
#include "../thirdparty/nob.h"

int main(int argc, char **argv)
{
    NOB_GO_REBUILD_URSELF(argc, argv);

    if (!mkdir_if_not_exists("build")) return 1;

    Cmd cmd = {0};
    cmd_append(
        &cmd, "gcc", "-Wall",  "-Wextra",
        "-I../thirdparty", "-I../jasm/src",
        "-o", "build/jlang",
        "src/arena.c",
        "src/bang_diag.c",
        "src/bang_lexer.c",
        "src/bang_parser.c",
        "src/main.c",
        "../jasm/src/jvm_class.c"
    );
    if (!cmd_run(&cmd)) return 1;

    return 0;
}
