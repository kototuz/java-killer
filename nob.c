#include <stdio.h>

#define NOB_IMPLEMENTATION
#define NOB_STRIP_PREFIX
#include "thirdparty/nob.h"

int main(int argc, char **argv)
{
    NOB_GO_REBUILD_URSELF(argc, argv);

    if (!mkdir_if_not_exists("build")) return 1;
    if (!mkdir_if_not_exists("build/examples/")) return 1;

    Cmd cmd = {0};
    cmd_append(&cmd, "gcc", "-Wall",  "-Wextra", "-Ithirdparty", "-o", "build/jasm", "src/jasm.c", "src/jvm_class.c");
    if (!cmd_run(&cmd)) return 1;

    File_Paths examples = {0};
    if (!read_entire_dir("examples", &examples)) return 1;
    da_foreach(const char *, example, &examples) {
        if (**example == '.') continue;
        cmd.count = 0;
        cmd_append(&cmd, "./build/jasm", temp_sprintf("examples/%s", *example), "build/examples");
        if (!cmd_run(&cmd)) return 1;
    }

    return 0;
}
