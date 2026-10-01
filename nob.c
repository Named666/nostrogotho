#define NOB_IMPLEMENTATION
#define NOB_STRIP_PREFIX
#include "nob.h"
#include "src_build/folders.h"
#include <string.h>

/* ============================================================================
 * Build dispatcher.
 *
 *   nob              -> auto-detect the host OS and build for it
 *   nob win|linux    -> force the requested target
 *   nob [target] -hr -> run the hot-reload supervisor
 *   nob [target] -test -> build and run the C unit/integration suite
 * ============================================================================ */

int main(int argc, char **argv)
{
    NOB_GO_REBUILD_URSELF_PLUS(argc, argv, "nob.h", "src_build/folders.h");

    /* Parse the target argument: "win" or "linux". Anything else falls back
     * to auto-detection based on the compiler's host target. */
    int want_win = -1; /* -1 = auto */
    int hot_reload = 0;
    int run_tests = 0;
    int separator = argc;
    int target_argc = 0;
    char **target_argv = NULL;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) { separator = i + 1; break; }
        else if (strcmp(argv[i], "win") == 0)        want_win = 1;
        else if (strcmp(argv[i], "linux") == 0) want_win = 0;
        else if (strcmp(argv[i], "-hr") == 0)   hot_reload = 1;
        else if (strcmp(argv[i], "-test") == 0) run_tests = 1;
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            nob_log(INFO, "Usage: nob [win|linux] [-hr] [-test] [-- relay-args...]");
            nob_log(INFO, "  (no argument)  auto-detect host OS");
            nob_log(INFO, "  -hr            build, run, and watch reloadable module");
            nob_log(INFO, "  -test          build and run the C test suite");
            return 0;
        } else if (argv[i][0] == '-') {
            nob_log(ERROR, "Unknown nob option: %s", argv[i]);
            return 1;
        }
    }
    if (separator < argc) {
        target_argc = argc - separator;
        target_argv = &argv[separator];
    }
    if (want_win < 0) {
#ifdef _WIN32
        want_win = 1;
#else
        want_win = 0;
#endif
        nob_log(INFO, "No target specified; auto-detected: %s",
                want_win ? "win" : "linux");
    }

    if (!nob_mkdir_if_not_exists(BUILD_FOLDER)) return 1;

    Cmd cmd = {0};
    Nob_String_Builder sb = {0};

    const char *conf_path = BUILD_FOLDER"config.h";
    int exists = file_exists(conf_path);
    if (exists < 0) return 1;
    if (exists == 0) {
        nob_log(INFO, "Generating initial %s", conf_path);
        sb_append_cstr(&sb, "#ifndef CONFIG_H_\n");
        sb_append_cstr(&sb, "#define CONFIG_H_\n");
        sb_append_cstr(&sb, "// #define FOO // Enables FOO feature\n");
        sb_append_cstr(&sb, "// #define BAR // Enables BAR feature\n");
        sb_append_cstr(&sb, "#endif // CONFIG_H_\n");
        if (!nob_write_entire_file(conf_path, sb.items, sb.count)) return 1;
        sb.count = 0;
        nob_log(INFO, "==================================");
        nob_log(INFO, "EDIT %s TO CONFIGURE YOUR BUILD!!!", conf_path);
        nob_log(INFO, "==================================");
    }

    const char *output_path = BUILD_FOLDER"nob_configed";
#ifdef _WIN32
    const char *executable_path = BUILD_FOLDER"nob_configed.exe";
#else
    const char *executable_path = output_path;
#endif
    const char *input_path = want_win ? SRC_BUILD_FOLDER"nob_win.c"
                                      : SRC_BUILD_FOLDER"nob_linux.c";
    nob_log(INFO, "Building target: %s (%s)", want_win ? "win" : "linux", input_path);

    nob_cc(&cmd);
    nob_cmd_append(&cmd, "-I.", "-I"BUILD_FOLDER, "-I"SRC_BUILD_FOLDER); // -I is usually the same across all compilers
    nob_cc_output(&cmd, output_path);
    nob_cc_inputs(&cmd, input_path);
    if (!cmd_run(&cmd)) return 1;

    cmd.count = 0;
    cmd_append(&cmd, executable_path);
    if (hot_reload) nob_cmd_append(&cmd, "-hr");
    if (run_tests) nob_cmd_append(&cmd, "-test");
    for (int i = 0; i < target_argc; i++) nob_cmd_append(&cmd, target_argv[i]);
    if (!cmd_run(&cmd)) return 1;

    return 0;
}
