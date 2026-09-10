/* CPython's public embedding API; no replacement interpreter or WASI shims. */
#include <Python.h>
#include "frozen-stdlib.h"

int main(int argc, char **argv) {
    PyImport_FrozenModules = vibe_stdlib;
    /* WASI argv is UTF-8 even when libc's locale is the default C locale. */
    PyPreConfig preconfig;
    PyPreConfig_InitIsolatedConfig(&preconfig);
    preconfig.utf8_mode = 1;
    PyStatus status = Py_PreInitialize(&preconfig);
    if (PyStatus_Exception(status))
        Py_ExitStatusException(status);
    PyConfig config;
    PyConfig_InitIsolatedConfig(&config);
    config.parse_argv = 1;
    config.site_import = 0;
    config.user_site_directory = 0;
    config.write_bytecode = 0;
    config.use_frozen_modules = 1;
    config.module_search_paths_set = 1;
    /* This stdio-only profile has no entropy grant. Explicitly disable hash
       randomization, as with PYTHONHASHSEED=0; never invent random_get bytes. */
    config.use_hash_seed = 1;
    config.hash_seed = 0;
    status = PyConfig_SetBytesString(&config, &config.home, "/");
    if (!PyStatus_Exception(status))
        status = PyConfig_SetBytesString(&config, &config.executable, "/python.wasm");
    if (!PyStatus_Exception(status))
        status = PyConfig_SetString(&config, &config.stdio_encoding, L"utf-8");
    if (!PyStatus_Exception(status))
        status = PyConfig_SetBytesArgv(&config, argc, argv);
    if (!PyStatus_Exception(status))
        status = Py_InitializeFromConfig(&config);
    PyConfig_Clear(&config);
    if (PyStatus_Exception(status))
        Py_ExitStatusException(status);
    return Py_RunMain();
}
