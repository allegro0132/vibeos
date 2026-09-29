/* Explicit invocation environment; never import host/newlib environ. */
#include "uv.h"
#include "uv-common.h"
#include "vibeos-env.h"
#include "vibeos-process.h"
#include "vibeos-sync.h"

static int env_error(int error) {
  return error == -9 ? UV_EINVAL : error == -20 ? UV_E2BIG : UV_ENOMEM;
}
int uv_os_getenv(const char* name, char* buffer, size_t* size) {
  if (!name || !buffer || !size || !*size) return UV_EINVAL;
  const char* value = vibeos_native_env_get(name, strnlen(name, 256));
  if (!value) return UV_ENOENT;
  size_t length = strlen(value);
  if (*size <= length) { *size = length + 1; return UV_ENOBUFS; }
  memcpy(buffer, value, length + 1);
  *size = length;
  return 0;
}
int uv_os_setenv(const char* name, const char* value) {
  if (!name || !value) return UV_EINVAL;
  int status = vibeos_native_env_set(name, strnlen(name, 256), value, strnlen(value, 4097), 1);
  return status ? env_error(status) : 0;
}
int uv_os_unsetenv(const char* name) {
  if (!name) return UV_EINVAL;
  int status = vibeos_native_env_unset(name, strnlen(name, 256));
  return status ? env_error(status) : 0;
}
int uv_os_environ(uv_env_item_t** output, int* count) {
  if (!output || !count) return UV_EINVAL;
  size_t length = vibeos_native_env_count();
  uv_env_item_t* items = length ? uv__calloc(length, sizeof(*items)) : NULL;
  if (length && !items) return UV_ENOMEM;
  for (size_t i = 0; i < length; i++) {
    const char *key, *value;
    if (vibeos_native_env_entry(i, &key, &value)) {
      uv_os_free_environ(items, (int) i);
      return UV_EIO;
    }
    size_t key_size = strlen(key) + 1, value_size = strlen(value) + 1;
    items[i].name = uv__malloc(key_size + value_size);
    if (!items[i].name) { uv_os_free_environ(items, (int) i); return UV_ENOMEM; }
    memcpy(items[i].name, key, key_size);
    items[i].value = items[i].name + key_size;
    memcpy(items[i].value, value, value_size);
  }
  *output = items;
  *count = (int) length;
  return 0;
}


int uv_set_process_title(const char* title) {
  if (!title) return UV_EINVAL;
  int status = vibeos_native_set_title(title, strnlen(title, 4097));
  return status ? env_error(status) : 0;
}
int uv_get_process_title(char* buffer, size_t size) {
  ptrdiff_t status = vibeos_native_get_title(buffer, size);
  return status >= 0 ? 0 : status == -21 ? UV_ENOBUFS : UV_EINVAL;
}
char** uv_setup_args(int argc, char** argv) {
  /* Native titles own their storage; never overwrite or retain argv memory. */
  if (argc > 0 && argv && argv[0]) uv_set_process_title(argv[0]);
  return argv;
}
uv_pid_t uv_os_getpid(void) {
  /* A logical invocation identity, not a host PID or a source of authority. */
  return (uv_pid_t) vibeos_native_thread_id();
}
uv_pid_t uv_os_getppid(void) {
  /* Native invocations have no POSIX parent process or child-process tree. */
  return 0;
}
void uv_disable_stdio_inheritance(void) {
  /* Stdio consists solely of explicitly granted invocation endpoints.
   * There is no inherited ambient fd table; child creation is unsupported. */
}
int uv_exepath(char* buffer, size_t* size) {
  if (!buffer || !size || !*size) return UV_EINVAL;
  /* The embedded image has no executable file in the current project root.
   * A production launcher/tool mount must supply its virtual executable path.
   * Node's upstream Environment::GetExecPath uses argv[0] on this failure. */
  return UV_ENOTSUP;
}

int uv_os_homedir(char* buffer, size_t* size) {
  /* HOME is an explicit invocation value, interpreted in the virtual namespace
   * by filesystem consumers. Never consult a host account database or cwd. */
  int status = uv_os_getenv("HOME", buffer, size);
  return status == UV_ENOENT ? UV_ENOTSUP : status;
}

int uv_os_gethostname(char* buffer, size_t* size) {
  /* A launcher-declared virtual host label, not the build host or an ambient
   * network namespace. No fallback when the invocation did not supply one. */
  int status = uv_os_getenv("HOSTNAME", buffer, size);
  return status == UV_ENOENT ? UV_ENOTSUP : status;
}
int uv_os_uname(uv_utsname_t* output) {
  if (!output) return UV_EINVAL;
  uv_utsname_t value = {0};
  char* fields[] = { value.sysname, value.release, value.version, value.machine };
  for (unsigned i = 0; i < 4; i++) {
    const char* label = vibeos_native_system_label(i);
    if (!label) return UV_EIO;
    size_t length = strlen(label);
    if (length >= sizeof(value.sysname)) return UV_ENOBUFS;
    memcpy(fields[i], label, length + 1);
  }
  *output = value;
  return 0;
}
