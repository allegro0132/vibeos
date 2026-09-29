#ifndef VIBEOS_NODE_INVOCATION_H_
#define VIBEOS_NODE_INVOCATION_H_
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
// Trusted launcher ABI. argv includes "node" and excludes launcher --root.
// Strings remain readable until return; eval may contain NUL bytes and is
// selected by a non-null pointer (including an empty source). All execution
// occurs on the caller's admitted, suspendable native stack.
int vibeos_node_run(unsigned argc, const char* const* argv,
                    const char* eval, size_t eval_length);
#ifdef __cplusplus
}
#endif
#endif
