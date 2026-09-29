#ifndef VIBEOS_NODE_LIFECYCLE_H
#define VIBEOS_NODE_LIFECYCLE_H
#include <stddef.h>
#ifdef VIBEOS_NODE_LIFECYCLE_AUDIT
extern "C" void vibeos_node_libc_snapshot(size_t* output);
#endif
#endif
