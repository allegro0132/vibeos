#ifndef VIBEOS_NODE_PROCESS_H_
#define VIBEOS_NODE_PROCESS_H_
namespace v8 { class Platform; }
namespace vibeos {
// All calls run on an admitted native stack. The runtime process is initialized
// once; each invocation owns a separate environment/isolate/loop and native TLS.
int InitializeNodeProcess();
v8::Platform* NodePlatform();
void ShutdownNodeProcess();
}
#endif
