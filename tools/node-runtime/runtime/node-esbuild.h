#ifndef VIBEOS_NODE_ESBUILD_H
#define VIBEOS_NODE_ESBUILD_H
#include <memory>
namespace node { class Environment; }
struct uv_loop_s;
namespace vibeos {
class EsbuildBridge {
 public:
  EsbuildBridge(node::Environment*, uv_loop_s*);
  ~EsbuildBridge();
  void Close();
 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};
}
#endif
