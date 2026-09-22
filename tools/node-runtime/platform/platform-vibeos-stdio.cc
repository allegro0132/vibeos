// V8 diagnostics use the invocation's newlib streams. The kernel must supply
// the capability-aware newlib write bridge; no UART or global filesystem bypass.
#include "src/base/platform/platform.h"
#include <cstdio>

namespace v8::base {
char OS::DirectorySeparator() { return '/'; }
bool OS::isDirectorySeparator(char ch) { return ch == '/'; }
const char* const OS::LogFileOpenMode = "w+";

void OS::Print(const char* format, ...) {
  va_list args;
  va_start(args, format);
  VPrint(format, args);
  va_end(args);
}
void OS::VPrint(const char* format, va_list args) {
  std::vfprintf(stdout, format, args);
}
void OS::FPrint(FILE* out, const char* format, ...) {
  va_list args;
  va_start(args, format);
  VFPrint(out, format, args);
  va_end(args);
}
void OS::VFPrint(FILE* out, const char* format, va_list args) {
  std::vfprintf(out, format, args);
}
void OS::PrintError(const char* format, ...) {
  va_list args;
  va_start(args, format);
  VPrintError(format, args);
  va_end(args);
  std::fflush(stderr);
}
void OS::VPrintError(const char* format, va_list args) {
  std::vfprintf(stderr, format, args);
}
}  // namespace v8::base
