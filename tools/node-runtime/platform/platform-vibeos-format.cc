// Formatting follows the upstream POSIX adapter. No filesystem/stdio grant
// is involved: these operations write only to the caller's buffer.
#include "src/base/platform/platform.h"
#include <cstdio>
#include <cstring>

namespace v8::base {
int OS::SNPrintF(char* buffer, int length, const char* format, ...) {
  va_list args;
  va_start(args, format);
  const int result = VSNPrintF(buffer, length, format, args);
  va_end(args);
  return result;
}

int OS::VSNPrintF(char* buffer, int length, const char* format, va_list args) {
  if (length < 0) return -1;
  const int result = std::vsnprintf(buffer, static_cast<size_t>(length), format, args);
  if (result < 0 || result >= length) {
    if (length > 0) buffer[length - 1] = '\0';
    return -1;
  }
  return result;
}

void OS::StrNCpy(char* dest, int /* length */, const char* source, size_t count) {
  // Match strncpy, including padding and no forced terminator on truncation.
  std::strncpy(dest, source, count);
}
}  // namespace v8::base
