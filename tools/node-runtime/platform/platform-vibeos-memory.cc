// VibeOS jitless V8 data-page adapter. Static builtins live in linker RX text.
#include "src/base/platform/platform.h"
#include "src/base/logging.h"
#include "vibeos-memory.h"
#include <cerrno>
#include <cstdint>

namespace v8::base {
namespace {
bool PageRange(void* address, size_t size) {
  const auto start = reinterpret_cast<uintptr_t>(address);
  if (size == 0 || start % VIBEOS_NATIVE_PAGE_SIZE != 0 ||
      size % VIBEOS_NATIVE_PAGE_SIZE != 0 || start > UINTPTR_MAX - size) {
    errno = EINVAL;
    return false;
  }
  return true;
}
int Permission(OS::MemoryPermission access) {
  switch (access) {
    case OS::MemoryPermission::kNoAccess: return VIBEOS_PAGE_NONE;
    case OS::MemoryPermission::kRead: return VIBEOS_PAGE_READ;
    case OS::MemoryPermission::kReadWrite: return VIBEOS_PAGE_READ_WRITE;
    case OS::MemoryPermission::kReadWriteExecute:
    case OS::MemoryPermission::kReadExecute:
    case OS::MemoryPermission::kNoAccessWillJitLater:
      errno = EPERM;
      return -1;
  }
  errno = EINVAL;
  return -1;
}
bool Unsupported() { errno = ENOTSUP; return false; }
}

size_t OS::AllocatePageSize() { return VIBEOS_NATIVE_PAGE_SIZE; }
size_t OS::CommitPageSize() { return VIBEOS_NATIVE_PAGE_SIZE; }
bool OS::HasLazyCommits() { return false; }
void OS::SetRandomMmapSeed(int64_t seed) { vibeos_native_page_hint_seed(seed); }
void* OS::GetRandomMmapAddr() { return vibeos_native_page_hint(); }

void* OS::Allocate(void* hint, size_t size, size_t alignment,
                   MemoryPermission access) {
  const int permission = Permission(access);
  if (permission < 0) return nullptr;
  if (size == 0 || size % VIBEOS_NATIVE_PAGE_SIZE != 0 ||
      alignment < VIBEOS_NATIVE_PAGE_SIZE || (alignment & (alignment - 1)) != 0) {
    errno = EINVAL;
    return nullptr;
  }
  return vibeos_native_pages_allocate(hint, size, alignment, permission);
}
void OS::Free(void* address, size_t size) {
  CHECK(PageRange(address, size));
  CHECK_EQ(0, vibeos_native_pages_release(address, size));
}
void OS::Release(void* address, size_t size) { Free(address, size); }
bool OS::SetPermissions(void* address, size_t size, MemoryPermission access) {
  const int permission = Permission(access);
  return permission >= 0 && PageRange(address, size) &&
         vibeos_native_pages_protect(address, size, permission) == 0;
}
bool OS::RecommitPages(void* address, size_t size, MemoryPermission access) {
  return SetPermissions(address, size, access);
}
bool OS::DiscardSystemPages(void* address, size_t size) {
  return PageRange(address, size) && vibeos_native_pages_discard(address, size) == 0;
}
bool OS::DecommitPages(void* address, size_t size) {
  return PageRange(address, size) && vibeos_native_pages_decommit(address, size) == 0;
}
void OS::SetDataReadOnly(void* address, size_t size) {
  CHECK(PageRange(address, size));
  CHECK_EQ(0, vibeos_native_static_readonly(address, size));
}
bool OS::SealPages(void*, size_t) { return Unsupported(); }

// No shared mappings, file-backed remapping, or large VA reservations in v1.
void* OS::AllocateShared(size_t, MemoryPermission) { Unsupported(); return nullptr; }
void* OS::AllocateShared(void*, size_t, MemoryPermission,
                         PlatformSharedMemoryHandle, uint64_t) {
  Unsupported(); return nullptr;
}
void* OS::RemapShared(void*, void*, size_t) { Unsupported(); return nullptr; }
void OS::FreeShared(void*, size_t) { FATAL("VibeOS shared pages are unsupported"); }
PlatformSharedMemoryHandle OS::CreateSharedMemoryHandleForTesting(size_t) {
  Unsupported(); return kInvalidSharedMemoryHandle;
}
void OS::DestroySharedMemoryHandle(PlatformSharedMemoryHandle) {
  FATAL("VibeOS shared memory handles are unsupported");
}
bool OS::RemapPages(const void*, size_t, void*, MemoryPermission) { return Unsupported(); }
bool OS::CanReserveAddressSpace() { return false; }
std::optional<AddressSpaceReservation> OS::CreateAddressSpaceReservation(
    void*, size_t, size_t, MemoryPermission) { Unsupported(); return std::nullopt; }
void OS::FreeAddressSpaceReservation(AddressSpaceReservation) {
  FATAL("VibeOS address space reservations are unsupported");
}
std::optional<OS::MemoryRange> OS::GetFirstFreeMemoryRangeWithin(
    OS::Address, OS::Address, size_t, size_t) { Unsupported(); return std::nullopt; }

bool AddressSpaceReservation::Allocate(void*, size_t, OS::MemoryPermission) { return Unsupported(); }
bool AddressSpaceReservation::Free(void*, size_t) { return Unsupported(); }
bool AddressSpaceReservation::AllocateShared(void*, size_t, OS::MemoryPermission,
                                             PlatformSharedMemoryHandle, uint64_t) { return Unsupported(); }
bool AddressSpaceReservation::FreeShared(void*, size_t) { return Unsupported(); }
bool AddressSpaceReservation::SetPermissions(void*, size_t, OS::MemoryPermission) { return Unsupported(); }
bool AddressSpaceReservation::RecommitPages(void*, size_t, OS::MemoryPermission) { return Unsupported(); }
bool AddressSpaceReservation::DiscardSystemPages(void*, size_t) { return Unsupported(); }
bool AddressSpaceReservation::DecommitPages(void*, size_t) { return Unsupported(); }
std::optional<AddressSpaceReservation> AddressSpaceReservation::CreateSubReservation(
    void*, size_t, OS::MemoryPermission) { Unsupported(); return std::nullopt; }
bool AddressSpaceReservation::FreeSubReservation(AddressSpaceReservation) { return Unsupported(); }
}  // namespace v8::base
