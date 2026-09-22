// Non-ICU timezone support for the pinned newlib runtime. The launcher must
// install/reset the invocation's TZ environment before constructing an isolate.
#include "src/base/platform/platform.h"
#include "src/base/timezone-cache.h"
#include <cmath>
#include <ctime>
#include <limits>
extern "C" {
#include <sys/_tz_structs.h>
}

namespace v8::base {
namespace {
// newlib's rules store seconds west of UTC; V8 uses milliseconds east of UTC.
class VibeTimezoneCache final : public TimezoneCache {
 public:
  const char* LocalTimezone(double milliseconds) override {
    struct tm local;
    if (!LocalTime(milliseconds, &local)) return "";
    const char* name = tzname[local.tm_isdst > 0 ? 1 : 0];
    return name ? name : "";
  }
  double DaylightSavingsOffset(double milliseconds) override {
    struct tm local;
    if (!LocalTime(milliseconds, &local))
      return std::numeric_limits<double>::quiet_NaN();
    if (local.tm_isdst <= 0) return 0;
    const auto* rules = __gettzinfo()->__tzrule;
    // Preserve half-hour and negative DST; never assume a one-hour change.
    return (static_cast<double>(rules[0].offset) -
            static_cast<double>(rules[1].offset)) * 1000;
  }
  double LocalTimeOffset(double, bool) override {
    // Match V8's non-ICU standard-offset contract, excluding DST.
    tzset();
    return -static_cast<double>(__gettzinfo()->__tzrule[0].offset) * 1000;
  }
  void Clear(TimeZoneDetection detection) override {
    if (detection == TimeZoneDetection::kRedetect) tzset();
  }
 private:
  static bool LocalTime(double milliseconds, struct tm* local) {
    static_assert(std::numeric_limits<time_t>::is_signed);
    if (!std::isfinite(milliseconds)) return false;
    const double seconds = std::floor(milliseconds / 1000);
    // Use an exclusive power-of-two upper bound: converting INT64_MAX to
    // double rounds up and would otherwise permit an undefined integer cast.
    const double limit = std::ldexp(1.0, std::numeric_limits<time_t>::digits);
    if (seconds < -limit || seconds >= limit) return false;
    const time_t value = static_cast<time_t>(seconds);
    return localtime_r(&value, local) != nullptr;
  }
};
}
TimezoneCache* OS::CreateTimezoneCache() { return new VibeTimezoneCache(); }
}  // namespace v8::base
