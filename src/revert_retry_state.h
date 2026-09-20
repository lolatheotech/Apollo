#pragma once
#include <optional>
#include <set>
#include <string>

namespace display_device {
// Empty enumeration is a real observation, not "already attempted".
// Only a non-transient failure suppresses an identical subsequent observation.
class RevertRetryState {
public:
  bool shouldAttempt(const std::set<std::string>& devices) const {
    return !failed_devices || *failed_devices != devices;
  }
  void failed(const std::set<std::string>& devices) { failed_devices = devices; }
  void temporarilyUnavailable() { failed_devices.reset(); }
private:
  std::optional<std::set<std::string>> failed_devices;
};
}
