/**
 * @file src/platform/windows/cursor_broker.h
 * @brief Interactive-session cursor metadata broker.
 */
#pragma once

#include <cstdint>
#include <string>

namespace platf::cursor_broker {
  struct snapshot_t {
    bool visible {false};
    std::string shape {"unsupported"};
    std::uint64_t sequence {0};
  };

  // Runs inside the active interactive user's session. Intended only for the
  // private cursor-broker child command launched by Apollo.
  int run(int argc, char **argv);

  // Returns a recent broker sample, or a safe unsupported/hidden fallback.
  snapshot_t snapshot();
}
