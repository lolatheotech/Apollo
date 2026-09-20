#include "../../src/revert_retry_state.h"
#include <iostream>
#include <stdexcept>
using display_device::RevertRetryState;
void require(bool value, const char* message) {
  if (!value) throw std::runtime_error(message);
}
int main() {
  RevertRetryState state;
  const std::set<std::string> empty, physical{"physical"}, changed{"physical", "added"};
  require(state.shouldAttempt(empty), "first empty enumeration must attempt restore");
  state.failed(empty);
  require(!state.shouldAttempt(empty), "same hard-failed empty enumeration must not spin");
  require(state.shouldAttempt(physical), "device appearance must retry");
  state.temporarilyUnavailable();
  require(state.shouldAttempt(empty), "transient result after device churn must invalidate old failure");
  state.failed(physical);
  require(!state.shouldAttempt(physical), "same hard failure is suppressed");
  require(state.shouldAttempt(changed), "device addition retries");
  state.temporarilyUnavailable();
  require(state.shouldAttempt(physical), "return to prior topology after transient failure retries");
  state.temporarilyUnavailable();
  require(state.shouldAttempt(physical), "repeated transient failure retries unchanged topology");
  RevertRetryState new_schedule;
  require(new_schedule.shouldAttempt(physical), "new schedule must not inherit failure");
  std::cout << "PASS: 9 recovery scheduler assertions; no display API linked or invoked\n";
}
