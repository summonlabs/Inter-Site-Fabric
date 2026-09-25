// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Real OS process management for the multiprocess tests. Nothing here uses
// threads as a substitute for a second process: the runtime under test is
// exercised across process boundaries.

#ifndef ISF_TEST_PROCESS_HPP
#define ISF_TEST_PROCESS_HPP

#include "isf/status.hpp"

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace isf::test {

enum class ProcessState : std::uint8_t {
  Running = 0,
  Exited,
  Killed,
  SpawnFailed,
};

[[nodiscard]] const char* process_state_name(ProcessState s) noexcept;

/// A child process with redirected output.
class ChildProcess {
 public:
  ChildProcess() = default;
  ~ChildProcess();
  ChildProcess(ChildProcess&& other) noexcept;
  ChildProcess& operator=(ChildProcess&& other) noexcept;
  ChildProcess(const ChildProcess&) = delete;
  ChildProcess& operator=(const ChildProcess&) = delete;

  /// Spawn argv[0] with the remaining arguments. Output is redirected to the
  /// given files (empty means discard).
  [[nodiscard]] static Expected<ChildProcess> spawn(const std::vector<std::string>& argv,
                                                    const std::string& working_directory,
                                                    const std::string& stdout_path,
                                                    const std::string& stderr_path);

  /// Wait for the child to exit. The bound is an observation bound, not a test
  /// timeout: when it expires the caller is told Running, and every caller in
  /// this suite treats that as a FAILURE and then terminates the child so the
  /// suite can continue.
  [[nodiscard]] ProcessState wait_for_exit(std::uint64_t bound_ms, std::uint32_t& exit_code);

  /// Hard termination. No cleanup is performed in the child.
  [[nodiscard]] bool terminate();

  [[nodiscard]] bool running() const noexcept { return running_; }
  [[nodiscard]] std::uint32_t pid() const noexcept { return pid_; }

 private:
  void close_handles();

#if defined(_WIN32)
  void* process_{nullptr};
  void* thread_{nullptr};
#else
  int pid_{-1};
#endif
  std::uint32_t pid_{0};
  bool running_{false};
};

/// Resolve the path of a runtime program built alongside the tests.
[[nodiscard]] Expected<std::string> find_program(const std::string& name);

/// Absolute path of the directory containing the test binaries.
[[nodiscard]] std::string binary_directory();

/// Sleep for a bounded amount of wall time.
void sleep_ms(std::uint64_t milliseconds);

/// Poll a file into existence and return its parsed key=value content.
/// Returns Status::Unavailable when the file does not appear within bound_ms.
[[nodiscard]] Expected<std::vector<std::pair<std::string, std::string>>> wait_for_report(
    const std::string& path, std::uint64_t bound_ms);

}  // namespace isf::test

#endif  // ISF_TEST_PROCESS_HPP
