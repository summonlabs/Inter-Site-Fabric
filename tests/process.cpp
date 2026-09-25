// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "process.hpp"

#include "isf/clock.hpp"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <csignal>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace isf::test {
namespace {

[[nodiscard]] std::filesystem::path executable_path() {
#if defined(_WIN32)
  char buffer[MAX_PATH]{};
  const DWORD length = GetModuleFileNameA(nullptr, buffer, MAX_PATH);
  if (length == 0) {
    return {};
  }
  return std::filesystem::path(std::string(buffer, length));
#else
  std::error_code ec;
  return std::filesystem::read_symlink("/proc/self/exe", ec);
#endif
}

}  // namespace

const char* process_state_name(ProcessState s) noexcept {
  switch (s) {
    case ProcessState::Running:
      return "RUNNING";
    case ProcessState::Exited:
      return "EXITED";
    case ProcessState::Killed:
      return "KILLED";
    case ProcessState::SpawnFailed:
      return "SPAWN_FAILED";
  }
  return "INVALID";
}

ChildProcess::~ChildProcess() {
  if (running_) {
    (void)terminate();
  }
  close_handles();
}

ChildProcess::ChildProcess(ChildProcess&& other) noexcept {
#if defined(_WIN32)
  process_ = other.process_;
  thread_ = other.thread_;
  other.process_ = nullptr;
  other.thread_ = nullptr;
#else
  pid_ = other.pid_;
  other.pid_ = -1;
#endif
  pid_ = other.pid_;
  running_ = other.running_;
  other.running_ = false;
}

ChildProcess& ChildProcess::operator=(ChildProcess&& other) noexcept {
  if (this != &other) {
    if (running_) {
      (void)terminate();
    }
    close_handles();
#if defined(_WIN32)
    process_ = other.process_;
    thread_ = other.thread_;
    other.process_ = nullptr;
    other.thread_ = nullptr;
#else
    pid_ = other.pid_;
    other.pid_ = -1;
#endif
    pid_ = other.pid_;
    running_ = other.running_;
    other.running_ = false;
  }
  return *this;
}

void ChildProcess::close_handles() {
#if defined(_WIN32)
  if (thread_ != nullptr) {
    CloseHandle(static_cast<HANDLE>(thread_));
    thread_ = nullptr;
  }
  if (process_ != nullptr) {
    CloseHandle(static_cast<HANDLE>(process_));
    process_ = nullptr;
  }
#endif
}

std::string binary_directory() {
  const std::filesystem::path executable = executable_path();
  if (executable.empty()) {
    return std::filesystem::current_path().string();
  }
  return executable.parent_path().string();
}

Expected<std::string> find_program(const std::string& name) {
  std::error_code ec;
  const std::filesystem::path here = binary_directory();
  const std::vector<std::filesystem::path> candidates = {
      here / name,
      here / (name + ".exe"),
      here / "apps" / name,
      here / "apps" / (name + ".exe"),
      here.parent_path() / "apps" / name,
      here.parent_path() / "apps" / (name + ".exe"),
      here.parent_path().parent_path() / "apps" / name,
      here.parent_path().parent_path() / "apps" / (name + ".exe"),
  };
  for (const auto& candidate : candidates) {
    if (std::filesystem::exists(candidate, ec) && !ec) {
      return candidate.string();
    }
  }
  return Outcome(Status::NotFound, "could not locate the '" + name + "' program near the tests");
}

#if defined(_WIN32)

Expected<ChildProcess> ChildProcess::spawn(const std::vector<std::string>& argv,
                                           const std::string& working_directory,
                                           const std::string& stdout_path,
                                           const std::string& stderr_path) {
  if (argv.empty()) {
    return Outcome(Status::Invalid, "spawn requires a program path");
  }
  SECURITY_ATTRIBUTES attributes{};
  attributes.nLength = sizeof(attributes);
  attributes.bInheritHandle = TRUE;

  const auto open_sink = [&attributes](const std::string& path, bool is_stdout) -> HANDLE {
    if (path.empty()) {
      return INVALID_HANDLE_VALUE;
    }
    const DWORD flags = is_stdout ? GENERIC_WRITE : GENERIC_WRITE;
    return CreateFileA(path.c_str(), flags, FILE_SHARE_READ | FILE_SHARE_WRITE, &attributes,
                       CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  };

  HANDLE out_handle = open_sink(stdout_path, true);
  HANDLE err_handle = open_sink(stderr_path, false);
  if (out_handle == INVALID_HANDLE_VALUE) {
    out_handle = CreateFileA("NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                             &attributes, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  }
  if (err_handle == INVALID_HANDLE_VALUE) {
    err_handle = CreateFileA("NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                             &attributes, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  }

  std::string command_line;
  for (const auto& argument : argv) {
    if (!command_line.empty()) {
      command_line.push_back(' ');
    }
    const bool needs_quotes = argument.find(' ') != std::string::npos ||
                              argument.find('\t') != std::string::npos || argument.empty();
    if (needs_quotes) {
      command_line.push_back('"');
      for (const char c : argument) {
        if (c == '"') {
          command_line.push_back('\\');
        }
        command_line.push_back(c);
      }
      command_line.push_back('"');
    } else {
      command_line += argument;
    }
  }

  STARTUPINFOA startup{};
  startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESTDHANDLES;
  startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
  startup.hStdOutput = out_handle;
  startup.hStdError = err_handle;

  PROCESS_INFORMATION info{};
  std::vector<char> mutable_command(command_line.begin(), command_line.end());
  mutable_command.push_back('\0');
  const char* directory = working_directory.empty() ? nullptr : working_directory.c_str();

  const BOOL created =
      CreateProcessA(nullptr, mutable_command.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW,
                     nullptr, directory, &startup, &info);

  if (out_handle != INVALID_HANDLE_VALUE) {
    CloseHandle(out_handle);
  }
  if (err_handle != INVALID_HANDLE_VALUE) {
    CloseHandle(err_handle);
  }

  if (created == FALSE) {
    return Outcome(Status::Unavailable,
                   "CreateProcess failed with error " + std::to_string(GetLastError()));
  }
  ChildProcess child;
  child.process_ = info.hProcess;
  child.thread_ = info.hThread;
  child.pid_ = info.dwProcessId;
  child.running_ = true;
  return child;
}

ProcessState ChildProcess::wait_for_exit(std::uint64_t bound_ms, std::uint32_t& exit_code) {
  exit_code = 0;
  if (process_ == nullptr) {
    return ProcessState::SpawnFailed;
  }
  const DWORD bound = bound_ms > 0xFFFFFFFFULL ? 0xFFFFFFFFU : static_cast<DWORD>(bound_ms);
  const DWORD waited = WaitForSingleObject(static_cast<HANDLE>(process_), bound);
  if (waited == WAIT_TIMEOUT) {
    return ProcessState::Running;
  }
  if (waited != WAIT_OBJECT_0) {
    return ProcessState::Running;
  }
  DWORD code = 0;
  if (GetExitCodeProcess(static_cast<HANDLE>(process_), &code) == FALSE) {
    return ProcessState::Running;
  }
  running_ = false;
  exit_code = static_cast<std::uint32_t>(code);
  return ProcessState::Exited;
}

bool ChildProcess::terminate() {
  if (process_ == nullptr) {
    return false;
  }
  const BOOL killed = TerminateProcess(static_cast<HANDLE>(process_), 0xDEADU);
  (void)WaitForSingleObject(static_cast<HANDLE>(process_), 30000);
  running_ = false;
  return killed != FALSE;
}

#else  // POSIX

Expected<ChildProcess> ChildProcess::spawn(const std::vector<std::string>& argv,
                                           const std::string& working_directory,
                                           const std::string& stdout_path,
                                           const std::string& stderr_path) {
  if (argv.empty()) {
    return Outcome(Status::Invalid, "spawn requires a program path");
  }
  const pid_t pid = ::fork();
  if (pid < 0) {
    return Outcome(Status::Unavailable, "fork failed");
  }
  if (pid == 0) {
    if (!working_directory.empty()) {
      (void)::chdir(working_directory.c_str());
    }
    const auto redirect = [](const std::string& path, int target) {
      if (path.empty()) {
        return;
      }
      FILE* file = std::freopen(path.c_str(), "wb", target == 1 ? stdout : stderr);
      (void)file;
    };
    redirect(stdout_path, 1);
    redirect(stderr_path, 2);
    std::vector<char*> raw;
    raw.reserve(argv.size() + 1);
    for (const auto& argument : argv) {
      raw.push_back(const_cast<char*>(argument.c_str()));
    }
    raw.push_back(nullptr);
    ::execv(raw[0], raw.data());
    ::_exit(127);
  }
  ChildProcess child;
  child.pid_ = pid;
  child.pid_ = static_cast<std::uint32_t>(pid);
  child.running_ = true;
  return child;
}

ProcessState ChildProcess::wait_for_exit(std::uint64_t bound_ms, std::uint32_t& exit_code) {
  exit_code = 0;
  if (pid_ <= 0) {
    return ProcessState::SpawnFailed;
  }
  const std::uint64_t deadline = isf::monotonic_ms() + bound_ms;
  for (;;) {
    int status = 0;
    const pid_t result = ::waitpid(pid_, &status, WNOHANG);
    if (result == pid_) {
      running_ = false;
      if (WIFEXITED(status)) {
        exit_code = static_cast<std::uint32_t>(WEXITSTATUS(status));
        return ProcessState::Exited;
      }
      if (WIFSIGNALED(status)) {
        exit_code = static_cast<std::uint32_t>(WTERMSIG(status));
        return ProcessState::Killed;
      }
      return ProcessState::Exited;
    }
    if (isf::monotonic_ms() >= deadline) {
      return ProcessState::Running;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
  }
}

bool ChildProcess::terminate() {
  if (pid_ <= 0) {
    return false;
  }
  const bool killed = ::kill(pid_, SIGKILL) == 0;
  int status = 0;
  (void)::waitpid(pid_, &status, 0);
  running_ = false;
  return killed;
}

#endif

void sleep_ms(std::uint64_t milliseconds) {
  std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
}

Expected<std::vector<std::pair<std::string, std::string>>> wait_for_report(
    const std::string& path, std::uint64_t bound_ms) {
  const std::uint64_t deadline = isf::monotonic_ms() + bound_ms;
  for (;;) {
    std::ifstream in(path, std::ios::binary);
    if (in) {
      std::vector<std::pair<std::string, std::string>> out;
      std::string line;
      while (std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r') {
          line.pop_back();
        }
        const std::size_t equals = line.find('=');
        if (equals == std::string::npos) {
          continue;
        }
        out.emplace_back(line.substr(0, equals), line.substr(equals + 1));
      }
      if (!out.empty()) {
        return out;
      }
    }
    if (isf::monotonic_ms() >= deadline) {
      return Outcome(Status::Unavailable, "report file did not appear within the bound");
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }
}

}  // namespace isf::test
