// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "isf/log.hpp"

#include <atomic>
#include <cstdarg>
#include <cstdio>
#include <ctime>
#include <mutex>
#include <string>
#include <vector>

namespace isf {
namespace {

std::atomic<LogLevel> g_level{LogLevel::Info};
std::mutex g_sink_mutex;
std::FILE* g_sink = nullptr;  // null means stderr

[[nodiscard]] std::string timestamp() {
  const std::time_t now = std::time(nullptr);
  std::tm parts{};
#if defined(_WIN32)
  if (gmtime_s(&parts, &now) != 0) {
    return "1970-01-01T00:00:00Z";
  }
#else
  if (gmtime_r(&now, &parts) == nullptr) {
    return "1970-01-01T00:00:00Z";
  }
#endif
  char buffer[32];
  if (std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &parts) == 0) {
    return "1970-01-01T00:00:00Z";
  }
  return buffer;
}

[[nodiscard]] std::string format_message(const char* fmt, std::va_list args) {
  std::va_list copy;
  va_copy(copy, args);
  const int needed = std::vsnprintf(nullptr, 0, fmt, copy);
  va_end(copy);
  if (needed <= 0) {
    return {};
  }
  std::vector<char> buffer(static_cast<std::size_t>(needed) + 1);
  std::vsnprintf(buffer.data(), buffer.size(), fmt, args);
  return std::string(buffer.data(), static_cast<std::size_t>(needed));
}

}  // namespace

const char* log_level_name(LogLevel level) noexcept {
  switch (level) {
    case LogLevel::Error:
      return "error";
    case LogLevel::Warn:
      return "warn";
    case LogLevel::Info:
      return "info";
    case LogLevel::Debug:
      return "debug";
    case LogLevel::Trace:
      return "trace";
  }
  return "unknown";
}

bool log_level_from_name(std::string_view name, LogLevel& out) noexcept {
  if (name == "error") {
    out = LogLevel::Error;
    return true;
  }
  if (name == "warn") {
    out = LogLevel::Warn;
    return true;
  }
  if (name == "info") {
    out = LogLevel::Info;
    return true;
  }
  if (name == "debug") {
    out = LogLevel::Debug;
    return true;
  }
  if (name == "trace") {
    out = LogLevel::Trace;
    return true;
  }
  return false;
}

void set_log_level(LogLevel level) noexcept { g_level.store(level, std::memory_order_relaxed); }

LogLevel log_level() noexcept { return g_level.load(std::memory_order_relaxed); }

bool set_log_file(const std::string& path) {
  std::lock_guard<std::mutex> guard(g_sink_mutex);
  if (g_sink != nullptr) {
    std::fclose(g_sink);
    g_sink = nullptr;
  }
  if (path.empty()) {
    return true;
  }
  std::FILE* fp = std::fopen(path.c_str(), "ab");
  if (fp == nullptr) {
    return false;
  }
  g_sink = fp;
  return true;
}

void log_message(LogLevel level, std::string_view component, const std::string& message) {
  if (static_cast<std::uint8_t>(level) > static_cast<std::uint8_t>(log_level())) {
    return;
  }
  const std::string line = timestamp() + " [" + std::string(log_level_name(level)) + "] " +
                           std::string(component) + ": " + message + "\n";
  std::lock_guard<std::mutex> guard(g_sink_mutex);
  std::FILE* sink = g_sink != nullptr ? g_sink : stderr;
  (void)std::fwrite(line.data(), 1, line.size(), sink);
  (void)std::fflush(sink);
}

namespace detail {

void log_formatted(LogLevel level, std::string_view component, const char* format, ...) {
  if (static_cast<std::uint8_t>(level) > static_cast<std::uint8_t>(log_level())) {
    return;
  }
  std::va_list args;
  va_start(args, format);
  const std::string message = format_message(format, args);
  va_end(args);
  log_message(level, component, message);
}

}  // namespace detail

}  // namespace isf
