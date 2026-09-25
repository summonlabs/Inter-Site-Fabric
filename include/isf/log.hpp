// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Process-local logging. Output goes to stderr or an operator supplied file.
// There is no remote sink, no telemetry, and no network egress of any kind.

#ifndef ISF_LOG_HPP
#define ISF_LOG_HPP

#include <cstdint>
#include <string>
#include <string_view>

namespace isf {

enum class LogLevel : std::uint8_t {
  Error = 0,
  Warn = 1,
  Info = 2,
  Debug = 3,
  Trace = 4,
};

[[nodiscard]] const char* log_level_name(LogLevel level) noexcept;
[[nodiscard]] bool log_level_from_name(std::string_view name, LogLevel& out) noexcept;

/// Set the process-wide minimum level. Defaults to Info.
void set_log_level(LogLevel level) noexcept;
[[nodiscard]] LogLevel log_level() noexcept;

/// Redirect logs to a file. An empty path restores stderr. Returns false when
/// the file cannot be opened.
bool set_log_file(const std::string& path);

/// Emit one line. Component names are short, stable identifiers.
void log_message(LogLevel level, std::string_view component, const std::string& message);

namespace detail {
void log_formatted(LogLevel level, std::string_view component, const char* format, ...);
}  // namespace detail

#define ISF_LOG_ERROR(component, ...) \
  ::isf::detail::log_formatted(::isf::LogLevel::Error, component, __VA_ARGS__)
#define ISF_LOG_WARN(component, ...) \
  ::isf::detail::log_formatted(::isf::LogLevel::Warn, component, __VA_ARGS__)
#define ISF_LOG_INFO(component, ...) \
  ::isf::detail::log_formatted(::isf::LogLevel::Info, component, __VA_ARGS__)
#define ISF_LOG_DEBUG(component, ...) \
  ::isf::detail::log_formatted(::isf::LogLevel::Debug, component, __VA_ARGS__)
#define ISF_LOG_TRACE(component, ...) \
  ::isf::detail::log_formatted(::isf::LogLevel::Trace, component, __VA_ARGS__)

}  // namespace isf

#endif  // ISF_LOG_HPP
