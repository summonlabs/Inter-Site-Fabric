// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Shared command line helpers for the runtime programs. No third-party
// dependency, no shelling out, no telemetry.

#ifndef ISF_APPS_CLI_HPP
#define ISF_APPS_CLI_HPP

#include "isf/checked.hpp"
#include "isf/status.hpp"

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace isf::cli {

/// A very small argument parser: "--flag", "--key value", and positionals.
class Arguments {
 public:
  Arguments(int argc, char** argv);

  [[nodiscard]] bool has(std::string_view flag) const;
  [[nodiscard]] std::optional<std::string> value(std::string_view flag) const;
  [[nodiscard]] std::string value_or(std::string_view flag, std::string fallback) const;
  [[nodiscard]] std::uint64_t u64_or(std::string_view flag, std::uint64_t fallback) const;
  [[nodiscard]] std::int64_t i64_or(std::string_view flag, std::int64_t fallback) const;
  [[nodiscard]] bool flag_or(std::string_view flag, bool fallback) const;
  [[nodiscard]] const std::vector<std::string>& positionals() const noexcept {
    return positionals_;
  }
  [[nodiscard]] std::string positional(std::size_t index, std::string fallback) const;
  [[nodiscard]] std::size_t positional_count() const noexcept { return positionals_.size(); }

  /// Status::Invalid with a specific reason when a declared flag is missing or
  /// a value does not parse.
  [[nodiscard]] Outcome validate(const std::vector<std::string>& required) const;

  [[nodiscard]] const std::string& error() const noexcept { return error_; }

 private:
  std::map<std::string, std::string> options_{};
  std::vector<std::string> positionals_{};
  std::string error_{};
};

/// Resolve an endpoint string, defaulting the host to loopback.
[[nodiscard]] Expected<std::pair<std::string, std::uint16_t>> parse_endpoint(
    std::string_view text);

/// Write a small key=value report file atomically (write, flush, rename).
[[nodiscard]] Outcome write_report_file(
    const std::string& path,
    const std::vector<std::pair<std::string, std::string>>& entries);

/// Ensure every parent directory of a path exists.
[[nodiscard]] Outcome ensure_parent_directory(const std::string& path);

/// A stable identifier for this process incarnation.
[[nodiscard]] std::string short_hex(const std::string& prefixed_identity);

}  // namespace isf::cli

#endif  // ISF_APPS_CLI_HPP
