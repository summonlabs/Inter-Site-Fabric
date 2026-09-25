// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "cli.hpp"

#include "isf/net.hpp"

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <system_error>

namespace isf::cli {
namespace {

[[nodiscard]] bool parse_u64(std::string_view text, std::uint64_t& out) {
  if (text.empty()) {
    return false;
  }
  std::uint64_t value = 0;
  for (const char c : text) {
    if (c < '0' || c > '9') {
      return false;
    }
    const std::uint64_t digit = static_cast<std::uint64_t>(c - '0');
    if (value > (kAmountMax - digit) / 10ULL) {
      return false;
    }
    value = value * 10ULL + digit;
  }
  out = value;
  return true;
}

}  // namespace

Arguments::Arguments(int argc, char** argv) {
  for (int i = 1; i < argc; ++i) {
    const std::string token = argv[i];
    const bool is_flag =
        token.size() > 2 && token[0] == '-' && token[1] == '-' && token[2] != '-';
    if (!is_flag) {
      positionals_.push_back(token);
      continue;
    }
    const std::string key = token.substr(2);
    if (i + 1 < argc) {
      const std::string next = argv[i + 1];
      const bool next_is_flag =
          next.size() > 2 && next[0] == '-' && next[1] == '-' && next[2] != '-';
      if (!next_is_flag) {
        options_[key] = next;
        ++i;
        continue;
      }
    }
    options_[key] = "true";
  }
}

bool Arguments::has(std::string_view flag) const {
  return options_.find(std::string(flag)) != options_.end();
}

std::optional<std::string> Arguments::value(std::string_view flag) const {
  const auto it = options_.find(std::string(flag));
  if (it == options_.end()) {
    return std::nullopt;
  }
  return it->second;
}

std::string Arguments::value_or(std::string_view flag, std::string fallback) const {
  const auto found = value(flag);
  return found.has_value() ? *found : std::move(fallback);
}

std::uint64_t Arguments::u64_or(std::string_view flag, std::uint64_t fallback) const {
  const auto found = value(flag);
  if (!found.has_value()) {
    return fallback;
  }
  std::uint64_t parsed = 0;
  if (!parse_u64(*found, parsed)) {
    return fallback;
  }
  return parsed;
}

std::int64_t Arguments::i64_or(std::string_view flag, std::int64_t fallback) const {
  const auto found = value(flag);
  if (!found.has_value()) {
    return fallback;
  }
  bool negative = false;
  std::string_view body = *found;
  if (!body.empty() && (body.front() == '-' || body.front() == '+')) {
    negative = body.front() == '-';
    body.remove_prefix(1);
  }
  std::uint64_t parsed = 0;
  if (!parse_u64(body, parsed)) {
    return fallback;
  }
  const auto value_signed = static_cast<std::int64_t>(parsed);
  return negative ? -value_signed : value_signed;
}

bool Arguments::flag_or(std::string_view flag, bool fallback) const {
  const auto found = value(flag);
  if (!found.has_value()) {
    return fallback;
  }
  if (*found == "true" || *found == "1" || *found == "yes" || *found == "on") {
    return true;
  }
  if (*found == "false" || *found == "0" || *found == "no" || *found == "off") {
    return false;
  }
  return fallback;
}

std::string Arguments::positional(std::size_t index, std::string fallback) const {
  if (index >= positionals_.size()) {
    return fallback;
  }
  return positionals_[index];
}

Outcome Arguments::validate(const std::vector<std::string>& required) const {
  for (const auto& flag : required) {
    if (!has(flag)) {
      return Outcome(Status::Invalid, "missing required option --" + flag);
    }
  }
  return Status::Ok;
}

Expected<std::pair<std::string, std::uint16_t>> parse_endpoint(std::string_view text) {
  auto endpoint = Endpoint::parse(text);
  if (!endpoint.ok()) {
    return endpoint.status();
  }
  return std::make_pair(endpoint.value().host, endpoint.value().port);
}

Outcome ensure_parent_directory(const std::string& path) {
  const std::filesystem::path fs_path(path);
  const std::filesystem::path parent = fs_path.parent_path();
  if (parent.empty()) {
    return Status::Ok;
  }
  std::error_code ec;
  std::filesystem::create_directories(parent, ec);
  if (ec) {
    return Outcome(Status::Unavailable, "could not create " + parent.string());
  }
  return Status::Ok;
}

Outcome write_report_file(const std::string& path,
                           const std::vector<std::pair<std::string, std::string>>& entries) {
  if (path.empty()) {
    return Status::Ok;
  }
  const Outcome prepared = ensure_parent_directory(path);
  if (prepared != Status::Ok) {
    return prepared;
  }
  std::string body;
  for (const auto& entry : entries) {
    body += entry.first;
    body += '=';
    body += entry.second;
    body += '\n';
  }
  const std::string temporary = path + ".tmp";
  {
    std::ofstream out(temporary, std::ios::binary | std::ios::trunc);
    if (!out) {
      return Outcome(Status::Unavailable, "could not open the report file for writing");
    }
    out.write(body.data(), static_cast<std::streamsize>(body.size()));
    out.flush();
    if (!out) {
      return Outcome(Status::Unavailable, "could not write the report file");
    }
  }
  std::error_code ec;
  std::filesystem::remove(path, ec);
  ec.clear();
  std::filesystem::rename(temporary, path, ec);
  if (ec) {
    return Outcome(Status::Unavailable, "could not publish the report file");
  }
  return Outcome::success();
}

std::string short_hex(const std::string& prefixed_identity) {
  const std::size_t colon = prefixed_identity.find(':');
  const std::string body =
      colon == std::string::npos ? prefixed_identity : prefixed_identity.substr(colon + 1);
  if (body.size() <= 8) {
    return body;
  }
  return body.substr(0, 8);
}

}  // namespace isf::cli
