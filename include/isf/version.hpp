// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Build and protocol version identity for the Inter-Site Fabric runtime.

#ifndef ISF_VERSION_HPP
#define ISF_VERSION_HPP

#include "isf/version_config.hpp"

#include <cstdint>
#include <string>

namespace isf {

/// Semantic version of the runtime.
struct Version {
  std::uint32_t major{0};
  std::uint32_t minor{0};
  std::uint32_t patch{0};

  friend bool operator==(const Version&, const Version&) = default;
};

/// Version of this build of the runtime.
[[nodiscard]] Version runtime_version() noexcept;

/// Compile-time version string, e.g. "1.0.0".
[[nodiscard]] const char* runtime_version_string() noexcept;

/// Wire protocol version understood by this build. Peers negotiate on this.
inline constexpr std::uint16_t kWireProtocolVersion = 1;

/// On-disk store format version understood by this build.
inline constexpr std::uint32_t kStoreFormatVersion = 1;

/// Human readable one-line build description (no host-identifying data).
[[nodiscard]] std::string build_description();

}  // namespace isf

#endif  // ISF_VERSION_HPP
