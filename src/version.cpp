// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "isf/version.hpp"

#include <string>

namespace isf {

Version runtime_version() noexcept {
  return Version{static_cast<std::uint32_t>(ISF_VERSION_MAJOR),
                 static_cast<std::uint32_t>(ISF_VERSION_MINOR),
                 static_cast<std::uint32_t>(ISF_VERSION_PATCH)};
}

const char* runtime_version_string() noexcept { return ISF_VERSION_STRING; }

std::string build_description() {
  std::string out = "inter-site-fabric ";
  out += runtime_version_string();
  out += " (wire protocol ";
  out += std::to_string(kWireProtocolVersion);
  out += ", store format ";
  out += std::to_string(kStoreFormatVersion);
  out += ")";
#if defined(NDEBUG)
  out += " [release]";
#else
  out += " [debug]";
#endif
  return out;
}

}  // namespace isf
