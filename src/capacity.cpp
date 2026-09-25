// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "isf/capacity.hpp"

#include <string>

namespace isf {

const char* capacity_class_name(CapacityClass c) noexcept {
  switch (c) {
    case CapacityClass::Free:
      return "FREE";
    case CapacityClass::Reserved:
      return "RESERVED";
    case CapacityClass::Committed:
      return "COMMITTED";
    case CapacityClass::Protected:
      return "PROTECTED";
    case CapacityClass::Unavailable:
      return "UNAVAILABLE";
  }
  return "INVALID";
}

Expected<Amount> CapacityLedger::allocated() const {
  auto sum = checked_add(committed, withdrawing);
  if (!sum.ok()) {
    return sum.status();
  }
  return checked_add(sum.value(), reserved);
}

Expected<Amount> CapacityLedger::basis() const {
  return checked_add(authoritative_usable, authorized_extension);
}

Status CapacityLedger::verify_closure() const {
  auto sum = checked_add(free, committed);
  if (!sum.ok()) {
    return sum.status();
  }
  const Amount parts[] = {reserved, protected_headroom, unavailable};
  for (const Amount part : parts) {
    sum = checked_add(sum.value(), part);
    if (!sum.ok()) {
      return sum.status();
    }
  }
  auto expected = basis();
  if (!expected.ok()) {
    return expected.status();
  }
  auto with_over = checked_add(expected.value(), oversubscribed);
  if (!with_over.ok()) {
    return with_over.status();
  }
  if (sum.value() != with_over.value()) {
    return Status::Incomplete;
  }
  auto held = allocated();
  if (!held.ok()) {
    return held.status();
  }
  if (reclaimable > held.value()) {
    return Status::Conflicting;
  }
  return Status::Ok;
}

std::string CapacityLedger::to_string() const {
  std::string out = "usable=";
  out += std::to_string(authoritative_usable);
  out += " free=";
  out += std::to_string(free);
  out += " allocatable=";
  out += std::to_string(allocatable);
  out += " committed=";
  out += std::to_string(committed);
  out += " withdrawing=";
  out += std::to_string(withdrawing);
  out += " reserved=";
  out += std::to_string(reserved);
  out += " protected=";
  out += std::to_string(protected_headroom);
  out += " unavailable=";
  out += std::to_string(unavailable);
  out += " reclaimable=";
  out += std::to_string(reclaimable);
  if (authorized_extension != 0) {
    out += " extension=";
    out += std::to_string(authorized_extension);
  }
  if (oversubscribed != 0) {
    out += " oversubscribed=";
    out += std::to_string(oversubscribed);
  }
  return out;
}

Amount oversubscription_extension(Amount usable, std::uint32_t ratio_bps) noexcept {
  if (ratio_bps <= 10000U) {
    return 0;
  }
  return fraction_bps(usable, ratio_bps - 10000U);
}

Amount fraction_bps(Amount value, std::uint32_t basis_points) noexcept {
  if (basis_points == 0 || value == 0) {
    return 0;
  }
  constexpr Amount kScale = 10000;
  const Amount whole = value / kScale;
  const Amount remainder = value % kScale;
  if (whole > kAmountMax / basis_points) {
    return kAmountMax;  // saturating: more protected headroom, never less
  }
  auto scaled = checked_mul(whole, basis_points);
  if (!scaled.ok()) {
    return kAmountMax;
  }
  auto tail = checked_mul(remainder, basis_points);
  if (!tail.ok()) {
    return kAmountMax;
  }
  auto total = checked_add(scaled.value(), tail.value() / kScale);
  if (!total.ok()) {
    return kAmountMax;
  }
  return total.value();
}

}  // namespace isf
