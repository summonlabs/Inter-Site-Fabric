// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// isfctl: operator inspection and control tooling for the fabric daemon. Every
// command is a real protocol exchange over loopback TCP; nothing here reaches
// into daemon memory.

#include "cli.hpp"

#include "isf/client.hpp"
#include "isf/clock.hpp"
#include "isf/log.hpp"

#include <cstdio>
#include <string>
#include <vector>

namespace {

using isf::cli::Arguments;

[[nodiscard]] std::string quote(const std::string& text) {
  std::string out = "\"";
  for (const char c : text) {
    if (c == '\"' || c == '\\') {
      out.push_back('\\');
    }
    if (static_cast<unsigned char>(c) < 0x20) {
      char buffer[8];
      std::snprintf(buffer, sizeof(buffer), "\\u%04x", static_cast<unsigned>(c));
      out += buffer;
      continue;
    }
    out.push_back(c);
  }
  out.push_back('"');
  return out;
}

struct Out {
  bool json{false};

  void field(std::string_view key, const std::string& value, bool last = false) const {
    if (json) {
      std::printf("  %s: %s%s\n", quote(std::string(key)).c_str(), quote(value).c_str(),
                  last ? "" : ",");
    } else {
      std::printf("%-24s %s\n", (std::string(key) + ":").c_str(), value.c_str());
    }
  }
  void number(std::string_view key, std::uint64_t value, bool last = false) const {
    if (json) {
      std::printf("  %s: %llu%s\n", quote(std::string(key)).c_str(),
                  static_cast<unsigned long long>(value), last ? "" : ",");
    } else {
      std::printf("%-24s %llu\n", (std::string(key) + ":").c_str(),
                  static_cast<unsigned long long>(value));
    }
  }
};

void usage() {
  std::fputs(
      "isfctl - inter-site fabric control and inspection\n"
      "\n"
      "usage: isfctl --daemon HOST:PORT [--json] COMMAND [options]\n"
      "\n"
      "inspection\n"
      "  status | sites | paths | grants | digest | verify | snapshot | probe\n"
      "  ledger --path ID\n"
      "\n"
      "topology and policy\n"
      "  site-register --name N [--site-id ID] [--capacity C] [--incarnation HEX]\n"
      "  site-state --site ID --state STATE [--reason R]\n"
      "  path-register --path ID --name N --a SITE --b SITE [--domain ID]\n"
      "                [--generation G] [--state S] [--advertised A] [--observed O]\n"
      "  path-state --path ID --state S [--reason R]\n"
      "  attest --path ID --usable N [--advertised A] [--observed O]\n"
      "         [--capacity-generation G] [--source S] [--principal ID] [--evidence HEX]\n"
      "  oversubscribe --path ID --ratio-bps N [--not-after-ms T]\n"
      "  policy-install [--generation G] [--protected-units N] [--protected-bps N]\n"
      "                 [--min-free-units N] [--min-free-bps N]\n"
      "                 [--max-oversubscription-bps N] [--max-lease-ms N]\n"
      "                 [--max-grants-per-path N] [--max-grants-per-site N]\n"
      "                 [--srd-concentration-bps N] [--allow-degraded-activation BOOL]\n"
      "                 [--require-verification BOOL] [--auto-reconcile BOOL]\n"
      "  epoch-bump --epoch N\n"
      "\n"
      "grant lifecycle\n"
      "  grant-propose --site ID --path ID --amount N [--duration-ms N]\n"
      "                [--class general|protected] [--incarnation HEX]\n"
      "  grant-evaluate | grant-reserve | grant-activate | grant-degrade\n"
      "  grant-withdraw | grant-retire | grant-cancel | grant-ack  --grant ID\n"
      "  grant-verify --grant ID --result verified|failed|indeterminate [--evidence HEX]\n"
      "  grant-reconcile --grant ID --target retired|active\n"
      "\n"
      "  tick | shutdown\n",
      stdout);
}

/// Accepts both the bare 32-digit form and the canonical "<prefix>:..." form
/// that the runtime itself prints, for every identity flag.
[[nodiscard]] bool parse_id(const Arguments& args, const char* flag, isf::Id128& out) {
  if (!args.has(flag)) {
    return false;
  }
  std::string text = args.value_or(flag, "");
  const std::size_t colon = text.find(':');
  if (colon != std::string::npos) {
    text.erase(0, colon + 1);
  }
  auto parsed = isf::Id128::parse(text);
  if (!parsed.ok()) {
    return false;
  }
  out = parsed.value();
  return true;
}

/// Incarnation flags accept both the bare 32-digit form and the canonical
/// "inc:..." form that the runtime itself prints.
[[nodiscard]] bool parse_incarnation(const Arguments& args, const char* flag,
                                     isf::Incarnation& out) {
  if (!args.has(flag)) {
    return false;
  }
  auto parsed = isf::Incarnation::parse(args.value_or(flag, ""));
  if (!parsed.ok()) {
    return false;
  }
  out = parsed.value();
  return true;
}

[[nodiscard]] bool parse_state(const std::string& text, isf::SiteState& out) {
  return isf::site_state_from_name(text, out);
}

[[nodiscard]] bool parse_path_state(const std::string& text, isf::PathState& out) {
  return isf::path_state_from_name(text, out);
}

const char* const kCommands[] = {
    "status",     "sites",           "paths",           "grants",       "ledger",
    "digest",     "verify",          "snapshot",        "probe",        "site-register",
    "site-state", "path-register",   "path-state",      "attest",       "oversubscribe",
    "policy-install", "epoch-bump",  "grant-propose",   "grant-evaluate",
    "grant-reserve", "grant-activate", "grant-degrade", "grant-withdraw",
    "grant-retire", "grant-cancel",  "grant-ack",       "grant-verify",
    "grant-reconcile", "tick",       "shutdown"};

}  // namespace

int main(int argc, char** argv) {
  Arguments args(argc, argv);
  if (args.has("help") || args.positional_count() == 0) {
    usage();
    return args.has("help") ? 0 : 2;
  }
  isf::set_log_level(isf::LogLevel::Error);

  const std::string command = args.positional(0, "");
  bool known = false;
  for (const char* candidate : kCommands) {
    if (command == candidate) {
      known = true;
      break;
    }
  }
  if (!known) {
    std::fprintf(stderr, "isfctl: unknown command '%s'\n", command.c_str());
    return 2;
  }

  if (command == "probe") {
    // Probe deliberately runs before any handshake logic so that a version or
    // framing mismatch is reported rather than hidden.
  }

  const isf::Outcome required = args.validate({"daemon"});
  if (required != isf::Status::Ok) {
    std::fprintf(stderr, "isfctl: %s\n", required.to_string().c_str());
    return 2;
  }

  isf::ClientOptions options;
  auto endpoint = isf::Endpoint::parse(args.value_or("daemon", ""));
  if (!endpoint.ok()) {
    std::fprintf(stderr, "isfctl: %s\n", endpoint.detail().c_str());
    return 2;
  }
  options.endpoint = endpoint.value();
  options.client_kind = "isfctl";

  auto client = isf::FabricClient::connect(options);
  if (!client.ok()) {
    std::fprintf(stderr, "isfctl: %s\n", client.outcome().to_string().c_str());
    return 3;
  }

  Out out;
  out.json = args.has("json");
  const std::uint64_t now = isf::now_ms();
  const isf::Epoch epoch = client.value().hello().epoch;

  if (command == "probe") {
    if (out.json) {
      std::printf("{\n");
    }
    out.field("endpoint", endpoint.value().to_string());
    out.field("protocol_version", std::to_string(client.value().hello().protocol_version));
    out.field("server_incarnation", client.value().hello().server_incarnation.to_string());
    out.field("epoch", client.value().hello().epoch.to_string());
    out.field("store_fidelity", isf::recovery_fidelity_name(client.value().hello().store_fidelity));
    out.field("frame_bound", std::to_string(client.value().hello().max_frame_bytes));
    out.field("store_servable", client.value().hello().store_servable ? "true" : "false", true);
    if (out.json) {
      std::printf("}\n");
    }
    return 0;
  }

  if (command == "status") {
    auto status = client.value().status();
    if (!status.ok()) {
      std::fprintf(stderr, "isfctl: %s\n", status.outcome().to_string().c_str());
      return 4;
    }
    const isf::StatusReport& report = status.value();
    if (out.json) {
      std::printf("{\n");
    }
    out.field("version", isf::runtime_version_string());
    out.field("incarnation", report.incarnation.to_string());
    out.field("epoch", report.epoch.to_string());
    out.field("policy_generation", report.policy.generation.to_string());
    out.field("store_fidelity", isf::recovery_fidelity_name(report.store_fidelity));
    out.field("store_servable", report.store_servable ? "true" : "false");
    out.field("store_truncated_on_open", report.store_truncated_on_open ? "true" : "false");
    out.number("store_records", report.store_records);
    out.number("store_bytes", report.store_bytes);
    out.number("ambiguous_intents", report.ambiguous_intents);
    out.number("sites", report.sites);
    out.number("paths", report.paths);
    out.number("grants", report.grants);
    out.number("mutations_applied", report.mutations_applied);
    out.number("mutations_refused", report.mutations_refused);
    out.number("mutations_failed", report.mutations_failed);
    out.number("uptime_ms", report.uptime_ms);
    out.field("aggregate_ledger", report.aggregate.to_string());
    out.field("state_digest", report.state_digest.to_string());
    out.field("detail", report.detail, true);
    if (out.json) {
      std::printf("}\n");
    }
    return 0;
  }

  if (command == "sites") {
    auto sites = client.value().list_sites();
    if (!sites.ok()) {
      std::fprintf(stderr, "isfctl: %s\n", sites.outcome().to_string().c_str());
      return 4;
    }
    for (const auto& site : sites.value()) {
      if (out.json) {
        std::printf("{\n");
      }
      out.field("id", site.id.to_string());
      out.field("name", site.name);
      out.field("state", isf::site_state_name(site.state));
      out.field("incarnation", site.incarnation.to_string());
      out.field("generation", site.generation.to_string());
      out.field("epoch", site.epoch.to_string());
      out.number("advertised_capacity", site.advertised_capacity);
      out.number("last_heartbeat_ms", site.last_heartbeat_ms);
      out.field("provenance", isf::provenance_name(site.provenance));
      out.field("fence_reason", site.fence_reason, true);
      if (out.json) {
        std::printf("}\n");
      }
    }
    if (sites.value().empty()) {
      std::fputs("no sites registered\n", stdout);
    }
    return 0;
  }

  if (command == "paths") {
    auto paths = client.value().list_paths();
    if (!paths.ok()) {
      std::fprintf(stderr, "isfctl: %s\n", paths.outcome().to_string().c_str());
      return 4;
    }
    for (const auto& path : paths.value()) {
      if (out.json) {
        std::printf("{\n");
      }
      out.field("id", path.id.to_string());
      out.field("name", path.name);
      out.field("state", isf::path_state_name(path.state));
      out.field("endpoint_a", path.endpoint_a.to_string());
      out.field("endpoint_b", path.endpoint_b.to_string());
      out.field("shared_risk_domain", path.shared_risk_domain.to_string());
      out.field("generation", path.generation.to_string());
      out.field("capacity_generation", path.capacity_generation.to_string());
      out.number("advertised", path.advertised);
      out.number("observed", path.observed);
      out.number("authoritative_usable", path.authoritative_usable);
      out.number("unavailable", path.unavailable);
      out.field("provenance", isf::provenance_name(path.provenance), true);
      if (out.json) {
        std::printf("}\n");
      }
    }
    if (paths.value().empty()) {
      std::fputs("no paths registered\n", stdout);
    }
    return 0;
  }

  if (command == "grants") {
    isf::ListFilter filter;
    filter.include_terminal = args.flag_or("include-terminal", true);
    filter.limit = static_cast<std::uint32_t>(args.u64_or("limit", 4096));
    if (args.has("path")) {
      auto parsed = isf::PathId::parse(args.value_or("path", ""));
      if (!parsed.ok()) {
        std::fprintf(stderr, "isfctl: --path is not a valid identity\n");
        return 2;
      }
      filter.path = parsed.value();
    }
    if (args.has("site")) {
      auto parsed = isf::SiteId::parse(args.value_or("site", ""));
      if (!parsed.ok()) {
        std::fprintf(stderr, "isfctl: --site is not a valid identity\n");
        return 2;
      }
      filter.site = parsed.value();
    }
    auto grants = client.value().list_grants(filter);
    if (!grants.ok()) {
      std::fprintf(stderr, "isfctl: %s\n", grants.outcome().to_string().c_str());
      return 4;
    }
    for (const auto& grant : grants.value()) {
      if (out.json) {
        std::printf("{\n");
      }
      out.field("id", grant.id.to_string());
      out.field("state", isf::grant_state_name(grant.state));
      out.field("class", isf::grant_class_name(grant.grant_class));
      out.number("amount", grant.amount);
      out.field("holder", grant.binding.holder.to_string());
      out.field("path", grant.binding.path.to_string());
      out.field("lease", grant.binding.lease.to_string());
      out.field("arbitration", grant.arbitration.to_string());
      out.field("verification", isf::verification_state_name(grant.verification));
      out.field("acknowledged", grant.acknowledged ? "true" : "false");
      out.field("historical", grant.historical ? "true" : "false");
      out.field("ambiguous", grant.ambiguous ? "true" : "false");
      out.field("provenance", isf::provenance_name(grant.provenance));
      out.field("reason", grant.reason, true);
      if (out.json) {
        std::printf("}\n");
      }
    }
    if (grants.value().empty()) {
      std::fputs("no grants\n", stdout);
    }
    return 0;
  }

  if (command == "ledger" || command == "verify") {
    auto paths = client.value().list_paths();
    if (!paths.ok()) {
      std::fprintf(stderr, "isfctl: %s\n", paths.outcome().to_string().c_str());
      return 4;
    }
    std::vector<isf::PathRecord> selected;
    if (command == "ledger") {
      auto parsed = isf::PathId::parse(args.value_or("path", ""));
      if (!parsed.ok()) {
        std::fprintf(stderr, "isfctl: --path is required for ledger\n");
        return 2;
      }
      for (const auto& path : paths.value()) {
        if (path.id == parsed.value()) {
          selected.push_back(path);
        }
      }
      if (selected.empty()) {
        std::fprintf(stderr, "isfctl: no such path\n");
        return 4;
      }
    } else {
      selected = paths.value();
    }
    int failures = 0;
    for (const auto& path : selected) {
      auto ledger = client.value().ledger(path.id);
      if (!ledger.ok()) {
        std::fprintf(stderr, "isfctl: path %s: %s\n", path.id.to_string().c_str(),
                     ledger.outcome().to_string().c_str());
        ++failures;
        continue;
      }
      const isf::Status closure = ledger.value().verify_closure();
      if (out.json) {
        std::printf("{\n");
      }
      out.field("path", path.id.to_string());
      out.number("authoritative_usable", ledger.value().authoritative_usable);
      out.number("committed", ledger.value().committed);
      out.number("withdrawing", ledger.value().withdrawing);
      out.number("reserved", ledger.value().reserved);
      out.number("protected_headroom", ledger.value().protected_headroom);
      out.number("unavailable", ledger.value().unavailable);
      out.number("free", ledger.value().free);
      out.number("allocatable", ledger.value().allocatable);
      out.number("reclaimable", ledger.value().reclaimable);
      out.number("oversubscribed", ledger.value().oversubscribed);
      out.number("authorized_extension", ledger.value().authorized_extension);
      out.field("closure", isf::status_name(closure), true);
      if (out.json) {
        std::printf("}\n");
      }
      if (closure != isf::Status::Ok) {
        ++failures;
      }
    }
    return failures == 0 ? 0 : 5;
  }

  if (command == "digest") {
    auto digest = client.value().digest();
    if (!digest.ok()) {
      std::fprintf(stderr, "isfctl: %s\n", digest.outcome().to_string().c_str());
      return 4;
    }
    if (out.json) {
      std::printf("{\n");
    }
    out.field("state_digest", digest.value().state_digest.to_string());
    out.field("policy_digest", digest.value().policy_digest);
    out.number("last_arbitration", digest.value().last_arbitration);
    out.number("sites", digest.value().sites);
    out.number("paths", digest.value().paths);
    out.number("grants", digest.value().grants, true);
    if (out.json) {
      std::printf("}\n");
    }
    return 0;
  }

  if (command == "snapshot") {
    auto snapshot = client.value().snapshot();
    if (!snapshot.ok()) {
      std::fprintf(stderr, "isfctl: %s\n", snapshot.outcome().to_string().c_str());
      return 4;
    }
    if (out.json) {
      std::printf("{\n");
    }
    out.field("epoch", snapshot.value().epoch.to_string());
    out.field("incarnation", snapshot.value().incarnation.to_string());
    out.number("sites", snapshot.value().sites.size());
    out.number("paths", snapshot.value().paths.size());
    out.number("domains", snapshot.value().domains.size());
    out.number("attestations", snapshot.value().attestations.size());
    out.number("grants", snapshot.value().grants.size());
    out.number("verifications", snapshot.value().verifications.size());
    out.number("oversubscriptions", snapshot.value().oversubscriptions.size());
    out.number("last_arbitration", snapshot.value().last_arbitration.value, true);
    if (out.json) {
      std::printf("}\n");
    }
    return 0;
  }

  if (command == "tick") {
    auto ticked = client.value().tick(now);
    if (!ticked.ok() && ticked.status() != isf::Status::Refused) {
      std::fprintf(stderr, "isfctl: %s\n", ticked.outcome().to_string().c_str());
      return 4;
    }
    std::puts(ticked.ok() ? "tick applied" : "nothing to expire");
    return 0;
  }

  if (command == "shutdown") {
    const isf::Outcome status = client.value().request_shutdown();
    if (status != isf::Status::Ok) {
      std::fprintf(stderr, "isfctl: %s\n", status.to_string().c_str());
      return 4;
    }
    std::puts("shutdown accepted");
    return 0;
  }

  // ---- mutations -----------------------------------------------------------

  if (command == "site-register") {
    isf::SiteDescriptor descriptor;
    descriptor.name = args.value_or("name", "");
    descriptor.id = isf::SiteId::from_seed(isf::fnv1a64(descriptor.name), 0x15F0517EULL);
    isf::Id128 explicit_id;
    if (parse_id(args, "site-id", explicit_id)) {
      descriptor.id = isf::SiteId::from_raw(explicit_id);
    }
    descriptor.advertised_capacity = args.u64_or("capacity", 0);
    isf::Incarnation incarnation = isf::Incarnation::random();
    isf::Incarnation explicit_incarnation;
    if (parse_incarnation(args, "incarnation", explicit_incarnation)) {
      incarnation = explicit_incarnation;
    }
    auto result = client.value().register_site(descriptor, incarnation, epoch, now);
    if (!result.ok()) {
      std::fprintf(stderr, "isfctl: %s\n", result.outcome().to_string().c_str());
      return 4;
    }
    auto site = isf::extract_site(result.value());
    if (!site.ok()) {
      std::fprintf(stderr, "isfctl: reply carried no site record\n");
      return 4;
    }
    out.field("site_id", site.value().id.to_string());
    out.field("generation", site.value().generation.to_string());
    out.field("incarnation", site.value().incarnation.to_string());
    out.field("state", isf::site_state_name(site.value().state), true);
    return 0;
  }

  if (command == "site-state") {
    auto site = isf::SiteId::parse(args.value_or("site", ""));
    isf::SiteState state{};
    if (!site.ok() || !parse_state(args.value_or("state", ""), state)) {
      std::fprintf(stderr, "isfctl: --site and --state are required and must be valid\n");
      return 2;
    }
    auto result = client.value().set_site_state(site.value(), state, args.value_or("reason", ""), now);
    if (!result.ok()) {
      std::fprintf(stderr, "isfctl: %s\n", result.outcome().to_string().c_str());
      return 4;
    }
    std::printf("site %s set to %s\n", site.value().to_string().c_str(), isf::site_state_name(state));
    return 0;
  }

  if (command == "path-register") {
    isf::PathRegistration registration;
    auto path = isf::PathId::parse(args.value_or("path", ""));
    auto a = isf::SiteId::parse(args.value_or("a", ""));
    auto b = isf::SiteId::parse(args.value_or("b", ""));
    if (!path.ok() || !a.ok() || !b.ok()) {
      std::fprintf(stderr, "isfctl: --path, --a and --b are required and must be valid\n");
      return 2;
    }
    registration.descriptor.id = path.value();
    registration.descriptor.name = args.value_or("name", args.value_or("path", ""));
    registration.descriptor.endpoint_a = a.value();
    registration.descriptor.endpoint_b = b.value();
    isf::Id128 domain;
    if (parse_id(args, "domain", domain)) {
      registration.descriptor.shared_risk_domain = isf::DomainId::from_raw(domain);
    }
    isf::Id128 edge;
    if (parse_id(args, "edge", edge)) {
      registration.descriptor.edge = isf::EdgeId::from_raw(edge);
    }
    registration.path_generation = isf::Generation{args.u64_or("generation", 1)};
    registration.advertised = args.u64_or("advertised", 0);
    registration.observed = args.u64_or("observed", 0);
    registration.now_ms = now;
    isf::PathState state = isf::PathState::Up;
    (void)parse_path_state(args.value_or("state", "UP"), state);
    registration.state = state;
    auto result = client.value().register_path(registration);
    if (!result.ok()) {
      std::fprintf(stderr, "isfctl: %s\n", result.outcome().to_string().c_str());
      return 4;
    }
    auto record = isf::extract_path(result.value());
    if (!record.ok()) {
      std::fprintf(stderr, "isfctl: reply carried no path record\n");
      return 4;
    }
    out.field("path_id", record.value().id.to_string());
    out.field("generation", record.value().generation.to_string());
    out.field("capacity_generation", record.value().capacity_generation.to_string());
    out.number("authoritative_usable", record.value().authoritative_usable, true);
    return 0;
  }

  if (command == "path-state") {
    auto path = isf::PathId::parse(args.value_or("path", ""));
    isf::PathState state{};
    if (!path.ok() || !parse_path_state(args.value_or("state", ""), state)) {
      std::fprintf(stderr, "isfctl: --path and --state are required and must be valid\n");
      return 2;
    }
    auto result = client.value().set_path_state(path.value(), state, args.value_or("reason", ""), now);
    if (!result.ok()) {
      std::fprintf(stderr, "isfctl: %s\n", result.outcome().to_string().c_str());
      return 4;
    }
    std::printf("path %s set to %s\n", path.value().to_string().c_str(), isf::path_state_name(state));
    return 0;
  }

  if (command == "attest") {
    auto path = isf::PathId::parse(args.value_or("path", ""));
    if (!path.ok() || !args.has("usable")) {
      std::fprintf(stderr, "isfctl: --path and --usable are required\n");
      return 2;
    }
    auto paths = client.value().list_paths();
    if (!paths.ok()) {
      std::fprintf(stderr, "isfctl: %s\n", paths.outcome().to_string().c_str());
      return 4;
    }
    isf::Generation path_generation{};
    isf::Generation capacity_generation{};
    bool found = false;
    for (const auto& record : paths.value()) {
      if (record.id == path.value()) {
        path_generation = record.generation;
        capacity_generation = record.capacity_generation;
        found = true;
      }
    }
    if (!found) {
      std::fprintf(stderr, "isfctl: no such path\n");
      return 4;
    }
    isf::CapacityAttestation attestation;
    attestation.id = isf::AttestationId::random();
    attestation.path = path.value();
    attestation.path_generation = path_generation;
    attestation.capacity_generation = isf::Generation{args.u64_or(
        "capacity-generation", capacity_generation.value + 1)};
    attestation.usable = args.u64_or("usable", 0);
    attestation.advertised = args.u64_or("advertised", 0);
    attestation.observed = args.u64_or("observed", 0);
    attestation.issuer = client.value().hello().server_incarnation;
    attestation.epoch = epoch;
    attestation.principal = isf::PrincipalId::from_seed(isf::fnv1a64(args.value_or("principal", "operator")), 7);
    isf::Id128 principal;
    if (parse_id(args, "principal", principal)) {
      attestation.principal = isf::PrincipalId::from_raw(principal);
    }
    attestation.observed_at_ms = now;
    attestation.source = args.value_or("source", "isfctl");
    const std::string evidence_text = args.value_or(
        "evidence", isf::Digest256::of(isf::ByteSpan(
                        reinterpret_cast<const isf::Byte*>(attestation.source.data()),
                        attestation.source.size()))
                        .to_hex());
    auto evidence = isf::Digest256::parse(evidence_text);
    if (!evidence.ok()) {
      std::fprintf(stderr, "isfctl: --evidence must be a sha256 digest\n");
      return 2;
    }
    attestation.evidence = evidence.value();
    auto result = client.value().attest_capacity(attestation);
    if (!result.ok()) {
      std::fprintf(stderr, "isfctl: %s\n", result.outcome().to_string().c_str());
      return 4;
    }
    std::printf("path %s attested usable=%llu capacity_generation=%s\n",
                path.value().to_string().c_str(),
                static_cast<unsigned long long>(attestation.usable),
                attestation.capacity_generation.to_string().c_str());
    return 0;
  }

  if (command == "oversubscribe") {
    auto path = isf::PathId::parse(args.value_or("path", ""));
    if (!path.ok() || !args.has("ratio-bps")) {
      std::fprintf(stderr, "isfctl: --path and --ratio-bps are required\n");
      return 2;
    }
    auto paths = client.value().list_paths();
    if (!paths.ok()) {
      std::fprintf(stderr, "isfctl: %s\n", paths.outcome().to_string().c_str());
      return 4;
    }
    isf::OversubscriptionAuthority authority;
    authority.id = isf::OversubscriptionId::random();
    authority.path = path.value();
    authority.epoch = epoch;
    authority.policy_generation = client.value().hello().epoch.value == 0
                                      ? isf::Generation{1}
                                      : isf::Generation{1};
    authority.issuer = client.value().hello().server_incarnation;
    authority.principal =
        isf::PrincipalId::from_seed(isf::fnv1a64(args.value_or("principal", "operator")), 8);
    authority.ratio_bps = static_cast<std::uint32_t>(args.u64_or("ratio-bps", 0));
    authority.issued_at_ms = now;
    authority.not_after_ms = args.u64_or("not-after-ms", 0);
    bool found = false;
    for (const auto& record : paths.value()) {
      if (record.id == path.value()) {
        authority.path_generation = record.generation;
        authority.capacity_generation = record.capacity_generation;
        found = true;
      }
    }
    if (!found) {
      std::fprintf(stderr, "isfctl: no such path\n");
      return 4;
    }
    auto status = client.value().status();
    if (!status.ok()) {
      std::fprintf(stderr, "isfctl: %s\n", status.outcome().to_string().c_str());
      return 4;
    }
    authority.policy_generation = status.value().policy.generation;
    auto result = client.value().issue_oversubscription(authority);
    if (!result.ok()) {
      std::fprintf(stderr, "isfctl: %s\n", result.outcome().to_string().c_str());
      return 4;
    }
    std::printf("oversubscription issued for path %s ratio=%u bps\n",
                path.value().to_string().c_str(), authority.ratio_bps);
    return 0;
  }

  if (command == "policy-install") {
    auto current = client.value().status();
    if (!current.ok()) {
      std::fprintf(stderr, "isfctl: %s\n", current.outcome().to_string().c_str());
      return 4;
    }
    isf::Policy policy = current.value().policy;
    policy.generation = isf::Generation{args.u64_or("generation", policy.generation.value + 1)};
    policy.protected_floor_units = args.u64_or("protected-units", policy.protected_floor_units);
    policy.protected_floor_bps =
        static_cast<std::uint32_t>(args.u64_or("protected-bps", policy.protected_floor_bps));
    policy.min_free_units = args.u64_or("min-free-units", policy.min_free_units);
    policy.min_free_bps =
        static_cast<std::uint32_t>(args.u64_or("min-free-bps", policy.min_free_bps));
    policy.max_oversubscription_bps = static_cast<std::uint32_t>(
        args.u64_or("max-oversubscription-bps", policy.max_oversubscription_bps));
    policy.max_lease_duration_ms = args.u64_or("max-lease-ms", policy.max_lease_duration_ms);
    policy.max_grants_per_path =
        static_cast<std::uint32_t>(args.u64_or("max-grants-per-path", policy.max_grants_per_path));
    policy.max_grants_per_site =
        static_cast<std::uint32_t>(args.u64_or("max-grants-per-site", policy.max_grants_per_site));
    policy.max_srd_concentration_bps = static_cast<std::uint32_t>(
        args.u64_or("srd-concentration-bps", policy.max_srd_concentration_bps));
    policy.allow_degraded_activation =
        args.flag_or("allow-degraded-activation", policy.allow_degraded_activation);
    policy.require_verification_for_active =
        args.flag_or("require-verification", policy.require_verification_for_active);
    policy.auto_reconcile_on_restart =
        args.flag_or("auto-reconcile", policy.auto_reconcile_on_restart);
    policy.allow_partition_optimistic_recovery = false;
    auto result = client.value().install_policy(
        policy, isf::PrincipalId::from_seed(isf::fnv1a64(args.value_or("principal", "operator")), 9));
    if (!result.ok()) {
      std::fprintf(stderr, "isfctl: %s\n", result.outcome().to_string().c_str());
      return 4;
    }
    std::printf("policy generation %s installed\n", policy.generation.to_string().c_str());
    return 0;
  }

  if (command == "epoch-bump") {
    isf::Epoch next{args.u64_or("epoch", epoch.value + 1)};
    auto result = client.value().bump_epoch(
        next, isf::PrincipalId::from_seed(isf::fnv1a64(args.value_or("principal", "operator")), 10));
    if (!result.ok()) {
      std::fprintf(stderr, "isfctl: %s\n", result.outcome().to_string().c_str());
      return 4;
    }
    std::printf("epoch advanced to %s\n", next.to_string().c_str());
    return 0;
  }

  if (command == "grant-propose") {
    auto site = isf::SiteId::parse(args.value_or("site", ""));
    auto path = isf::PathId::parse(args.value_or("path", ""));
    if (!site.ok() || !path.ok() || !args.has("amount")) {
      std::fprintf(stderr, "isfctl: --site, --path and --amount are required\n");
      return 2;
    }
    auto sites = client.value().list_sites();
    if (!sites.ok()) {
      std::fprintf(stderr, "isfctl: %s\n", sites.outcome().to_string().c_str());
      return 4;
    }
    isf::Incarnation incarnation;
    isf::Generation generation{};
    bool found = false;
    for (const auto& record : sites.value()) {
      if (record.id == site.value()) {
        incarnation = record.incarnation;
        generation = record.generation;
        found = true;
      }
    }
    if (!found) {
      std::fprintf(stderr, "isfctl: no such site\n");
      return 4;
    }
    isf::Incarnation explicit_incarnation;
    if (parse_incarnation(args, "incarnation", explicit_incarnation)) {
      incarnation = explicit_incarnation;
    }
    isf::GrantProposal proposal;
    proposal.request = isf::RequestId::random();
    isf::Id128 explicit_request;
    if (parse_id(args, "request", explicit_request)) {
      proposal.request = isf::RequestId::from_raw(explicit_request);
    }
    proposal.holder = site.value();
    proposal.holder_incarnation = incarnation;
    proposal.holder_generation = generation;
    proposal.path = path.value();
    proposal.amount = args.u64_or("amount", 0);
    proposal.grant_class = args.value_or("class", "general") == "protected"
                               ? isf::GrantClass::Protected
                               : isf::GrantClass::General;
    proposal.duration_ms = args.u64_or("duration-ms", 60000);
    proposal.now_ms = now;
    proposal.reason = args.value_or("reason", "operator proposal");
    isf::Id128 explicit_grant;
    if (parse_id(args, "grant", explicit_grant)) {
      proposal.grant_id = isf::GrantId::from_raw(explicit_grant);
    }
    auto result = client.value().propose_grant(proposal);
    if (!result.ok()) {
      std::fprintf(stderr, "isfctl: %s\n", result.outcome().to_string().c_str());
      return 4;
    }
    auto grant = isf::extract_grant(result.value());
    if (!grant.ok()) {
      std::fprintf(stderr, "isfctl: reply carried no grant record\n");
      return 4;
    }
    out.field("grant_id", grant.value().id.to_string());
    out.field("state", isf::grant_state_name(grant.value().state));
    out.field("lease", grant.value().binding.lease.to_string());
    out.field("arbitration", grant.value().arbitration.to_string(), true);
    return 0;
  }

  if (command == "grant-evaluate" || command == "grant-reserve" || command == "grant-activate" ||
      command == "grant-degrade" || command == "grant-withdraw" || command == "grant-retire" ||
      command == "grant-cancel") {
    auto grant_id = isf::GrantId::parse(args.value_or("grant", ""));
    if (!grant_id.ok()) {
      std::fprintf(stderr, "isfctl: --grant is required and must be valid\n");
      return 2;
    }
    isf::GrantOperation op;
    op.grant = grant_id.value();
    op.epoch = epoch;
    op.now_ms = now;
    op.reason = args.value_or("reason", "isfctl " + command);
    if (args.has("site")) {
      auto site = isf::SiteId::parse(args.value_or("site", ""));
      if (site.ok()) {
        op.actor = site.value();
      }
    }
    isf::Incarnation incarnation;
    if (parse_incarnation(args, "incarnation", incarnation)) {
      op.actor_incarnation = incarnation;
    }
    isf::Expected<isf::MutationReport> result = isf::Status::Unsupported;
    if (command == "grant-evaluate") {
      result = client.value().evaluate_grant(op);
    } else if (command == "grant-reserve") {
      result = client.value().reserve_grant(op);
    } else if (command == "grant-activate") {
      result = client.value().activate_grant(op);
    } else if (command == "grant-degrade") {
      result = client.value().degrade_grant(op);
    } else if (command == "grant-withdraw") {
      result = client.value().withdraw_grant(op);
    } else if (command == "grant-retire") {
      result = client.value().retire_grant(op);
    } else {
      result = client.value().cancel_grant(op);
    }
    if (!result.ok()) {
      std::fprintf(stderr, "isfctl: %s\n", result.outcome().to_string().c_str());
      return 4;
    }
    auto grant = isf::extract_grant(result.value());
    if (!grant.ok()) {
      std::fprintf(stderr, "isfctl: reply carried no grant record\n");
      return 4;
    }
    out.field("grant_id", grant.value().id.to_string());
    out.field("state", isf::grant_state_name(grant.value().state), true);
    return 0;
  }

  if (command == "grant-ack") {
    auto grant_id = isf::GrantId::parse(args.value_or("grant", ""));
    if (!grant_id.ok()) {
      std::fprintf(stderr, "isfctl: --grant is required and must be valid\n");
      return 2;
    }
    isf::GrantAcknowledgement ack;
    ack.grant = grant_id.value();
    ack.epoch = epoch;
    ack.now_ms = now;
    auto result = client.value().acknowledge_grant(ack);
    if (!result.ok()) {
      std::fprintf(stderr, "isfctl: %s\n", result.outcome().to_string().c_str());
      return 4;
    }
    auto grant = isf::extract_grant(result.value());
    std::printf("grant %s acknowledged=%s verification=%s\n", grant_id.value().to_string().c_str(),
                grant.ok() && grant.value().acknowledged ? "true" : "false",
                grant.ok() ? isf::verification_state_name(grant.value().verification) : "UNKNOWN");
    return 0;
  }

  if (command == "grant-verify") {
    auto grant_id = isf::GrantId::parse(args.value_or("grant", ""));
    if (!grant_id.ok()) {
      std::fprintf(stderr, "isfctl: --grant is required and must be valid\n");
      return 2;
    }
    isf::GrantVerification verification;
    verification.id = isf::VerificationId::random();
    verification.grant = grant_id.value();
    verification.verifier =
        isf::PrincipalId::from_seed(isf::fnv1a64(args.value_or("verifier", "verifier")), 11);
    const std::string result_text = args.value_or("result", "verified");
    if (result_text == "verified") {
      verification.result = isf::VerificationState::Verified;
    } else if (result_text == "failed") {
      verification.result = isf::VerificationState::Failed;
    } else if (result_text == "indeterminate") {
      verification.result = isf::VerificationState::Indeterminate;
    } else {
      std::fprintf(stderr, "isfctl: --result must be verified, failed or indeterminate\n");
      return 2;
    }
    const std::string evidence_text = args.value_or(
        "evidence", isf::Digest256::of(isf::ByteSpan(reinterpret_cast<const isf::Byte*>(command.data()),
                                                     command.size()))
                        .to_hex());
    auto evidence = isf::Digest256::parse(evidence_text);
    if (!evidence.ok()) {
      std::fprintf(stderr, "isfctl: --evidence must be a sha256 digest\n");
      return 2;
    }
    verification.evidence = evidence.value();
    verification.now_ms = now;
    verification.detail = args.value_or("detail", "");
    auto result = client.value().verify_grant(verification);
    if (!result.ok()) {
      std::fprintf(stderr, "isfctl: %s\n", result.outcome().to_string().c_str());
      return 4;
    }
    std::printf("grant %s verification=%s\n", grant_id.value().to_string().c_str(),
                isf::verification_state_name(verification.result));
    return 0;
  }

  if (command == "grant-reconcile") {
    auto grant_id = isf::GrantId::parse(args.value_or("grant", ""));
    if (!grant_id.ok()) {
      std::fprintf(stderr, "isfctl: --grant is required and must be valid\n");
      return 2;
    }
    isf::GrantState target = isf::GrantState::Retired;
    if (args.value_or("target", "retired") == "active") {
      target = isf::GrantState::Active;
    }
    isf::GrantOperation op;
    op.grant = grant_id.value();
    op.epoch = epoch;
    op.now_ms = now;
    op.reason = args.value_or("reason", "operator reconciliation");
    auto result = client.value().reconcile_grant(
        op, target,
        isf::PrincipalId::from_seed(isf::fnv1a64(args.value_or("principal", "operator")), 12));
    if (!result.ok()) {
      std::fprintf(stderr, "isfctl: %s\n", result.outcome().to_string().c_str());
      return 4;
    }
    auto grant = isf::extract_grant(result.value());
    out.field("grant_id", grant_id.value().to_string());
    out.field("state", grant.ok() ? isf::grant_state_name(grant.value().state) : "UNKNOWN", true);
    return 0;
  }

  std::fprintf(stderr, "isfctl: command '%s' is not implemented\n", command.c_str());
  return 2;
}
