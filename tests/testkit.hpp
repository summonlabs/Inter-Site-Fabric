// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// A deliberately small, dependency-free test harness.
//
// There is no timeout machinery anywhere in this project. A test either runs to
// completion or it fails; a hang is a defect to diagnose. The only bounded wait
// is the observation of a child process that is expected to have exited, and a
// bound that expires is reported as a FAILURE, never as a pass.

#ifndef ISF_TESTKIT_HPP
#define ISF_TESTKIT_HPP

#include "isf/client.hpp"
#include "isf/daemon.hpp"
#include "isf/server.hpp"
#include "isf/store.hpp"

#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>

namespace isf::test {

/// Thrown by ISF_REQUIRE to abort the current test.
class TestFailure : public std::runtime_error {
 public:
  explicit TestFailure(const std::string& what) : std::runtime_error(what) {}
};

using TestFunction = void (*)();

void register_test(const char* suite, const char* name, TestFunction fn);

/// Runs every registered test. Returns a process exit code.
int run_all(int argc, char** argv, const char* program);

/// The seed selected for this run.
[[nodiscard]] std::uint64_t run_seed() noexcept;
/// The iteration budget selected for this run.
[[nodiscard]] std::uint64_t run_iterations() noexcept;

// ---- deterministic randomness --------------------------------------------

/// SplitMix64. Fast, tiny, and fully reproducible from a single seed.
class Rng {
 public:
  explicit Rng(std::uint64_t seed) : state_(seed == 0 ? 0x9E3779B97F4A7C15ULL : seed) {}

  [[nodiscard]] std::uint64_t next() noexcept;
  /// Uniform value in [0, bound). Returns 0 when bound is 0.
  [[nodiscard]] std::uint64_t below(std::uint64_t bound) noexcept;
  [[nodiscard]] std::uint64_t in_range(std::uint64_t low, std::uint64_t high) noexcept;
  [[nodiscard]] bool chance(std::uint32_t percent) noexcept;
  [[nodiscard]] std::uint64_t seed() const noexcept { return seed_; }

 private:
  std::uint64_t state_{0};
  std::uint64_t seed_{0};
};

// ---- diagnostics ----------------------------------------------------------

[[nodiscard]] std::string describe(bool value);
[[nodiscard]] std::string describe(const std::string& value);
[[nodiscard]] std::string describe(const char* value);
[[nodiscard]] std::string describe(std::uint64_t value);
[[nodiscard]] std::string describe(std::int64_t value);

template <class T>
[[nodiscard]] std::string describe(const T& value) {
  if constexpr (std::is_enum_v<T>) {
    return std::to_string(static_cast<long long>(value));
  } else if constexpr (std::is_integral_v<T>) {
    return std::to_string(static_cast<long long>(value));
  } else if constexpr (requires { value.to_string(); }) {
    return value.to_string();
  } else if constexpr (requires { value.to_hex(); }) {
    return value.to_hex();
  } else if constexpr (std::is_convertible_v<T, const char*>) {
    return std::string(static_cast<const char*>(value));
  } else {
    return "<unprintable>";
  }
}

// ---- scratch directories --------------------------------------------------

/// A fresh directory that is removed on destruction unless ISF_KEEP_SCRATCH is
/// set in the environment.
class ScratchDir {
 public:
  explicit ScratchDir(const std::string& tag);
  ~ScratchDir();
  ScratchDir(const ScratchDir&) = delete;
  ScratchDir& operator=(const ScratchDir&) = delete;

  [[nodiscard]] const std::string& path() const noexcept { return path_; }
  [[nodiscard]] std::string file(const std::string& name) const;

 private:
  std::string path_{};
  bool keep_{false};
};

/// Root directory for all scratch state, derived from ISF_TEST_BINARY_DIR.
[[nodiscard]] std::string scratch_root();

/// Read a key=value report file.
[[nodiscard]] std::vector<std::pair<std::string, std::string>> read_report(const std::string& path);
[[nodiscard]] std::string report_value(const std::vector<std::pair<std::string, std::string>>& report,
                                       const std::string& key, const std::string& fallback = "");

// ---- in-process fabric ----------------------------------------------------

/// An in-process daemon plus its loopback TCP server, for tests that need real
/// sockets but do not need separate operating system processes.
class LocalFabric {
 public:
  struct Options {
    StoreOptions store{StoreOptions::for_tests()};
    Policy policy{Policy::conservative_default()};
    bool enable_ticker{false};
    bool auto_compact{true};
    bool verify_after_mutation{true};
    std::size_t max_connections{32};
    std::size_t max_frame_bytes{kDefaultMaxFrameBytes};
    std::uint64_t io_timeout_ms{30000};
    std::function<void(const char*)> commit_stage_hook{};
  };

  static Expected<std::unique_ptr<LocalFabric>> start(const std::string& state_path,
                                                      const Options& options = Options{});
  ~LocalFabric();

  [[nodiscard]] Daemon& daemon() noexcept { return *daemon_; }
  [[nodiscard]] FabricServer& server() noexcept { return *server_; }
  [[nodiscard]] Endpoint endpoint() const { return server_->local_endpoint(); }
  [[nodiscard]] Expected<FabricClient> client(const std::string& kind = "test-client");

  void stop();

 private:
  LocalFabric() = default;
  std::unique_ptr<Daemon> daemon_{};
  std::unique_ptr<FabricServer> server_{};
};

// ---- small model builders -------------------------------------------------

[[nodiscard]] SiteId site_from_name(const std::string& name);
[[nodiscard]] PathId path_from_name(const std::string& name);
[[nodiscard]] DomainId domain_from_name(const std::string& name);
[[nodiscard]] PrincipalId principal_from_name(const std::string& name);

// ---- fixture builders -----------------------------------------------------

/// Two sites, one inter-site path, and an attested authoritative capacity.
struct FabricFixture {
  SiteId a{};
  SiteId b{};
  Incarnation a_incarnation{};
  Incarnation b_incarnation{};
  Generation a_generation{};
  Generation b_generation{};
  PathId path{};
  Generation path_generation{};
  Generation capacity_generation{};
  Amount usable{0};
};

/// Build the fixture directly on an authority.
[[nodiscard]] Expected<FabricFixture> setup_fabric(Authority& authority, const std::string& tag,
                                                   Amount usable, std::uint64_t now);

/// Build the fixture through a live client, exercising the real protocol.
[[nodiscard]] Expected<FabricFixture> setup_fabric(FabricClient& client, const std::string& tag,
                                                   Amount usable);

/// Drive propose, evaluate, reserve, activate, acknowledge on behalf of one
/// endpoint site. Returns the resulting grant record.
[[nodiscard]] Expected<GrantRecord> request_grant(FabricClient& client, const FabricFixture& fixture,
                                                  bool site_a, Amount amount,
                                                  GrantClass klass = GrantClass::General,
                                                  std::uint64_t duration_ms = 600000);

/// A reference implementation of the capacity accounting rules, used as an
/// independent differential model. It shares no code with the Authority.
class ReferenceLedger {
 public:
  ReferenceLedger(Amount usable, Amount protected_floor) : usable_(usable), floor_(protected_floor) {}

  /// Try to allocate. Returns false when the request does not fit.
  [[nodiscard]] bool allocate(Amount amount);
  void release(Amount amount) { held_ = held_ >= amount ? held_ - amount : 0; }
  [[nodiscard]] Amount held() const noexcept { return held_; }
  [[nodiscard]] Amount free() const noexcept {
    const Amount capacity = usable_ > floor_ ? usable_ - floor_ : 0;
    return held_ >= capacity ? 0 : capacity - held_;
  }
  [[nodiscard]] bool consistent() const noexcept { return held_ + free() == (usable_ > floor_ ? usable_ - floor_ : 0); }

 private:
  Amount usable_{0};
  Amount floor_{0};
  Amount held_{0};
};

}  // namespace isf::test

// ---- macros ---------------------------------------------------------------

#define ISF_TEST(suite_name, test_name)                                                  \
  static void suite_name##_##test_name##_body();                                         \
  namespace {                                                                            \
  struct suite_name##_##test_name##_registration {                                       \
    suite_name##_##test_name##_registration() {                                          \
      ::isf::test::register_test(#suite_name, #test_name, &suite_name##_##test_name##_body); \
    }                                                                                    \
  } suite_name##_##test_name##_registration_instance;                                    \
  }                                                                                      \
  static void suite_name##_##test_name##_body()

#define ISF_FAIL(message)                                                                \
  throw ::isf::test::TestFailure(std::string(__FILE__) + ":" + std::to_string(__LINE__) + \
                                 ": " + (message))

#define ISF_REQUIRE(expr)                                                                \
  do {                                                                                   \
    if (!(expr)) {                                                                       \
      ISF_FAIL(std::string("required condition failed: ") + #expr);                      \
    }                                                                                    \
  } while (false)

#define ISF_CHECK(expr)                                                                  \
  do {                                                                                   \
    if (!(expr)) {                                                                       \
      ::isf::test::record_check_failure(std::string(__FILE__) + ":" +                    \
                                        std::to_string(__LINE__) +                       \
                                        ": check failed: " + #expr);                     \
    }                                                                                    \
  } while (false)

#define ISF_REQUIRE_EQ(actual, expected)                                                 \
  do {                                                                                   \
    const auto isf_actual = (actual);                                                   \
    const auto isf_expected = (expected);                                               \
    if (!(isf_actual == isf_expected)) {                                                 \
      ISF_FAIL(std::string("required equality failed: ") + #actual + " == " + #expected +\
               " (actual=" + ::isf::test::describe(isf_actual) +                         \
               ", expected=" + ::isf::test::describe(isf_expected) + ")");               \
    }                                                                                    \
  } while (false)

#define ISF_CHECK_EQ(actual, expected)                                                   \
  do {                                                                                   \
    const auto isf_actual = (actual);                                                   \
    const auto isf_expected = (expected);                                               \
    if (!(isf_actual == isf_expected)) {                                                 \
      ::isf::test::record_check_failure(std::string(__FILE__) + ":" +                    \
                                        std::to_string(__LINE__) +                       \
                                        ": equality failed: " + #actual + " == " +       \
                                        #expected + " (actual=" +                        \
                                        ::isf::test::describe(isf_actual) +              \
                                        ", expected=" + ::isf::test::describe(isf_expected) + ")"); \
    }                                                                                    \
  } while (false)

#define ISF_REQUIRE_OK(expr)                                                             \
  do {                                                                                   \
    const auto& isf_result = (expr);                                                     \
    if (!isf_result.ok()) {                                                              \
      ISF_FAIL(std::string("required success failed: ") + #expr + " -> " +               \
               isf_result.outcome().to_string());                                        \
    }                                                                                    \
  } while (false)

#define ISF_REQUIRE_STATUS(expr, expected)                                               \
  do {                                                                                   \
    const auto& isf_result = (expr);                                                     \
    if (isf_result.status() != (expected)) {                                             \
      ISF_FAIL(std::string("expected status ") + ::isf::status_name(expected) +          \
               " from " + #expr + " but got " +                                          \
               ::isf::status_name(isf_result.status()) + " (" + isf_result.detail() + ")"); \
    }                                                                                    \
  } while (false)

/// Require a bare Status (not an Expected) to equal the expected status.
#define ISF_REQUIRE_STATUS_EQ(expr, expected)                                            \
  do {                                                                                   \
    const ::isf::Status isf_status = (expr);                                             \
    if (isf_status != (expected)) {                                                      \
      ISF_FAIL(std::string("expected status ") + ::isf::status_name(expected) +          \
               " from " + #expr + " but got " + ::isf::status_name(isf_status));         \
    }                                                                                    \
  } while (false)

namespace isf::test {
void record_check_failure(const std::string& message);
}  // namespace isf::test

#endif  // ISF_TESTKIT_HPP
