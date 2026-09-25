# Contributing to Inter-Site Fabric

Inter-Site Fabric is an open-source project of Summon Software Labs and is
distributed under the **Apache License, Version 2.0**.

## Contribution terms

By submitting a contribution to this project (a pull request, patch, patch
file, or any other form of material intended to be merged into the project),
you agree that:

1. Your contribution is licensed to Summon Software Labs and to every
   downstream recipient under the terms of the **Apache License, Version 2.0**
   (the same license that covers the project), without any additional terms
   or conditions.
2. You retain copyright in your contribution. You are not asked to assign
   copyright.
3. You have the legal right to submit the contribution under those terms.

**No Contributor License Agreement (CLA) is required.** There is no copyright
assignment agreement, no corporate CLA, and no sign-off bot gating merges.
The inbound license equals the outbound license: Apache-2.0.

## Developer Certificate of Origin

You are encouraged (but not required) to add a `Signed-off-by: Your Name
<you@example.com>` trailer to commits, certifying the Developer Certificate of
Origin 1.1. This is a courtesy signal, not a gate.

## Source file headers

New source files should carry an SPDX identifier:

```
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
```

## Building and testing

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

## Coding standards

* C++20, no compiler extensions required.
* Warning-clean under MSVC `/W4 /WX` and GCC/Clang `-Wall -Wextra -Werror`.
* No third-party runtime dependencies. The project links only the C++ standard
  library and the platform socket library.
* No new network egress, telemetry, or analytics. The project never transmits
  data it was not explicitly asked to transmit over a connection the operator
  configured.
* Determinism matters: seeded property tests must reproduce failures from the
  seed alone.

## Reporting defects

Include the failing seed for any probabilistic test, the exact command line,
the compiler and version, and the observed versus expected behavior. Security
relevant reports should avoid publishing a working exploit before a fix lands.
