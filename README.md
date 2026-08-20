# Bazarish - common

Shared C++ library for the [Bazarish](https://github.com/bazarish/docs-main) messenger.
Protocol types, OpenSSL wrappers and JSON helpers consumed by every other
component, so there is no duplicated crypto code.

## What it provides

- **Identity** - post-quantum hybrid keys: ECDSA P-256 **+** ML-DSA-65 (FIPS 204).
  Every identity statement is dual-signed and valid only when both signatures
  verify. The fingerprint covers both public keys (base32 of SHA-256).
- **Certificates** (CMS SignedData over JSON) - subscription certificate
  (with an optional sealing **prekey**), alias certificate, server card.
- **CMS sealing** - ECDH P-256 + AES-256-GCM envelopes for delivery metadata
  and E2E payloads.
- **SAM client** - SAM v3 client for I2P routers (sessions and streams).
- **Auth** - hybrid request signing/verification for the client API.
- **Addressing**, one-time **delivery tokens**, typed **errors**, base32/64
  and hex helpers.

Cryptography uses OpenSSL only, with standardized algorithms and containers
(PEM, DER, CMS). No custom cryptographic constructions.

## Build

Requires CMake >= 3.20, a C++20 compiler and OpenSSL >= 3.0.

```bash
cmake -S . -B build && cmake --build build -j
ctest --test-dir build
```

The library target is `Bazarish::Common`.

## Use

The other components consume this repository as a git submodule (`./common`)
and add it with `add_subdirectory`. `third_party/` vendors single-header
`nlohmann/json`. HTTP - server and client, plain or TLS - is Boost.Beast on an
asio loop with C++20 coroutines (`HttpServer` / `HttpClient`); there is one HTTP
stack in the fleet, not two.
