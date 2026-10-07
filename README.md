# Bazarish - common

Shared C++ library for the [Bazarish](https://github.com/bazarish/docs-main) messenger.
Protocol types, OpenSSL wrappers and JSON helpers consumed by every other
component, so there is no duplicated crypto code.

## What it provides

- **Identity** - post-quantum hybrid keys: Ed25519 **+** ML-DSA-65 (FIPS 204).
  Every identity statement is dual-signed and valid only when both signatures
  verify. The fingerprint covers both public keys (base32 of SHA-256).
- **Certificates** (one composite CBOR frame over JSON) - the user's contact card
  (with a sealing **prekey** a first-contact sender encrypts to), the alias
  certificate and its delegation chain, and the server card.
- **Composite sealing** (`Hybrid`) - X25519 **+** ML-KEM-768 into one
  AES-256-GCM layer, for delivery metadata and E2E payloads. `Cms` keeps the
  password envelope (RFC 3211 PWRI) that the account backup and file transfer
  use.
- **I2P transport** - one facade (`bazarish::i2p`) over three engines: libi2pd
  inside the process; a router outside it over **SAM v3** (`bazarish::sam`,
  loopback only), which lets one router serve many processes; and a **private
  gateway** reached over a pinned-TLS WebSocket, which is a router somebody else
  runs for this device.
- **Auth** - hybrid request signing/verification for the client API.
- **Addressing**, the **delivery passes** that admit mail to a mailbox, typed
  **errors**, base32/64 and hex helpers.

Cryptography uses OpenSSL only, with standardized algorithms and containers
(PEM, DER, CMS). No custom cryptographic constructions.

## Build

Requires CMake >= 3.20, a C++20 compiler and OpenSSL >= 3.5.

```bash
cmake -S . -B build && cmake --build build -j4
ctest --test-dir build
```

The library target is `Bazarish::Common`.

## Use

The other components consume this repository as a git submodule (`./common`)
and add it with `add_subdirectory`. `third_party/` vendors single-header
`nlohmann/json`. HTTP - server and client, plain or TLS - is Boost.Beast on an
asio loop with C++20 coroutines (`HttpServer` / `HttpClient`); there is one HTTP
stack in the fleet, not two.
