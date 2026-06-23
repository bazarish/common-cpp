# i2pd patch overlay

`common/third_party/i2pd` is the **pristine** PurpleI2P/i2pd submodule, pinned to a
commit on the `openssl` branch. We keep **zero** edits inside the submodule so it
stays trivial to bump against upstream. Every bazarish-specific change to i2pd
lives here as a `*.patch` and is applied to the submodule working tree at CMake
configure time (idempotently) by `common/cmake/I2pdBazarish.cmake`. The applied
patch is never committed into the superproject - only the pristine gitlink is.

## Building

```
cmake -S common -B build -DBAZARISH_WITH_I2PD=ON
cmake --build build --target i2pd_bazarish
```

This compiles only the router core (`libi2pd`) + `i18n` into `libi2pd_bazarish.a`
(target `Bazarish::I2pd`). The client-bridge library (SAM, BOB, SOCKS, HTTP/SOCKS
proxy, I2CP server, addressbook, client tunnels) and the daemon (webconsole,
I2PControl, UPnP) are never compiled. Floodfill-server and transit stay
config-gated in the upstream sources (never enable floodfill; pass notransit for
client role).

## Bumping i2pd

```
cd common/third_party/i2pd && git fetch origin openssl && git checkout <new-commit>
cd - && git add common/third_party/i2pd            # record the new gitlink
cmake -S common -B build -DBAZARISH_WITH_I2PD=ON    # re-applies the patches
```

If a patch no longer applies after a bump, refresh it: apply by hand against the
new tree, regenerate with `git -C common/third_party/i2pd diff`, and update the
file here.

## Patches

- `0001-libi2pd-log-callback-sink.patch` - adds an `eLogCallback` log destination
  (a `std::function` sink) so an embedder can route i2pd logging into its own log
  system with the severity preserved. Drop this patch if/when the feature is
  merged upstream.
