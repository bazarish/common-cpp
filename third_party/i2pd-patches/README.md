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
- `0002-libi2pd-optional-leaseset-key-persistence.patch` - adds the I2CP parameter
  `i2cp.persistLeaseSetKeys` (default true, i.e. today's behaviour). With it set
  to false a published destination keeps its leaseset encryption keys in memory
  instead of writing them to `destinations/<b32>.<type>.dat`. Those files are
  named after the destination, so on a router that serves one destination per
  user they amount to a plain-text roster of the addresses this installation has
  served. Drop this patch if/when the parameter is merged upstream.
- `0003-libi2pd-reseed-url-may-name-the-archive.patch` - an entry in `reseed.urls`
  that already ends in `.su3` is fetched as it stands; only a bare host still gets
  `i2pseeds.su3` appended. A Bazarish server publishes its reseed at whatever path
  its operator already serves (a portal page), not at the conventional one, and
  the address in a server descriptor names the archive itself. Drop this patch
  if/when upstream accepts a full-URL reseed entry.
