// Bazarish project (c) 2026
#pragma once

namespace bazarish {

// What a service exits with when an operator asked it to restart from the admin
// panel. It is not zero on purpose: a unit with the usual `Restart=on-failure`
// then starts the service again, so the same code works whether the operator's
// unit says on-failure or always. The panel is the only caller, and the request
// is operator-signed.
inline constexpr int kRestartExitCode = 90;

}  // namespace bazarish
