# Changelog

## v3.0.2 (2026-10-13)

### Fixes

- **Config web server: no out-of-bounds read on a damaged peer allowlist.** When an allowlist saved by an old version was loaded, the peer count stored in it was not checked against the size of the saved data. A damaged or cut-short entry in NVS made the copy read past the end of the buffer. The count is now limited to the entries actually stored; if it doesn't fit, the list is dropped. The old limit check also did nothing when `CONFIG_ML_CONFIG_MAX_ALLOWED_PEERS` was 255 or more (512 in the S3 examples).
- **`cellular_connect` builds without warnings in both UDP and TCP mode.**

All five examples build with ESP-IDF v5.3.2 with no warnings.

## v3.0.1 (2026-10-13)

Completes the v3.0.0 notes and finishes the rename. No change to how the library works.

### Log output changed in v3.0.0 (missing from its notes)

| Before | After |
|---|---|
| Log tag `microlink` | `tailtiny` |
| `MicroLink v2 initialized (max_peers=N)` | `TailTiny initialized (max_peers=N)` |
| Config web page title "MicroLink" | "TailTiny" |
| Example logs: "MicroLink state", "Failed to initialize MicroLink", ... | "TailTiny state", "Failed to initialize TailTiny", ... |

If you call `esp_log_level_set("microlink", ...)`, or a script or test rig looks for `microlink` or `MicroLink v2 initialized` in the serial output, change it to `tailtiny` / `TailTiny initialized`.

### Examples

All examples now build as `tailtiny_<name>` (for example `build/tailtiny_failover_connect.bin`). v3.0.0 had renamed only `basic_connect` and `cellular_connect`; `cellular_heartbeat`, `failover_connect` and `rebind_test` follow now.

### Code comments

- The NVS namespace `"microlink"` now has a comment explaining why it must not be renamed (devices would lose their Tailscale identity).
- Source references point again to the upstream MicroLink v1 files they came from.

## v3.0.0 (2026-10-13)

MicroLink is now **TailTiny**. Only the name changed; the code does the same as v2.3.1.

### Updating an existing project

| Before | After |
|---|---|
| `components/microlink/` | `components/tailtiny/` |
| `REQUIRES microlink` | `REQUIRES tailtiny` |
| `#include "microlink.h"` | `#include "tailtiny.h"` |
| `#include "microlink_internal.h"` | `#include "tailtiny_internal.h"` |
| `microlink_*` functions and types (`microlink_init()`, `microlink_t`, ...) | `tailtiny_*` (`tailtiny_init()`, `tailtiny_t`, ...) |
| menuconfig: "MicroLink V2 Configuration" | "TailTiny Configuration" |
| github.com/Asimmimx/microlink | github.com/Asimmimx/tailtiny (the old link redirects) |

Unchanged: the `CONFIG_ML_*` options and `ml_*` names, so `sdkconfig` and `sdkconfig.credentials` files keep working. The keys are still stored in the NVS namespace `"microlink"`, so a device updated from v2.x keeps its Tailscale identity and doesn't need a new auth key.

## v2.3.1 (2026-10-09)

A RAM re-measurement for the ESP32-C2 entry of the compatibility chart. It found two low-RAM problems, fixed here, and a wrong number in v2.2.0.

### How much RAM MicroLink needs

Measured on the ESP32-C3 by holding RAM from boot to mimic a smaller chip, with a test build that forces a control reconnect 60 s in (as when the server closes the connection):

| Free after WiFi connects | Joins | Re-joins after a reconnect |
|---|---|---|
| 226 KB (C3 as is) | Yes | Yes |
| 185 KB | Yes | Yes (lowest free 25 KB) |
| 164 KB | Yes | No: the peer list no longer fits in one block |
| 156 KB | Yes | No |
| 143 KB | Joins, then loses the control connection (v2.2.0 too) | No |

So a board needs about **185 KB free after WiFi** to stay on the tailnet over time. The ESP32-C2 has about 95 KB by default and about 169 KB with Espressif's deepest RAM tuning, so it stays "Low RAM". The v2.2.0 note "still joins with only 185 KB free at boot" (about 143 KB after WiFi) was wrong: it joined, but lost the control connection right after.

### Fixes

| Problem | Before | After |
|---|---|---|
| Re-registering with little RAM | The RegisterResponse (~600 bytes) was read into 16 KB + 8 KB buffers; with ~143 KB after WiFi every re-registration failed | 6 KB + 4 KB; re-registration passes at that level |
| Long-poll message when RAM is tight | The 22 KB full netmap sent first on each long-poll was taken even with little RAM left | Skipped when it would leave less than 48 KB (keepalives and small updates are always taken). Normal boards still parse it |
| Running out of memory reading a control message | No log, and `errno` could still hold an old EAGAIN, so the half-read stream was treated as "no data" | Logged with the frame size and free heap, and the connection is reopened |
| Build warnings | 9 (unused functions and variables) | 0 |

`Out of memory for MapResponse` now also shows the free heap and the largest free block.

## v2.3.0 (2026-10-09)

Checked on an ESP32-C3 without PSRAM (ESP-IDF v5.3.2) on a 6-device tailnet, with a Windows peer and an Android peer on the same LAN.

### Fixes

| Problem | Before | After |
|---|---|---|
| Device sometimes shown offline in the admin console while its log said `CONNECTED` ([#40](https://github.com/CamM2325/microlink/pull/40)) | The control watchdog was reset by our own 5 s HTTP/2 PINGs, which keep succeeding on a dead long-poll, so it never fired. Server GOAWAY, RST_STREAM and END_STREAM on the long-poll, and a closed socket (`recv()` = 0 read as "no data"), went unnoticed | Watchdog only counts data on the long-poll stream (the server sends a keepalive about once a minute). GOAWAY, RST_STREAM, END_STREAM and a closed socket reconnect at once. A test build that ignored the long-poll reconnected 120 s later, in 7 s, and was never shown offline |
| Long-poll updates larger than one Noise message (~4 KB) | Split HTTP/2 frames were dropped, and their remaining bytes were read as frame headers. The full netmap sent at the start of every long-poll was never parsed | HTTP/2 frames and MapResponses are reassembled across Noise messages. The long-poll copy of the DERPMap is skipped (it is loaded on every connect), so the lowest free heap after joining stays 62–66 KB |
| Registration errors were silent ([#23](https://github.com/CamM2325/microlink/pull/23)) | A rejected or used-up auth key only showed as `MapRequest failed, will retry` forever | The server's reason is logged: `Registration rejected by the control server: ...`, `Registration needs a login: ...` (invalid, expired or already-used key), or a warning when the device waits for approval. Not reproduced on hardware: it would need the device's identity erased |
| Direct path flipping between a peer's LAN and public address | A peer on the same LAN answers on both (the router hairpins the public one). Whichever PONG came first won, so the path flipped every ~2 min and each flip forced a new WireGuard handshake: 14 flips in 8 min | A trusted direct path is kept; it is left only for a LAN path or once it stops answering. 0 flips in 10 min, settled on the LAN path |
| `DISCO PONG unmatched` warnings | One ping goes out on several paths with the same txid, and the peer answers each. Only the first PONG matched; the rest were logged as warnings, dozens per minute | Extra PONGs are recognised as duplicates (DEBUG). A direct PONG that arrives after a DERP one now still sets up the direct path. 0 warnings in 10 min |
| Endpoint update every 23 s | Each STUN re-probe sent a new MapRequest to the control server, even when nothing had changed | Sent only after a change, or every 10 minutes: 2 in 10 min |

### Behaviour changes to know about

- **Logs**: `STUN probe sent`, `STUN mapped`, `MapRequest includes N endpoint(s)` and repeated `WG endpoint stored (no session)` lines are now DEBUG.
- `ml_coord` logs `Control plane watchdog timeout: no long-poll data for 120s` when it reconnects for that reason. `ctrl_watchdog_ms` keeps its default of 120000; don't set it below about 70000, since the server's keepalive comes about once a minute.

### Still open

- Unvalidated endpoints for peers behind CGNAT ([#18](https://github.com/CamM2325/microlink/issues/18)) and stale endpoints for peers reached through DERP ([#41](https://github.com/CamM2325/microlink/issues/41)). Testing these needs a phone on mobile data.

### Removed

- The Cortex-M0 assembly X25519 and the sample platform file in `wireguard_lwip`. They were never built and can't run on an ESP32.

## v2.2.0: maintained fork (2026-10-05)

First release of [Asimmimx/microlink](https://github.com/Asimmimx/microlink), a maintained fork of [CamM2325/microlink](https://github.com/CamM2325/microlink) v2.1.0.

Every fix below was checked on real hardware (ESP32-C3 without PSRAM, ESP-IDF v5.3.2), usually by reproducing the bug first and then measuring before and after. Each one is a separate commit. Upstream pull requests were not merged; where one existed, the bug was reproduced here and the fix written and tested independently.

### Fixes

| Problem | Before | After |
|---|---|---|
| Single-core chips (C3, C6) | Reboot loop on start (task pinned to Core 1) | Connects normally |
| Boards without PSRAM | `MapRequest failed` forever (out of memory) | Peer list loads |
| Crash when a packet arrived while a socket was opening ([#17](https://github.com/CamM2325/microlink/issues/17)) | Load access fault in `udp_input`, reboot | lwIP is only touched from its own thread. Checked with `CONFIG_LWIP_CHECK_THREAD_SAFETY` |
| Peak RAM while joining a tailnet | Free RAM dipped to 9.7 KB on a C3 | Lowest point 84–93 KB; still joins with only 185 KB free at boot (corrected in v2.3.1: at that level the control connection is lost right after joining) |
| Long-poll allocated 64 KB per message | Control connection lost when RAM was tight | Stays connected |
| FreeRTOS at 100 Hz, the ESP-IDF default ([#36](https://github.com/CamM2325/microlink/issues/36)) | Watchdog every 5 s; app task never ran | No watchdog trips |
| Packet loss under load (as in PRs [#30](https://github.com/CamM2325/microlink/pull/30), [#32](https://github.com/CamM2325/microlink/pull/32), [#38](https://github.com/CamM2325/microlink/pull/38)) | Per-packet INFO logs throttled the tunnel: 50 msg/s gave 71% loss and 784 ms | 100 msg/s: 0% loss, 19 ms |
| DERP relay fixed to Dallas ([#19](https://github.com/CamM2325/microlink/issues/19)) | Relay latency from Turkey: 168 ms | Closest region measured and remembered: about 60 ms |
| Failed DERP connects ([#37](https://github.com/CamM2325/microlink/pull/37)) | ~10 KB leaked per attempt; gave up after 3 attempts | No leak; retries with 2–60 s backoff |
| Peer online status ([#24](https://github.com/CamM2325/microlink/pull/24)) | Every peer reported online | Matches `tailscale status` |
| UDP RX task priority ([#39](https://github.com/CamM2325/microlink/pull/39)) | Same as ESP-IDF's reserved Bluetooth controller priority | 12, below the system tasks; same throughput |
| Tunnel MTU ([#34](https://github.com/CamM2325/microlink/issues/34)) | 1420 (plain WireGuard) | 1280 (Tailscale) |
| Web config panel on the original ESP32 | Build error (no temperature sensor) | Builds |

### Setup

- One component folder. The `wireguard_lwip` symlink that broke every Windows build is replaced by `idf_component.yml`.
- `sdkconfig.credentials` is actually read now (it was documented but ignored).
- `basic_connect` builds for any chip with `idf.py set-target <chip>`. Buffer sizes follow PSRAM automatically.
- `AGENTS.md` lets an AI assistant set the project up end to end. Two helper scripts support it: `tools/serial_log.py` and `tools/udp_echo.py`.

### Behaviour changes to know about

- **PreferredDERP**: the device now reports the region it measured as closest, not region 9. It is stored in NVS under the key `derp_pref`.
- **`microlink_peer_info_t.online`** now means "online according to the control plane". Before, it meant "has a slot in the local peer table".
- **Logs**: per-packet and per-tick lines (`UDP RX`, `WG RX/TX`, `DISCO ...`, `DERP status`, `HEARTBEAT`) are now DEBUG. Set the `ml_*` tags to DEBUG to see them again.
- **Defaults without PSRAM**: `ML_H2_BUFFER_SIZE_KB` 80 (a cap, not a reservation), `ML_JSON_BUFFER_SIZE_KB` 64 (no longer used for the initial MapResponse), `ML_MAX_PEERS` 8.

### Still open

- Unvalidated endpoints for peers behind CGNAT ([#18](https://github.com/CamM2325/microlink/issues/18)) and stale endpoints for peers reached through DERP ([#41](https://github.com/CamM2325/microlink/issues/41)). Testing these needs a phone on mobile data.
- Registration errors are silent ([#23](https://github.com/CamM2325/microlink/pull/23)). Fixed in v2.3.0.
- RST_STREAM/GOAWAY on the long-poll are not handled ([#40](https://github.com/CamM2325/microlink/pull/40)). Fixed in v2.3.0.
