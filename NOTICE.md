# Notices

TailTiny is licensed under the MIT License (see [LICENSE](LICENSE)). It is a fork of [MicroLink](https://github.com/CamM2325/microlink) by Cameron Malone.

## Bundled third-party code

| Code | Where | License |
|---|---|---|
| wireguard-lwip, by Daniel Hope (Smartalock / Floorsense) | `components/tailtiny/components/wireguard_lwip/` | BSD-3-Clause, see [its LICENSE](components/tailtiny/components/wireguard_lwip/LICENSE) |
| X25519, by Cryptography Research, Inc. | `components/tailtiny/src/x25519.c` and `components/tailtiny/components/wireguard_lwip/src/crypto/refc/x25519.c` | MIT, see [x25519-license.txt](x25519-license.txt) |

## Trademarks

WireGuard is a registered trademark of Jason A. Donenfeld. Tailscale is a trademark of Tailscale Inc.

TailTiny is an independent implementation of the Tailscale client protocol, written from the open-source Tailscale client for interoperability. It is not affiliated with or endorsed by Tailscale Inc. or Espressif.

## Disclaimer

Use at your own risk. The authors make no guarantees about security, correctness, or compatibility with official Tailscale software.
