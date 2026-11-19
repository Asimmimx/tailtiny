# Security policy

TailTiny puts devices on people's private networks, so security reports are welcome and get priority over everything else in this project.

## Reporting a vulnerability

Please **don't open a public issue** for a security problem. Report it privately instead:

- **[Report a vulnerability](https://github.com/Asimmimx/tailtiny/security/advisories/new)** (GitHub's private vulnerability reporting). Only the maintainer sees it, and we can work on a fix and an advisory together there.

Helpful to include: the TailTiny version or commit, the chip and ESP-IDF version, what an attacker needs (a tailnet peer? someone on the same LAN? anyone on the internet?), and steps or a packet capture that show the problem. A host test or a patch is welcome but not needed.

## What to expect

TailTiny is maintained by one person in their spare time, so these are goals, not guarantees:

- A first reply within a week.
- For a confirmed issue: a fix on `main` and a release, then a published [security advisory](https://github.com/Asimmimx/tailtiny/security/advisories) that credits you (unless you'd rather not be named).
- If the problem is also in [MicroLink](https://github.com/CamM2325/microlink), the upstream project, or in the bundled [wireguard-lwip](https://github.com/smartalock/wireguard-lwip), it's reported to them as well, with your permission.

## Supported versions

Only the latest release gets security fixes. TailTiny is a component you build into your own firmware, so updating means pulling the new version and rebuilding.

| Version | Supported |
|---|---|
| Latest 3.x release | Yes |
| Older releases | No, please update |

## Scope

In scope: everything in this repository, including the bundled wireguard-lwip and X25519 code, the optional config web UI and the examples.

Out of scope: Tailscale's own servers and clients (report those to [Tailscale](https://tailscale.com/security)), ESP-IDF itself (report to [Espressif](https://www.espressif.com/en/security)), and problems that need physical access to the device's flash, since TailTiny doesn't use flash encryption or secure boot by itself (your firmware can turn them on).
