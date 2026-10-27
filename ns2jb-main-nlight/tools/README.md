# Tool index

All tools assume a live READY session (see `USAGE.txt` / `docs/OPERATIONS.md`)
and run inside the lab netns:
`sudo -n ip netns exec switchlab runuser -u nlight -- node <tool>`.

## dump/ — content and firmware capture
- `game-dump.cjs` — **the general game-content dump route** for any installed
  title: base + updates + DLC, RomFS + ExeFS + control.nacp, in one standard
  layout per game (NCM discovery → es license (joint patch+base rights for
  updates) → fs cmd 206 OpenDataStorageByPath → decrypted RomFS as IStorage;
  ExeFS via fs 618 → ldr:ro cmd 0 CodeFS; control via fs cmd 10 fsType 3 with
  the OWNING APP tid).

  Standard complete invocation (one attach, ~3 service opens):
  `node tools/dump/game-dump.cjs <appId> --control --overlay --content all --section all`

  Standard layout:
  ```
  <roms>/<appId>/game.json                # inventory + per-section status ledger
  <roms>/<appId>/base/                    # control.nacp + exefs/ + romfs/ (+ manifests)
  <roms>/<appId>/update-v<N>/             # the update's control.nacp + exefs/
  <roms>/<appId>/active-overlay/          # (--overlay) the RUNNING app's composed
                                           #   RomFS diff vs base (update-replaced files)
  ```
  Rules learned live: per-key resolution (no synthesized keys), cmd-10 mount id
  = owning application tid, update RomFS is composed-only (delta view is
  partial in-band; use --overlay when the game is the running app), every
  section isolated (a failure records in game.json and the dump continues),
  resumable manifests, `--verify` re-hashes from disk.
  `--probe` = discovery + mount + header check only.
- `dump-romfs.cjs` — streams a mounted RomFS handle (`--handle` from cmd 2).
- `fw-dump.cjs`, `dump-system.cjs`, `dump-firmware.cjs`, `ncm-db-dump.cjs` —
  fw23 system-code and NCM database dumpers.
- `debug-dump.cjs`, `owned-dump.cjs`, `bis-boot-dump.cjs`, `fs-dump.cjs`,
  `dump-fs-gap.cjs`, `retry-dump-errors.cjs`, `run-dump-slice.sh` — targeted
  capture helpers.

## memory/ — session memory primitives
- `fs-heap-chase.cjs` — 0010 walk, rig reads, and the window-slide
  read/dump/write modes (walk-rule validated).
- `fix-session-identity.cjs` — deterministic strong-session promotion
  (the cmd-2 strength oracle).
- `l3-load.cjs`, `raw-*.cjs`, `flip-read.cjs`, `gap-region-probe.cjs`,
  `copy-region.cjs` — targeted memory probes.

## pm/ — process-manager research
- `mkw-create.cjs` — create-only LaunchTitle route (closed: pm desc-02
  refusal; kept for the record). `pm-sweep.cjs` / `pm-dump.cjs` /
  `pm-handle-sweep.cjs` — pm surface characterization.
- `capture-titles.cjs`, `mount-triangulate.cjs` — content/title experiments.

## rig/ — RO monitor and rig control
- `deploy-monitor.cjs`, `debug-relay.cjs` — monitor lifecycle.
- `rig-harness.cjs` / `rig-*.cjs` — rig experiments.
- `alive.cjs`, `roprobe.cjs`, `worker-state.cjs`, `fresh-ro-test.cjs`,
  `svc-recon.cjs`, `sub20-test.cjs`, `bulk-ab.cjs` — liveness and probes.

## bis/ — BIS partition and save surface
- `probe-bis-map.cjs`, `probe-bis-structure.cjs` — partition inventory.
- `probe-save-explore.cjs`, `probe-save-update.cjs`, `write-tns2new.cjs`,
  `validate-persistence.cjs` — save access and persistence validation.

## mount/ — content-mount probes (historical; superseded by tools/dump)
- `am-mount.cjs`, `content-mount-probe*.cjs`.

## hipc2/ — HIPC2/TLS/nvdrv experiment series (research archive)
- The parked-worker HIPC2 senders and nvdrv probes; see
  `FIRMWARE_FINDINGS.md` §7 for the mechanism and outcomes.

## npdm/ — NPDM tooling
- `npdm-tool.py` (decoder), `npdm-svc-patch.py` (svc-mask patcher),
  `npdm-survey.cjs` (capture survey).

## session/ — host/session helpers
- `keep-host.sh`, `ready-watcher.sh`, `dance.py`, `proctl.py`.

## maint/ — repo maintenance
- `audit-runs.cjs` (+ test) — run-directory hygiene audit.

## Top level
- `ghidra-scripts/` — Ghidra headless analysis scripts.
- `nso-unpack.py`, `decompile-ns.py`, `xref.py`, `test_xref.py` — NS/NRO
  unpacking and reversing.
