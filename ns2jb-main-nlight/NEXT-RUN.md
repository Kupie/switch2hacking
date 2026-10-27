# NEXT-RUN.md — the reserved console window plan (updated post-7.2t)

State: package2 keys DO NOT EXIST in the scene (ask answered 2026-10-27) —
package2 decryption is a long game (T239/tsec RE). One-boot experiments
are back to the top of the queue. Session protocol unchanged: fresh host
(`./session.sh start`), console `LOAD "TXT:NS2" -> RUN -> V=GO2()`.

## Step 1 — copy-region: the vtable read WITHOUT the kernel's permission (NEW)

The 7.2t wall was kernel-side: attrs-16 regions refuse both the alias-map
and the permission flip (0xd401). But fs reads its own rodata constantly —
`rpc.call3(sdk+0x586fb0, dst, src, len)` runs memcpy IN fs context (the
proven snapshot-copy class). The `copy-region` dispatch command
(fs-memory-control.cjs, hot-reloadable) + `copy-region.cjs` tool do this:

    sudo -n ip netns exec switchlab runuser -u <user> -- node copy-region.cjs

Default target = the qual's fsRodata slice (the fsp-pr vtables, 0x11000).
Arbitrary ranges: `copy-region.cjs <src> <len>`. Poison-prefill guards
against a silent no-op. On success: identify fsp-pr session-table handlers
offline (Ghidra, the FS-REGISTRY-NOTES vtable map) -> the RegisterProgram
slide-write fallback design.

NOTE: this also moots part of the executor track (the debug-read was only
needed for this region). The executor remains the HIPC2/GSH vehicle.

## Step 2 — the staged-codefs LaunchTitle test (the surviving MKW hypothesis)

The budget theory died (7.2t). What separates every accepted launch from
every refused one: a staged-codefs mount exists (the deploy/loader-gate
flow). Test: run a deploy that stages a code volume (the proven
deploy-monitor.cjs dance), and DURING the staged state fire
`tools/pm/mkw-create.cjs --create`. If accepted -> --verify (pid, identity, cmd-2
oracle, RomFS proof) -> the 21.7 GiB dump handoff. If refused while staged
-> the coupling theory dies too; fsp-pr RegisterProgram becomes the only
content route left.

## Step 3 — the executor A/B (wedge diagnosis, cheap)

Deploy the ERA v10 executor binary (recovered from git, sha 78431862...)
instead of the current build (dbdd3bca). If v10 passes its phases on a
fresh boot -> my build is the bug (bisect). If v10 also wedges -> the sm's
silent-send class hit the 0036 process too (7.2q deflection family); the
executor needs a wedge-proof init (echo-verified, monitor's sub-29 recipe)
before any OP_GSH/OP_CMIF work.

External intel (7.2u): the region is confirmed readable in fs context by
an independent capture (intel only — their files are not available to us,
so copy-region remains the route). The "OunceCake route" (NCM license +
fs cmd 206) from the same thread is being integrated by another agent; if
it verifies, it preempts step 2 as the content route.

Order rationale: step 1 is read-only + zero new console code paths; step 2
is the content prize; step 3 is diagnostics. Do NOT batch them — one
variable per boot unless step 1 is fully clean and quick (it should be:
one memcpy + one fetch).

## Offline queue (no console needed)
- Acquisition reliability work per the state-mining verdict
  (`docs/acquisition-state-mining.md`, FINDINGS 2026-10-27):
  APPLIED + policy-replay-verified — (a) extent-prefix wave trials dropped
  from the probe's qualification-failure path (read-only lookups kept),
  (b) acquire.cjs placement-fail gate → explicit reboot-required stop
  (0/80 corpus successes regress; 61 futile attempts no longer spawned).
  DROPPED as unsupported: the positive-budget cut and the inter-attempt
  scratch sweep (next boot's stage-1 orphan sweep already covers the
  save-space class). OPEN: per-boot steering design (action 4) and
  stage-local reset-scope retries (action 5).
- package2 header format + PSC-FW location hunt (the long-game track)
- ldr:ro NRO-loader decode (the exec-vehicle candidate)
- The 0x524f0016-era anomaly: whether the REDEPLOYED monitors (vs boot
  monitors) ever served a 0x16 bulk read (today's A/B suggests healthy —
  fsText read fine from monitor 212)
