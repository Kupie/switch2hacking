# Switch 2 firmware (fw23) — reversing findings log

Dump: `~/dev/switch/dumps/fw23/` — unpacked HOS 23.x system modules + system applets
(87 titles, 422 MiB). Per title: `text.bin` / `rodata.bin` / `data.bin` /
`main.npdm` / `meta.json` (segment addresses in meta.json; NPDM carries
program ID, service ACLs, kernel caps). `manifest.json`: 86 unpacked,
1 error (`0400000000000006` **usb.gen2 — failed to unpack**, worth re-dumping).

Tooling (all in `switchhax/fw-re/`):
- `npdm_parse.py` (+ `npdm-inventory.txt`, `npdm-inventory.json` — service
  ACLs for all 87 titles).
- **Ghidra 12.2 installed at `~/tools/ghidra_12.2_PUBLIC`** (needs JDK 25+;
  system jdk27 via `JAVA_HOME_OVERRIDE` in `support/launch.properties`).
- `make_elf.py` — wraps any module dir into a loadable ELF64 (text@0,
  rodata/data at meta.json offsets; layout verified vs objdump). ELFs for all
  modules in `~/dev/switch/dumps/fw23/elf/`.
- Ghidra scripts (`ghidra-scripts/`): `DumpInventory.java` (function list +
  string/xref dump per module → `out/`), `XrefDecompile.java` (decompiles
  every function referencing a regex pattern).
- `analyze-all.sh` — batch import+analyze of all 85 modules into
  `ghidra-proj` (headless), inventory dumped per module.
Workflow: `make_elf.py <moduledir>` → `analyzeHeadless ... -postScript
XrefDecompile.java "<pattern>"` → read `out/*.decomp-*.c`.

---

## 1. NPDM format on fw23 (reverse-engineered, new vs Switch 1)

The NPDMs are tool-rebuilt but the ACI0 payloads are intact. Verified layout:

- **META**: name string at +0x20 (16 bytes — identifies every "unknown" dir);
  ACI0 offset/size in a trailer at **+0x70/+0x74**.
- **ACI0**: program ID at +0x10; fs-ACL offset/size at +0x20; **SAC** at
  +0x28; **kernel caps** at +0x30 (offsets relative to ACI0).
- **New SAC format**: entries are `(len_byte, name)` with
  `name_len = (len_byte & 0x1F) + 1`. High bit (`0x80`) marks a **hosted
  (server-side) service declaration**; low entries are client accesses.
  Switch 1 NPDMs only declare client access — fw23 NPDMs additionally declare
  *what each module serves*. Full map extracted in `npdm-inventory.txt`.
  (This gives us the complete fw23 service topology without touching the
  console.)
- **New kernel-capability format**: fixed u32 array, NOT the Switch-1 TLV
  descriptors. Nearly all modules share the same base words
  (`1fffffcf 207fffef ... 00d83fff`) + a per-module word (e.g.
  `47e0060f` most modules, `4000060f` applets, `7efde00f` hw-touching
  modules) + a trailing gradient word (`00007fff` … `02007fff`), then
  extended entries for hw drivers (Bus/gpio/pwm/i2c maps, nvservices/vi2/
  pcie/device-map ranges — looks like MMIO-range ACLs). **Not yet decoded
  to syscall numbers — TODO; needs one reference decode or live probing.**

## 2. Module map (from NPDM names + hosted-service lists)

New/renamed vs Switch 1, notable:

| Title | Name | Hosts (selected) | Notes |
|---|---|---|---|
| 0x0a | Bus | gpio i2c pwm spi uart led pinmux sasbus | hw bus access (client: `bpmpmr:`) |
| 0x31 | glue | arp:r arp:w time:* bgtc:* ectx:* notif:* pl:u | glue/gateway services |
| 0x33 | es | es **ndrm:la ndrm:lu** | clients: `spl:es`, fsp-srv, ssl:s, set:cal | high-priv crypto; rodata: `ticket.bin`, `ticket_list.bin`, `estitlekey:/`, `eticket_key_version` |
| 0x3f | ns | ns:am2 ns:dev ns:ec ns:rid ns:ro ns:rt ns:su ns:sweb ns:vm ns:web | install/update logic |
| 0x42 | pgl | pgl | |
| 0x4d | lrp | lrp:d lrp:m lrp:s lrp:u lcs | |
| 0x4f | **nvkernel** | **gpuk:drv gpuk:gsv** | Switch-2 GPU kernel-side service (nn::gsdrv, userspace side of GPU driver) |
| 0x50 | **ngc** | ngc:u ngct:u | new; zlib/NintendoSDK 23.3.0 |
| 0x52 | cmptldr | — | **client of `ldr:cmp`** (compatibility loader — parses legacy formats) |
| 0x62 | **gc** | — | game-card controller; devicetree strings `nintendo,gc`, `nintendo,gc-controller`, `nintendo,vcc-control` |
| 0x63 | vi2 | vi2:m1 vi2:m2 vi2:nv vi2:v syncpt:* disp:* hdcp lbl cec-mgr | Switch-2 display stack |
| 0x65 | host1x | host1x | |
| 0x71 | capsrv2 | caps2:r caps2:s | second capture service |
| 0x72 | **adraw** | adraw:a adraw:m | referenced by many applets as client (`adraw:`) |
| 0x80/81/83/84 | gsvm/gsv1/gsv3/gsv4 | gsv:* | "gsview"/video-stream pipeline modules |
| 0x8d | **tsec.autogen** | **tsec:m** | sysmodule managing TSEC (crypto co-processor). Uses nn::ro dynamic loading (`tsecMOD0`, `tsec.nss`), IPC server thread, host1x. Small (~138 KiB text) |
| 0xb240 | htc.stub | — | dev/test stub present in retail build (54 KiB) |

The `0400000000001xxx` "unknown" dirs are **system applets/libapplets** (all
run with an identical generic NPDM template — clients acc:s/acc:u + adraw:,
no hosted services):

0x1000 System (qlaunch), 0x1001 Pin, 0x1003 Controller, 0x1005 Viewer,
0x1007 Account, 0x1008 TextEditor, 0x1009 MiiEdit, 0x100c Overlay,
0x100d **Album**, 0x100e Setting, 0x100f LibAppletOff, 0x1013 MyPage,
0x1015 Maintenance, 0x1041 NxSwkbd, 0x1042 **SystemWeb**,
0x1043 **LibAppletWeb**, 0x1045 News, 0x1048 Splay, 0x104b LibAppletOff,
0x104c QuestSA, 0x104d Hdr, 0x1054 Vgc.

**SystemWeb/LibAppletWeb (0x1042/0x1043) are NX WebKit (WKC symbol set:
`WKCWebKit*`, WKCPrefs, MediaPlayer procs).** Album (0x100d) embeds a
curl-class HTTP client + JPEG decode (nghttp2, byte-range, "Wrong JPEG
library version" strings).

## 3. Coverage gaps (important for planning)

This dump contains only "extended" sysmodules + applets. **Not in the dump:**
`fs` (0x8000), `loader` (0x8001), `sm` (0x8002-ish), `pm` (0x7), `spl`,
`boot`, `ncm` (nim/ns reference `ncm` as client but no module hosts it),
`usb.gen2` (unpack error) — and no kernel (KTN), package1/package2,
warmboot, or Secure Monitor. So:

- **Kernel bugs cannot be hunted from this dump** — KTN binary needed
  (separate acquisition from package2).
- FS/SM/loader/pm are the highest-privilege userspace processes; not here.
- We *do* already own the FS root live (ns2jb session), so FS itself is less
  interesting statically than the services we can't otherwise reach.

## 3b. NPDM kernel caps (SVC masks) — decoded; full system-wide capability map

fw23 KAC SVC-mask descriptor format (decoded independently; matches
ns2jb-session/npdm-tool.py): each u32 with **4 trailing one-bits** = SVC mask:
`idx = (u32 >> 29) & 7`, `bits = (u32 >> 5) & 0xFFFFFF`, svc = `idx*24 + bit`
(max svc 191). Other descriptors = memory/IRQ ranges (trailing-ones count
tags the type). Numbering of known svcs matches HOS 1 (0x21 SendSyncRequest,
0x43 ReplyAndReceive, 0x60 DebugActiveProcess, 0x74 MapProcessMemory …).

Key results (all 85 dumped ACI0 halves decoded):
- **Only creport (0x36) has the debug suite** — {0x60, 0x63, 0x67, 0x69,
  0x6A, 0x6D}; no 0x64 Continue, no 0x6B Write. **Nobody in the dump has
  CreateProcess (0x79) or CallSecureMonitor (0x7F) in ACI0** (pm/spl
  undumped; ACID halves may add).
- cmptldr (0x52) has MapProcMem/UnmapProcMem (0x74/0x75).
- Many drivers (Bus, pcie, nvservices, nvkernel, host1x, gsv*, tsec)
  have 0x5C UnmapDeviceAddressSpace + 63-69 svc sets.
- System applets (0x1xxx): none have the interesting suites.

## 3c. NEW ESCALATION PATH — process handles via pm:dmnt → full-system R/W

(status: strategy, next live experiment — not yet executed)

The monitor process (takeover's own, ro policy 0x37) holds the **loader
suite**: svc 0x73 SetProcessMemoryPermission(handle, addr, size, perm)
[takes a PROCESS HANDLE — used cross-process in payload/process.c], 0x74
MapProcessMemory, 0x75 Unmap, 0x76 QueryProcessInformation, 0x77/0x78
map/unmap code. The takeover's rig already exposes these as cross-process
ops (worker `ro-process`, ids 0x524f0010-16).

The missing input has always been **process handles for arbitrary pids**.
Two facts close the gap:
1. **The fs process holds a live pm:dmnt session** (proven in session
   RfKcA9's live service list; id-7 liveness sweeps run through it).
2. **pm:dmnt speaks plain cmif from the fs bridge** (root-native-ipc works —
   no HIPC2 wall, unlike nvdrv). pm:dmnt's whole purpose is debug
entitlements:
   HOS 1 pm:dmnt is the interface that returns **process handles by pid**.

Experiment (next strong boot, after fix-session-identity):
1. Sweep pm:dmnt command ids 0..16 via root-native-ipc with the monitor's
   own pid as arg (safe, self-owned target; id 7 = GetProcessInfo is proven
   live). A handle-returning command reveals itself via reply moves.
   Same for pm:shell (fs bridge holds it too).
2. With GetProcessHandle(pid): handle → rig `ro-process` ops →
   QueryProcessInformation = full memory map of ANY process (sm, spl, es,
   am …); SetProcessMemoryPermission + MapProcessMemory = **injection
   pipeline into any process** (the exact machinery that built the fs
   takeover: RWX cave + payload map + hijack).
3. That is full-system R/W + code exec in every sysmodule WITHOUT a kernel
   bug and WITHOUT the executor sm-namespace wall. Kernel-only leftovers
   would be KASLR/KTN-level defenses.

Fallback if pm:dmnt won't return handles on retail: launch sacrificial
titles via the takeover's pm-launch + CodeFS-gate machinery (proven) and
confirm handle extraction from the launch reply; and/or the debug
executor relay (creport policy — blocked on the sm namespace wall,
FINDINGS.md in ns2jb-session).

## 4. Target list, ranked by payoff vs. our current position

Position: SmileBASIC userland + armed takeover → owned FS root, BIS R/W.
What we lack: arbitrary code exec in a normal process, sysmodule code exec,
unforgeable game decryption (titlekeys), persistence across reboot.

1. **es (0x33)** — highest privilege of what we have. Ticket/eticket
   handling (`ticket.bin`, `ticket_list.bin`, `estitlekey:/`), `spl:es`
   (secure-monitor crypto), new `ndrm:la/ndrm:lu` services. Bugs here or
   forged IPC from our foothold → titlekey extraction → **clean game
   dumping** from registered NCAs we can already read via FS root.
2. **SystemWeb/LibAppletWeb (0x1042/0x1043)** — full **WKC** (Nintendo
   WebKit-derived engine) build, confirmed in the Ghidra strings: complete
   `WKC::WKCWebView`/`WKCPrefs`/`GraphicsLayer` API, `WkcVersion` report
   format, GLSL/RTC subsystems, plus `sd:/NXWebApplet` offline-content
   paths. The engine identity means Switch-1 WKC/WebKit bug classes
   (JIT/parser/layout) are the prior-art pool. 11,848 strings inventoried in
   1042 alone — full audit is a separate campaign.
   Web applet is launchable from a normal process (web applet IPC), so this
   is our best "userland code exec upgrade" target: known WebKit audit
   surface + brand-new Switch 2 build. Prior art: many public Switch-1
   WebKit bugs.
3. **tsec.autogen (0x8d)** — the fw23 way to talk to TSEC. Small, hosts
   `tsec:m`; loads RO modules dynamically (`tsec.nss`). Reversing its command
   surface = map of TSEC crypto operations reachable from EL1 (and any
   missing auth checks on `tsec:m` users).
4. **cmptldr (0x52)** + `ldr:cmp` — compat loader for legacy titles = old
   container formats re-parsed in a privileged process; classic forger-
   friendly target.
5. **Album (0x100d) + capsrv2/Overlay (0x100c/0x71)** — untrusted image/HTTP
   parsing in applet context; reachable from user content.
6. **ldn (0x18) / bsdsocket (0x12)** — untrusted network data (ldn peers,
   sfdnsres DNS parsing); reachable from any online game userland; historic
   bug-rich.
7. **nvkernel/vi2/host1x/gsvm* (GPU/display)** — brand-new Switch-2 driver
   services exposed to processes (`gpuk:drv` etc.); complex new code, classic
   escalation-adjacent surface once we have code exec anywhere.
8. **glue (0x31)** — hosts arp (all registration), time, bgtc, ectx, notif
   — the system glue; forging arp registration from our foothold could
   matter for persistence/clean boot-time hooks.

## 5. Deep-dive: es (0x33) — first results

Fully analyzed in Ghidra (1977 functions). Key findings:

**Save-data layout (from context init @ 0x2bd70 and save-mount code @
0x1afe0)** — es owns these SYSTEM saves (owner 0x400000000000033):

| save ID | name | size | contents |
|---|---|---|---|
| 0x80000000000000e0 | escertificate | 200 000 | certs |
| 0x80000000000000e1 | escommon | 20 000 000 | `ticket.bin`, `ticket_list.bin`, `version.bin` |
| 0x80000000000000e3 | esmetarecord | 0x4a380 | ticket_list meta |
| 0x80000000000000e4 | eselicense | 0x3800000 | licenses |
| 0x80000000000000e5 | esinternal | 0x1388000 | `index.bin`, `data.bin`, `version.bin` |
| (+ esinternalcert) | | | index/data certs |

→ Tickets live in **escommon:/ticket.bin + ticket_list.bin**; with our live
FS root these paths are directly reachable in SYSTEM save 0x...e1. Next:
mount that save via the fs bridge and compare es's parse logic for
vulnerabilities (parse happens in es with our controlled file content —
memory-corruption candidate).

**spl:es** — connected lazily via a global interface (conn setup @ 0x15be0,
service name string @ 0x1067d4). The es→spl crypto proxy uses
`nn::spl::detail::IEsInterface/ICryptoInterface/IGeneralInterface` (cmif,
HIPC MessageType 6). Ro strings: `eticket_key_version`, `estitlekey:/`,
`estitlekey` → es keeps an on-device estitlekey store (titlekey crypto path).

**ndrm** — es hosts a second service family: `ndrm:la`, `ndrm:lu` (+ string
`nn.ndrm.LowIpcServer`, `ndrm.low`) — new fw23 "low IPC" DRM server running
in the es process. Completely undocumented service surface; command table
not yet enumerated (dispatch tables are stripped, needs dispatch-object
tracing — next analysis task).

es also mounts `escertificate:/certificate`, reads `%s/certificate` etc.
All these paths are now mapped for the live probes.

### 5.1 es internal titlekey DB (esinternal:/) — structure mapped

es keeps a titlekey store in `esinternal:/index.bin` + `data.bin` (save
0x80000000000000e5) with **plaintext field names in rodata** (record schema,
`$.`-prefixed KV ids):

- `$.rights_id`, `$.kid`, `$.key_id`, `$.derivative_key_id`, `$.volatile`
- `$.wrapped_title_key` (id 0x41), `$.wrapped_per_title_common_key` (0x59),
  `$.wrapped_primary_key_seed` (0x59), `$.wrapped_secondary_key_seed` (0x59)
- **`$.wrapped_title_master_seed_key_for_development` (0x2d),
  `$.wrapped_title_master_seed_iv_for_development` (0x11),
  `$.wrapped_title_master_seed_tag_for_development` (0x19)**
  — a full *development-mode* master-seed provisioning path baked into retail es.

Record pipeline (FUN_000ad800 @ 0xad800):
1. TLV records read from data.bin (0x18-byte headers, tag/flags + 16-byte id,
   length must be ≤ 0x800 — bounds-checked).
2. Payload decrypted in-place (FUN_0006d410 / FUN_0006dec0, device-key
   context) into a 0x800 heap buffer.
3. Decrypted record must be `a.b` (exactly two `.` chars), then KV-parsed
   (`$.kid`, `$.wrapped_title_key`, …).

Security-relevant:
- The record bytes are **fully attacker-controlled via the es save files**
  (writable with our FS root), and everything after decryption parses with
  our data → parser-audit target (strict length checks seen so far — 0x291
   errors everywhere; no bug yet).
- The dev master-seed path means es accepts *dev-provisioned* key material in
   retail builds — worth checking whether retail-mode es reads the
   `for_development` fields unconditionally (if so: key-forgery route to
   arbitrary title decryption without console-unique keys).
- Related funcs: FUN_0009ee60 (dev-seed field ops), FUN_0009f200 (titlekey
   record builder), FUN_0009cd20/FUN_0009d5a0 (kid/rights_id records).

### 5.2 tsec.autogen (0x8d) — it's the HDCP manager

`tsec:m` hosts **`nn::tsec::detail::IHdcpSession`** (impl:
`nn::tsec::impl::HdcpAdapter`, template args `nnd4tsec::FirmwareType=0,
56, 32, 2`) — i.e. the Switch-2 tsec module loads TSEC firmware to run
**HDCP session** operations for HDMI (not console crypto). Clients: `spl:nv`,
`fatal:u`, `host1x`, `srepo:u/a`, `syslog:u`; psc power-state callbacks drive
TSEC on/off. New undocumented command surface (IHdcpSession), but value is
moderate (HDCP keys ≠ game dumping). Full Inventory in `out/`.

### 5.3 es IPC command tables — extracted

The es process registers four cmif command tables (stride 0x10
{InProc*, OutProc*} per command; machine-readable in
`out/es-cmd-tables.json`):

| table | commands | notes |
|---|---|---|
| 0x135920 | **56** | the real `es` service command set (lambdas 0x2a340–0x2b610) |
| 0x135cc0 | 56 | all entries = stub 0x1d8c ("unsupported" table — server init picks the real table at boot) |
| 0x136060 | **56** | the ndrm:la/ndrm:lu service (lambdas 0xdd810–0xdeab0) |
| 0x136d20 | 128 | es's client proxy for `set:sys` |

Service registration confirmed at 0x1bc74: name "es", max sessions 0x1e,
object vtable 0x1387e0, session-creation helper 0xbeb40. Command →
implementation mapping (lambdas call shared context methods with per-command
state slots at ctx+0x11c98+0x90*cmd) still to be named per SwitchBrew docs —
mechanical from here.

### 5.4 curl 7.64.1 (Feb 2019) in 10 sysmodules

`curl 7.64.1` embedded in: bcat, friends, nifm, account (dauth client), nim,
pctl, npns, eupld, migration, olsc — 2019-era HTTP stack on retail fw23.
Notable post-7.64.1 curl CVEs (cookie/STARTTLS/HTTP2 parsing). Attackable on
an online console via DNS/response MITM; less relevant in our offline netns,
but prime audit surface for the scene.

### 5.5 SystemWeb applet (0x1042) — target profile

Analyzed: **26,564 functions**. Confirmed NX WebKit (WKC) full browser:
- Build path leak: `Q:/JetCruiser/Daily/ReleaseBuild/cruiser-code/product/src/sys/extApplet/OpenWeb.cpp`
  (browser source tree = "cruiser-code"), UA template
  `NintendoBrowser/%d.%d.%d.%s` / `AppleWebKit/%s (KHTML, like Gecko)`
- **Offline web applet reads web content from `sd:/NXWebApplet/`** — fully
  user-controlled input to WKC WebKit with no network needed.
- Web applet modes via AppletId: OfflineWeb / OfflineWebSystem /
  OfflineWebApp_0/_3 / LibraryAppletWeb — whitelist ("BlockWhiteList")
  handling from the *launching application's* arguments.
- Launchable from any game (incl. our SmileBASIC foothold) with a
  game-supplied URL list → attacker-rendered content in applet context →
  WebKit memory bug = userland code exec upgrade.
- Next: pin the exact WKC build (version ints near the UA format) and
  diff-audit against known-vulnerable NX-WebKit bugs (JS engine, media,
  font/image decode paths).

### 5.6 Debug/development settings keys in retail sysmodules (LEAD — gating unverified)

`ns` (0x1f) rodata carries debug-mode settings keys, read via set:sys:
- **`redirected_rom_storage_id_for_debug`** — redirect an application's
  "ROM" (content) to another storage id.
- **`assign_all_device_linked_elicenses`**, `elicense_and_ticket_count`,
  `PersonalizedTicketCount` / `CommonTicketCount` /
  `DeviceLinkedPermanentELicenseCount` (ns introspects the eselicense store).
- `enable_debug`, `enable_download_task_list`, `enable_auto_commit_forcibly`,
  `ipc_failure_interface_type_for_debug`,
  `content_availability_settings_for_debug_account_6`,
  `is_compatibility_info_for_debug_enabled` (+ per-app debug compat info),
  `is_cleanup_enabled_for_develop`.

`am` (0x23): `screenshot_debug_mode`, `disable_launch_overlay_applet`,
`is_language_selection_limited_debug_mode`.

If any of these keys are consumed without a dev-mode gate (or the gate is a
writable setting), we may get debug behaviors in retail via the FS-bridge
settings-save write. TODO: decompile the consumers (data refs at ns
0x4175a8/0x4177xx/0x4179xx region) and check gating.

### 5.7 `redirected_rom_storage_id_for_debug` — no gate at the consumer (VERIFIED STATICALLY)

Follow-up on 5.6: the ns getter for `redirected_rom_storage_id_for_debug`
(descriptor @ data 0x417748, getter @ 0xd1f28, value = single byte) is called
from ns content-resolution (0x239410/0x239530/0x2397b0):

```
bl getter; tst w0,#0xff; b.eq normal;
// if nonzero and != current storage → re-resolve with the redirected
// storage id (0x23da80), i.e. application "ROM" content is served from
// the storage named by the key
```

**No dev-mode/retail check in the consumer** — the only gate is whether the
settings module serves the key. The settings module (0x9) keeps debug
settings in a separate section of the settings save: `settings_debug`
section + `FwdbgSettingsD/S` (hosted via `set:fd` /
`IFirmwareDebugSettingsServer`, `is_debug_mode_enabled` key).

⇒ Proposed chain to verify live: BIS-write the settings save
(SYSTEM:/save/…, we have root-write to SYSTEM restricted to /temp —
needs the user to unlock SYSTEM writes) → inject
`redirected_rom_storage_id_for_debug` into the settings_debug section →
reboot → ns serves application content from the redirected storage.
Would be a retail "content redirect" primitive (Nintendo's own dev tool
left in retail). Also candidate keys: `enable_debug`,
`assign_all_device_linked_elicenses`, am's `screenshot_debug_mode`.

### 5.8 settings save internals (for the debug-key chain)

- Settings module loads debug keys from files literally named
  **`FwdbgSettingsD` / `FwdbgSettingsS`** (+ `PfcfgSettingsD`) in a SYSTEM
  save (filter id 0x818), mounted via standard fs; no signature/hash checks
  seen in the loader (0x40480–0x405c0 region).
- `is_debug_mode_enabled` is itself a `settings_debug` key — i.e. the debug
  mode flag lives in the writable settings save. Whether the settings
  module gates other `_for_debug` reads on it needs the 0x3e260 fetch path
  traced (or one live test).

## 7. Kernel attack path — LIVE progress (nvdrv GPU surface)

**Session: live console, retained session switch2-AhV9wV.**

Verified live from the fs bridge (borrowed pm:shell SM client):

- **`nvdrv:t`, `nvdrv:s`, `nvdrv:v`, `nvdrvdbg`, `nvgem:cd` sessions all OPEN**
  (result 0, handle moved) — the kernel GPU ioctl surface is one
  protocol-format away from being fuzzable with arbitrary args from the
  fs process. (`nvgem:c` errors 1557.)
- nvdrv sessions **reject both cmif (SFCI) and sm-style legacy TIPC** messages
  with hipc error 0xF601 — they speak **HIPC2** (fw23 next-gen IPC; matches
  `Hipc2ProxyKindBase<detail::MessageType=6>` templates and the
  `HipcSimpleAllInOneServerManager`/`Hipc2ClientSessionManager` mangled names
  across the dump).
- HIPC2 client context identified: an object built around magic
  `0x45585048` ("EXPH") — seen in es (`FUN_000eb8f0`) and tsec
  (`0xd6f0`); tsec's `spl:nv` connect (0xcccc) constructs it.
- fw23 svc table is renumbered: `send` wrapper = **svc 2** (likely
  `SendSyncRequestWithUserBuffer(buffer, size, handle)` — arg shape fits),
  `CloseHandle` = svc 0x21 (unchanged). tsec's svc-wrapper block at
  text+0xc8–0x310 maps the fw23 syscall surface per-module.

**New tooling (hot-reloaded, permanent):** `root-native-raw-ipc` command in
`ro/control.cjs` (TIPC-style + HIPC descriptor framing) with `bare` mode for
arbitrary raw message bytes; `nvdrv-survey.cjs`, `nvframe*.cjs` probes.

**Next to unlock the fuzzer:** reverse the EXPH client send path (tsec
`0xd6f0` chain) to learn the HIPC2 wire format — or find the fs process's own
live HIPC2 client sessions (fs→spl:fs etc.) in the owned heap and copy the
message layout from a live session.

### 7.1 HIPC2 wire format decoded (static, from tsec 0xd0b0 + 0xd110)

```
+0x00: u32 = 6        (message type 6 — matches Hipc2ProxyKindBase<MessageType=6>)
+0x04: u32 = 8        (constant word — count or flags)
+0x10: SFCI magic
+0x14: u32 token = 1
+0x18: u32 command id
+0x1c: u32 sequence — loaded from *(TPIDRRO+0x1f8)+0x100 (per-thread seq)
+0x20: cmif args...
```
Sent via svc 0x22(msgbuf, 0x100) in tsec's wrapper table (fw23 renumbered
svc space; our fs-bridge `send` = svc 2 = user-buffer send and works for cmif
sessions — sm, pm:dmnt — so HIPC2 should accept a buffer send with the
type-6 framing). Test queued for the next READY session (console rebooted
mid-experiments; session AhV9wV died, RfKcA9 acquiring at time of writing).
No SFCI string constants in fw23 binaries — magic is movz/movk-built.

### 7.2 HIPC2 live experiments (session RfKcA9, post-reboot)

Live matrix (bare-mode `root-native-raw-ipc`, all from the fs bridge):

| message | size | result |
|---|---|---|
| cmif SFCI to nvdrv:t / pm:dmnt | 4096 | 0xF601 (rejected) |
| sm-legacy word0 0x11-style to nvdrv | 4096 | 0xF601 |
| `[6][handle][SFCI][1][cmd][seq]` to nvdrv:t / pm:dmnt | 4096 | **0x20801** |
| same | 0x100/0x200 | 0xCA01 |

- 0x20801 is protocol-level (identical on nvdrv:t and pm:dmnt) — we're inside
  the HIPC2 validator, one step short.
- **cmif to pm:dmnt is rejected too** — fw23 modern services are HIPC2-only;
  only legacy (sm) and fsp-srv-style sessions still accept the old framings.
- Interpretation of the tsec constant: HIPC2 word1 = **client session INDEX**
  (assigned by the "EXPH" hipc2 client manager at registration; tsec's spl:nv
  client uses static index 8) — a raw handle in word1 is *almost* right,
  hence the new error.
- Remaining gate: reverse the EXPH client-manager registration
  (tsec 0xd6f0 chain: session creation → message-buffer registration →
  index assignment), then either drive the fs process's own hipc2 machinery
  or replicate the registration. That unlocks arbitrary nvdrv Ioctl →
  kernel-surface fuzzing.

Note: the `RO pivot` pm:dmnt cmif path in ro/control.cjs will also be
0xF601 on fw23 for the same reason — needs the hipc2 treatment.

### 7.2b HIPC2 client fully decoded (pgl 0x0b0f0 disasm, 2026-10-25)

pgl's pm:shell proxy wrapper (FUN_0000ab40 → send-shape 0x0b0f0) shows the
COMPLETE modern fw23 client send, correcting 7.2's model:

```
build at THREAD TLS+0 (mrs tpidrro_el0):
  TLS+0x00 u32 6            (HIPC2 type — 7.1 confirmed)
  TLS+0x04 u32 wordcount    (observed 0xA for a 1-arg cmd; NOT a handle/index)
  TLS+0x10 "SFCI" (16-aligned; earlier probes wrote it at +8 = malformed)
  TLS+0x14 u32 1            (constant token)
  TLS+0x18 u32 cmd
  TLS+0x1C u32 seq = ldar(*(TLS+0x1f8)+0x100)   (per-thread seq counter)
  TLS+0x20 args...
send: svc 0x22(TLS, 0x100, session_handle)
   (same-thread path uses svc 0x21(handle) — the kernel TLS-send)
reply: "SFCO"-magic block; error filter compares against 0xF601
```

Implications:
- 7.2's `[6][handle][SFCI@+8]` probes were simply MALFORMED; the 0x20801/
  0xCA01 kernel errors on static buffers additionally indicate the hipc2
  message buffer must be the thread's REGISTERED TLS page (OS registers each
  thread's TLS as a hipc2 message buffer — explains why takeover-launched
  processes, which never get TLS setup, can never speak HIPC2; executor
  v4-v6 "alive but silent" mystery solved).
- The wave CAN speak HIPC2: its RPC threads are OS-threaded inside fs
  (their TLS is registered — the fs worker already serves/sends via svc
  0x21). Recipe: worker pthread struct (native-worker start() returns it)
  → read its tpidrro field → SDK-memcpy the frame to TLS+0 → SDK
  send(TLS, 0x100, handle) → parse SFCO back out. No new payload code.
- fw23 session refcounting is token-CAS'd: every client session
  acquire/release does casa/casl on a manager global using the TLS+0x110
  per-thread token (same +0x110 the takeover machinery already reads).
- pm:shell numbering on fw23 matches HOS 1 (pgl proxy thunks use ids 0..0xa
  for its subset).

### 7.2c Live results (session 2ddp51, 2026-10-25) — pm numbering CONFIRMED; TLS gate stands

- **fw23 pm:dmnt id 7 = GetProgramId(pid)** — monitor pid 209 answered
  `0x0400000000000037` (its ro-policy program id). **pm tables are HOS1-numbered.**
  pm:shell independently confirmed (bridge's own calls): cmd 3 =
  GetProcessEventHandle (event move), cmd 5 = NotifyBootFinished, cmd 6 =
  GetApplicationProcessIdForShell → **pid 207**, cmd 12 = GetProcessId.
- **Neither pm:dmnt nor pm:shell has a process-handle-by-pid command** on
  HOS1 tables → Branch A (full-system R/W via monitor rig ops) needs a
  different handle source (loader/gate-side, or fw23-only commands at
  ids 8+ on pm:dmnt remain unprobed — budget exhausted mid-sweep).
- **HIPC2 static-buffer sends are rejected even with the CORRECT frame**
  (7.2b layout, all wordcount/seq variants): nvdrv:t consistently 0xF601,
  size 4096 required (0x100/0x200 → kernel 0xCA01). The only remaining
  difference vs pgl's working client = the buffer is the thread's
  REGISTERED TLS. The TLS-send is the last gate.
- **pm session budget**: ~4-6 concurrent sessions per service name per fs
  sm client; exhaustion → GSH returns 0x615; wedged-session GSH can block
  the wave's busy mutex for minutes (observed self-recovery ~3 min).
- **2ddp51 session death (our bug)**: the first TLS attempt ran a gadget on
  a SERVING RPC executor thread, clobbering its live TLS+0..0x100 (the
  wave's in-flight message area) — same lesson as the monitor's sub-20
  crash. Fix shipped: `root-native-worker-hipc2-prepare` — a worker spawned
  PARKED at its gate sends from its OWN quiescent, kernel-registered TLS
  (tpidr offset derived from the thread ring via cross-thread +0x1f8
  agreement), frame patched while parked, released only afterwards.

### 7.2d HIPC2 worker-TLS chase — POST-MORTEM (5 console deaths; live path HALTED)

Sessions lost: 2ddp51 (gadget on a serving executor's TLS), Jer6aO +
0dSsB1 + vEkYmj (worker frames missing the leading `wait(gate)` call0 —
placeholder call0 executed at spawn = NULL memcpy = fs death; ROOT-CAUSED
and fixed: worker-prepare PREPENDS wait(gate), the real park), and
VkpjcN (the fully-fixed worker — PC-side ring scan (memory.read, the
boot's primitive), validated TLS, patched frame, released — WOKE and its
execution [memcpy(TLS,cfg,0x100) → send(TLS,0x100,h) → memcpy → exit]
killed the console anyway).

**Conclusion: even a correctly-parked, validated-TLS worker send is lethal
in ways we cannot iterate on without paying a console reboot per test.**
Live worker-TLS HIPC2 experiments are HALTED. The static-buffer variant is
settled (0xF601 at any framing — the buffer must be a registered TLS).

FULL SENDER DECODED (pgl 0xb0f0, complete disasm):
```
sender(x0=proxy, x1=firstArg, w2=cmd):
  w2 = [proxy+4]                 // the RAW SESSION HANDLE (only x0 use!)
  build HIPC2 at calling thread's TLS+0..0x2F:
    {6, 0xA}, SFCI@0x10, token 1, cmd@0x18, seq@0x1C = ldar(*(*(TLS+0x1f8)+0x100)),
    arg@0x20
  same-thread path: svc 0x21(handle)   // kernel sends THE CALLING THREAD'S TLS
  reply: SFCO block located+parsed; returns the service result in w0
```
THE FAKE-PROXY TRICK: the sender only reads [x0+4] — an 8-byte owned
{0, handle} is a sufficient proxy. Calling the REAL sender via
s.rpc.call3(live.sdk+senderOffset, fakeProxy, arg, cmd) on the RPC executor
= the OS's own client code path (its own registered TLS, its own seq, its
own reply parsing) — no workers, no synthetic frames, no TLS writes.

Remaining live steps (all read-only or OS-pattern):
1. memory.read the fs SDK (~6MB, read-only) → find the sender by its
   byte pattern: c90080d2 e803022a 020440b9 (movz w9,#6 / mov w8,w2 /
   ldr w2,[x0,#4]) + full-shape verify PC-side (NEVER call an unverified
   offset — RfKcA9 lesson).
2. s.write the 8-byte fake proxy (owned).
3. Open the target service via the proven sm-service; call the sender;
   the return value IS the service result (w0). Reply payloads: snapshot
   the 7 executor TLSs before/after (ring structs give their tpidrs) and
   diff — the changed one holds the fresh SFCO block.
Cross-module deltas vary (each module links its own SDK build) — the offset
must be scanned live per SDK, not derived.

### 5b-2. Live results: identity→am WORKS; BIS-boot wall = fs hard-gate
(session ueJtpC, 2026-10-25)

- **The am promotion WORKED live**: fix-session-identity --pid <amPid> →
  the BIS-30 listing of @User:/Contents/registered returned the content
  subdirs (0000009E, 00000061, 00000001, ...). The identity graph fields
  accept arbitrary sysmodule pids ✓.
- **BIS 0/10 (boot partitions) = 0x320002 for EVERY identity** tried:
  helper (null-title), am, nvkernel, capsrv, nim, vi2, adraw, gsv1/3/4,
  sdb, applet-100c — i.e. the boot-partition gate is NOT any fsaccess bit
  held by a dumped module (boot2 itself, bit 0x1e holder, has EXITED by
  the time the session is READY). Boot partitions are either gated by an
  undumped boot-chain-only bit or hard-coded in the fs module. The
  package2/KTN acquisition needs the fs module binary (see fs-dump) or a
  different route.
- **fs-dump (fs process memory dump) = the new unlock target**: the fs
  module is the one missing sysmodule, and its binary contains the
  fsaccess bit→partition table + the mount authorization internals.
  SAFETY (ueJtpC death): bulk-read ONLY type-3 RX + type-4 RO regions
  with attributes 0 — a t1 p3 RW block read HUNG the wave (device alias
  or special mapping class).
- The am-mount experiment stopped one step short (missing fsp-srv session
  — fixed in am-mount.cjs: opens via borrowed SM).

### 8. fw23 fs sysmodule — LIVE DUMP + first analysis (2026-10-25, sessions k3FMD7)

**THE FS BINARY IS BANKED** (the first boot-critical module ever captured):
`~/dev/switch/dumps/fw23-live-fs/` — 10 regions, 18,292,736 bytes + the 36MB
owned-region (live object graph) + SHA256SUMS + FSDUMP.md (the method).
Text (2.3MB, X-only) via rig 0x524f0015 flip + 0x524f0016 bulk read; rodata
regions plain bulk reads; all fetches via the fast readOwned channel
(~24ms/64KB — the retained read is 2min+/64KB and FREEZES sessions).

Ghidra: fw-re/ghidra-proj-fs (fs-live.elf, 4308 functions analyzed).
Analysis findings (§ numbers refer to decompiled corpus in fw-re/out/):

8a. **fsp-srv partition mask** (FUN_59921611c0): allowed BIS ids =
`(1 << id) & 0x8AD8100401` → {0, 10, 20, 27, 29, 30, 31, 35, 37, 39}.
**BOOT PARTITIONS 0 AND 10 ARE IN THE MASK** — the 0x320002 wall is deeper
(the per-session access-bit check), not an id-level rejection.
Partition slots: 0→1, 10→1, 20→4, 27→2, 28→3, 30→5, 31→6, 35→7 (registry
at ctx+0x50+slot*0x30). Boot partitions get special size handling: default
16MB cap when the partition's size field is 0 (the package2 window).
8b. **Process-context registration** (FUN_599207eb80): the per-process flags
at ctx+0x8c (`|= 0x2002` on registration success), per-program access tables
(letter-indexed, stride 0x250, at DAT_59931c2290). This is the SetCurrent-
Process path; the "strong identity" = the pid lookup miss → the internal-trust
fallback.
8c. **Mount-path decoder** (FUN_59920d1800): @SystemContent0/3, @UserContent,
@SdCardContent, @CalibFile, @Safe, @User, @System0/@System, @Sdcard, @Host
→ storage ids.
8d. **The actual access check** = a VIRTUAL call (session vtable+0x30) — the
vtable region (type 4, attr 16, at text_end, 0x5992296000+0x11000, 68KB) is
**unreadable by every external path**: the kernel refuses cross-process alias
maps of ALL module-class regions (attrs≠0 included; rig 0x11 map = 0xd401
BAD_INPUT empirically = the legacy small-read op is dead in this payload).
THE VTABLES + the t5 heap (the live process registry) remain the walls.

**Remaining walls**: the 0x320002 site (the access-bit test) sits behind the
vtable indirection; the vtable region + the fs heap registry = in-process-only
memory. Next: (1) identify the vtable's check function from the calling side
(the partition manager's callers), (2) the t5 heap = only via the dead 0x11 —
a future payload with a heap-capable bulk op would unlock ~70MB of live fs
state.

### 9. THE BOOT-PARTITION GATE — FULLY DECODED + THE PATCH (2026-10-25)

The chain, verified end-to-end in the banked fs binary:

9a. **The check function** (FUN_59920f03d0): partition SLOT -> access-bit-id
map: slot 1 (BIS 0/10, BOOT0/package2) -> id 0x36; slot 2 (27) -> 0x31;
4 (20) -> 0x32; 5 (30) -> 0x33; 6 (31) -> 0x34; 7 (35) -> 0x35; default
(slots 0/3) -> 0x36. The process registry lookup (FUN_59921114a0, the global
at DAT_59931cb2d0) by the session's process key -> the process-context ->
the access bits at +0x18.
9b. **The bit tester** (FUN_59920cf440): id 0x36 = read the 64-bit access
field's HIGH word bits 62+63; the check passes only when BOTH are set.
The other ids = multi-bit mask patterns (e.g. 0x8000200000000801).
9c. **The access field = the NPDM FsAccess maskA** (verified: boot2's NPDM
= maskA 0x4000000000000000 = bit 62 exactly; every sysmodule we can name
= maskA 0; the 64-bit field = the 28-byte FsAccess section's u64@+4).
9d. **THE PATCH**: the monitor (pid 8, the launched 0x37 donor process —
the identity the promoted fs session uses) is staged with OUR policy file
at every standard boot (the donor-prepare pins
policies['0400000000000037'].npdmFile). Patched:
`npdm-captures/0400000000000037-boot.npdm` (sha e0a19424ff0eb42a...) with
maskA = 0xC000000000000000 (bits 62+63). Pinned in the payload manifest.
**The next standard dance stages it; the loader's registration carries the
bits; the promoted session's BIS 0/10 check should PASS.**
9e. Safety: the ACI0 policy edit = the same class as the proven -sac
modified policy (launched successfully before); a rejected policy = the
dance aborts cleanly (gate restore), retryable — not a brick vector. The
bits are inert to the monitor itself (only the fs consults them).
9f. The watcher chain now probes BIS 0/10 after identity: result 0 =
**package2/KTN unlocked** -> run bis-boot-dump.cjs (ready, proven read path).

### 7.2e. HIPC2 round 3: the exec cave (2026-10-25)

- The sdk-sender scan (dispatch op 'hipc2-sdk-send') scanned the RPC
  executor's own main+sdk ranges: NO sender patterns. Conclusion: the
  executor = the host app process with a pre-HIPC2 nn SDK (6 MB at
  live.sdk — the verified helper functions at +0x586fb0 etc. live there).
  The HIPC2 senders exist only in fw23 module texts (fs binary: 1-arg CORE
  @text+0x1f4134, noarg CORE @+0x212eb4/0x212ff4/0x213124/0x214bf4).
- The exec rig (payload main.c 0x524F0003, the author's code cave:
  upload→commit(FNV)→run(args[8])→results[8], 3 execution modes, RX-flip
  on its own pages, "a wedged blob can only take this disposable service
  down") = the vehicle. Blob `experiments/hipc2.c` (92 B): builds the
  HIPC2 frame in out[0..7] = the reply buffer; one svc #0x22 (proven in
  takeover-launched processes per executor v7+). Disasm-verified.
- Frame recap (7.2b): +0x00 {6, wc}, +0x08 zeros, +0x10 SFCI (16-aligned),
  +0x14 token(1), +0x18 cmd, +0x1C seq, +0x20 args u64; wc = 8 + 2n;
  send size = wc*4. Reply: SFCO at +0x10 (out[2] low half = 0x4F434653).
- Driver `hipc2-cave-client.cjs`: staged (--upload-only / --control-only /
  full), pre-built blob (never compile inside the netns), per-step logs.
  First live run aborted unlogged — retry staged.

### 7.2f. HIPC2 round 4: the W^X wall + the cmif test (2026-10-25, uGSHLc)

- The exec-cave run: the blob uploaded + committed cleanly (the rig's
  0x524F0003 machinery works) but ALL THREE execution strategies failed:
  cave-flip 54273, stack-flip 52225, map-code 0xFFD00D41. **fw23 enforces
  strict W^X**: X→RX flips via handle = ALLOWED (the fs-text flip = proven),
  but SELF RW→RX flips and the JIT map svcs from a sysmodule-class process
  = REFUSED. The exec rig v3 (the author's data-blob cave) cannot run code
  on fw23 — it was unfinished work.
- The cmif-to-nvdrv test: nvdrv:t opens fine (the borrowed sm) but every
  bare/cmif frame = transport 0xF601 (protocol rejection). **HIPC2 is
  genuinely required for nvdrv** — no dual-stack on this class of service.
- THE PATH FORWARD: the **instruction-challenge mechanism** — the boot's
  own 0x524F0014 op patches fs text (map RW alias + exact-expected write +
  publish_code + readback, PROVEN at every boot) and the fs process
  executes the patched code. Design: stage the HIPC2 frame + the handle +
  a reply buffer in the FS HEAP (module maps for PATCHING = proven; the
  heap = mappable), patch an fs command handler with a multi-block stub
  (mov args, svc #0x21 — the fs = OS-launched so the TLS send works,
  store reply, return), trigger via the corrupted session (e.g. the
  fsp-srv cmd-2 oracle path), read the reply via the rig bulk read,
  restore the original bytes. ~3 patch blocks; all proven op classes.

### 7.2g. HIPC2 round 5: the fs-text patch sender WORKS; the speculative-frame wedge (2026-10-26, uGSHLc)

**The mechanism is proven live** — every piece of the patch-sender design:
- The 3-block patch install of a hand-assembled 48-byte ARM64 stub
  (landing hint + movz/movk frame-address + movz x1 size + movz/movk w2
  handle + svc #0x22 + ret) into the notifier's GetEventHandle: expected
  matched, readback matched, all three blocks.
- The root-hipc2-stage/fetch wave commands: the frame staged + read back
  from the idle big-write region (bisDataAddr).
- THE STUB EXECUTED IN THE FS PROCESS (pid 8): the notifier-probe trigger
  wedged pending — the only consistent story = the fs dispatcher ran the
  stub and blocked inside svc 0x22 (a REAL send, not an error path).

**The wedge (lesson #8)**: svc 0x22 (nvdrv:t, type-6 frame cmd 0, wc 8,
no descriptors) never got a reply — the fs dispatcher thread is blocked
forever, the rig worker (the patch/restore channel) wedged behind it, and
the restore could not run (the stub stays armed in fs text — inert unless
GetEventHandle is called). Closing the nvdrv session does NOT cancel the
blocked send. The waves (root control, memory control, BIS, owned fetch)
are unaffected — the session is stable-degraded until the next boot.
**NEVER send a speculative frame to an unknown-dispatch service** — the
control must be a service with a known command table and a known-good
frame shape, sent FIRST (pm:shell cmd 6 was the plan; its session budget
was exhausted by earlier sweeps — at a fresh boot it comes first).

Next-boot iteration: (a) an invalid-handle stub run (expect a clean svc
error + NO pending worker — proves the wedge = a real send), (b) the
pm:shell cmd 6 control (fresh budget at boot; the cmif-known answer),
(c) only then nvdrv:t, with the correct command shape for cmd 0/3.

### 7.2h. HIPC2 round 6 (xqTFs2): the invalid-control answers — svc 0x22 IS the block (2026-10-26)

The --invalid control wedged IDENTICALLY to round 5 (bogus handle 0x7BAD0001:
patch installed, probe pending, frame untouched, restore blocked). An invalid
handle cannot block a real SendSyncRequestWithUserBuffer — **the svc call
itself is the blocker**: svc 0x22 from the fs process on fw23 is either a
different (blocking) svc or an unpermitted-svc hang. The control did its job
exactly as designed: the block is ours, not nvdrv's dispatch.

**Correct transport (the evidence, all live-proven):**
- The executor's bidirectional RPC works → its sends = the SDK svc 0x21
  wrapper (`210400d4 c0035fd6` = svc 0x21; ret — a register passthrough),
  called with the handle in **x0** — the OLD (pre-3.0.1) ABI, consistent
  with fw23's pm = HOS1 command numbering. fw23's kernel = an evolved
  HOS1-generation kernel with the old register ABI.
- The fs binary's OWN HIPC2 senders (text+0x1f4134 1-arg, +0x212eb4 etc.
  no-arg) build the frame in the CALLING THREAD'S TLS + svc 0x21 — the OS
  nested-call pattern: a server handler making its own client call reuses
  its own TLS message area, and the server library rewrites the TLS reply
  area AFTER the handler returns — so the reply must be copied out by the
  sender (it writes out-args to arg pointers) or by our stub.

**Round 7 = the sender-call stub (next boot):** don't hand-roll the TLS
dance — CALL THE FS'S OWN SENDER from the patched stub:
- stage the 8-byte fake proxy {0, handle} in the fs heap (root-hipc2-stage)
- verify the sender bytes live via the rig read BEFORE patching (pattern
  match against the banked binary)
- a ~13-instruction stub: materialize (proxy, cmd, args...), x16 =
  the sender address, blr x16, ret — ~4 patch blocks
- the sender's ABI: re-derive OFFLINE from the banked disasm (the pgl
  0xb0f0 shape: reads [x0+4] = the handle; the arg registers need the
  exact decode from FIRMWARE_FINDINGS 7.2d/7.2e before any live build)
- nvdrv:t only with a VERIFIED command shape, control (pm:shell cmd 6)
  FIRST as always.

Session state: xqTFs2 = stable-degraded (rig wedged, waves alive, stub
armed+inert). The waves carry the smc-oracle policy (d965b748) — the
game-mount track (am-pid) can run on THIS session's waves.

### 7.2i. Death #9: the am-pid promotion froze the app (xqTFs2, 2026-10-26)

The am-mount track's plan — "promote the session identity to am's pid so
content authorization passes" — is WRONG at the mechanism level:
fix-session-identity rewrites the corrupted session's identity fields
(root+0x30 + graph slots). The PROVEN promotion target = the null-title
helper pid (8): its process-info lookup MISSES, so the fs falls back to
internal trust (the strong boot — every BIS 30/31 success rode this).
am's pid (158) = a LIVE sysmodule: the lookup HITS am's real process
state, the fs mixes our session's traffic into am's identity accounting,
the session wedges — and the app (whose own fs calls ride the same
corrupted session) froze mid-call; the bridge died with it.

RULES (added to the ledger):
- **Never promote the corrupted session's identity to a live process pid.**
  Only the null-title helper (pid 8) — the miss = the internal-trust
  fallback is the entire point.
- The pid->program sweep result (pids 189-209 = the sysmodule map,
  monitor = 0x37) is valid and useful; the sweep itself is a proven class.

The next boot's game-mount track: strong-promote with the tool's DEFAULT
(helper pid, proven) — then the content-mount probes under the
full-trust + forged-policy identity (the boot-partition-dump combination).
NO am-pid promotion, ever again.

### 7.2j. Content-mount probes: the E002 content-authorization wall (JKd5i0, 2026-10-26)

Strong boot (native, no promotion needed) + fsp-srv cmd-10 MountContent
probes over 7 registered NCAs (fsType 6, tid=MKW, both '@User:' and
'@User0:' path shapes): ALL refused with the consistent 0xE002 class
(incrementing handle bits in the upper word = per-attempt allocations).
Conclusion: the BIS partition gate (the 0x8AD8100401 mask, bits 62+63 —
FORGED and proven) is NOT the content-mount gate. MountContent checks a
DIFFERENT per-process right: the NPDM per-title content access
(AccessibleTitleIDs / application-type class). The forged 0037 donor =
the BOOT sysmodule class = no title-content rights.

Next options (the game-dumping track):
1. POLICY ROUND: add the MKW tid to the donor NPDM's AccessibleTitleIDs
   (both sections) + possibly the application-type field — the same
   forge class as the FsAccess bits; next boot.
2. The smc-oracle route (svc 126/127 already in the policy d965b748):
   titlekey derivation = decrypted content without any mount.
3. The E002's exact check = decodable from the banked fs binary (the
   MountContent authorization path — offline RE, the 0x2EE002 sibling).

### 7.2k. Death #10: the rig wedges on the first sm-get after MountContent probes (JKd5i0, 2026-10-26)

The round-7 sender stub never installed: Client.open()'s ro:dmnt sm-get
hung 12s -> 'Native worker is pending'. The worker was idle at the health
check; the ONLY intervening work = the wave-side MountContent probes
(root-native-content-mount, the RO-pivot wave sends on the fsp-srv
session). The E002-refused mount sequence = 10 completed sends, but the
next NEW session open (sm-get) from the native worker = blocked forever.
Same irrecoverable class as rounds 5/6 (the monitor-side IPC thread wedged
mid-send; nothing wave-side cancels it; the handles are not in the
fs-process table so root-native-close-handle cannot reach them).

RULES:
- **Rig work FIRST, wave-side probes after.** The native worker's session
  opens are fragile after wave-side mount/send sequences; order the
  session: settle -> the sender stub (rig) -> then the mounts (waves).
- The sender stub driver (hipc2-sender-stub.cjs) is READY and verified
  against the banked binary: 16 insns, 4 blocks, (x0=proxy, x1=out,
  x2=cmd), the sender entry verified live pre-patch.

### 7.2l. HIPC2 round 7 (TWfuBk): the mechanism WORKS; the handle-space answer (2026-10-26)

Round 7 ran the full chain cleanly for the first time: the live sender
prologue VERIFIED (the fs text base = ASLR'd per boot — the region query
at the vtable target relocates it; the sender at region+0x212ea0 matched
byte-exact), 4 patch blocks installed, the notifier-probe trigger
executed the stub, and the stub's blr into the fs's own sender ran —
the send went out and BLOCKED. Root cause: the root-native-sm-service
handles = THE MONITOR'S table (the RO-pivot wave's process), but the
stub executes IN THE FS PROCESS — the handle number is foreign there:
empty slot or a colliding unrelated session -> no reply -> the fs
dispatcher wedges -> the probe never completes (the standing lesson-8
class, now fully attributed).

THE REMAINING PIECE: an fs-TABLE target handle. Options, in order:
1. The BIS-filesystem handles (root-probe-bis-filesystem ->
   state.filesystems, fs-side opens) = fs-table sessions — a stub send
   to one = a clean error or a self-send (server-side) -> the perfect
   MECHANISM control (expect completion + restore, no wedge).
2. The fs's OWN sm session (its internal dependency): the handle number
   is findable OFFLINE in the banked 36MB owned-heap dump (the object
   graph) + the sm protocol = the payload's own sm-get code. With it,
   the stub (or a two-stage stub) opens pm:shell/nvdrv IN THE FS TABLE,
   then sends the real frame.
3. Same-boot stage two: the fresh fs-table handle from (2) feeds the
   sender directly — the complete HIPC2 client, fs-side.

The rig on TWfuBk wedged on the probe (the fs dispatcher is blocked);
the waves remain alive. The ordering rule stands: rig first, and now
ALL rig experiments must be designed so a wedge is impossible or the
handle is pre-verified (fs-table) before the trigger.

### 7.2m. The silent-drop isolation complete (oW2ej1, the 68269afc era, 2026-10-27)

The session's systematic tests closed every remaining variable:
- The rig sub-bodies DO run (the tag echo through deferOp proved the
  dispatch + bodies execute — the "fall-through" reads were the spill
  layout + the all-zero outputs of dropped sends, not dead branches).
- The deferred clean-state executor (main's loop, between receives — the
  exact state where register_service provably works) = engaged; its sends
  = STILL silently dropped.
- The dual-read combo (sub 24: svc 0x22 + reads of BOTH the TLS and the
  buffer after) on the sm itself: transport 0, both zones zero, the
  request frame consumed. THE REPLY NEVER LANDS ANYWHERE.
- The sm GSH from the monitor = dropped even on the BOOT'S OWN SM PORT;
  the boot's register_service on that same port works every boot.
- The executor process (the 0036-donor launch) proves {0x11, 2, name} GSH
  works on fw23 — in ITS process.

CONCLUSION: the monitor's outbound sends are dropped per-frame or
per-connection-state, not per-thread/handle/port. The remaining suspects:
(a) the sm's per-client state — the monitor's boot InitializeClient may
itself have been silently dropped (its "success" check p[2]==0 is
indistinguishable from the drop), leaving the connection uninitialized
while RegisterService is tolerated pre-init; (b) a frame-shape delta on
fw23's sm for GSH-class commands.

OFFLINE NEXT: decode the fw23 SM SYSMODULE (check the 85-module dump for
it) — the GSH/RegisterService/InitializeClient handlers give the exact
frames, the per-process checks, and whether init is required before GSH.
Also: the payload's boot init should VERIFY a real reply (e.g. check
p[0]==0x10 echo) instead of the ambiguous p[2]==0.

Session oW2ej1 left running per instruction (waves + rig healthy).

### 7.2n. The REAL RO module decoded — the sm TIPC protocol byte-exact; the GSH shape delta (2026-10-27)

The fw23 store dump's five "error" titles were artifacts (EEXIST double-run
collisions). Re-unpacked offline: **ro (0x37, text 164 KB — the module our
donor impersonates)** + usb.gen2 (0x06). 0x837/843/85d = meta-only (no main
in CodeFS, live-verified on oW2ej1). The sm/pm/loader/spl/boot class remains
package2-resident (not installed content — the ncm/CodeFS route structurally
cannot reach them).

Ghidra on the real ro gives the byte-exact sm client protocol (its
FUN_0001cc60/1d020/18520 = ensure-connected, frame-builder, register):

- **connect**: ConnectToNamedPort("sm:"), retried on **0xF201** (sm
  not-ready) with 50 ms sleeps. Handle stored in a once-guarded global.
- **InitializeClient (cmd 0x10)**: TLS+0 = `0x8000000000000010`
  ({cmd 0x10, token 0x80000000}), TLS+8 (u32) = **1**, TLS+0xc = 0.
  Reply check: `(TLS+0 & 0x800003ffffffffff) == 0x100000010` AND
  TLS+8 == 0. Our payload's frame = byte-identical; our old success check
  (p[2]==0 after pre-writing 1) was already drop-safe — a drop leaves
  p[2]=1 and parks the monitor. Boot progresses → **the init reply really
  lands — 7.2m suspect (a) (dropped init) is ELIMINATED**.
- **RegisterService (cmd 0x12)**: TLS+0 = `0x500000012` ({cmd 0x12,
  token 5}), **TLS+8 (u32) = the SPACE (1 or 2)**, name string at
  **TLS+0xc**, maxSessions (u32) at TLS+0x14, flags byte at TLS+0x18.
  Reply: echo `0x8000000100000012`, TLS+8 == 0x20, out-handle at TLS+0xc,
  result word at TLS+0x10. **Our register_service matches this layout
  exactly** (our check p[1]==0x80000001 is drop-proof: the request token
  5 never equals the reply high word) — and the takeover's clients reach
  our ports every boot → **the register reply provably lands too.**
  The real ro registers: ro:dmnt (space 1, 2 sessions), ldr:ro (space 1,
  0x10), ro:1 (space 1, 2), ldr:ro AGAIN (space 2, 0x10). We register
  ro:dmnt space 1 (matches) and ro:1 space 2 (the real one is space 1 —
  documented, not changed: it demonstrably works).
- **THE SILENT-DROP ANSWER CANDIDATE**: init (0x10) and register (0x12)
  provably work from the monitor; only the GSH (0x11) drops. The ro's
  RegisterService proves fw23's sm evolved the TIPC arg layout —
  **space (u32) at TLS+8, name string at TLS+0xc** — while our GSH still
  sends the legacy HOS1 shape (name u64 at TLS+8, no space word). A GSH
  handler reading the evolved layout from our legacy frame sees garbage in
  the space word and an empty name — a malformed-frame silent rejection
  is fully consistent with every 7.2m observation.

**Payload b7a4c093 (10817B)**: the GSH (sub 25) now takes a space param —
0 = legacy shape (A/B regression), 1/2 = the evolved shape (space u32 at
+8, name at +0xc) — and the init now also verifies the ro's masked echo
(hard-fail visible instead of an ambiguous pass). Driver:
`hipc2-rig-client.cjs --gsh <name> [space]` (default space 1).

NEXT-BOOT MATRIX: `--gsh pm:shell` (evolved, space 1) → if dropped,
`--gsh pm:shell 2` (space 2) → if dropped, `--gsh pm:shell 0` (legacy —
the known-dropped control). A real GSH reply unlocks the HIPC2 vehicle
end-to-end: nvdrv:t, then arbitrary service calls.

### 7.2o. The pre-boot review: the shape and SAC hypotheses both DEAD; the executor recipe is the test (2026-10-27)

The staged b7a4c093 (evolved-shape GSH as the prime test) was re-reviewed
against the executor evidence BEFORE the dance. The v10 executor's GSH —
the only GSH that ever got real replies on fw23 — used:
- the LEGACY shape ({0x11, token 2}, name u64 at +8) → the evolved-shape
  hypothesis was wrong to call the shape the gate;
- a FRESH sm: session (its own connect + init) — never GSH'd on the boot
  session that registered services;
- svc 0x22 with a 4096-aligned user buffer (its message() = ipcArea), the
  reply read from the buffer.

Live-session falsification rounds (oW2ej1, all via the deferred sub 25):
- GSH("fatal:") — fatal: IS in the monitor's ro-SAC — STILL dropped →
  the simple SAC-gate theory dead.
- The executor's actual staged NPDM (npdm-captures/0400000000000036-sac,
  sha bfd263ac) decodes with an OFF-BY-ONE length bug in the hand-patched
  SAC ("ro:dmn" truncated, cascading garbage) — yet BOTH its GSH probes
  resolved → the sm does NOT SAC-gate GSH at all.
- The one recipe never replicated from the monitor = fresh session +
  svc 0x22 buffer + legacy shape. That is now rig sub 29 (--gshx in
  hipc2-rig-client.cjs): deferred to main's clean loop, fresh connect +
  init (echo-verified) + legacy GSH via the buffer + close, results
  packed as {init_t|gsh_t, init_echo, buf[0..5]}.

Payload cd9801e7 (11189B): sub 29 added; the evolved-shape sub 25 kept as
the SECONDARY probe; the init masked-echo check kept (verified against the
ro's own expectation — note the init reply's high word = 0x1 WITHOUT the
SFCO bit, vs register's 0x80000001).

Mount-track tempering: our cmd-10 probes get 0x2ee002 (the "launch
authorization family"), NOT 0x320002 (the fsaccess-denied code) — so the
maskA bits 4+6 forge (policy 6a8c2b09) may not flip E002. Kept anyway:
same proven forge class, ns carries bit 4 for a reason, and no content
route works without it. Expected-value: plausible, not probable.

NEXT-BOOT ORDER (all rig-side first): 1) --gshx pm:shell (the prime
test), 2) --gshx fatal: (in-SAC control), 3) the shape probes --gsh,
4) content probes LAST. If --gshx also drops → the remaining delta is
the process identity itself → the executor-relay route (a 0036-donor
GSH relay process, SAC irrelevant, names arbitrary) becomes the design.

### 7.2p. The fresh boot (AbiWxG): the persistence test FALSIFIED; the rig byte-order discovery (2026-10-27)

The boot landed on the second dance (one lottery miss, stage 2/4
heap-shaping — the usual dice, not payload-related). SESSION READY with
payload cd9801e7 + policy 6a8c2b09 (maskA bits 4+6, both ACID+ACI0).

**Persistence: the BIS /temp markers did NOT survive the reboot.** All
four markers (the write test, marker A, the subdirectory marker, the
192 KiB multi-cluster file) read back 0x202 and are absent from the
directory listing. Caveat that keeps the question half-open: /temp is the
only USER path our write gate allows, and is exactly the directory a
system may purge at boot by design — so the result proves at least
"temp is volatile", and any future persistence test needs a non-temp
path (which the gate currently forbids) to distinguish purge from
non-persistence.

**The rig request byte-order (critical tooling fact):** the rig driver
encodes its hex words as the value's hex string (a big-endian byte image),
while the monitor parses the frame words as little-endian u64s. On this
payload generation the parsed sub lands byte-swapped (the echo word shows
e.g. 0x1900000000000000 for sub 25), NO dispatch case matches, and every
queue/poll silently reads as state 0 + all-zero results. The workaround,
proven live: pre-byte-swap each input word (making the hex string the
LE image — equivalent to writing the words with writeBigUInt64LE, which
is what the debug-relay driver has always done). With the swap, subs
dispatch cleanly (sub 29 queued, executed, reported). Unresolved: the
previous payload generation (68269afc-era, oW2ej1) appeared to parse the
BE-imaged words cleanly with the identical source expression — suspected
is a frame-offset difference between builds, but it was not root-caused.
All new-build rig calls must use the swapped (LE-image) encoding.

### 7.2q. Sub 29 live: the SILENT DROP is SOLVED operationally; the sm deflects the monitor's client relationship with 0xE401 (2026-10-27, AbiWxG)

The executor-recipe GSH (fresh sm: connect + init + the legacy-shape GSH
via svc 0x22 from the 4096-aligned buffer) ran from the monitor's clean
deferred loop via the swapped rig encoding. Results:

- **init**: transport 0, but the reply buffer came back ALL ZEROS —
  including the word we pre-set to 1 (so something replied), yet with
  none of the ro's expected masked echo (0x100000010). The sm deflects
  the monitor's client-init with an empty frame. Note the asymmetry: the
  BOOT-TIME init (svc 0x21, the TLS transport, same frame bytes) gets a
  proper echo every boot — the transports see different sm behavior.
- **GSH**: 0xE401 — the loud "operation not permitted" class (the same
  error class the fs gave the fs-text stub's ConnectToNamedPort attempt).
- **fatal: — which IS in the monitor's ro-SAC — also 0xE401**: the SAC
  gate theory is dead for the third time (the executor's own staged NPDM
  has an off-by-one bug making its patched SAC literal garbage, and both
  its probe names resolved — the sm does not SAC-gate GSH at all).

**The operational solution to the whole silent-drop mystery: the TLS
transport (svc 0x21) silently eats the sm's refusals, while the buffer
transport (svc 0x22) reports them as loud errors.** The monitor's GSH was
never mysteriously vanishing — it was being refused, and the TLS path
swallowed the reply. What remains per-process: the sm lets the monitor
REGISTER services (its ports land every boot) but refuses its client
relationship (deflected init + 0xE401 GSH) regardless of name, session,
or transport. The executor process (the 0036-donor class) gets real GSH
replies on its boots — the per-pid difference is unresolved; the executor
is the practical GSH vehicle (see 7.2r).

### 7.2r. The live-deploy machinery: the monitor and executor can be redeployed WITHOUT a console reboot (2026-10-27)

deploy-monitor.cjs completed two live cycles on one session:
- **The monitor redeploy**: the donor cycle (cleanup -> reset -> prepare
  with the rebuilt image) -> the gated PM/Loader launch dance -> start ->
  terminate-previous -> execution-record update. The new monitor (relay
  subs 17/18 + the RELAY_TAG poll branch restored) served rig requests
  immediately.
- **The --second executor deploy** (--policy=0400000000000036): staged the
  new executor (OP_GSH = the parameterized executor recipe, OP_CMIF =
  an arbitrary TIPC send on a held handle, 2584 bytes) and launched it as
  a second process under the creport policy.

Gotchas hit and fixed, for the record:
- The run-dir payload copies AND the run-dir manifest must be synced with
  a rebuild ("The payload for this console is unsupported" otherwise —
  the check reads the run-dir manifest pin against the run-dir image).
- The --second deploy needs the run-dir code-capture directory for the
  0036 NPDM (main.npdm) unless the manifest policies entry carries
  npdmFile; the capture dir can be recreated from the pinned -sac file
  (the handler hash-verifies against the pin).
- A completed-but-unjoined native worker blocks the next client open
  ("Another native worker is active") — clear it with a worker-join.

### 7.2s. Death #11: the attach-class op killed the monitor AGAIN; THE SM REGISTRATION LEAK; the reboot verdict (2026-10-27)

**Death #11 (the death-#6 class, repeated)**: debug-dump.cjs — a tool
from an earlier era whose fs-mediated design no longer matches the
current client pid-gate — routed a DebugActiveProcess attach through the
monitor's rig; the monitor died mid-attach (the pid-gate error was the
first symptom; both the boot monitor and its redeploy were gone within
minutes). Quarantined. The rule stands unchanged and must be absolute:
**no attach-class (svc 0x60) operations through the monitor, ever.**

**THE SM REGISTRATION LEAK (proven live)**: after the monitor died, a
FRESH wave-side GSH(ro:dmnt) was still granted (result 0) — but a probe
against the granted session got no reply at all: the sm was still
resolving the name to the DEAD process's registration. The replacement
monitor (redeployed cleanly, pid 212) could not re-register the name
(the already-exists refusal) and every rig client resolved to the dead
port, where sends queue forever (the lesson-#8 wedge). The ro:dmnt name
is poisoned until the sm restarts — which on this console means a reboot.
This is consistent with the client-init deflection from 7.2q: the sm
never fully bookkeeps our forged-NPDM monitors as clients, so its
process-death cleanup for their registrations does not run.

**The executor wedge explained**: the deployed executor (pid 211) stayed
alive past every death-clock crash path but never entered its relay loop
(zero relay polls processed). Consistent with its probe-phase GSH having
resolved to the previous dead monitor's leaked registration: the granted
session pointed at a dead port, and the executor's first poll send
blocked forever in that port's queue (a lesson-#8 wedge, alive-forever,
crash-free — which is why the death-clock timing table did not decode).

**Verdict**: console reboot required — which also clears the poisoned
name. The next fresh-boot window is RESERVED for the MKW create-only
LaunchTitle route (see NEXT-RUN.md): the pm per-boot launch budget dies
fast, so the create runs immediately after SESSION READY, before any
other experiment touches pm. The executor-relay route (debug-relay gsh/
cmif against the dbdd3bca executor) and the content re-probes (the
maskA bits 4+6 vs the E002 class — still untested live) queue behind it.

### 7.2t. The fresh-boot window (session the run after AbiWxG): the budget theory FALSIFIED; the vtable region is kernel-protected; the bits are inert (2026-10-27)

**The MKW create-only LaunchTitle = REFUSED ON A FRESH BOOT** (0xc307d802,
the desc-02 class), as the boot's second launch within a minute of SESSION
READY. The per-boot launch budget theory is dead: the refusal is not
boot-age-dependent. What still separates the accepted from the refused
launches: EVERY accepted launch (the acquisition monitor, the redeploy
dances, the lUQn26-era MKW acceptance) ran during a STAGED-CODEFS mount
(the loader-gate flow); the bare pm:shell LaunchTitle never carries one.
Strongest remaining hypothesis: pm's LaunchTitle acceptance is coupled to
the content/codefs staging state — the create-only route needs the staged
volume first (the deploy-donor class), not a bare launch.

**The fsp-pr vtable region is kernel-PROTECTED.** The "gap" = a separate
0x11000 fsRodata slice (type 4, perms R, **attributes 16**). The alias-map
(map_process) AND the permission flip (SetProcessMemoryPermission) BOTH
return the kernel's 0xd401 refusal on it — attrs 16 = a locked/protected
region class. The rig's attrs!=0 filter was correct to exist. The only
read path = the kernel debug-read (svc 0x6a), whose only sanctioned context
is the executor process (three monitor attach deaths: FBEa7V, JKd5i0, and
today's repeat — the rule is absolute).

**The executor wedges on fresh boots too** (deployed, alive forever past
every death-clock crash path, zero relay polls): the stale-registration
theory is falsified. The wedge = the sm's silent-send class — the
executor's buffer init/GSH send never returns. The death-clock cannot
diagnose its own wedge (no crash = no timing report). Open A/B: the era's
v10 binary vs the rebuilt one; open redesign: a wedge-independent status
channel. NOTE: the sm deflection work (7.2q) suggests the 0036 process's
client relationship may now be deflected the same way the monitor's is.

**The maskA bits 4+6 are INERT for the E002 gate** (proven live this
boot): cmd-10 OpenFileSystemWithId refused 0x??ee002 for MKW, our own
tid, and MK8D with the bits staged. The content mount is NOT an fsaccess
problem. The mount/registration surface now funnels entirely through the
fsp-pr registry (the staged-launch route above) or the titlekey/smc route.

**Session state at close**: the mount probes ran last (death-#10 ordering)
— the session's wave-side sm-gets are spent. Strategic consequence: every
content/debug route now terminates at the same walls (pm's staging
coupling, the protected vtable region, the executor wedge) — the
**package2 decryption track is the highest-leverage route left** (it moots
the vtable gap, the sm/pm/loader decodes, and the KTN kernel question at
once). The fw23 package2-key scene ask stands; the PSC-FW location hunt
continues offline.

### 7.2u. Correction (external intel, 2026-10-25): the vtable region is NOT kernel-protected — the 7.2t wall was a CROSS-PROCESS wall

A correspondent's independent capture (their own FW-dump path, not our
payload tooling) shows the region readable: 282/512 qwords of page 0 are
live pointers into the fs module span (self-consistent: their base
0x5af2296000 shares the …2296000 low bits with both our old-boot
0x5992296000 and the 92LuGr ASLR base — same region; their pointers land
below it in the fs text/rodata span, a genuine vtable page). They also
hold a COMPLETE fs main.nso: 10,932,496 bytes, buildId 094c1cae…,
including this region.

Reconciliation — no contradiction existed: 7.2t's 0xd401 refusals were
the kernel gating CROSS-PROCESS access (the monitor's alias-map and
permission-flip handles). The region is an ordinary readable rodata slice
IN fs context — fs dereferences those vtables constantly. This is
exactly the memcpy-in-fs-context class the `copy-region` command
(e4b673c) was built on, so their capture CONFIRMS our route rather than
competing with it. Corrections to 7.2t:
- "kernel-PROTECTED, only the debug-read reaches it" → wrong on "only":
  the in-process memcpy route reaches it without any debug handle; the
  executor is NOT needed for the gap read.
- The copy-region step (NEXT-RUN step 1) stands, but its offline prize is
  partly preempted: their complete main.nso is a far better reversing base
  than any live slice read (the RegisterProgram handler is static code;
  live addresses follow from the base delta).
Resolution (2026-10-27): the correspondent shared INTEL ONLY — no files
(the main.nso and their vtable capture are not coming). So their capture
proves the region is readable in fs context, but our live `copy-region`
read remains the only route to its content for us. The complete-main.nso
reversing base is off the table; the fsp-pr RegisterProgram decode goes
back to: copy-region live read + the banked fs-live.elf slices + the
Ghidra project. The "OunceCake route (NCM license + fs cmd 206)"
reference is being integrated by a separate agent — if it holds up it
re-prioritizes the content track ahead of fsp-pr; until then NEXT-RUN
stands (copy-region first, the staged-codefs launch test second).

### 7.2w. The nvdrv/kernel decode begins (offline, the 0x19/0x4f modules) — 2026-10-27

Focus shift: the mkw dump window belongs to the other agent; this track =
privilege escalation, kernel R/W, kernel bugs, nvdrv (KERNEL-TRACK.md).

**fw23 svc ABI confirmed from both sides**: the syscall id lives in the
`svc #imm` immediate (not HOS1's w8) — our live-proven `svc #0x22` payload
and nvservices' own wrapper thunks agree. Every id has exactly ONE wrapper
in the target's text (nvservices: a thunk table at text+0x310-0x38c,
e.g. svc 0x59 = `d4000b21` at text+0x370). This makes static call-site
scans trivial: pack the instruction word, grep the text.

**nvservices (0x19) holds the full device-address-space syscall class
ITSELF** (NPDM 63 svc: 0x55-0x5C incl. MapDeviceAddressSpaceByForce) —
it calls the kernel directly, no nvkernel proxy needed. Same list in
nvkernel (0x4f). The kernel-bug surface chain is therefore entirely
user-reachable: nvdrv session (userland) -> nvservices ioctl -> svc
0x59/0x57/0x56 -> kernel SMMU mapping code.

**The MapDeviceAddressSpaceByForce call site decoded** (FUN_00116b80, the
only two callers of the svc-0x59 wrapper):
`MapDASByForce(processHandle, dasHandle, processAddress, pageAlign(size),
deviceAddress, perm | 0x10000)` with perm = 1(R) or 3(RW) from a config
byte; a flags byte on the session object selects the |0x10000 variant
(the RM path). Tolerated kernel errors: 0xd401/0xe401/0xce01/0xd001 —
anything else hits an abort path (an nvservices crash, recoverable, not
a console death). The user-controlled fields to audit: processAddress,
size, deviceAddress — the parameter-flow audit from the ioctl layer is
the next decode step.

**The NVIDIA driver module registry** (data 0x16d110, 0x48-byte
{name, init} entries): nvmap→0x111ec0, nvhwpm→0x10c9e0, nvhost→0x104060,
nvgpu→0x596e0, nvsched→0x11cc70, nverpt→0x527d0 (veneer-indirected).
Plus RM API tables nearby (exec_reg_ops — register-write batches,
alloc_pma_stream, update_get_put, query_allowlist).

**The nvmap device family**: base /dev/nvmap plus /dev/nvmap-vm1..vm7,
tsec, disp — NINE SMMU virtual-machine instances on T239. The nvmap
class init (FUN_00111ec0) builds the "tegra-smmu" window bookkeeping
(page-aligned [start,end) windows, page counts) with the device
descriptor at data 0x232c88 and sub-device table at 0x232d98.

**Dispatch reachability of the ByForce mapper**: invoked indirectly via
four function-pointer tables (0x2016bc — a method-ID region; 0x20cdcc /
0x210b1c — per-VM method tables, packed {bss-slot, fn} entries at 0x18
stride; 0x232e38 — the tegra-smmu driver ops referenced from the nvmap
init). The ioctl-command → method-slot mapping is the next decode step
(the service shim: nvdrv:t/s/v session handlers).

**gpuk:gsv/gpuk:drv are TIPC services** (RTTI: nn::gsdrv::tipc
TTipcServiceHolder KGsvRootDispatcher/KGsvSessionDispatcher) — explains
why the old cmif 0xF601 probes bounced; they need TIPC framing, a
different client shape than the nvdrv cmif family.

**Live plan (next console window, read-only)**: fs-context GSH(nvdrv:t)
via the held sm session (proven openable) + the v4 SDK-pattern sender;
Initialize + Ioctl with the decoded shapes. Nothing speculative (lesson
#8: unknown-dispatch sends wedge the fs dispatcher).

### 7.2x. THE NVDRV SHIM LAYER DECODED (offline, nvservices 0x19) — 2026-10-27

The complete address map of the nvdrv service layer, top to bottom. This
is the protocol ground truth for the live probe (fs-context HIPC2 into
nvdrv:t) and the parameter-flow audit into the kernel SMMU syscalls.

## EUREKA 1 — the fw23 svc ABI (id in the `svc #imm` immediate)

Confirmed from BOTH sides: our live-proven payload (`svc #0x22`) and
nvservices' own wrapper thunks (text+0x310..0x38c, one thunk per id;
svc 0x59 = word `d4000b21` at text+0x370). Every syscall has exactly ONE
wrapper site in a module's text → static call-site analysis is a grep of
the packed instruction word. This generalizes the whole RE method.

## EUREKA 2 — nvservices calls the kernel SMMU syscalls DIRECTLY

Both nvservices (0x19) and nvkernel (0x4f) NPDMs carry the full
device-address-space class (0x55-0x5C incl. MapDeviceAddressSpaceByForce).
No proxy: userland nvdrv ioctls → nvservices → kernel. The bug chain is
entirely user-reachable. The ByForce call site (FUN_00116b80):
`MapDASByForce(processHandle, dasHandle, processAddress, pageAlign(size),
deviceAddress, perm|0x10000)`; tolerated kernel errors 0xd401/0xe401/
0xce01/0xd001, anything else = an nvservices ABORT (a crash of the
sysmodule — a pm crash report, NOT a console death: a fuzzable target).

## EUREKA 3 — the ioctl codes are Linux _IOC-shaped and IN THE DISPATCH

The nvdrv ioctl layer compares raw 32-bit codes (`param_2 & 0xc000ffff`
masks dir+nr): per-dispatcher NR sets decoded so far —
- dispatcher A (FUN_0005baa0): nr 0x4715 + the 0x48xx family (0x4809,
  0x480b, 0x480c, 0x481a, 0x481d, 0x481f, 0x4821) — the GPFIFO submit
  family (8 ioctls)
- dispatcher B (FUN_0005d3d0): 0x4701, 0x4702, 0x4704, 0x4714, 0x471c
- dispatcher C (FUN_0005edf0): 0x440b, 0x440c, 0x4413, 0x441d
- dispatcher D (FUN_0005b3c0): 0x410b (dir=2)
fw23 numbers differ from HOS1 — these are the authoritative live-probe
codes, straight from the binary.

## The shim layer (service → device → ioctl)

- FUN_00062a40 = the main nvdrv service command handler (veneer 0x1360):
  guards on DAT_00aa3000 (initialized flag; not-init → error 0xFFFFFFED /
  -0x13 family), indexes the command-args table at rodata 0x137cb8
  (`DAT_137cb8[*args * 4]`, values 0x1c8/0x5d8/0x298/0x368/0x438/0x17e0 =
  per-command struct offsets/sizes), then reaches devices via
  FUN_00047440 — the (fd, cmd) handler lookup. The small-id list at
  rodata 0x137c88 right before it (8, 0xc, 0xd, 0x18, 0x19, 0x1f, 0x20,
  0x25) = per-device ioctl counts or the NR sub-classes.
- Method family (the veneer table at data 0x212880, 0x18-stride records
  {veneer, packed{smallfn, bss-slot}}): 0x5b3c0, 0x5baa0, 0x5d3d0,
  0x5edf0, 0x62a40 (the shim), 0x64a00, 0x65ad0, 0xa41b0 — the nvdrv
  interface methods; the ioctl dispatchers A-D above are family members.
- FUN_00047440 = the fd/ioctl handler lookup: walks the module registry
  (0x16d110, stride 0x48 = 9 qwords: {name, ..., module, sub-entries}),
  sub-entries stride 0x18; matches `(int)(entry+0x20) == fd &&
  (int)(entry+0x10) == ioctlCmd`.
- The module registry: nvmap→0x111ec0, nvhwpm→0x10c9e0, nvhost→0x104060,
  nvgpu→0x596e0, nvsched→0x11cc70, nverpt→0x527d0. The nvmap family:
  base /dev/nvmap + vm1..vm7 + tsec + disp (NINE SMMU VM instances),
  sub-device name table at 0x232d98; the tegra-smmu window bookkeeping in
  FUN_00111ec0.
- Device entries with handler arrays: data 0x22e8d0 {id=1,
  "/dev/nvhost-prof-dev-gpu", handlers {0x10cc, 0x10d4, 0x1360=the shim,
  0x1ea4, 0x1ea8}} and 0x22e948 {id=2, "/dev/nvhost-prof-ctx-gpu", ...}.

## EUREKA 4 — nvdrv sessions are PID-PINNED to the initializer

Every method (0x5b3c0, 0x5baa0, 0x5d3d0, 0x5edf0, 0x62a40, 0x65ad0) opens
with the same guard: `*(char*)(state+0x69) == 1 && *(uint*)(TLS+0x110) ==
(*(uint*)(state+0x80) & 0xbfffffff)` — the CURRENT pid (TLS+0x110, masked)
must equal the pid that ran Initialize (stored at state+0x80); mismatch →
FUN_00012b90/0x12c30 teardown-reinit. The state object = DAT_00a8fa00.
CONSEQUENCE FOR THE LIVE ROUTE: the fs-context HIPC2 client must do BOTH
Initialize and every Ioctl from the SAME process — which the wave does
naturally (all calls run as fs). This kills any idea of mixing callers
and explains why a half-initialized session wedges.

## The uninitialized-error codes seen in the shim
0xFFFFFFED (session-pool exhausted?) and 0xFFFFFFEA/-0x13/0x16-class —
to be pinned exactly when we see them live.

## Remaining decode (next offline pass)
1. The cmif command IDs of nvdrv:t (the wire protocol above the shim):
   the dispatcher mapping cmif cmd → the method family. The generated
   cmif dispatch table was NOT found as {id,pad,fn} runs — it is either
   a code switch or a different layout; find via callers of the family
   veneers (0x1350-0x136c) through data-pointer tables (three tables
   reference 0x1360: 0x2128b0, 0x22e900, 0x22e978 — the latter two are
   per-device, the first is the interface vtable).
2. The per-ioctl handler semantics (which 0x48xx/0x47xx/0x44xx codes
   reach FUN_00116b80 → MapDeviceAddressSpaceByForce): the parameter
   flow from the ioctl arg struct {processAddress, size, deviceAddress}
   to the kernel call — THE validation audit for the kernel-bug hunt.
3. nvkernel (0x4f) gpuk TIPC interfaces (KGsvRootDispatcher/
   KGsvSessionDispatcher) — the second kernel surface.

### 7.2y. The cmif CommandMeta array found + the live-probe simplification — 2026-10-27

**The 0x18-stride metadata array** (data ~0x20D000-0x212A00+, ~900+
records): each record = {handler veneer (code addr), {next veneer,
args-slot}, {out-slot, 0}} — the per-command marshaling metadata for
essentially every cmif interface in nvservices. The nvdrv method family
lives at records ~617-621 (veneers 0x1350-0x1370 → the decoded shim
methods 0x5b3c0..0x65ad0), with arg slots at bss 0x182608+. The exact
cmif-command-ID ↔ record mapping is the one remaining unknown; the
interface base record is registration-order dependent.

**The simplification (important for the live window)**: the cmif ID
mapping does NOT need full static decode. The earlier round's
"both reject cmif 0xF601" observation = the generated dispatcher's
CLEAN unknown-command rejection — meaning a command-ID sweep against
nvdrv:t is SAFE (each unknown ID answers 0xF601, no wedge; lesson #8
concerned unknown-DISPATCH services, and nvdrv's dispatch is now fully
decoded). The live plan: sweep cmif IDs 0..8 with the proper cmif shape,
read the SFCO/0xF601 pattern to map the command space empirically, then
identify Initialize by its descriptor requirements (a missing
TransferMemory descriptor also rejects cleanly). This converts the
wire-protocol decode into a bounded live experiment.

The pid-pinning (7.2x EUREKA 4) still applies: whatever process opens
the nvdrv:t session must run BOTH Initialize and the ioctls — the wave
(fs) does both naturally.

### 7.2z. The SMMU dispatch chain + the HOS1 ioctl correspondence — 2026-10-27

**The ByForce mapper is reached ONLY through driver-object dispatch** (no
direct code callers): the tegra-smmu driver-ops struct at data 0x232e38
{0x984→FUN_00116b80 (MapDeviceAddressSpaceByForce), 0x998→0x100e10,
0xdcc, 0x164c} is assigned to the SMMU window objects in the nvmap init
(text 0x111f8c: `state->drvops = &0x232e38`), and the per-VM method
tables (0x20cdcc / 0x210b1c, {bss-slot, cmd/veneer-id} records at 0x18
stride) are runtime-built into the VM objects. The mapper's callers =
ioctl handlers that construct the {.., deviceAddress, .., perm} struct —
the audit continues from the dispatcher decode below.

**The 0x48xx family = the HOS1 nvhost-gpu GPFIFO interface** — 0x4809
matches NVHOST_IOCTL_CHANNEL_SUBMIT_GPFIFO (the Linux-tegra nr/magic
layout), so fw23 KEEPS the nvidia ioctl numbering for the channel class:
dispatcher A (FUN_0005baa0: 0x4809/0x480b/0x480c/0x481a/0x481d/0x481f/
0x4821 + 0x4715) = the gpu-channel submit family; dispatcher B
(0x4701/0x4702/0x4704/0x4714/0x471c) and C (0x440b/0x440c/0x4413/0x441d)
= the other nvhost classes; dispatcher D (0x410b) = likely nvmap.
The GPFIFO submit path (0x4809) is the classic kernel-adjacent surface:
the command-buffer processing drives SMMU mappings.

**Veneer vs number tables (methodology note)**: consecutive values in
the metadata regions must be veneer-checked before treating them as
function pointers (0x981/0x982/0x983 decode as udf = number-table
entries; 0x980/0x984/0x988/0x98c/0x990 are real veneers). The ~900-record
0x18-stride array mixes both.

**Remaining audit targets (in order)**:
1. dispatcher D (FUN_0005b3c0, nr 0x410b — nvmap?) + the nvmap pin/map
   ioctl handlers: the user fields → the mapper struct {deviceAddress,
   perm} — THE validation audit.
2. dispatcher A's 0x4809 (SubmitGpfifo) handler: the command-buffer
   validation chain (the deepest kernel-adjacent attack surface).
3. The cmif ID sweep (live, safe per 7.2y) to pin the wire layer.

### 7.2aa. fw23's NEW syscall class + the nvmap Alloc audit — 2026-10-27

## EUREKA — fw23 has NEW syscalls that DO NOT EXIST on HOS1 (id > 0x7F)

Both GPU modules call a syscall class above 0x7F — territory HOS1 never
had: **0x80, 0x81, 0x82, 0x84, 0x85, 0x90, 0x91** (nvservices: 0x80/
0x84/0x85/0x90/0x91; nvkernel: 0x80/0x81/0x82/0x90/0x91 + 0x51/0x52/
0x55). One wrapper thunk per id in each module (the grep method).
Shapes so far:
- svc 0x81 (nvkernel 0x320): a QUERY returning a 24-byte struct via an
  out-pointer ({base?, size?, attrs?}) — Query-class, NO static callers
  (dead cap in nvkernel).
- svc 0x82: (handle, start, count) — a RANGE operation over enumerated
  items; the MOST-USED new syscall (15+ nvkernel sites, incl. a loop that
  enumerates [uVar7, uVar9] then applies the range op per element).
- svc 0x90: 2-arg, GPU-class; wrapped at nvkernel 0x146d00 with kernel
  errors translated to NVIDIA RM codes (0xce01→0x1203, 0xd401→0x3ec03,
  0xd001→0x1003) — any OTHER kernel error hits a FATAL abort (the
  nvservices-crash-not-console-death class again: fuzzable).
- svc 0x91: (x0, x2) — called once, adjacent to the 0x90 wrapper; on
  nonzero result → fatal abort.
A brand-new kernel interface in its first firmware generation = the
prime hunting ground for under-tested validation. Decoding the
semantics (especially 0x82's range op and the 0x90/0x91 pair) is now a
top-priority RE track.

## nvkernel NEVER maps: all SMMU mapping flows through nvservices

nvkernel's text never calls Create/Attach/Map/UnmapDeviceAddressSpace —
only QueryMemoryMapping (0x55), which (like 0x81) has no static callers
at all. The gpuk TIPC surface therefore reaches the kernel via the NEW
syscalls, not the DAS class. The DAS audit stays focused on nvservices.

## The nvmap ioctl dispatcher D fully decoded (FUN_0005b3c0)

nr 0x41-base = nvmap. Four branches:
- 0x40004101: id-lookup (FUN_000598c0(fd, id) → entry, refcount+0x38,
  +0x240 state check) — the GetId/FromId class.
- 0xc0004108: Create (FUN_0005b8c0, 16-byte user args).
- 0x40284109: Alloc — the 40-BYTE user struct; requires the fd's nvmap
  object allocated; dispatches to FUN_00070120 with 7 user words.
- 0x8000410b: a 12-byte-out query (guarded by DAT_0097d228 /
  *DAT_00974218 — error -22 otherwise).

## The Alloc validation chain (FUN_00070120 → 71470 → 706d0) — SOUND so far

- param_4 (alignment): must be power-of-two; gated by a per-VM
  capability mask from the global tables ((mask & align) == 0 → -22).
- param_5/param_6: a 2MiB-ALIGNED WINDOW pair (both & 0x1fffff == 0,
  param_5 < param_6); param_7: a third 2MiB-aligned point that must be
  STRICTLY INSIDE (param_5 < param_7 < param_6) in the aligned case,
  or zero (with a VM-cap bit 15 check) otherwise.
- FUN_000706d0 adds CARRY-based overflow checks on window sums before
  allocating (window base+size+extent vs a bound).
- Error domain: -22 invalid arg (0xFFFFFFEA), -12 OOM (0xFFFFFFF4),
  0xFFFFFFED not-initialized.
No validation gap found yet in this chain; the audit continues at
FUN_0006c320 (the region allocator, page 0x1000, perms 0x3f) and the
actual SMMU-map call on the Pin path.

## Session state note
switch2-7qEq1b came up SESSION READY (first try post-revert — the
acquisition regression fix confirmed live) and the other agent's mkw
dump is running on it. This work is pure offline RE; no switch contact.

### 7.2ab. The new syscalls are ON the nvdrv-reachable path — 2026-10-27

Follow-up to 7.2aa, nvservices side:
- **svc 0x85 = the workhorse** (17 call sites: the per-op helper clusters
  at 0x26xxx/0x29xxx/0x2exxx/0x2fxxx).
- The 0x84/0x85/0x90/0x91 hub at FUN_00045340 = an IDENTICAL
  RM-error-translation wrapper to nvkernel's (0xce01→0x1203,
  0xd401→0x3ec03, 0xd001→0x1003, other → FATAL abort) — the shared
  GPU-kernel interface convention across both modules.
- **FUN_00059b20 = the shared session-buffer allocator**: page-aligns
  (param_2+0xfff & ~0xfff), allocates via the session allocator
  (FUN_00118a60), splits on a class enum (param_1 < 4 vs >= 4 → two
  different allocators, FUN_000fcee0 vs FUN_000fd4f0), then calls
  **svc 0x80(allocated, pageSize, 0x20, 0)** — fatal abort on
  unexpected kernel errors.
- **0x642f4 — the call site of FUN_00059b20 — is INSIDE the nvdrv shim
  (FUN_00062a40) itself**: the nvdrv Initialize-class command reaches
  svc 0x80 on its FIRST leg. The nvmap layer calls the same helper
  (0x70ea0/0x71c38 = the Alloc neighborhood).

**Consequence**: the fw23-new kernel interface (0x80 at minimum) is
directly exercisable through the nvdrv:t session the fs-context route
can open — no guessing required about reachability. The full chain for
the live window: nvdrv:t cmif → the shim (pid-pinned, initialize from
fs only) → FUN_00059b20 → svc 0x80(handle, size, 0x20, 0) with the
fatal-abort safety property (a bad parameter = an nvservices crash
report, not a console death).

Semantic IDs still open: 0x80 (map/share-class on an allocated page,
attr 0x20), 0x82 (handle,start,count range op), 0x84/0x85 (the per-op
workhorses), 0x90/0x91 (the RM power/class pair). The kernel side
needs package2 (blocked) — the userspace-context RE continues.

### 7.2ac. Offline queue completed + full review pass — 2026-10-27

## svc 0x85 semantic ID: the UNMAP (64KB granularity)
The workhorse's call pattern (FUN_00026340, 3 identical sites):
`svc 0x85(handle, addr & ~0xffff, 0x10000)` after refcount teardown,
then `remaining -= 0x10000` — a per-64KB-block unmap on a process
handle. 0x84 = presumably the map counterpart (single caller = the hub).
The new class is a REVAMPED memory-mapping interface: 0x80 map/share
(attr 0x20), 0x81 query (dead in nvkernel), 0x82 (handle, start, count)
range op, 0x84 map?, 0x85 unmap (64KB), 0x90/0x91 the RM pair. All
wrapped in the fatal-abort error convention (crash, not console death).

## The region allocator (FUN_0006c320) — sound
Power-of-two alignment required; base and size both checked against
`(align-1)`; the sub-alignment carve case handled; the CARRY overflow
checks live in the caller (706d0). No gap found.

## The SubmitGpfifo branch structure (0x4809, dispatcher A)
Channel-object lookup (FUN_0008c960, pid-guarded) → mode check →
entry-count bound (`count * 0x400` vs the channel buffer limit,
violation = fatal) → FUN_00070500 (submit prep) → FUN_00088120
(command-buffer build) → 0x8a7a0/0x88600/0x5cf60 chain. The deep
command-buffer validation audit = the documented next pass.

## dispatcher D = nvmap CONFIRMED (was "likely")
The 0x4101/0x4108/0x4109/0x410b branch semantics (id-lookup, create,
alloc-with-40B-struct, query) + the movz verification (0x4109 built at
text 0x5b450/0x5b4f4, unique module-wide) settle it.

## gpuk TIPC (nvkernel): the xref yields only the registration main
(FUN_0000c160) — the KGsv dispatchers are class objects reached via
the tipc framework; decoding them = a separate pass, queued behind
the nvdrv route (which is confirmed reachable).

## REVIEW PASS — all session claims re-verified against raw artifacts
- svc ABI (id-in-immediate): 1 site per id re-confirmed (0x59, 0x22) ✓
- nvkernel never calls DAS map ops (0x56-0x5C = zero sites; only 0x55) ✓
- The ByForce call sites inside FUN_00116b80's bounds ✓
- The ioctl constants: movz-built, unique, inside the right dispatchers ✓
- The pid-pinning guard: present in all 6 sampled method entries ✓
Corrections issued: none needed — the 7.2w-7.2ab series stands as
written. Open items carried: cmif wire IDs (live sweep), svc 0x80/0x82/
0x90/0x91 kernel-side semantics (package2-blocked), the submit-chain
deep audit, gpuk TIPC decode.

### 7.2ad. THE SCP CIPHERTEXT IS BANKED — external intel evaluation — 2026-10-27

## EUREKA — the fw23 tsec sysmodule (0x040000000000008d) carries the
## encrypted SCP/FalconOS image, and we already hold it

The 0x8d module ("tsec.autogen" — we almost dismissed it as a stub: it
registers tsec:m + thread names, zero crypto strings, no AES tables)
embeds in .data (data_addr 0x2d000):
- A proper image header at data+0x3fe4 (vaddr 0x30fe4):
  {magic "TSEC" (u32 0x43455354), base 0x2d000, 0, 0x10000, 0}
- Followed by ~176KiB (data+0x4000..0x30000) of contiguous 7.99-entropy
  encrypted material = the SCP/RISC-V FalconOS µcode image (the direct
  analog of HOS1's tsec Falcon µcode blob). 260 zero bytes at 0x4000
  (alignment padding), first random byte 0x4104.
We hold it offline in the banked module dump — the package2-track
ciphertext, no switch contact needed to touch it.

## The verified fw23 SCP architecture (all from our banked binaries)

- vi2 (0x63, the display server) = THE host1x caller of the cluster:
  owns /dev/nvhost-tsec + /dev/nvhost-tsecb channels, holds a
  nn::tsec::detail::IHdcpSession CmifProxy → the tsec:m manager RPC
  (HDCP sessions), plus nn.tsec worker threads and falcon assert
  strings. Display-side HDCP runs THROUGH the SCP.
- am (0x23) also carries nv::rm::host1x::INvDrvProxy + a CmifProxy to
  INvDrvServices (nvdrv:t client).
- nvservices (0x19) = the nvhost/nvmap driver host (host1x string at
  rodata 0x12e163, referenced from the nvhost init region 0x104060+).
- tsec (0x8d) registers tsec:m and carries the encrypted image.
- HOS1 precedent: the tsec Falcon µcode was encrypted with a GLOBAL key
  (build-time), signature-checked, and derived per-console keys INSIDE
  the µcode from fuses — a global hardcoded key is the expected class.

## External intel (user-relayed, from leaked fw23 source, NOT yet
## verified by us): "whichever service calls host1x is able to get and
## use the actual riscv security co-processor key raw — the actual
## FalconOS decryption key, not the sigenc variant; possibly a stub."

## Evaluation: YES — potentially the single highest-leverage find of
## the project

IF the key is real: key + our banked 176KiB blob = offline SCP firmware
decryption → full T239 security co-processor RE → the fw23
package2/boot-derivation territory (the long-blocked kernel track).
The "stub or fuckup" question is mechanically answerable: decrypt the
blob with the claimed key and check for valid FalconOS µcode structure.
If garbage → stub/test value; if valid → they fucked up for real.

## Live path (fallback only, per the same intel): flip the --x flag to
## rw on the host1x job path and read the SCP memory as host1x runs a
## job — only needed if the key turns out per-device/derived. If it is
## hardcoded in module memory (vi2/am/nvservices .data), the fs-context
## read routes (copy-region) reach it with no host1x DMA job at all.

## NEXT (blocked on the key): obtain the claimed key value (or its
## leak source location) → offline decrypt test against the banked
## blob. Independent of any console window; zero brick risk.

### 7.2ae. The decrypt harness is READY — what we need from the leak — 2026-10-27

Follow-up to 7.2ad. The external correspondent (relayed) has seen the
exact siggen code that PRODUCES the SCP blob — so the key value (or its
derivation) is IN the leaked source; it is knowable, not just guessed.
A second correspondent's reaction ("those keys are ever used outside of boot,
raw, especially with nvidia's secure enclave on board") = the same
architecture claim: the key is exposed on a runtime path.

TWO ROUTES to the key:
(a) OFFLINE (preferred): get from the correspondent the siggen specifics:
    - the key constant itself (hex), or the source file/function so we
      can cross-locate the same constant in our banked module binaries;
    - cipher + mode + IV/nonce (AES-CTR? CBC? key stream? nonce source);
    - whether the value is the GLOBAL build-time key (HOS1 precedent) or
      per-console derived (changes everything).
(b) LIVE fallback (needs a window): the host1x job path — vi2 owns
    /dev/nvhost-tsec; run a job and read SCP memory as host1x does. Only
    needed if the key is per-console. NOTE: if the key is hardcoded in
    module memory (any driver-service .data), our fs-context read routes
    (copy-region) reach it with no host1x job at all.

READY NOW (committed): tools/scp/scp-decrypt-test.cjs — AES-128/192/256
× CTR/CBC/ECB × IV variants against the banked 176KiB blob
(fw23/040000000000008d-tsec.autogen/data.bin+0x4000), scoring entropy +
RISC-V opcode plausibility + ASCII strings. Sanity-checked with a dummy
key (correctly "still random"). ONE COMMAND once the real key arrives:
    node tools/scp/scp-decrypt-test.cjs <hexkey>
If it decrypts to valid FalconOS/RISC-V µcode → the T239 SCP firmware is
ours offline → the entire package2/boot-derivation track unblocks.

Structural notes from the banked blob (for the siggen cross-check):
- TSEC header at data+0x3fe4: u32 fields {magic "TSEC", 0x2d000,
  0, 0x10000, 0} — 0x2d000 = the module data base (self-descriptor?),
  0x10000 = 64KiB (segment/size field; the encrypted region is larger:
  0x4000..0x30000 file offset, contiguous 7.99 entropy, first random
  byte at +0x4104).
- tsec module text has ZERO adrp+add references into the blob range —
  the transport is not a direct code reference (service-side channel,
  via vi2's nvhost-tsec class or the tsec:m session objects).

### 7.2af. THE HOST1X SYSMODULE (0x0400000000000065) — the leak's target module — 2026-10-27

## EUREKA — fw23 has a DEDICATED host1x sysmodule (new architecture)

The 87-module bank contains `0400000000000065-host1x` — a dedicated
host1x sysmodule (HOS1 had none). It:
- carries the FULL DAS syscall class in its NPDM (63 svc, incl.
  CreateDeviceAddressSpace 0x56 / Attach 0x57 / MapAligned 0x5a /
  QueryMemoryMapping 0x55) — and its text CALLS 0x55/56/57/5a
  (one wrapper each; 0x58/0x59/0x5c uncalled);
- embeds ENGINE FIRMWARE + descriptor blobs (strings:
  "nvhost_vic050.fw", "nvhost_nvenc081.fw",
  "nvhost_vic050.desc", "nvhost_nvdec0%d%d_desc_prod.bin")
  as three high-entropy islands in .data: 0x18200-0x22800 (~42KiB),
  0x24000-0x30e00 (~52KiB), 0x31000-0x60000 (~192KiB) — no
  compression magic (zstd/lz4/lzma) at any island start = encrypted
  or headered-encrypted content, host-side;
- is the "service that calls host1x" target: both vi2 (0x63) and am
  (0x23) instantiate `nv::rm::host1x::INvDrvProxyE` (RTTI at vi2
  data 0x422bf8, am data 0x2357e0) — the host1x client proxy class.

Per the leak (relayed): whichever service calls host1x can GET AND USE
the RISC-V SCP key RAW (the actual FalconOS decryption key, not the
sigenc variant) — "hardware register key for decrypting high/heavy
secure falcon tsec shit", the fw23 analog of HOS1's package1/tsec-fw
key class (the one Atmosphere decrypted via a Falcon keygen exploit
and used to encrypt custom tsec payloads).

## Static key hunt — NEGATIVE so far (all driver-stack modules)
- AES key-schedule scan (128/192/256, all offsets, 8 modules incl.
  nvservices/nvkernel/am/vi2/host1x/tsec): ZERO real schedules found
  (one degenerate 0xff-pattern false positive in am).
- Exhaustive static-key decrypt sweep (every 4-aligned 16/32B window ×
  ECB/CBC/CTR vs entropy-scored plaintext): ZERO hits in host1x
  (200K ops, islands excluded as key sources) — the earlier driver-
  stack run produced only statistical noise (fixed scoring; completed
  for tsec/am/host1x; vi2/nvservices/nvkernel re-run queued).
CONCLUSION SO FAR: no static AES key constant in the banked driver-stack
binaries — CONSISTENT with the hardware-register-key model (the key
lives in SCP/SE registers, written at µcode load time (per a third
correspondent's "loaded on device boot" read) — and would then be ABSENT from all static
binaries) and with the "get and use raw" path being a RUNTIME exposure.

## THE LIVE PLAN (the runtime hunt) — the key will be in MEMORY
Model (per the leak + our decode): HDCP/auth flows run THROUGH the SCP
("these are the libraries that protect hdcp"); vi2 owns the nvhost-tsec
channels; when a session runs, key material passes through host-visible
memory. Trigger: CONNECT HDMI (the dock) → HDCP authentication → dump.
Cross-process read options (our fs-context primitives don't reach vi2):
(a) the EXECUTOR attach class (svc 0x60 + debug-read 0x6a — proven,
    currently WEDGED; the v10-binary A/B is the fix candidate);
(b) the DAS-BY-FORCE route: nvservices' decoded MapDeviceAddressSpace
    ByForce path maps ARBITRARY process memory into ITS OWN address
    space — if the ioctl protocol lets a client request foreign
    mappings, it is a LEGITIMATE cross-process R/W primitive (the
    ioctl → mapper audit is already queued);
(c) the host1x service API itself (vi2/am's INvDrvProxy surface) —
    decode what host1x: offers (the fw/desc load path).
NOTE: --x flag patching (proven class, "that's how fs is being dumped")
flips pages we HOLD handles for; foreign-process pages need (a)/(b).

## The offline queue (unchanged + host1x additions)
- finish the fixed static sweep over vi2/nvservices/nvkernel (cheap);
- decode host1x's fw/desc LOADER (which channel/ioctl loads the islands;
  where the descriptors go) + its service surface;
- decode the tsec blob transport (tsec:m session objects) further;
- the DAS-ByForce ioctl audit → potential cross-process primitive.
## And the fastest path of all
Ask the correspondent (he has SEEN the siggen code) for: the key
constant (or its source location), cipher/mode/IV, and whether it is
the global build-time key or per-console derived. With that, the
committed decrypt harness answers "stub or fuckup" in one command:
    node tools/scp/scp-decrypt-test.cjs <hexkey>
against the banked 176KiB tsec blob.

### 7.2ag. External intel: the community's NSO0 question + "nnCompat" — 2026-10-27

Discord (relayed): a correspondent has an NSO0 FILE-format dump of a
fw23 sysmodule ("the dump i was given was a nso0") — produced by SOMEONE
with fw23 NCA→NSO0 capability; his read: "different nca header
verification, but it doesn't go over nhr0, so it must be nnCompat".
The community at large does NOT have CodeFS file access ("do you have a
codefs FS dump??? probably not i assume").

Interpretation vs our bank:
- Our banked modules are MAPPED-MEMORY dumps (text/rodata/data bins,
  relocations applied, the executed images — the correct form for our
  static scans; we wrap them with make_elf.py, no NSO0 loader needed).
- The ".autogen" suffix family in our bank (bluetooth.autog,
  wlan/vi2/camera/tsec.autogen) + cmptldr(0x52, `ldr:cmp`) matches the
  "nnCompat" read: fw23 sysmodules split between standard nn builds and
  autogen/compat builds. The NSO0 the correspondent has is likely one
  of these.
- "different nca header verification ... doesn't go over nhr0" =
  fw23 changed the NCA header layout vs HOS1 (consistent with the
  evolved-HOS1 theme: new svc ids, new sysmodules, new NCA header).

Actionable (questions to relay): WHICH module + buildId the NSO0 is;
WHO produced it and with what tool; whether the method generalizes to
arbitrary fw23 sysmodule NCAs (if yes = a whole new dumping route:
pristine files incl. the tsec NCA, no live acquisition needed);
what exactly "nhr0" is (a fw23 NCA header magic?); and whether the
NSO0 source == the siggen source the first correspondent saw.

Impact on the SCP key hunt: unchanged. Our static scans ran on mapped
images (the executed form — a static key would be visible there); the
negative result stands. The NSO0 route would give PRISTINE files +
relocation diffs, useful for validation, not for the runtime key.
The live plan (HDMI/HDCP trigger → vi2/host1x memory scan via spl:nv /
host1x surfaces) remains the discriminating experiment.

### 7.2ah. cmptldr (0x52) = THE nnCompat LAYER + the community's NSO0 — 2026-10-27

## EUREKA (re-identification of a banked module): cmptldr IS nnCompat

Our banked `0400000000000052-cmptldr` ("client of ldr:cmp", per the old
table) is actually the **fw23 nnCompat engine** — the per-title
compatibility LOADER-PATCHER:
- `RoModule::RelocatePltRel`, `RoModule::RelocateRel`,
  `RoModule::FixRelativeRel`, "[ro] warning: unresolved symbol = '" —
  it processes REAL ELF relocations: it loads/relocates legacy
  (Switch-1) module images.
- A per-title runtime patch family: `nnCompatPatchForAecna`,
  `PatchForA87ma*`, `PatchForBn65a*`, `PatchForAeb8aInsertMutexUnlock`,
  `PatchForBjbsa`, `PatchForBaqxa`, `PatchForAmwca`, `PatchForA356a`,
  `PatchForBe7ca`, `PatchForA2l7a`, plus `nnCompatSetTexturePointer`,
  `nnCompatSignalAsyncReadComplete(2)`, `nnCompatWaitForSignal`,
  `nnCompatPatchForA87maShouldSkipClearBuffer` — per-title function
  REPLACEMENT hooks (record-window-texture/present-index bookkeeping,
  skip-clear hacks: per-game GPU compat shims), keyed by short
  hash-like ids.
CONSEQUENCE: OUR LAUNCH POINT (SmileBASIC, a Switch-1 title) IS LOADED
AND PATCHED BY THIS MODULE — cmptldr sits in our own process ancestry.
Its patch-descriptor tables are a load-time code-modification surface
into our host app; the RoModule reloc path is the loader the takeover
has coexisted with all along.

## The community's NSO0 (relayed) — NOT in our bank
He has an NSO0 FILE dump (memory-dumped, "from smilebasic which
explains that right" — a second correspondent), with a decoded payload.txt (7KB):
- a JWT: {typ: JWT, alg: PS384, iss: "Nintendo001CA1Prod0",
  sub: "001 Prod 1 - 4054E88940F46A8209B641685EB4306D",
  exp: 2052-10-01, iat: 2024-12-10, jti: 4f289ea3-…} — a
  Nintendo "CA1" (content-auth?) product token, 28-year validity,
  firmware built 2024-12-10.
- ext (64B), pqc (32B), duk_t (44 × 16B), duk_b (43 × 43B) tables.
His read: "the encryption/decryption scheme is bit different [vs
Switch 1] … they are part of the nnCompat layer", and "its nca check
doesn't make sense, so it must be nnCompat".
CROSS-CHECK DONE: NONE of the JWT/duk/ext/pqc byte patterns exist in
ANY of our 87 banked sysmodules (verbatim scan). CONCLUSION: their
NSO0 is a TITLE-side image (SmileBASIC itself or a compat component
in the title's own codefs) — sysmodules are not the home of the
Duktape/JWT data. We hold cmptldr (the ENGINE) but not the payload
it patches with.
- duk_* naming: Duktape-class JS-engine tables is the parsimonious
  read (a JS engine in the compat layer = a giant new bug surface),
  UNVERIFIED; "pqc" might be post-quantum-crypto material, UNVERIFIED.

## Open questions to relay back
- WHICH module is the NSO0 (name/buildId)? If it is SmileBASIC's own
  image we can cross-dump it live from the helper process memory and
  diff against his file.
- His "whole set of sources" — do they include the siggen/sigenc for
  the SCP blobs (the 7.2ae ask), and the nnCompat patch-table format?
- What produced "nhr0" in his read (the fw23 NCA header layout)?

## Impact on our tracks
- The JWT verification ("different nca check") is the fw23 content
  gate for COMPAT titles — relevant to any future title-launch route
  (the pm LaunchTitle track), not to the sysmodule tracks.
- cmptldr's patch engine is a NEW attack surface class (load-time
  code modification of our own host) — parked behind the SCP/executor
  tracks but noted: a corrupted patch descriptor = code injection at
  SmileBASIC load.
- The SCP key hunt is unchanged: static hunt negative; the live
  HDMI/HDCP experiment remains the discriminator.

### 7.2ai. THE SM SESSION BUDGET + the stuck-worker diagnosis (session JeBXQE) — 2026-10-27

## EUREKA (budget law): every process-client open() BURNS one sm-get on the
## borrowed pm:shell handle — the budget is ~2 per boot, then refusal, then SILENCE

The empirical timeline (all one boot, session JeBXQE):
- 13:12 — the pipeline's own client open(): sm-get('ro:dmnt') → OK (handle).
- 13:26 — the dump client's open(): sm-get → REFUSED, result 0x615 (an sm
  error in the reply frame — the borrowed pm:shell SM client's session
  budget exhausted).
- 16:18 — a THIRD open() attempt (a redundant standalone qualify — my
  mistake: the boot was already qualified; the run was not needed):
  sm-get → NO REPLY AT ALL. The worker (kind sm-get, frame call0=wait →
  call1=send(tls,0x100,handle)) parked with call0=0 done and call1's
  result slot still SENTINEL = blocked IN the send syscall — the sm
  deflection class (7.2q): silent send, never returns, handle-close
  does not cancel (lesson #8).
CONSEQUENCE: the sm GetService path via the borrowed handle has a hard
per-boot budget (~2). Tools that open a process client repeatedly (or
redundantly) degrade the boot: OK → 0x615-refusal → silence. PLAN RULE:
ONE process client per boot; reuse it; never run standalone
qualify/probe clients on a boot that already has a verified RO process.

## The worker-slot law (abandon class, confirmed again)
A released worker stuck mid-batch = the slot is dead for the boot
('A native worker is still active' guards every new prepare), but the
session is STABLE: the stuck pthread is blocked in its own send on its
own private frame area — it does not hold the fs dispatcher, the wave,
or any TLS other than its own. The wave RPC + memory socket + memory
window all remained healthy (verified live: worker-state/tryWait via
the wave answered; the memory socket routed). Everything NOT
worker-based stays available; everything worker-based (monitor/
executor deploys, hipc2 worker routes, fresh sm-get lookups) is dead
until reboot.

## What this means for the SCP/nvdrv live plan
The nvdrv:t GSH route (root-native sm-get + the worker hipc2 frames)
and the executor route both REQUIRE the worker slot + a live sm —
both burned on this boot. The SCP runtime hunt (HDMI/HDCP trigger →
vi2/host1x memory) is therefore NOT reachable this boot. A fresh boot
restores the budget; the plan then needs the discipline fixes above
(one client, no redundant probes) to not burn it again.
