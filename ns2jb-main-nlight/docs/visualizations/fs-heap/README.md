# When a pointer changes

A restrained dark-mode, single-screen HTML/SVG animation of the filesystem exploit's core mechanism: a path copy overflows into cache metadata, the corrupted pointer redirects data access, and two retained entries separate pointer control from data transfer. The camera and memory locations stay fixed.

Open `index.html` directly in a browser. The player has pause/play, scrubbing, playback speed, fullscreen, keyboard controls and reduced-motion support. Detailed qualifications are in the collapsed notes, outside the video. No external assets or network requests are used.

The 40-second export is silent and captioned, at 1920 × 1080 and 30 fps. Its default output is `runs/visualizations/fs-heap-dark-1080p.mp4`; generated artifacts remain gitignored. `captions.vtt` is the matching caption sidecar.

## Visual direction

The built-in imagegen tool produced the second design reference using the exact prompt saved in `design-reference.txt`. Its selected PNG is `runs/visualizations/minimal/design-reference.png`. This reference informed the fine outlines, restrained palette and open spacing. A further built-in imagegen reference explores allocation containment and the miss/reach comparison: `runs/visualizations/heap-region/design-reference.png`, with exact prompt in `heap-reference-prompt.txt`. Its geometric hierarchy informed the native SVG; generated textures and extra field-byte rows were not copied. The current revision adapts that composition to dark mode at the requested contrast and adds selective explanatory context. The animation is independently drawn SVG; it does not embed the generated bitmap. The generated reference's inaccurate buffer outline was corrected: the dashed boundary coincides with the actual end of the drawn buffer.

Phase rails, status badges and sidebars remain removed. A larger heap-region enclosure now contains the buffer, schematic neighboring and intervening chunks, and one owned cache array. An increasing-address arrow establishes the spatial order. A brief miss/reach comparison shows identical copy lengths against two hypothetical cache placements; allocations do not slide through live memory. Each cache entry has its own card grouping range, state and address. The address names its destination and anchors the outgoing arrow; CONTROL and DATA label entry roles instead of replacing the pointer label. The second card appears only when installed. Byte squares occupy fixed outlined slots in the path buffer, cache metadata strips, memory blocks and result tray. A moving cube front fills the path slots; trailing overflow cubes visibly cross the allocation boundary through a dedicated byte lane and land in cache slots. The intervening lane is schematic, not a count of heap chunks; decoded field text stays below the byte strip. Small dots on pointer arrows indicate transfers. Slot counts are schematic, and the strip and decoded fields are two views of the same metadata. One nearby two-line note explains the current mechanism. Captions remain short. Marker readback is explicitly animated before restoration. The upper tray represents read results or write inputs, not another heap allocation. The second descriptor occupies existing cache-array space; its appearance does not imply the allocator expands the array.

The simplified sequence assumes successful placement and compresses multiple qualified copies. It explains the canary without animating allocation waves, omits the clean-alias proof and detailed bucket encoding, and simplifies range and dirty-state setup. Cleanup verification is kept in the notes. Those are necessary parts of the implementation and remain documented below. Editing only a pointer is not presented as a complete reproduction recipe.

## Underlying implementation and deliberate omissions

The application is already able to issue filesystem IPC. A path-normalization helper in `fs` uses a temporary buffer of `0x301` bytes. Certain parent-directory/backslash paths reach a copy that can exceed that allocation. **The allocation size is not the overflow length.** The overflow and its target live in the filesystem service's heap, across the application's process boundary.

The acquisition code coordinates concurrent requests and verifies an owned path canary before attempting to reuse its slot with owned cache storage. This is a placement-sensitive sequence, not a guarantee that the next allocation follows the temporary buffer. The diagram compresses reservations, intermediate chunks, receive-buffer extent qualification, guard checks, and retries into one understandable slot lifecycle.

The fork first qualifies a **clean alias**: altered range metadata makes a different logical storage offset return a known prefix, with `dirty = 0` and the genuine buffer handle preserved. This distinguishes a cache-mapping effect from ordinary file contents. It does not by itself establish arbitrary memory access.

The later bootstrap installs a synthetic cache header. It uses constrained signed-offset encoding, a large range and a synthetic buffer address; the flags enable the dirty-entry path. A dirty cache entry represents modified in-memory data pending write-back. In the corrupted entry, storage operations instead follow the selected process-memory mapping. The address relation behind the animation is: buffer address plus the difference between requested offset and entry offset. Actual requests must also satisfy cache-bucket selection, storage bounds and encoding constraints. The normal baseline read is illustrative context, not a replay of an acquisition trace. Small colored tiles represent groups of bytes; the large blocks represent allocations. Metadata fields are enlarged and stacked for visibility. The current version shows a schematic allocation neighborhood and a hypothetical placement comparison, but no allocation/free waves or concrete canary placement. The diagram compresses several qualified copies into a single traveling wave; its lower row depicts other locations in the same address space, not contiguous physical addresses.

Promotion creates **two entries in one owned cache array**, not two independent filesystem services. The control entry exposes metadata; the data entry exposes the selected memory region. The control channel changes and reads back the data pointer. Retargeting after promotion does not repeat pathname corruption. Installation also sets the owner's bucket count to zero: the code verifies that the fixed nonnegative lookup indices still work while flush/finalize loops skip synthetic buffers. This is why a simple drawing of a forever-dirty redirected pointer is an incomplete account of the retained implementation.

The code proves reads with output-poison controls and content comparisons, proves writes through another view, and restores scratch bytes exactly. These are checks performed by the implementation; producing this animation did not run a new console experiment. Source inspection establishes the implemented sequence, not a fresh measurement of its success rate.

The animation stops at retained memory access and restoration. Later client-identity changes and loader filesystem substitution are separate steps and are not animated here. This visualization does not equate process read/write with kernel execution.

## Source map

Paths below are relative to the repository root. Function names are provided because line numbers can change.

| Mechanism | Evidence in this fork |
| --- | --- |
| Application boundary | `docs/ARCHITECTURE.md`, section 2; `bootstrap.bas` |
| Temporary buffer; omitted placement details | `docs/research/sync-victim-survey.md`, initial placement discussion; `engine/switch2/memory/probe-reserved-gap.cjs`, request roles, extent controls and canary qualification |
| Clean alias (not animated) | `probe-reserved-gap.cjs`, `installCombinedLeak`, `restoreAlias`, `readStorage`, `selectedAlias` checks |
| Synthetic memory window | `engine/switch2/memory/signed-cache-plan.cjs`, `plan`; `probe-reserved-gap.cjs`, `address.readVerified` and write-marker verification |
| Two retained channels | `engine/switch2/retained/retained-memory.cjs`, `install`, `controlWrite`, `setPointer`, `logicalRead`, `logicalWrite` |
| Cleanup-loop treatment (not animated) | `retained-memory.cjs`, `zeroCountVerified` and the count-zero lookup/release check |
| Read/write proof | `retained-memory.cjs`, scratch-marker checks and exact restoration; `probe-reserved-gap.cjs`, two poison values and ordinary-content comparison |

The root-cause account was also cross-checked against the upstream public explanation. The local architecture note's wording “0x301-byte overflow” is imprecise; this animation consistently calls it a **0x301-byte temporary buffer**. This animation does not reconstruct firmware machine code. All heap sizes on screen except explicitly labeled byte counts are schematic, and the ordering diagram is not a trace from a particular boot.

## Reproduce the video

Requires Node.js, `ffmpeg`, Chrome, and `playwright-core`. Dependencies and outputs can remain in ignored storage:

```sh
npm install --prefix runs/visualizations/tooling playwright-core --no-audit --no-fund
NODE_PATH="$PWD/runs/visualizations/tooling/node_modules" node docs/visualizations/fs-heap/record.cjs
```

Set `CHROME_BIN` if Chrome is not available as `google-chrome-stable`. The default output is `runs/visualizations/fs-heap-dark-1080p.mp4`. An optional first argument changes the MP4 output path. Add `--preview` after that path to produce just the nine timeline-beat previews and check text bounds:

```sh
NODE_PATH="$PWD/runs/visualizations/tooling/node_modules" node docs/visualizations/fs-heap/record.cjs runs/visualizations/fs-heap-dark-1080p.mp4 --preview
```

The renderer samples `window.renderAt(seconds)` deterministically and pipes the frames into H.264 encoding, with YUV 4:2:0 and fast-start metadata. It does not depend on wall-clock playback speed. Four independent browser pages capture contiguous frame ranges concurrently; the resulting video segments are concatenated without another encode. NVENC is selected only after an actual hardware-encoding probe succeeds. Otherwise, the renderer uses CPU H.264 with the `veryfast` preset. This accelerates encoding without assuming GPU acceleration eliminates browser-capture costs.

Useful options:

- `--width 1920` (default) or `--width 1280`.
- `--fps 30` (default), `24`, or `60`.
- `--workers 4` (default); accepts 1–8. More workers are not always faster.
- `--encoder auto` (default), `nvenc`, or `cpu`.
- `--seconds 6` renders a short benchmark to the supplied output path.

The HTML remains editable independently of the MP4. Timing, encoder choice and output dimensions are printed at completion.


## Teaching and research-communication choices

The design uses concise wording, a fixed spatial frame and learner control, informed by [educational-video guidance](https://www.vanderbilt.edu/brightspace/2016/04/04/considerations-for-effectively-creating-educational-videos/) and [pause/stop guidance](https://www.w3.org/WAI/WCAG22/Understanding/pause-stop-hide.html). This specific animation has not been evaluated for learning outcomes.

The same source and destination remain visible while the pointer changes. Byte groups visibly travel before the destination changes. A temporary dashed arrow preserves the old destination during redirection. Text names the blocks and explains the current action; it does not duplicate the full research notes. The result is explicitly scoped to fs process memory access, with later privilege and execution steps outside the animation.
