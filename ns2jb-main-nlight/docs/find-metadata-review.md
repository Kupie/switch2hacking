## Verdict

`resolvePool()` is bounded as currently written, assuming reads and saves return, but it is neither complete nor fully sound:

- It can exclude the true pool and return a wrong singleton.
- It can exhaust hundreds of captures without resolving.
- Its expansion enumerates the upper side but not the lower side.
- After sufficient expansion, it reads buckets outside every hypothesis.
- Removing the expansion cap does not make the search complete.
- With only `linksFrom()` observations, strict progress cannot be guaranteed: the routine lacks a reliable same-allocation/other-allocation discriminator.

### 1. Loop invariants and failure modes

Let:

- `P = 0x4000` — page size
- `S = 0x2000000` — pool size
- `A = 0x200000` — pool alignment
- `C = bucketPeriod`, normally `0x28000`
- `contains(h,x) := h <= x && x + P <= h + S`

For a seed, the geometric candidate universe is:

```text
G = { h : h is A-aligned,
          seed + P - S <= h <= seed }
```

There are at most 16 candidates.

For links `L`, [poolBounds()](engine/switch2/retained/find-metadata.cjs:10) actually computes:

```text
inside(h) = { l in L : contains(h, l.source) }

valid(h) =
    inside(h) is nonempty
    and every l in inside(h) satisfies contains(h, l.value)
```

#### Candidate-set invariants

The loop relies on the following assumptions:

1. The true start is always in `candidates`.
2. Adding captures only removes candidates.
3. `first` and `last` adequately describe the remaining set.
4. A singleton candidate is conclusive.

Only part of this is true.

- Candidates can contain holes. `first..last` is an envelope, not a continuous set.
- If every geometric candidate already has at least one inside link, new links can only remove candidates.
- Without that precondition, the set is not monotone. A candidate excluded because `inside.length === 0` can reappear when a later capture contributes its first inside link.
- More seriously, the true candidate can be excluded immediately when the seed capture’s recognized links all belong to the neighboring allocation. This is exactly the situation mentioned by the comment at lines 18–19, but `inside.length` still rejects the no-evidence true candidate.
- A pointer-shaped false positive inside the true pool whose value is outside it eliminates the true candidate permanently. [linksFrom()](engine/switch2/retained/links.cjs:2) applies only plausibility checks; `zeroTail` is recorded but never used for validation.

Thus `first === last` can mean “only one currently supported candidate,” not “only one possible candidate.”

#### `covered()` invariant

`covered(start)` means one recorded capture wholly contains `[start,start+C)`.

This guarantees an exact bucket is not reread after a successful `C`-byte capture, but:

- Coverage assembled from multiple captures is not recognized.
- Partly overlapping reads can therefore be redundant.
- It says nothing about whether the capture can distinguish hypotheses.
- It does not track negative evidence; a captured bucket with no link changes nothing.

#### `inside()` invariant

At `expansion === 0`:

```text
bounds.last <= start
start + C <= bounds.first + S
```

This is the full-bucket portion of the intersection of the extreme hypotheses. Therefore the line 57 comment is accurate only at expansion zero.

For `expansion > 0`, the search interval is:

```text
[bounds.last - expansion*C,
 bounds.first + S + expansion*C)
```

It is no longer contained in every hypothesis. Eventually it extends beyond their union:

```text
union = [bounds.first, bounds.last + S)
```

Any bucket wholly outside that union is guaranteed not to constrain `poolBounds()`, because every link source from it is ignored by every candidate.

There is also an edge-coverage problem: only buckets wholly contained in the current interval are eligible. Since `S/C = 204.8`, a pool can intersect 206 fixed-grid buckets even though `ceil(S/C) === 205`. Boundary-straddling buckets are not covered by the initial bound.

#### Expansion versus `maxCaptures`

The initial budget is:

```text
ceil(0x2000000 / 0x28000) = 205
```

There are at most 32 expansion steps:

```text
512 / 16 = 32
```

so `maxCaptures` can reach 717.

However:

- Each expansion opens 16 bucket periods on both sides—up to 32 new buckets—but adds budget for only 16.
- The expansion-only iteration itself increments `index`, consuming one budget slot without performing a capture.
- The linear fill always restarts at `bounds.last`; it never fills the newly opened lower side.
- Lower-side target captures consume budget that was effectively sized only for the upper-side fill.
- Candidate shrinkage can widen the intersection, while candidate reappearance can move its extremes outward; the budget is not recomputed from the actual uncaptured relevant set.
- Expansion is not constrained to the proven readable mapping. `lowerWindow()` only proves that the observed target is mapped and explicitly calls the lower address a hypothesis; its own backward prefix is capped at `0x4000000`, while expansion permits `512*C = 0x5000000`.

Assuming I/O terminates, the loop itself does terminate. The strongest code-level bound is 685 additional `0x28000` reads:

```text
717 total action slots - 32 expansion-only slots = 685 reads
```

The initial `0x500000` capture is separate.

#### Ways it can terminate without the true boundary

Algorithmically distinct outcomes are:

- `"The pool capture has no native links"`: no pointer-shaped link in the initial capture.
- `"Native links do not fit..."`: no current candidate survives, initially or after later captures.
- Incorrect singleton return because the true candidate had no inside link.
- Incorrect singleton return because a false-positive link eliminated the true candidate.
- `"Pool-sized search did not resolve..."`: the index budget is consumed by ambiguous, irrelevant, target, or expansion work.
- `"The shared pool range has no further uncaptured buckets"` at expansion 512, despite uncaptured lower non-target buckets.
- A read failure after expansion leaves the mapped/readable region.
- Genuine ambiguity: all available links are compatible with multiple starts.

#### Buckets that do not or cannot disambiguate

The selection policy can choose:

- A bucket in the common intersection whose links remain wholly in that intersection. It supplies no separation.
- A bucket containing no recognized link. Absence is not used as evidence.
- A link target outside all remaining hypotheses.
- After enough expansion, a bucket wholly outside the union of all hypotheses. Such a bucket cannot affect `poolBounds()`.
- A bucket belonging to only some candidates where the captured bytes belong to a neighboring allocation. Candidates not containing the source ignore it, and no negative inference is made for the others.

Alternating target order changes priority but provides no information-gain or progress guarantee. Distinct target values can also map to the same bucket; they are deduplicated before mapping, not afterward.

---

### 2. Unbounded expansion does not enumerate every hypothesis

The claim is false.

Take:

```js
const seed = 0x140000000;
const bucketPeriod = 0x28000;
const addressBias = 0;
const links = [{
  source: 0x140000000,
  value:  0x140000000
}];
```

Assume later captures yield no additional recognized links.

Because `seed` is aligned to `A`, `C`, and `P`, all 16 starts survive:

```text
first = seed - S + A = 0x13e200000
last  = seed           = 0x140000000
```

The bucket:

```text
[0x13e200000, 0x13e228000)
```

is wholly inside the earliest hypothesis, but lies below `last`.

The only target bucket is `seed`. The linear fill starts at:

```text
ceil_grid(last) = 0x140000000
```

and every later linear fill also starts there. Increasing `expansion` eventually makes the lower bucket satisfy `inside()`, but only target selection examines addresses below `last`; this bucket is not a target. It is therefore never captured.

Meanwhile, every expansion exposes new upper buckets, so with a genuinely unbounded budget the routine proceeds rightward indefinitely, eventually outside all hypotheses.

If only the 512 cap is removed while the existing `maxCaptures += 16` remains, the result is still incomplete: a full 16-bucket upper band plus its expansion iteration costs 17 loop indices but adds only 16. The `"Pool-sized search..."` budget eventually fires.

---

### 3. Corrected search

There is an information-theoretic limitation first: raw `linksFrom()` results do not guarantee a strictly shrinking capture.

Two executions can have identical bytes and identical links—for example, only the self-link in the counterexample and zeros elsewhere—but different true starts among the 16 compatible candidates. No algorithm observing only those bytes can distinguish them.

A guaranteed strict-shrink search therefore requires a total discriminator:

```text
sameAllocation(page, seed) =
    SAME       if page is provably in the seed's allocation
    DIFFERENT  if page is provably outside that allocation
    UNKNOWN    otherwise
```

`linksFrom()` alone is not such a discriminator. In particular, absence of a pointer-shaped value cannot safely mean `DIFFERENT`.

Given a validated total discriminator, candidate starts have an ordered binary-search property. For a page `q < seed`:

```text
q is in the seed allocation  iff  trueStart <= q
```

because every candidate already contains the seed page.

#### Exact pseudocode

```text
P = 0x4000
S = 0x2000000
A = 0x200000
C = bucketPeriod

containsPage(h, x):
    return h <= x and x + P <= h + S

geometricCandidates(seed):
    lo = alignUp(seed + P - S, A)
    hi = alignDown(seed, A)
    return [lo, lo+A, ..., hi]

normalizeLinks(links):
    require safe, P-aligned source and value

    discard exact duplicate (source, value) pairs

    if the same source was observed with two different values:
        fail STALE_OR_UNSTABLE_CAPTURE

    // Same value from different sources is not a duplicate.
    return normalized links

filterByLinks(H, links):
    return [
        h in H where every link l satisfies:
            not containsPage(h, l.source)
            or containsPage(h, l.value)
    ]

resolve(seed, initialLinks):
    H = geometricCandidates(seed)
    links = normalizeLinks(initialLinks)
    H = filterByLinks(H, links)

    // Do not require any candidate to contain an observed source.
    // A no-inside-link candidate is unproven, not disproven.
    if H is empty:
        fail INCONSISTENT_LINK_EVIDENCE

    cache = initial capture plus later bucket captures

    while size(H) > 1:
        sort H ascending
        oldCount = size(H)

        // Balanced split. Both halves are nonempty.
        k = ceil(oldCount / 2) - 1
        q = H[k]

        // q is page-aligned. The bucket grid must also be page-aligned,
        // as assumed by the existing plan.
        b = bias + floor((q - bias) / C) * C
        capture = cachedCaptureCovering(q, q + P)
        if capture does not exist:
            capture = read(b, C)
            cache.add(capture)

        side = sameAllocation(capture, q, seedEvidence)

        if side == UNKNOWN:
            return AMBIGUOUS_WITHOUT_TOTAL_DISCRIMINATOR(H)

        if side == SAME:
            H = [h in H where h <= q]
        else:
            H = [h in H where h > q]

        newLinks = verifiedAllocatorLinks(capture)
        links = normalizeLinks(links plus newLinks)
        H = filterByLinks(H, links)

        if H is empty:
            fail INCONSISTENT_OR_MUTATING_EVIDENCE

        assert size(H) < oldCount

    return H[0]
```

This handles the seed capture extending into a neighboring allocation correctly:

- The seed page, not the entire capture, is the trusted allocation evidence.
- A link constrains a candidate only if its source page lies inside that candidate.
- A candidate is not rejected merely because it currently contains no observed link.
- Extra pages in a boundary-crossing bucket are not attributed wholesale to the seed allocation.

#### Duplicates and out-of-range values

- Exact duplicate links should be removed.
- Same source with different values should be treated as mutation/read inconsistency.
- Same value from different sources should be retained.
- A link whose source lies outside every candidate is neighbor evidence; quarantine it and never schedule its value as a search target.
- If the source lies inside a candidate but the value does not, that link eliminates that candidate.
- A value outside every hypothesis does not justify expanding the candidate universe. If applying verified links eliminates every candidate, fail explicitly instead of widening the search.
- Pointer-shaped but unverified values must not be allowed to eliminate the true hypothesis.

#### Safe behavior without the discriminator

Without `sameAllocation()`, the correct fallback is bounded exhaustive collection followed by an ambiguity result, not unbounded expansion.

Enumerate exactly once every fixed-grid bucket intersecting:

```text
[min(H), max(H) + S)
```

including edge-straddling buckets. The exact count is:

```text
floor((end - 1 - bias) / C)
- floor((begin - bias) / C)
+ 1
```

Afterward:

- Return if one candidate remains.
- Otherwise return `AMBIGUOUS` with the surviving candidate set.
- Never select one candidate merely because the others lacked positive links.

This fallback terminates and cannot skip the true pool, though it cannot promise that the bytes contain enough information to identify it.

---

### 4. Capture complexity

For the current constants:

```text
S = 0x2000000
A = 0x200000
C = 0x28000
```

| Strategy | Worst-case `0x28000` captures | Guarantee |
|---|---:|---|
| Current loop | At most 685 | Terminates, but incomplete and may return the wrong singleton |
| Binary search with total discriminator | At most 4 | Complete for the actual 16 aligned candidates |
| Coarse bound using only `S/C` | At most `ceil(log2(ceil(S/C)+1)) = 8` | Covers a hypothetical bucket-granularity boundary space |
| Exhaustive safe fallback | At most 398 | Covers the union of all hypotheses; may correctly report ambiguity |

The exhaustive bound is 398 because the 16 aligned candidates can span `S-A`, so their allocation union has width:

```text
S + (S - A) = 0x3e00000
```

and a fixed bucket grid may require:

```text
ceil(0x3e00000 / 0x28000) + 1 = 398
```

intersecting buckets.

The binary algorithm is therefore the appropriate correction if the rig can expose a sound same-allocation discriminator. Without that property, exhaustive bounded collection plus an explicit ambiguity result is the strongest correct algorithm.