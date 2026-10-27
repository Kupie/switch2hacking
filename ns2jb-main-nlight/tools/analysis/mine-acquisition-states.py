#!/usr/bin/env python3
"""Offline corpus miner for acquisition wave states (no console needed).

Reads every runs/<session>/switch2/memory/reserved-gap-*.json acquisition
report plus the run's run.log outcome and answers three questions:

  1. within-run determinism: do identical per-wave state fingerprints
     (the 16 preRelease allocation counters + preReleaseUsed + the
     row-result vector) ever produce different wave outcomes inside one
     acquisition attempt?
  2. cross-run transfer: do fingerprints repeat across runs/boots, and if
     so do they carry their outcome with them (a shippable known-good /
     known-bad state table) or not (per-boot oracle only)?
  3. pre-positive separability: does the last pre-positive wave's telemetry
     separate placement-pass from placement-fail attempts?

Run from the repo root: python3 tools/analysis/mine-acquisition-states.py
[--json] [--era old|new] [--runs GLOB]
"""
import argparse
import glob
import json
import os
import re
import sys
from collections import Counter, defaultdict

# Fixed IPC role order used by the wave plan (probe-reserved-gap.cjs).
ROLES = ['commit', 'hole', 'tail0', 'tail1', 'tail2', 'tail3', 'canary',
         'filler0', 'filler1', 'guard0', 'guard1', 'trigger']
VARYING_COUNTERS = [0, 3, 5, 6, 9, 10]


def run_outcome(run_dir):
    """(era, ready, terminal error text) from run.log, or None if absent."""
    log = os.path.join(run_dir, 'run.log')
    if not os.path.isfile(log):
        return None
    with open(log, errors='replace') as handle:
        text = handle.read()
    era = 'old' if '/switchhax/' in text else 'new'
    ready = 'SESSION READY' in text
    errors = re.findall(r'^Error: (.+)$', text, re.M)
    return era, ready, (errors[-1].strip() if errors else None)


def wave_outcome(case):
    """Placement-relevant outcome class of one wave case row."""
    if case.get('triggerAborted'):
        return 'aborted'
    changed = case.get('changedPaths') or []
    canary_type = case.get('canaryType')
    if changed == ['canary'] and canary_type == 0:
        return 'hit'
    if not changed:
        return 'miss-clean'
    if 'canary' in changed:
        return 'canary-other'
    return 'miss-dirty'


def has_window(case):
    """The pipeline's own qualification predicate (fixed thresholds)."""
    return bool(case.get('restored') and not case.get('triggerAborted')
                and case.get('allPending')
                and (case.get('receiveOrderMarginUs') or 0) >= 300
                and (case.get('preReleaseUsed') or 0) >= 0x2600)


def state_key(case):
    """Full state fingerprint of a wave: 16 counters + usage + row results."""
    pre = next((row for row in case.get('rows', []) if row.get('role') == 'preRelease'), None)
    if not pre or pre.get('memory') is None:
        return None
    results = {row.get('role'): row.get('result') for row in case.get('rows', [])}
    row_vector = tuple(results.get(role) for role in ROLES)
    return (tuple(pre['memory']), case.get('preReleaseUsed'), row_vector)


def profile_class(profile):
    if profile == 'positive':
        return 'positive'
    if profile == 'negative':
        return 'negative'
    if profile == 'extent-present':
        return 'extent-present'
    if profile == 'extent-prefix':
        return 'extent-prefix-diagnostic'
    if profile in ('abort-control', 'abort-hole-control', 'extent-absent'):
        return 'control'
    if profile.startswith('cache-'):
        return 'leak-stage'
    return 'other:' + str(profile)


def auc(values_pass, values_fail):
    """Mann-Whitney AUC of a feature (pass>fail direction); 0.5 = chance."""
    if not values_pass or not values_fail:
        return None
    wins = ties = 0
    for p in values_pass:
        for f in values_fail:
            if p > f:
                wins += 1
            elif p == f:
                ties += 1
    auc = (wins + 0.5 * ties) / (len(values_pass) * len(values_fail))
    return max(auc, 1 - auc)


def load_corpus(runs_glob):
    corpus = []
    for run_dir in sorted(glob.glob(runs_glob)):
        if not os.path.isdir(run_dir):
            continue
        outcome = run_outcome(run_dir)
        REPORT_RE = re.compile(r'^reserved-gap-[0-9]+\.json$')
        reports = sorted(p for p in glob.glob(os.path.join(run_dir, 'switch2', 'memory',
                                                          'reserved-gap-*.json'))
                         if REPORT_RE.match(os.path.basename(p)))
        if not outcome and not reports:
            continue
        era, ready, error = outcome if outcome else (None, None, None)
        entry = {'run': os.path.basename(run_dir.rstrip('/')), 'era': era,
                 'ready': ready, 'error': error, 'attempts': [], 'corrupt': 0}
        for report_path in reports:
            try:
                with open(report_path, errors='replace') as handle:
                    report = json.load(handle)
            except (ValueError, OSError):
                entry['corrupt'] += 1
                continue
            cases = report.get('cases') or []
            entry['attempts'].append({
                'report': os.path.basename(report_path),
                'waves': cases, 'markerSelected': report.get('markerSelected'),
                'markerReproduced': report.get('markerReproduced'),
                'budgetExhausted': report.get('positiveWaveBudget'),
                'decidedMiss': report.get('decidedMiss'),
                'error': report.get('error'),
            })
        corpus.append(entry)
    return corpus


def analyze(corpus, era_filter):
    out = {}
    runs = [r for r in corpus if not era_filter or r['era'] == era_filter]
    out['inventory'] = {
        'runs': len(runs),
        'runs_with_reports': sum(1 for r in runs if r['attempts'] or r['corrupt']),
        'ready': sum(1 for r in runs if r['ready']),
        'era': Counter(r['era'] for r in runs),
        'corrupt_reports': sum(r['corrupt'] for r in runs),
    }

    # ---- wave-level inventory over all attempts -------------------------
    waves = []  # (run, era, attempt_index, case_index, profile, outcome, window, key)
    for r in runs:
        for i, attempt in enumerate(r['attempts']):
            for j, case in enumerate(attempt['waves']):
                waves.append({'run': r['run'], 'era': r['era'], 'attempt': i,
                              'case': j, 'profile': case.get('profile'),
                              'class': profile_class(case.get('profile')),
                              'outcome': wave_outcome(case),
                              'window': has_window(case),
                              'key': state_key(case),
                              'ready': r['ready']})
    out['waves_total'] = len(waves)
    out['waves_by_class'] = Counter(w['class'] for w in waves)
    positives = [w for w in waves if w['class'] == 'positive']
    out['positive_waves'] = len(positives)
    out['positive_outcomes'] = Counter(w['outcome'] for w in positives)
    out['positive_hits_with_window'] = sum(1 for w in positives
                                           if w['outcome'] == 'hit' and w['window'])
    out['positive_clean_miss_with_window'] = sum(
        1 for w in positives if w['outcome'] == 'miss-clean' and w['window'])
    # preReleaseUsed rejection rule check on qualifying windows
    lows = [w for w in positives if w['window'] and w['key'] is not None]
    out['pre_release_used_hits'] = Counter(
        (w['key'][1] // 512) * 512 for w in lows if w['outcome'] == 'hit')
    out['pre_release_used_misses'] = Counter(
        (w['key'][1] // 512) * 512 for w in lows
        if w['outcome'] in ('miss-clean', 'miss-dirty', 'canary-other'))

    # ---- Q1: within-run determinism (identical key, one attempt) --------
    within = {'groups': 0, 'waves_in_groups': 0, 'mixed': [], 'consistent': 0}
    per_attempt = defaultdict(list)
    for w in positives:
        if w['key'] is not None:
            per_attempt[(w['run'], w['attempt'])].append(w)
    for (run, attempt), ws in per_attempt.items():
        by_key = defaultdict(list)
        for w in ws:
            by_key[w['key']].append(w)
        for key, group in by_key.items():
            if len(group) < 2:
                continue
            within['groups'] += 1
            within['waves_in_groups'] += len(group)
            outcomes = {g['outcome'] for g in group}
            if len(outcomes) > 1:
                within['mixed'].append({'run': run, 'attempt': attempt,
                                        'key': key, 'outcomes': sorted(outcomes)})
            else:
                within['consistent'] += 1
    out['q1_within_run'] = within

    # ---- Q3: cross-run repeats and outcome transfer ----------------------
    cross = {'groups_ge2runs': 0, 'waves_in_cross_groups': 0,
             'mixed': [], 'consistent': 0, 'same_era_mixed': 0,
             'hit_only': 0, 'miss_only': 0, 'majority_policy_errors': 0,
             'majority_policy_waves': 0}
    by_key = defaultdict(list)
    for w in positives:
        if w['key'] is not None:
            by_key[w['key']].append(w)
    cross_groups = {k: g for k, g in by_key.items() if len({x['run'] for x in g}) >= 2}
    cross['distinct_positive_states'] = len(by_key)
    cross['groups_ge2runs'] = len(cross_groups)
    for key, group in cross_groups.items():
        outcomes = Counter(g['outcome'] for g in group)
        eras = {g['era'] for g in group}
        if 'hit' in outcomes and len(outcomes) == 1:
            cross['hit_only'] += 1
        elif 'hit' not in outcomes:
            cross['miss_only'] += 1
        cross['waves_in_cross_groups'] += len(group)
        if len(outcomes) > 1:
            cross['mixed'].append({'key': key, 'outcomes': sorted(outcomes),
                                   'eras': sorted(eras),
                                   'runs': sorted({g['run'] for g in group})})
            if len(eras) == 1:
                cross['same_era_mixed'] += 1
        else:
            cross['consistent'] += 1
        # in-sample majority policy: predict the group's majority outcome
        majority = outcomes.most_common(1)[0][0]
        cross['majority_policy_waves'] += len(group)
        cross['majority_policy_errors'] += sum(1 for g in group
                                                if g['outcome'] != majority)
    out['q3_cross_run'] = cross

    # transfer table: does a state seen in a READY run predict elsewhere?
    transfer = {'ready_states': 0, 'ready_states_seen_in_failed_runs': 0,
                'contradictions': []}
    ready_keys, failed_keys = set(), set()
    key_runs = defaultdict(set)
    for w in positives:
        if w['key'] is None:
            continue
        key_runs[w['key']].add((w['run'], w['ready']))
        (ready_keys if w['ready'] else failed_keys).add(w['key'])
    both = ready_keys & failed_keys
    transfer['ready_states'] = len(ready_keys)
    transfer['ready_states_seen_in_failed_runs'] = len(both)
    out['q3_transfer'] = transfer

    # ---- Q2: pre-positive last-wave separability (placement cohort) ------
    cohort_pass, cohort_fail = [], []
    for r in runs:
        for attempt in r['attempts']:
            waves = attempt['waves']
            positive_idx = next((j for j, c in enumerate(waves)
                                 if profile_class(c.get('profile')) == 'positive'), None)
            if positive_idx is None:
                continue
            features = None
            for case in reversed(waves[:positive_idx]):
                pre = next((row for row in case.get('rows', [])
                            if row.get('role') == 'preRelease'), None)
                if pre and pre.get('memory') is not None:
                    features = {'memory': pre['memory'],
                                'preReleaseUsed': case.get('preReleaseUsed'),
                                'marginUs': case.get('receiveOrderMarginUs')}
                    break
            if features is None:
                continue
            (cohort_pass if attempt.get('markerSelected') else cohort_fail).append(
                {'run': r['run'], 'features': features})
    out['q2_cohort'] = {'pass': len(cohort_pass), 'fail': len(cohort_fail)}
    aucs = {}
    feature_defs = {f'memory[{i}]': (lambda i: lambda x: x['features']['memory'][i])(i)
                    for i in VARYING_COUNTERS}
    feature_defs['preReleaseUsed'] = lambda x: x['features'].get('preReleaseUsed')
    feature_defs['marginUs'] = lambda x: x['features'].get('marginUs')
    for name, feature in feature_defs.items():
        p = [feature(x) for x in cohort_pass if feature(x) is not None]
        f = [feature(x) for x in cohort_fail if feature(x) is not None]
        aucs[name] = {'auc': auc(p, f), 'n_pass': len(p), 'n_fail': len(f)}
    out['q2_auc'] = aucs

    # preReleaseUsed rejection-rule calibration on qualifying-window waves
    rule = {'buckets': [], 'threshold_sweep': []}
    hits = sorted((w['key'][1] for w in lows if w['outcome'] == 'hit'))
    misses = sorted(w['key'][1] for w in lows
                    if w['outcome'] in ('miss-clean', 'miss-dirty', 'canary-other'))
    for threshold in [0x2600, 0x2800, 0x2600 * 2, 9920, 0x4000 * 2]:
        caught = sum(1 for m in misses if m < threshold)
        lost = sum(1 for h in hits if h < threshold)
        rule['threshold_sweep'].append({
            'threshold': threshold, 'misses_total': len(misses),
            'misses_caught': caught, 'hits_total': len(hits), 'hits_lost': lost})
    rule['min_hit_pre_release_used'] = hits[0] if hits else None
    out['pru_rule'] = rule

    # first-hit wave index among placement-passing attempts
    first_hit = Counter()
    for r in runs:
        for attempt in r['attempts']:
            positives_here = [w for w in attempt['waves']
                              if profile_class(w.get('profile')) == 'positive']
            hit_positions = [i + 1 for i, w in enumerate(positives_here)
                              if wave_outcome(w) == 'hit']
            if hit_positions:
                first_hit[hit_positions[0]] += 1
    out['first_hit_wave'] = dict(first_hit)

    # same-boot attempt rescue: per run, attempt outcome sequence
    rescue = Counter()
    multi = 0
    for r in runs:
        seq = ''.join('P' if a.get('markerSelected') else 'f'
                      for a in r['attempts'])
        if not seq:
            continue
        if 'P' in seq:
            rescue['pass_at_' + str(seq.index('P') + 1) + '_of_' + str(len(seq))] += 1
        else:
            rescue['all_fail_' + str(len(seq))] += 1
        if len(seq) >= 2:
            multi += 1
    out['same_boot_rescue'] = dict(rescue)

    # ---- P0 calibration: waves burned per attempt, by outcome -----------
    burn = {'pass': Counter(), 'fail': Counter()}
    for r in runs:
        for attempt in r['attempts']:
            if not attempt['waves']:
                continue
            label = 'pass' if attempt.get('markerSelected') else 'fail'
            counts = Counter(profile_class(case.get('profile'))
                              for case in attempt['waves'])
            burn[label]['attempts'] += 1
            for k, v in counts.items():
                burn[label][k] += v
    out['p0_burn'] = burn
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runs', default='runs/switch2-*')
    parser.add_argument('--era', choices=['old', 'new'])
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args()
    corpus = load_corpus(args.runs)
    if not corpus:
        sys.exit('no runs matched ' + args.runs)
    result = analyze(corpus, args.era)
    result['args'] = {'runs': args.runs, 'era': args.era}
    if args.json:
        def default(o):
            if isinstance(o, Counter):
                return dict(o)
            if isinstance(o, set):
                return sorted(o)
            if isinstance(o, tuple):
                return list(o)
            return str(o)
        print(json.dumps(result, indent=1, default=default))
        return
    inv = result['inventory']
    print(f"corpus: {inv['runs']} runs ({dict(inv['era'])}), "
          f"{inv['ready']} READY, {inv['corrupt_reports']} corrupt reports")
    print(f"waves: {result['waves_total']} total; "
          f"{result['positive_waves']} positive "
          f"{dict(result['positive_outcomes'])}")
    print(f"positive hits with qualifying window: "
          f"{result['positive_hits_with_window']}; clean misses with "
          f"window: {result['positive_clean_miss_with_window']}")
    q1 = result['q1_within_run']
    print(f"\nQ1 within-run: {q1['groups']} repeated-state groups, "
          f"{q1['waves_in_groups']} waves, consistent {q1['consistent']}, "
          f"MIXED {len(q1['mixed'])}")
    for m in q1['mixed'][:10]:
        print('  mixed:', m['run'], m['outcomes'])
    q3 = result['q3_cross_run']
    print(f"\nQ3 cross-run: {q3['distinct_positive_states']} distinct positive "
          f"states, {q3['groups_ge2runs']} repeat across runs "
          f"({q3['waves_in_cross_groups']} waves): hit-only {q3['hit_only']}, "
          f"miss-only {q3['miss_only']}, MIXED {len(q3['mixed'])} "
          f"(same-era mixed {q3['same_era_mixed']})")
    print(f"  majority-policy in-sample errors: "
          f"{q3['majority_policy_errors']}/{q3['majority_policy_waves']} waves")
    for m in q3['mixed'][:10]:
        print('  mixed:', m['outcomes'], m['eras'], m['runs'])
    t = result['q3_transfer']
    print(f"transfer: {t['ready_states']} states in READY runs; "
          f"{t['ready_states_seen_in_failed_runs']} also seen in failing runs")
    print(f"\nQ2 cohort: pass {result['q2_cohort']['pass']} / "
          f"fail {result['q2_cohort']['fail']}")
    for name, row in result['q2_auc'].items():
        auc = row['auc']
        print(f"  {name:18s} AUC {auc:.3f}" if auc is not None else f"  {name:18s} n/a")
    rule = result['pru_rule']
    print("\npreReleaseUsed rejection rule (qualifying-window waves):")
    print(f"  min preReleaseUsed among hits: {rule['min_hit_pre_release_used']}")
    for row in rule['threshold_sweep']:
        print(f"  T={row['threshold']:7d}: catches {row['misses_caught']}/{row['misses_total']} "
              f"misses, loses {row['hits_lost']}/{row['hits_total']} hits")
    print(f"\nfirst-hit wave distribution: {result['first_hit_wave']}")
    print(f"same-boot attempt sequences: {result['same_boot_rescue']}")
    print("\nP0 burn per attempt class:")
    for label in ('pass', 'fail'):
        c = result['p0_burn'][label]
        per = {k: (v / c['attempts']) if c['attempts'] else 0
               for k, v in c.items() if k != 'attempts'}
        print(f"  {label}: {c.pop('attempts', 0)} attempts, mean waves/attempt "
              f"{ {k: round(v, 1) for k, v in per.items()} }")


if __name__ == '__main__':
    main()