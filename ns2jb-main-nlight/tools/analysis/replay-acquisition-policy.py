#!/usr/bin/env python3
"""Replay a proposed acquire.cjs retry policy against the run corpus.

Answers, per run, whether the proposed placement-fail fail-fast gate would
change the run's terminal outcome (acquisition success vs failure) or only
skip provably-futile attempts. Also counts the extent-prefix diagnostic
waves the proposed probe change would no longer run.

Policy simulated (the proposed change):
  - attempt acceptance = report.memoryControl.ready && report.session ok &&
    !report.error && !report.cleanupError (mirrors acquire.cjs)
  - OLD policy: up to 3 attempts per launch (MAX_ATTEMPTS=3), stop at first
    accepted attempt.
  - NEW policy: identical, except an attempt whose report shows >= 1
    positive wave and no markerSelected (the corpus's 0/41-rescue
    placement-fail class) stops the launch with a reboot-required error —
    no further attempts are spawned.

Run from the repo root:
  python3 tools/analysis/replay-acquisition-policy.py [--json]
"""
import argparse
import glob
import json
import os
import re
import sys
from collections import Counter

REPORT_RE = re.compile(r'^reserved-gap-([0-9]+)\.json$')

MAX_ATTEMPTS = 3


def era_of(run):
    try:
        with open(f'runs/{run}/run.log', errors='replace') as handle:
            return 'old' if '/switchhax/' in handle.read() else 'new'
    except FileNotFoundError:
        return None


def attempt_state(report):
    """(accepted, placement_fail) for one probe attempt report."""
    cases = report.get('cases') or []
    has_positive = any(c.get('profile') == 'positive' for c in cases)
    marker_selected = bool(report.get('markerSelected'))
    accepted = bool(report.get('memoryControl', {}).get('ready')) and \
        not report.get('error') and not report.get('cleanupError')
    placement_fail = has_positive and not marker_selected and not accepted
    return accepted, placement_fail


def classify(report):
    accepted, placement_fail = attempt_state(report)
    cases = report.get('cases') or []
    if accepted:
        return 'SUCCESS'
    if placement_fail:
        return 'PLACEFAIL'
    if not cases:
        return 'EMPTY'
    if any(c.get('profile') == 'extent-prefix' for c in cases):
        return 'EXTFAIL'
    return 'SETUPFAIL'


def replay(attempts):
    """(old_outcome, new_outcome, attempts_old, attempts_new) for one run."""
    def run_policy(fail_fast):
        used = 0
        for report in attempts:
            used += 1
            accepted, placement_fail = attempt_state(report)
            if accepted:
                return 'success', used
            if fail_fast and placement_fail:
                return 'reboot-required', used
        return 'fail', used
    old = run_policy(False)
    new = run_policy(True)
    return old, new


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args()

    runs = {}
    diag_waves = 0
    diag_attempts = 0
    for path in sorted(glob.glob('runs/switch2-*/switch2/memory/reserved-gap-*.json')):
        if not REPORT_RE.match(os.path.basename(path)):
            continue
        run = path.split('/')[1]
        try:
            with open(path, errors='replace') as handle:
                report = json.load(handle)
        except (ValueError, OSError):
            continue
        runs.setdefault(run, []).append((int(REPORT_RE.match(os.path.basename(path)).group(1)), report))
        if not report.get('markerSelected'):
            cases = report.get('cases') or []
            if any(c.get('profile') == 'extent-prefix' for c in cases):
                pass  # diagnostics never ran on placed reports
        # count extent-prefix trial waves anywhere they ran
        diag_waves += sum(1 for c in (report.get('cases') or [])
                          if c.get('profile') == 'extent-prefix')
        diag_attempts += 1 if any(c.get('profile') == 'extent-prefix'
                                  for c in (report.get('cases') or [])) else 0

    changed = Counter()
    saved_attempts = 0
    runs_changed = []
    outcomes = Counter()
    for run, entries in runs.items():
        entries.sort()
        attempts = [report for _, report in entries]
        (old_out, _), (new_out, used_new) = replay(attempts)
        used_old = len(attempts)
        outcomes[(era_of(run), old_out, new_out)] += 1
        if old_out != new_out:
            changed[(old_out, new_out)] += 1
            runs_changed.append({'run': run, 'old': old_out, 'new': new_out,
                                 'attempts': [classify(a) for a in attempts]})
        saved_attempts += used_old - used_new

    if args.json:
        print(json.dumps({'outcomes': {f'{k[0]}|{k[1]}->{k[2]}': v for k, v in outcomes.items()},
                          'changed': {f'{k[0]}->{k[1]}': v for k, v in changed.items()},
                          'runs_changed': runs_changed,
                          'saved_attempts': saved_attempts,
                          'extent_prefix_waves_total': diag_waves,
                          'attempt_reports_with_diagnostics': diag_attempts}, indent=1))
        return
    print('policy replay over', len(runs), 'runs (all eras):')
    for (era, old, new), count in sorted(outcomes.items()):
        print(f'  {era or "?"}: old={old:14s} new={new:14s}  {count:3d} runs')
    print('\noutcome changes:', dict(changed) or 'NONE')
    for row in runs_changed[:20]:
        print('  CHANGED:', row)
    print('\nfutile attempts skipped by the gate (attempts never spawned):', saved_attempts)
    print('extent-prefix diagnostic waves present in corpus (never on successful attempts):',
          diag_waves, 'across', diag_attempts, 'attempt reports')


if __name__ == '__main__':
    main()