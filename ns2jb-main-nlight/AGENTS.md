# Repo rules (public fork — this tree gets published)

## Personal-information hygiene

**Every non-gitignored file in this repo is public.** Before committing —
and before writing into any doc, findings file, script, comment, or config
that is tracked — strip all personal information:

- **No usernames, real names, or emails** in file content. (The repo-local
  git author config is the one exception — it is already a placeholder.)
- **No absolute home paths** (`/home/<user>/...`, `~/...`). Write
  repo-relative paths (`engine/...`, `runs/...`) or use `__dirname`
  resolution; findings docs reference artifacts by name, not by full path.
- **No hostnames, desktop environment details, or machine-specific
  identifiers.** The documented lab constants (netns name, console/PC
  addresses) are fine — they are operational, not personal.
- Session IDs, run names, payload/policy sha256s, result codes, and
  timestamps are operational data — keep them, they are the evidence trail.

**Check before every commit:** `grep -rE "/home/|@[a-z]+\.(com|org)|<username>" --include="*.md" --include="*.cjs" --include="*.bas" .`
on the staged files, and fix any hit before pushing. Fix leaks by editing
the file — never by rewriting published history as a substitute for
cleaning the next commit (if a leak already got pushed, do both).

## Git hygiene

- Never commit: `pairing.json` (holds the real pairing token), `runs/`,
  `fw23/`, `npdm-captures/` — all gitignored, and `git add -A` must not
  pull them in. Tracked `.bas` files carry placeholder tokens only.
- The real pairing token lives only in the gitignored `pairing.json`;
  if a tracked file ever needs its shape, use the placeholder pattern.
- Keep the repo-local git author config as-is.

## Tooling notes

- Console-side probes run netns-wrapped:
  `sudo -n ip netns exec switchlab runuser -u <user> -- node <tool>.cjs`
  (the `<user>` here is a runtime invocation, not repo content — do not
  record local usernames in committed scripts or docs).
- Tools resolve the current session via `latest-session.json` — never
  hardcode a run directory.
