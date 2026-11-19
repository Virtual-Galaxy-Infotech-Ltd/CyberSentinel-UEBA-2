# Site state — where it lives and how to recover it

**Phase 0 of the HA plan** (`HA_IMPLEMENTATION_PLAN.md` §2). Applied to the
live install 19-Nov-2026.

## The rule

**Production reads its configuration and secrets from `/etc/ueba`, never from
the install tree.**

| File | Real location | Mode |
|---|---|---|
| Site configuration | `/etc/ueba/ueba_config.yaml` | 0640 root |
| Site settings + SSO secret | `/etc/ueba/ueba_site.env` | 0600 root |
| BLAS/torch thread pinning | `/etc/ueba/ueba_runtime.env` | 0600 root |

`/opt/ueba/ueba_site.env` and `/opt/ueba/ueba_runtime.env` remain as
**symlinks** into `/etc/ueba`, because six scripts (weekly retrain, rotate,
sync bridge, watchdog, bootstrap, installer) resolve the site env as
`${UEBA_SITE_ENV:-$(dirname "$0")/ueba_site.env}` and cron runs them with that
variable unset.

`/opt/ueba/ueba_config.yaml` is still a tracked repository file. It is now
**inert** — no service reads it. Leaving it tracked avoids rewriting every
working copy, which is what untracking it would do.

## Why

On 18-Nov-2026 a `git pull` in `/opt/ueba` deleted both `EnvironmentFile`s and
reverted `ueba_config.yaml` to the shipped defaults — wrong paths and port
3026, which collides with nginx. The console restart-looped behind a 502 for
about 25 minutes.

The `.gitignore` entries meant to protect those files had trailing comments on
the same line. Git has no inline comments in `.gitignore`, so each pattern was
the whole line including the `#` and matched nothing. Four entries were
decorative, including the one for `ueba_site.env`.

**The near-miss:** `UEBA_SSO_SECRET` existed in exactly one place after the
clean — the environment of the still-running engine, readable from
`/proc/<pid>/environ`. It is in no unit file and was not in the last backup.
One restart earlier and the 64-character HS256 secret shared with the SIEM
team would have been unrecoverable, invalidating every token minted against
it.

## Acceptance drill — run this after touching any of it

Reproduces the 18-Nov failure and proves it no longer bites. Fully reversible.

```bash
# 1. snapshot
install -d -m 0700 /root/ueba-site-state
cp -a /opt/ueba/ueba_config.yaml /root/ueba-site-state/drill-config.bak

# 2. reproduce the damage
rm -f /opt/ueba/ueba_site.env /opt/ueba/ueba_runtime.env
printf 'paths:\n  ueba_output: /tmp/wrong.jsonl\ndashboard:\n  port: 3026\n' \
  > /opt/ueba/ueba_config.yaml

# 3. restart as systemd would after a crash
systemctl restart ueba-engine ueba-dashboard && sleep 14

# 4. expected: 200, not 502
curl -sk -o /dev/null -w '%{http_code}\n' https://127.0.0.1:3026/

# 5. restore
ln -sfn /etc/ueba/ueba_site.env    /opt/ueba/ueba_site.env
ln -sfn /etc/ueba/ueba_runtime.env /opt/ueba/ueba_runtime.env
cp -a /root/ueba-site-state/drill-config.bak /opt/ueba/ueba_config.yaml
systemctl restart ueba-dashboard
```

Result on 19-Nov-2026: console `200`, both services active, SSO secret still
loaded (64 chars), engine still writing to the real alert store.
`git clean -nd` in the install tree reported nothing to delete.

## Recovery, if the secrets are ever lost anyway

In order of preference:

1. `/etc/ueba/` — the real files.
2. `/root/ueba-site-state/` — a copy outside the git tree, taken 18-Nov.
3. **The running process.** If a service is still up, its environment holds
   the values: `tr '\0' '\n' < /proc/$(systemctl show ueba-engine -p MainPID
   --value)/environ`. **Do not restart it first.** This is how the secret was
   recovered on 18-Nov.
4. Regenerating `UEBA_SSO_SECRET` is a last resort: it invalidates every token
   the SIEM team has minted and needs coordinating with them.

## Still open in phase 0

- **0.2** `/opt/ueba` is still simultaneously the production install, a git
  working tree, and where a teammate commits from. Production should be a
  deploy target, not a workspace. Not fixed by this change — only defused.
- **0.4** A deploy that snapshots, applies, health-checks and rolls back on
  failure. `rollback_deploy.sh` exists but restores a fixed file list from
  09-Nov, and the `git clean` deleted its snapshot directory.
- `install_ueba.sh` still writes both env files into the install tree, so a
  fresh install starts in the old shape. It needs to create `/etc/ueba` and
  the drop-ins instead.
