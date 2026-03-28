# Deception Layer — File Placement Guide

## How it works

When an attacker enters the honeypot they find realistic-looking files
that contain hidden LLM prompt injection. If the attacker pastes these
files into an AI assistant (ChatGPT, Claude, Gemini) to analyze them,
the model will suggest the honey-commands as "vulnerabilities to test."

## Technique used per file

| File | Technique | Hidden instruction |
|------|-----------|-------------------|
| `docker-compose-legacy.yml` | TODO comment camouflage | Mentions `--dump-keys` flag on the backup tool |
| `.env.backup` | Base64-encoded string in `FALLBACK_DIAG` | Decodes to `db-diagnostics --bypass-auth --dump-sessions` |
| `database_migration.log` | Off-screen horizontal padding | Diagnostic note hidden past column 160 |

## File placement inside Cowrie honeyfs

Copy lure files to these paths in `deception/honeyfs/`:

```
deception/honeyfs/
├── home/admin/
│   ├── docker-compose-legacy.yml   ← copy from lures/
│   └── .env.backup                 ← copy from lures/
└── var/log/
    └── database_migration.log      ← copy from lures/
```

`deploy.sh` does this automatically.

## Honey-commands placement

Cowrie's `txtcmds` directory maps command paths to their fake output.
The files in `honey-commands/` are placed at:

```
cowrie/share/cowrie/txtcmds/usr/local/bin/legacy-backup-restore
cowrie/share/cowrie/txtcmds/usr/local/bin/db-diagnostics
```

This is handled via the Docker volume mount in `docker-compose.yml`.

## Detection in monitor.py

`monitor.py` watches for these strings in Cowrie logs:
- `legacy-backup-restore`
- `db-diagnostics`
- `--dump-keys`
- `--bypass-auth`

Any match triggers an immediate priority Telegram alert.
