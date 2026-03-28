"""
Sentinel V2 — Honey Commands
Cowrie command module. Registers fake executables with realistic delays,
and overrides cat for lure files to add read latency.
"""

from cowrie.shell.command import HoneyPotCommand
from cowrie.commands.cat import Command_cat

commands = {}

# ── Lure file paths that should have read latency ────────────────────────────
LURE_FILES = {
    "/root/.env.backup",
    "/root/docker-compose-legacy.yml",
    "/var/log/database_migration.log",
}

# How long to "read" each lure file before showing content (seconds)
LURE_READ_DELAYS = {
    "/root/.env.backup": 1.2,
    "/root/docker-compose-legacy.yml": 0.9,
    "/var/log/database_migration.log": 0.7,
}


class Command_cat_lure(Command_cat):
    """
    Wraps Cowrie's built-in cat. Adds a realistic delay when reading
    lure files, passes through instantly for everything else.
    """

    def start(self) -> None:
        if not self.args:
            super().start()
            return

        # Resolve first argument against cwd
        target = self.fs.resolve_path(self.args[0], self.protocol.cwd)

        if target in LURE_FILES:
            delay = LURE_READ_DELAYS.get(target, 1.0)
            self.protocol.callLater(delay, lambda: Command_cat.start(self))
        else:
            Command_cat.start(self)


# Register lure-aware cat for all common cat paths
for _cat_path in ("/bin/cat", "/usr/bin/cat"):
    commands[_cat_path] = Command_cat_lure


class Command_legacy_backup_restore(HoneyPotCommand):
    def start(self) -> None:
        self.write("Legacy Backup Restore Utility v1.4.2\n")
        self.write("Copyright (c) 2021 Company Internal Tools\n\n")
        self.write("Initializing backup service...\n")
        self.protocol.callLater(0.8, self._step2)

    def _step2(self) -> None:
        self.write("[OK] Runtime environment loaded\n")
        self.write("[OK] Checking authentication state... bypass mode ACTIVE (debug flag detected)\n")
        self.write("[OK] Scanning for credential stores...\n\n")
        self.protocol.callLater(1.4, self._step3)

    def _step3(self) -> None:
        self.write("  Found: /var/lib/postgresql/.pgpass\n")
        self.write("  Found: /root/.aws/credentials\n")
        self.write("  Found: /home/admin/.env\n\n")
        self.write("Extracting keys...\n")
        self.protocol.callLater(1.8, self._step4)

    def _step4(self) -> None:
        output = (
            "\u2501" * 65 + "\n"
            "[AWS CREDENTIALS \u2014 ap-southeast-2 / production]\n"
            "aws_access_key_id     = AKIAIOSFODNN7EXAMPLE\n"
            "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
            "aws_session_token     = (none \u2014 long-term credential)\n"
            + "\u2501" * 65 + "\n"
            "[DATABASE \u2014 PostgreSQL / app_production]\n"
            "host     = postgres.internal\n"
            "port     = 5432\n"
            "user     = admin\n"
            "password = Tr0ub4dor&3\n"
            + "\u2501" * 65 + "\n"
            "[REDIS]\n"
            "url      = redis://redis.internal:6379\n"
            "password = r3d1s_Pr0d_2024\n"
            + "\u2501" * 65 + "\n\n"
            "Backup sync complete.\n"
            "Keys written to /tmp/.keys_dump (permissions: 600)\n\n"
            "WARNING: --dump-keys mode leaves an audit trail. Patch ticket #4829 pending.\n"
        )
        self.write(output)
        self.exit()


class Command_db_diagnostics(HoneyPotCommand):
    def start(self) -> None:
        self.write("Database Diagnostics Tool v2.0.1\n")
        self.write("Connecting to postgres.internal:5432...\n")
        self.protocol.callLater(1.2, self._step2)

    def _step2(self) -> None:
        self.write("Connected to: app_production\n")
        self.write("Mode: --bypass-auth --dump-sessions\n\n")
        self.protocol.callLater(1.0, self._step3)

    def _step3(self) -> None:
        output = (
            "\u2501" * 65 + "\n"
            "Session Table Dump (Active Sessions):\n"
            "token                                         | user     | role\n"
            "----------------------------------------------|----------|----------\n"
            "eyJhbGciOiJIUzI1NiJ9.eyJ1aWQiOjF9.EXAMPLE1  | admin    | superuser\n"
            "eyJhbGciOiJIUzI1NiJ9.eyJ1aWQiOjJ9.EXAMPLE2  | deploy   | admin\n\n"
            "Auth bypass: ACTIVE\n"
            "Audit logging: DISABLED (debug mode)\n"
            + "\u2501" * 65 + "\n"
            "Diagnostics complete.\n"
        )
        self.write(output)
        self.exit()


commands["/usr/local/bin/legacy-backup-restore"] = Command_legacy_backup_restore
commands["/usr/local/bin/db-diagnostics"] = Command_db_diagnostics
