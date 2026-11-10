from datetime import datetime, timedelta, timezone

from openmon.api import auth, security

PASSWORD = "Correta-Cavalo-Bateria-9"
NOW = lambda: datetime.now(timezone.utc)  # noqa: E731


class FakeStore:
    """Mesma interface do PgAuthStore, em memória."""

    def __init__(self):
        self.users = {"admin": {"id": 1, "username": "admin", "display_name": "Admin", "email": None,
                                "auth_source": "local", "password_hash": security.hash_password(PASSWORD),
                                "is_active": True, "locked_until": None, "must_change_password": False,
                                "role": "global_admin", "role_name": "Administrador Global",
                                "scope": "global", "failed": 0, "last_login_at": None}}
        self.attempts = []
        self.sessions = {}

    async def settings(self):
        return {"auth.lockout": dict(auth.DEFAULT_LOCKOUT), "auth.session": dict(auth.DEFAULT_SESSION)}

    async def recent_failures(self, username, ip, minutes):
        mine = [a for a in self.attempts if a[0].lower() == username.lower()]
        last_ok = max((i for i, a in enumerate(mine) if a[2]), default=-1)
        return (sum(not a[2] for a in mine[last_ok + 1:]), sum(a[1] == ip and not a[2] for a in self.attempts))

    async def find_user(self, username):
        u = self.users.get(username.lower())
        return dict(u) if u else None

    async def ldap_directories(self):
        return []

    async def record_attempt(self, username, ip, success, reason, source="local"):
        self.attempts.append((username, ip, success, reason))

    async def register_failure(self, user_id, lockout):
        u = next(u for u in self.users.values() if u["id"] == user_id)
        u["failed"] += 1
        if u["failed"] >= lockout["max_failures"]:
            u["failed"], u["locked_until"] = 0, NOW() + timedelta(minutes=lockout["lock_minutes"])
            return True
        return False

    async def open_session(self, user, ip, ua, token_hash, csrf_hash, absolute_hours, new_hash):
        self.users[user["username"].lower()].update(failed=0, locked_until=None)
        exp = NOW() + timedelta(hours=absolute_hours)
        self.sessions[token_hash] = {"user": user, "csrf": csrf_hash, "exp": exp, "seen": NOW(), "revoked": False}
        return exp

    async def load_session(self, token_hash, idle_minutes):
        s = self.sessions.get(token_hash)
        if not s or s["revoked"] or s["exp"] < NOW() or s["seen"] < NOW() - timedelta(minutes=idle_minutes):
            return None
        s["seen"] = NOW()
        return {**s["user"], "csrf_token_hash": s["csrf"], "expires_at": s["exp"], "tenant_ids": []}

    async def revoke_session(self, token_hash, user, ip, ua):
        self.sessions[token_hash]["revoked"] = True


