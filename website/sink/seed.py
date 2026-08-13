"""
Fake data for the detonation chamber.

Everything here is randomly generated at process start into a tmpfs (/tmp/lab), so a
payload that drops a table, writes a file, or reads a "secret" only ever touches this
disposable, fake dataset. Nothing in this file is real: the handles, chips and password
hashes are random, and the planted /etc/passwd and db.conf are inert literals.

Reproducible on purpose (random.seed): a scan re-run produces the same fake rows, so a
finding is stable between runs.
"""
import os
import random
import sqlite3

LAB = "/tmp/lab"
DOCROOT = os.path.join(LAB, "www")          # LFI open() joins user path onto this
SECRETS = os.path.join(LAB, "secrets")
DB_PATH = os.path.join(LAB, "players.db")   # SQLite target for the SQLi sink

_HANDLES = [
    "linh", "tuan", "mai", "khoa", "trang", "hieu", "vy", "quang", "nga", "duc",
    "phuong", "long", "an", "thu", "bao", "chi", "dat", "ha", "kien", "loan",
]
_FAKE_PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
    "poker:x:1000:1000:Friday Night Poker:/srv/poker:/bin/bash\n"
    "# FAKE lab data - randomly seeded, not a real host\n"
)
# A planted "secret" so path-traversal below the docroot returns something juicy-looking
# but worthless. Fake creds pointing at the throwaway mongo on the no-egress network.
_FAKE_DBCONF = (
    "[database]\n"
    "host = mongo\n"
    "user = poker_app\n"
    "password = f4ke-not-a-real-secret-{tok}\n"
    "note = FAKE lab data - this credential opens nothing real\n"
)

# Poker accounts for the Mongo-backed NoSQL sink, filled in by build(). Kept as a module
# global so sink_app can seed Mongo from it (and fall back to it when Mongo is down).
PLAYERS = []

# In-memory fake directory / documents, reused by the LDAP sink.
DIRECTORY = [
    {"dn": "cn=admin,dc=poker,dc=local", "uid": "admin", "objectclass": "person",
     "userpassword": "f4ke-admin-pw", "role": "admin"},
    {"dn": "cn=linh,dc=poker,dc=local", "uid": "linh", "objectclass": "person",
     "userpassword": "f4ke-linh-pw", "role": "player"},
    {"dn": "cn=mai,dc=poker,dc=local", "uid": "mai", "objectclass": "person",
     "userpassword": "f4ke-mai-pw", "role": "player"},
    {"dn": "cn=svc,dc=poker,dc=local", "uid": "svc", "objectclass": "account",
     "userpassword": "f4ke-svc-pw", "role": "service"},
]


def build():
    """(Re)create the fake filesystem and SQLite DB under /tmp/lab. Idempotent."""
    random.seed(1337)
    os.makedirs(os.path.join(DOCROOT, "static", "img"), exist_ok=True)
    os.makedirs(SECRETS, exist_ok=True)

    # A couple of legitimate files the "app" would serve, so the docroot is not empty.
    with open(os.path.join(DOCROOT, "static", "img", "logo.txt"), "w") as fh:
        fh.write("Friday Night Poker\n")
    with open(os.path.join(SECRETS, "db.conf"), "w") as fh:
        fh.write(_FAKE_DBCONF.format(tok="%06x" % random.randrange(16 ** 6)))
    # Overwrite the container's /etc/passwd view is not possible (read-only rootfs); the
    # LFI sink reads the container's real /etc/passwd, which is itself inert. This planted
    # copy is what a `../` into the docroot's parent finds first.
    with open(os.path.join(LAB, "etc_passwd_sample"), "w") as fh:
        fh.write(_FAKE_PASSWD)

    con = sqlite3.connect(DB_PATH)
    con.execute("DROP TABLE IF EXISTS players")
    con.execute(
        "CREATE TABLE players (id INTEGER PRIMARY KEY, handle TEXT, chips INTEGER, pw_hash TEXT)"
    )
    for i, handle in enumerate(_HANDLES, start=1):
        chips = random.randrange(100, 10000)
        # A bcrypt-shaped but entirely fake hash.
        pw = "$2b$12$" + "".join(random.choice(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./")
            for _ in range(53))
        con.execute("INSERT INTO players VALUES (?,?,?,?)", (i, handle, chips, pw))
    con.commit()
    con.close()

    # Poker accounts for the Mongo NoSQL sink. Deliberately juicy - password hashes,
    # emails, balances, and one admin carrying an API key - so a successful `$ne` / `$where`
    # injection visibly DUMPS rows instead of just returning 200. Every value is randomly
    # seeded and worthless. Generated last so the SQLite stream above is byte-for-byte
    # unchanged; read by sink_app._mongo_collection.
    global PLAYERS
    PLAYERS = []
    for i, handle in enumerate(_HANDLES, start=1):
        pw = "$2b$12$" + "".join(random.choice(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./")
            for _ in range(53))
        PLAYERS.append({
            "id": i,
            "username": handle,
            "email": "%s@fridaynightpoker.local" % handle,
            "password_bcrypt": pw,
            "chips": random.randrange(100, 200000),
            "role": "player",
            "vip": random.random() < 0.3,
        })
    # The planted admin: the account an authentication-bypass injection is really after.
    PLAYERS[0].update(
        role="admin", chips=999999, vip=True,
        api_key="fnp_live_" + "".join(random.choice("0123456789abcdef") for _ in range(24)),
        note="FAKE seed data - this account and key open nothing real",
    )
    return DB_PATH


if __name__ == "__main__":
    build()
