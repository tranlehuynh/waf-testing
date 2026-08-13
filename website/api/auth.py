"""
Friday Night Poker - real accounts + bearer-token sessions.

This is a genuine little auth system so the reflected-XSS demo has something real to steal:
register/login store a user in Mongo (hashed password), login mints a signed bearer token,
and /api/me exchanges that token for the account. Steal the token via XSS and you can call
/api/me as the victim - account takeover, not just "the WAF returned 200".

Deliberately conventional, NOT hardened as a filter: this is still a permissive test origin.
The token is also handed back in a JS-readable cookie on purpose - that cookie is the
document.cookie theft target. Everything here runs over fake data in the lab Mongo.

No third-party JWT/bcrypt libraries: the token is a real HS256 JWT built from the stdlib,
and passwords use PBKDF2. That keeps the api image dependency-light (only pymongo is added).
"""
import base64
import hashlib
import hmac
import json
import os
import time

# Signing key for the bearer token. A fixed dev default so the lab works out of the box;
# override with JWT_SECRET in docker-compose for anything you actually care about.
JWT_SECRET = os.environ.get("JWT_SECRET", "dev-not-secret-change-me")
TOKEN_TTL = 3600                 # seconds a session token is valid
PBKDF2_ROUNDS = 100_000

# Demo accounts created at startup (see seed_users), so `setup.sh up` yields a site you can
# log into immediately - no need to register first. Fake credentials over fake data; `linh`
# is an admin, so a token stolen from that session is an admin takeover.
DEMO_USERS = [
    {"username": "linh", "password": "poker123",  "role": "admin",  "chips": 999999},
    {"username": "tuan", "password": "allin2026",  "role": "player", "chips": 4200},
    {"username": "mai",  "password": "riverqueen", "role": "player", "chips": 1500},
]


# ---------- user store (lab Mongo, reachable because api is on the detonation net) -------
def _users():
    """The users collection, or None if Mongo is unreachable. Never raises."""
    url = os.environ.get("MONGO_URL")
    if not url:
        return None
    try:
        import pymongo
        client = pymongo.MongoClient(url, serverSelectionTimeoutMS=800)
        coll = client["lab"]["users"]
        coll.create_index("username", unique=True)
        return coll
    except Exception:
        return None


# ---------- password hashing (PBKDF2-HMAC-SHA256, stdlib) ---------------------------------
def hash_password(password, salt=None):
    salt = salt or os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ROUNDS)
    return "pbkdf2$%d$%s$%s" % (PBKDF2_ROUNDS, salt.hex(), dk.hex())


def verify_password(password, stored):
    try:
        _algo, rounds, salt_hex, hash_hex = stored.split("$")
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(rounds))
        return hmac.compare_digest(dk.hex(), hash_hex)
    except Exception:
        return False


# ---------- bearer token (HS256 JWT, stdlib) ---------------------------------------------
def _b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64u_decode(seg):
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def make_token(username, role):
    header = {"alg": "HS256", "typ": "JWT"}
    now = int(time.time())
    payload = {"sub": username, "role": role, "iat": now, "exp": now + TOKEN_TTL}
    signing_input = "%s.%s" % (
        _b64u(json.dumps(header, separators=(",", ":")).encode()),
        _b64u(json.dumps(payload, separators=(",", ":")).encode()),
    )
    sig = hmac.new(JWT_SECRET.encode(), signing_input.encode(), hashlib.sha256).digest()
    return "%s.%s" % (signing_input, _b64u(sig))


def verify_token(token):
    """Return the token's claims dict, or None if the signature or expiry is bad."""
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
        signing_input = "%s.%s" % (header_b64, payload_b64)
        expected = _b64u(hmac.new(JWT_SECRET.encode(), signing_input.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(expected, sig_b64):
            return None
        claims = json.loads(_b64u_decode(payload_b64))
        if int(claims.get("exp", 0)) < time.time():
            return None
        return claims
    except Exception:
        return None


# ---------- public operations, all returning a JSON-able dict ----------------------------
def _public(user):
    """Strip the password hash before a user document ever leaves the server."""
    return {"username": user.get("username"), "role": user.get("role", "player"),
            "chips": user.get("chips", 0)}


def register(username, password):
    if not username or not password:
        return {"ok": False, "error": "username and password are required"}
    coll = _users()
    if coll is None:
        return {"ok": False, "error": "user store unavailable (is the mongo container up?)"}
    doc = {"username": username, "password": hash_password(password),
           "role": "player", "chips": 1000}
    try:
        coll.insert_one(doc)
    except Exception as exc:
        if "duplicate" in str(exc).lower() or "E11000" in str(exc):
            return {"ok": False, "error": "that username is taken"}
        return {"ok": False, "error": "could not create the account"}
    return {"ok": True, "user": _public(doc)}


def login(username, password):
    if not username or not password:
        return {"ok": False, "error": "username and password are required"}
    coll = _users()
    if coll is None:
        return {"ok": False, "error": "user store unavailable (is the mongo container up?)"}
    user = coll.find_one({"username": username})
    if not user or not verify_password(password, user.get("password", "")):
        return {"ok": False, "error": "invalid username or password"}
    return {"ok": True, "token": make_token(username, user.get("role", "player")),
            "user": _public(user)}


def seed_users():
    """Create the demo accounts if the collection is empty. Idempotent and race-safe: the
    empty-check skips the (costly) password hashing once seeded, and the unique index on
    `username` deduplicates the rare case where concurrent workers both see it empty."""
    coll = _users()
    if coll is None:
        return False
    if coll.estimated_document_count() > 0:
        return True
    for user in DEMO_USERS:
        try:
            coll.insert_one({"username": user["username"],
                             "password": hash_password(user["password"]),
                             "role": user["role"], "chips": user["chips"]})
        except Exception:
            pass
    return True


def whoami(token):
    """Resolve a bearer token back to its account - the endpoint a stolen token owns."""
    if not token:
        return {"ok": False, "error": "no token"}
    claims = verify_token(token)
    if not claims:
        return {"ok": False, "error": "invalid or expired token"}
    coll = _users()
    user = coll.find_one({"username": claims["sub"]}) if coll is not None else None
    if not user:
        # Token is valid but the account is gone (or Mongo is down): still report the claims.
        return {"ok": True, "user": {"username": claims["sub"], "role": claims.get("role")}}
    return {"ok": True, "user": _public(user)}
