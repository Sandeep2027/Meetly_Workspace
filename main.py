"""
Meetly Workspace v4 - FastAPI + SQLite3 backend (dashboard, calls, files, credential files and account recovery).

    pip install fastapi "uvicorn[standard]" pydantic
    APP_SECRET=<long-random> uvicorn main:app --reload

All state lives in SQLite (WAL mode, foreign keys on). Schema is created on startup.
"""
import asyncio, base64, csv, hashlib, hmac, io, json, os, re, secrets, sqlite3, time, uuid
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from typing import List, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

BASE = Path(__file__).parent
DB_PATH = os.environ.get("DB_PATH", str(BASE / "meetly.db"))
TOKEN_TTL, MAX_CALL, MAX_FAILS, LOCK_SECS = 12 * 3600, 8, 5, 600
EMAIL_RE = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
ACCESS = ("admin", "manager", "member")

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS workspaces(
  id TEXT PRIMARY KEY, name TEXT NOT NULL, location TEXT NOT NULL, registration_number TEXT NOT NULL UNIQUE,
  industry TEXT DEFAULT '', description TEXT DEFAULT '', office_code TEXT NOT NULL UNIQUE,
  secret_hash TEXT NOT NULL, self_register INTEGER DEFAULT 1, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS users(
  id TEXT PRIMARY KEY, ws_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  name TEXT NOT NULL, email TEXT NOT NULL UNIQUE, role TEXT NOT NULL, department TEXT DEFAULT '', phone TEXT DEFAULT '',
  access TEXT NOT NULL DEFAULT 'member', active INTEGER DEFAULT 1, pw_hash TEXT NOT NULL,
  must_change INTEGER DEFAULT 0, token_ver INTEGER DEFAULT 0, fails INTEGER DEFAULT 0, locked_until INTEGER DEFAULT 0,
  created INTEGER NOT NULL, last_login INTEGER,
  recovery_hash TEXT, recovery_issued INTEGER, rec_fails INTEGER DEFAULT 0, rec_locked INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS teams(
  id TEXT PRIMARY KEY, ws_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  name TEXT NOT NULL, department TEXT NOT NULL, description TEXT DEFAULT '',
  owner_id TEXT NOT NULL REFERENCES users(id), room_id TEXT, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS team_members(
  team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, PRIMARY KEY(team_id,user_id));
CREATE TABLE IF NOT EXISTS rooms(
  id TEXT PRIMARY KEY, ws_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK(kind IN('dm','call','team','space','meeting')), title TEXT NOT NULL,
  team_id TEXT REFERENCES teams(id) ON DELETE CASCADE, owner_id TEXT, description TEXT DEFAULT '',
  scheduled_at TEXT, expires INTEGER, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS room_members(
  room_id TEXT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, PRIMARY KEY(room_id,user_id));
CREATE TABLE IF NOT EXISTS messages(
  id INTEGER PRIMARY KEY AUTOINCREMENT, room_id TEXT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
  user_id TEXT, text TEXT NOT NULL, ts INTEGER NOT NULL, edited INTEGER DEFAULT 0,
  deleted INTEGER DEFAULT 0, system INTEGER DEFAULT 0, reply_to INTEGER, file_id TEXT);
CREATE INDEX IF NOT EXISTS ix_msg_room ON messages(room_id, id);
CREATE TABLE IF NOT EXISTS reads(
  room_id TEXT NOT NULL, user_id TEXT NOT NULL, last_id INTEGER DEFAULT 0, cleared_id INTEGER DEFAULT 0, PRIMARY KEY(room_id,user_id));
CREATE TABLE IF NOT EXISTS audit(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ws_id TEXT NOT NULL, actor TEXT, action TEXT NOT NULL, ts INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS files(
  id TEXT PRIMARY KEY, room_id TEXT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE, user_id TEXT NOT NULL,
  name TEXT NOT NULL, size INTEGER NOT NULL, mime TEXT NOT NULL, key TEXT NOT NULL, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS hidden(message_id INTEGER NOT NULL, user_id TEXT NOT NULL, PRIMARY KEY(message_id,user_id));
CREATE TABLE IF NOT EXISTS reactions(
  message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE, user_id TEXT NOT NULL, emoji TEXT NOT NULL,
  PRIMARY KEY(message_id,user_id));
CREATE INDEX IF NOT EXISTS ix_users_ws ON users(ws_id);
CREATE INDEX IF NOT EXISTS ix_rooms_ws ON rooms(ws_id, kind);
"""


@contextmanager
def db():
    con = sqlite3.connect(DB_PATH, timeout=15)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    try:
        yield con
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()


def row(c, sql, *a):
    r = c.execute(sql, a).fetchone()
    return dict(r) if r else None


def rows(c, sql, *a):
    return [dict(r) for r in c.execute(sql, a).fetchall()]


now = lambda: int(time.time())
uid = lambda: uuid.uuid4().hex[:12]

with db() as _c:
    _c.execute("PRAGMA journal_mode=WAL")
    _c.executescript(SCHEMA)
    for ddl in ("ALTER TABLE messages ADD COLUMN reply_to INTEGER", "ALTER TABLE messages ADD COLUMN file_id TEXT",
                "ALTER TABLE reads ADD COLUMN cleared_id INTEGER DEFAULT 0",
                "ALTER TABLE users ADD COLUMN recovery_hash TEXT", "ALTER TABLE users ADD COLUMN recovery_issued INTEGER",
                "ALTER TABLE users ADD COLUMN rec_fails INTEGER DEFAULT 0", "ALTER TABLE users ADD COLUMN rec_locked INTEGER DEFAULT 0"):      # upgrade databases created by v2
        try:
            _c.execute(ddl)
        except sqlite3.OperationalError:
            pass
    if not row(_c, "SELECT v FROM meta WHERE k='key'"):
        _c.execute("INSERT INTO meta VALUES('key',?)", (secrets.token_hex(32),))
    SECRET_KEY = (os.environ.get("APP_SECRET") or row(_c, "SELECT v FROM meta WHERE k='key'")["v"]).encode()


# --------------------------------------------------------------------------- security
def hash_secret(value: str, salt: Optional[str] = None) -> str:
    salt = salt or secrets.token_hex(16)
    return f"{salt}${hashlib.pbkdf2_hmac('sha256', value.encode(), bytes.fromhex(salt), 200_000).hex()}"


def check_secret(value: str, stored: str) -> bool:
    return hmac.compare_digest(hash_secret(value, stored.split("$")[0]), stored)


def make_token(u: dict) -> str:
    body = base64.urlsafe_b64encode(json.dumps({"u": u["id"], "v": u["token_ver"], "e": now() + TOKEN_TTL}).encode()).decode()
    return f"{body}.{hmac.new(SECRET_KEY, body.encode(), hashlib.sha256).hexdigest()}"


def read_token(token: str):
    try:
        body, sig = token.rsplit(".", 1)
        if not hmac.compare_digest(sig, hmac.new(SECRET_KEY, body.encode(), hashlib.sha256).hexdigest()):
            return None
        d = json.loads(base64.urlsafe_b64decode(body))
        return (d["u"], d["v"]) if d["e"] > now() else None
    except Exception:
        return None


def load_user(token: str) -> Optional[dict]:
    t = read_token(token or "")
    if not t:
        return None
    with db() as c:
        u = row(c, "SELECT * FROM users WHERE id=?", t[0])
    return u if u and u["active"] and u["token_ver"] == t[1] else None


def pw_ok(pw: str):
    if len(pw) < 8 or not re.search(r"[A-Za-z]", pw) or not re.search(r"\d", pw):
        raise HTTPException(422, "Password needs 8+ characters with at least one letter and one number.")


_hits: dict = {}


def rate_limit(request: Request, limit=10, window=60):
    key = (request.client.host if request.client else "?", request.url.path)
    h = [t for t in _hits.get(key, []) if t > now() - window]
    if len(h) >= limit:
        raise HTTPException(429, "Too many attempts. Wait a minute and try again.")
    _hits[key] = h + [now()]


def auth(authorization: str = Header(None)) -> dict:
    u = load_user((authorization or "").removeprefix("Bearer ").strip())
    if not u:
        raise HTTPException(401, "Session expired. Sign in again.")
    return u


def admin_only(u: dict = Depends(auth)) -> dict:
    if u["access"] != "admin":
        raise HTTPException(403, "Workspace admin access required.")
    return u


def audit(c, u, action):
    c.execute("INSERT INTO audit(ws_id,actor,action,ts) VALUES(?,?,?,?)", (u["ws_id"], u["name"], action, now()))


# --------------------------------------------------------------------------- recovery keys + credential files
RK_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"       # no 0/O/1/I so keys are easy to read and type
REC_MAX_FAILS, REC_LOCK_SECS = 5, 1800


def new_recovery_key() -> str:
    return "MRK-" + "-".join("".join(secrets.choice(RK_ALPHABET) for _ in range(4)) for _ in range(5))   # 100 bits


def norm_key(k: str) -> str:
    return re.sub(r"[^A-Z0-9]", "", k.upper())


def set_recovery(c, user_id: str) -> str:
    """Issue a new personal recovery key. Only a PBKDF2 hash is stored; the plain key is returned once."""
    key = new_recovery_key()
    c.execute("UPDATE users SET recovery_hash=?, recovery_issued=?, rec_fails=0, rec_locked=0 WHERE id=?", (hash_secret(norm_key(key)), now(), user_id))
    return key


def credential_file(c, user: dict, password: Optional[str], key: str, issued_by: str, invite: Optional[dict] = None) -> dict:
    """Portable, versioned credential document the person downloads and keeps. Never stored on the server."""
    ws = row(c, "SELECT name, office_code FROM workspaces WHERE id=?", user["ws_id"])
    notes = ["Keep this file private. Anyone with it can sign in as you or reset your password.",
             "The recovery key never changes when you change your password, so this file stays useful.",
             "To reset a lost password: open the sign-in page, choose Forgot password, then upload this file or enter the email and recovery key.",
             "The server stores only a hash of the recovery key and cannot show it again. If you lose it, an admin can issue a new one.",
             "Using the recovery key replaces it with a new one, so download the new file that is shown afterwards."]
    notes.append("The password below is the one set when this file was issued. It may be out of date after you change your password."
                 if password else "No password is stored in this file.")
    out = {"schema": "meetly.credentials/v1", "issued_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "issued_by": issued_by,
           "workspace": {"name": ws["name"], "office_code": ws["office_code"]},
           "account": {"name": user["name"], "email": user["email"], "role": user["role"], "access": user["access"]},
           "credentials": {"email": user["email"], "password": password, "recovery_key": key},
           "fingerprint": hashlib.sha256((user["email"] + norm_key(key)).encode()).hexdigest()[:16], "notes": notes}
    if invite:
        out["workspace_invite"] = invite
    return out


# --------------------------------------------------------------------------- models
class WorkspaceIn(BaseModel):
    company_name: str = Field(min_length=2, max_length=80)
    location: str = Field(min_length=2, max_length=120)
    registration_number: str = Field(min_length=3, max_length=40)
    industry: str = Field("", max_length=60)
    description: str = Field("", max_length=300)
    admin_name: str = Field(min_length=2, max_length=60)
    admin_email: str = Field(pattern=EMAIL_RE)
    admin_password: str = Field(max_length=128)


class RegisterIn(BaseModel):
    name: str = Field(min_length=2, max_length=60)
    email: str = Field(pattern=EMAIL_RE)
    password: str = Field(max_length=128)
    role: str = Field(min_length=2, max_length=60)
    department: str = Field("", max_length=60)
    office_code: str = Field(min_length=3, max_length=20)
    secret: str = Field(min_length=4, max_length=60)


class RecoverIn(BaseModel):
    email: str = Field(pattern=EMAIL_RE)
    recovery_key: str = Field(min_length=8, max_length=60)
    new_password: str = Field(max_length=128)


class KeyIn(BaseModel):
    current: str = Field(max_length=128)


class LoginIn(BaseModel):
    email: str = Field(pattern=EMAIL_RE)
    password: str = Field(max_length=128)


class ProfileIn(BaseModel):
    name: Optional[str] = Field(None, min_length=2, max_length=60)
    role: Optional[str] = Field(None, min_length=2, max_length=60)
    department: Optional[str] = Field(None, max_length=60)
    phone: Optional[str] = Field(None, max_length=30)


class PasswordIn(BaseModel):
    current: str = Field(max_length=128)
    new: str = Field(max_length=128)


class AdminUserIn(BaseModel):
    name: str = Field(min_length=2, max_length=60)
    email: str = Field(pattern=EMAIL_RE)
    password: str = Field(max_length=128)
    role: str = Field(min_length=2, max_length=60)
    department: str = Field("", max_length=60)
    phone: str = Field("", max_length=30)
    access: str = "member"


class UserPatch(ProfileIn):
    access: Optional[str] = None
    active: Optional[bool] = None


class WorkspacePatch(BaseModel):
    name: Optional[str] = Field(None, min_length=2, max_length=80)
    location: Optional[str] = Field(None, min_length=2, max_length=120)
    industry: Optional[str] = Field(None, max_length=60)
    description: Optional[str] = Field(None, max_length=300)
    self_register: Optional[bool] = None


class TeamIn(BaseModel):
    name: str = Field(min_length=2, max_length=60)
    department: str = Field(min_length=2, max_length=60)
    description: str = Field("", max_length=300)
    member_ids: List[str] = []


class TeamPatch(BaseModel):
    name: Optional[str] = Field(None, min_length=2, max_length=60)
    department: Optional[str] = Field(None, min_length=2, max_length=60)
    description: Optional[str] = Field(None, max_length=300)


class MemberIn(BaseModel):
    user_id: str


class SpaceIn(BaseModel):
    name: str = Field(min_length=2, max_length=60)
    hours: int = Field(24, ge=1, le=720)


class MeetingIn(BaseModel):
    title: str = Field(min_length=2, max_length=80)
    scheduled_at: Optional[str] = Field(None, max_length=40)
    description: str = Field("", max_length=300)


class CallIn(BaseModel):
    title: str = Field("Group call", min_length=2, max_length=80)
    invite_ids: List[str] = Field(min_length=2, max_length=MAX_CALL - 1)


class MsgIn(BaseModel):
    text: str = Field(min_length=1, max_length=4000)


# --------------------------------------------------------------------------- domain helpers
def pub(u: dict) -> dict:
    return {"id": u["id"], "name": u["name"], "email": u["email"], "role": u["role"], "department": u["department"],
            "phone": u["phone"], "access": u["access"], "active": bool(u["active"]), "online": u["id"] in conns}


def new_room(c, ws_id, kind, title, members=(), rid=None, **kw) -> str:
    rid = rid or f"{kind[0]}_{uid()}"
    c.execute("INSERT INTO rooms(id,ws_id,kind,title,team_id,owner_id,description,scheduled_at,expires,created) VALUES(?,?,?,?,?,?,?,?,?,?)",
              (rid, ws_id, kind, title, kw.get("team_id"), kw.get("owner_id"), kw.get("description", ""),
               kw.get("scheduled_at"), kw.get("expires"), now()))
    c.executemany("INSERT OR IGNORE INTO room_members VALUES(?,?)", [(rid, m) for m in members])
    return rid


MAX_UPLOAD = 50 * 1024 * 1024
BLOCKED_EXT = {".exe", ".bat", ".cmd", ".com", ".scr", ".msi", ".vbs", ".ps1", ".jar", ".dll"}
INLINE_OK = ("image/png", "image/jpeg", "image/gif", "image/webp", "audio/", "video/", "application/pdf")


class LocalStorage:
    """Files on local disk (testing). Replace with S3/GCS/Azure later: keep the same path/delete interface."""

    def __init__(self):
        self.root = Path(os.environ.get("UPLOAD_DIR", BASE / "uploads"))
        self.root.mkdir(parents=True, exist_ok=True)

    def path(self, key: str) -> Path:
        return self.root / key

    def delete(self, key: str):
        try:
            self.path(key).unlink()
        except FileNotFoundError:
            pass


storage = LocalStorage()


def drop_files(c, room_sql, *args):
    for f in rows(c, f"SELECT key FROM files WHERE room_id IN (SELECT id FROM rooms WHERE {room_sql})", *args):
        storage.delete(f["key"])


def view_msgs(c, ms: list) -> list:
    if not ms:
        return []
    ids = [m["id"] for m in ms]
    react = {}
    for r in rows(c, f"SELECT message_id,user_id,emoji FROM reactions WHERE message_id IN ({','.join('?' * len(ids))})", *ids):
        react.setdefault(r["message_id"], {}).setdefault(r["emoji"], []).append(r["user_id"])
    fids = [m["file_id"] for m in ms if m.get("file_id")]
    files = {f["id"]: f for f in rows(c, f"SELECT id,name,size,mime FROM files WHERE id IN ({','.join('?' * len(fids))})", *fids)} if fids else {}
    rids = list({m["reply_to"] for m in ms if m.get("reply_to")})
    reps = {r["id"]: r for r in rows(c, f"SELECT id,user_id,text,deleted,file_id FROM messages WHERE id IN ({','.join('?' * len(rids))})", *rids)} if rids else {}
    out = []
    for m in ms:
        rp = reps.get(m.get("reply_to"))
        out.append({"id": m["id"], "user": m["user_id"], "text": "" if m["deleted"] else m["text"], "ts": m["ts"],
                    "edited": bool(m["edited"]), "deleted": bool(m["deleted"]), "system": bool(m["system"]),
                    "file": None if m["deleted"] else files.get(m.get("file_id")), "reactions": react.get(m["id"], {}),
                    "reply": {"id": rp["id"], "user": rp["user_id"], "text": rp["text"][:140], "file": bool(rp["file_id"])} if rp and not rp["deleted"] else None})
    return out


def msg_view(c, m: dict) -> dict:
    return view_msgs(c, [m])[0]


def add_msg(c, rid, user_id, text, system=False, reply_to=None, file_id=None) -> dict:
    cur = c.execute("INSERT INTO messages(room_id,user_id,text,ts,system,reply_to,file_id) VALUES(?,?,?,?,?,?,?)",
                    (rid, user_id, text, now(), int(system), reply_to, file_id))
    return msg_view(c, row(c, "SELECT * FROM messages WHERE id=?", cur.lastrowid))


def team_ids(c, tid):
    return [r["user_id"] for r in rows(c, "SELECT user_id FROM team_members WHERE team_id=?", tid)]


def can_access(c, u, r) -> bool:
    if not r or r["ws_id"] != u["ws_id"] or not u["active"]:
        return False
    if r["kind"] == "meeting":
        return True
    if r["team_id"]:
        return u["access"] == "admin" or bool(row(c, "SELECT 1 x FROM team_members WHERE team_id=? AND user_id=?", r["team_id"], u["id"]))
    return bool(row(c, "SELECT 1 x FROM room_members WHERE room_id=? AND user_id=?", r["id"], u["id"]))


def get_room(c, rid, u) -> dict:
    r = row(c, "SELECT * FROM rooms WHERE id=?", rid)
    if not r or not can_access(c, u, r):
        raise HTTPException(404, "Room not found or you do not have access.")
    if r["expires"] and r["expires"] < now():
        raise HTTPException(410, "This temporary space has expired.")
    return r


def get_team(c, tid, u) -> dict:
    t = row(c, "SELECT * FROM teams WHERE id=? AND ws_id=?", tid, u["ws_id"])
    if not t:
        raise HTTPException(404, "Team not found.")
    return t


def can_manage(t, u):
    return u["access"] == "admin" or t["owner_id"] == u["id"]


def team_view(c, t) -> dict:
    sp = rows(c, "SELECT id,title name,expires,owner_id FROM rooms WHERE team_id=? AND kind='space' AND (expires IS NULL OR expires>?) ORDER BY created", t["id"], now())
    return {"id": t["id"], "name": t["name"], "department": t["department"], "description": t["description"],
            "owner": t["owner_id"], "room": t["room_id"], "members": team_ids(c, t["id"]), "spaces": sp}


def meeting_view(r) -> dict:
    return {"id": r["id"], "title": r["title"], "description": r["description"], "scheduled_at": r["scheduled_at"], "owner": r["owner_id"], "created": r["created"]}


# --------------------------------------------------------------------------- app
async def purge_loop():
    while True:
        with db() as c:
            drop_files(c, "kind='space' AND expires IS NOT NULL AND expires<?", now() - 30 * 86400)
            c.execute("DELETE FROM rooms WHERE kind='space' AND expires IS NOT NULL AND expires<?", (now() - 30 * 86400,))
        await asyncio.sleep(3600)


@asynccontextmanager
async def lifespan(_):
    task = asyncio.create_task(purge_loop())
    yield
    task.cancel()


app = FastAPI(title="Meetly Workspace", docs_url="/api/docs", redoc_url=None, lifespan=lifespan)


@app.middleware("http")
async def headers(request: Request, call_next):
    r = await call_next(request)
    r.headers.update({"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "same-origin",
                      "Permissions-Policy": "camera=(self), microphone=(self), display-capture=(self)"})
    return r


@app.get("/")
def index():
    return FileResponse(BASE / "index.html")          # sign-in, join, register company


@app.get("/dashboard")
def dashboard():
    return FileResponse(BASE / "dashboard.html")      # the whole app after sign-in


@app.get("/api/health")
def health():
    with db() as c:
        c.execute("SELECT 1")
    return {"status": "ok", "online": len(conns)}


# ---- auth
@app.post("/api/workspaces", status_code=201)
def create_workspace(b: WorkspaceIn, request: Request):
    rate_limit(request, 5, 300)
    pw_ok(b.admin_password)
    with db() as c:
        reg = b.registration_number.strip().upper()
        if row(c, "SELECT 1 x FROM workspaces WHERE registration_number=?", reg):
            raise HTTPException(409, "A workspace with this registration number already exists.")
        if row(c, "SELECT 1 x FROM users WHERE email=?", b.admin_email.lower()):
            raise HTTPException(409, "This email is already registered.")
        prefix = re.sub(r"[^A-Z0-9]", "", b.company_name.upper())[:4] or "WS"
        code = f"{prefix}-{secrets.token_hex(2).upper()}"
        while row(c, "SELECT 1 x FROM workspaces WHERE office_code=?", code):
            code = f"{prefix}-{secrets.token_hex(2).upper()}"
        sec, wid, aid = secrets.token_urlsafe(9), uid(), uid()
        c.execute("INSERT INTO workspaces(id,name,location,registration_number,industry,description,office_code,secret_hash,created) VALUES(?,?,?,?,?,?,?,?,?)",
                  (wid, b.company_name.strip(), b.location.strip(), reg, b.industry, b.description, code, hash_secret(sec), now()))
        c.execute("INSERT INTO users(id,ws_id,name,email,role,access,pw_hash,created,last_login) VALUES(?,?,?,?,?,?,?,?,?)",
                  (aid, wid, b.admin_name.strip(), b.admin_email.lower(), "Workspace Admin", "admin", hash_secret(b.admin_password), now(), now()))
        key = set_recovery(c, aid)
        u = row(c, "SELECT * FROM users WHERE id=?", aid)
        audit(c, u, "Created workspace")
        invite = {"office_code": code, "office_secret": sec, "note": "Share these with employees so they can join. The secret is stored hashed and cannot be shown again."}
        cf = credential_file(c, u, b.admin_password, key, "workspace-registration", invite)
    return {"token": make_token(u), "office_code": code, "secret": sec, "credentials_file": cf}


@app.post("/api/auth/register", status_code=201)
def register(b: RegisterIn, request: Request):
    rate_limit(request)
    pw_ok(b.password)
    with db() as c:
        ws = row(c, "SELECT * FROM workspaces WHERE office_code=?", b.office_code.strip().upper())
        if not ws or not check_secret(b.secret, ws["secret_hash"]):
            raise HTTPException(403, "Office code or secret is incorrect.")
        if not ws["self_register"]:
            raise HTTPException(403, "Self-registration is off. Ask your workspace admin to create your account.")
        if row(c, "SELECT 1 x FROM users WHERE email=?", b.email.lower()):
            raise HTTPException(409, "This email is already registered.")
        i = uid()
        c.execute("INSERT INTO users(id,ws_id,name,email,role,department,pw_hash,created,last_login) VALUES(?,?,?,?,?,?,?,?,?)",
                  (i, ws["id"], b.name.strip(), b.email.lower(), b.role.strip(), b.department.strip(), hash_secret(b.password), now(), now()))
        key = set_recovery(c, i)
        u = row(c, "SELECT * FROM users WHERE id=?", i)
        audit(c, u, "Joined with office code")
        cf = credential_file(c, u, b.password, key, "self-registration")
    return {"token": make_token(u), "credentials_file": cf}


@app.post("/api/auth/login")
def login(b: LoginIn, request: Request):
    rate_limit(request, 20)
    with db() as c:
        u = row(c, "SELECT * FROM users WHERE email=?", b.email.lower())
        if u and u["locked_until"] > now():
            raise HTTPException(429, "Too many failed attempts. Try again in a few minutes.")
        if not u or not check_secret(b.password, u["pw_hash"]):
            if u:
                f = u["fails"] + 1
                c.execute("UPDATE users SET fails=?, locked_until=? WHERE id=?", (0 if f >= MAX_FAILS else f, now() + LOCK_SECS if f >= MAX_FAILS else 0, u["id"]))
                c.commit()
            raise HTTPException(401, "Email or password is incorrect.")
        if not u["active"]:
            raise HTTPException(403, "This account is deactivated. Contact your workspace admin.")
        c.execute("UPDATE users SET fails=0, last_login=? WHERE id=?", (now(), u["id"]))
    return {"token": make_token(u)}


@app.patch("/api/me")
def update_me(b: ProfileIn, u: dict = Depends(auth)):
    data = b.model_dump(exclude_none=True)
    with db() as c:
        for k, v in data.items():
            c.execute(f"UPDATE users SET {k}=? WHERE id=?", (v.strip(), u["id"]))
        return pub(row(c, "SELECT * FROM users WHERE id=?", u["id"]))


@app.post("/api/auth/recover")
def recover(b: RecoverIn, request: Request):
    """Forgot-password: email + personal recovery key sets a new password, then rotates the key."""
    rate_limit(request, 10, 300)
    pw_ok(b.new_password)
    with db() as c:
        u = row(c, "SELECT * FROM users WHERE email=?", b.email.lower())
        if u and u["rec_locked"] > now():
            raise HTTPException(429, "Too many wrong recovery attempts. Try again later or ask your admin to reissue your credentials.")
        if not u or not u["recovery_hash"]:
            hash_secret(norm_key(b.recovery_key))                      # same work either way: no account enumeration
            raise HTTPException(401, "Email or recovery key is incorrect.")
        if not check_secret(norm_key(b.recovery_key), u["recovery_hash"]):
            f = u["rec_fails"] + 1
            c.execute("UPDATE users SET rec_fails=?, rec_locked=? WHERE id=?", (0 if f >= REC_MAX_FAILS else f, now() + REC_LOCK_SECS if f >= REC_MAX_FAILS else 0, u["id"]))
            c.commit()
            raise HTTPException(401, "Email or recovery key is incorrect.")
        if not u["active"]:
            raise HTTPException(403, "This account is deactivated. Contact your workspace admin.")
        c.execute("UPDATE users SET pw_hash=?, must_change=0, token_ver=token_ver+1, fails=0, locked_until=0 WHERE id=?", (hash_secret(b.new_password), u["id"]))
        key = set_recovery(c, u["id"])                                  # rotate: a used key cannot be replayed
        fresh = row(c, "SELECT * FROM users WHERE id=?", u["id"])
        audit(c, fresh, "Reset password with recovery key")
        cf = credential_file(c, fresh, b.new_password, key, "password-recovery")
    return {"token": make_token(fresh), "credentials_file": cf}


@app.post("/api/me/recovery-key")
def regenerate_recovery_key(b: KeyIn, u: dict = Depends(auth)):
    if not check_secret(b.current, u["pw_hash"]):
        raise HTTPException(403, "Current password is incorrect.")
    with db() as c:
        key = set_recovery(c, u["id"])
        audit(c, u, "Generated a new recovery key")
        return {"credentials_file": credential_file(c, u, None, key, "recovery-key-regeneration")}


@app.post("/api/me/password")
def change_password(b: PasswordIn, u: dict = Depends(auth)):
    if not check_secret(b.current, u["pw_hash"]):
        raise HTTPException(403, "Current password is incorrect.")
    pw_ok(b.new)
    with db() as c:
        c.execute("UPDATE users SET pw_hash=?, must_change=0, token_ver=token_ver+1 WHERE id=?", (hash_secret(b.new), u["id"]))
        fresh = row(c, "SELECT * FROM users WHERE id=?", u["id"])
    return {"token": make_token(fresh)}


@app.get("/api/bootstrap")
def bootstrap(u: dict = Depends(auth)):
    with db() as c:
        ws = row(c, "SELECT * FROM workspaces WHERE id=?", u["ws_id"])
        users = [pub(x) for x in rows(c, "SELECT * FROM users WHERE ws_id=? AND active=1 ORDER BY name", ws["id"])]
        if u["access"] == "admin":
            tl = rows(c, "SELECT * FROM teams WHERE ws_id=? ORDER BY name", ws["id"])
        else:
            tl = rows(c, "SELECT t.* FROM teams t JOIN team_members m ON m.team_id=t.id WHERE t.ws_id=? AND m.user_id=? ORDER BY t.name", ws["id"], u["id"])
        teams = [team_view(c, t) for t in tl]
        meetings = [meeting_view(r) for r in rows(c, "SELECT * FROM rooms WHERE ws_id=? AND kind='meeting' ORDER BY created DESC LIMIT 100", ws["id"])]
        calls = [{"id": r["id"], "title": r["title"], "owner": r["owner_id"], "members": [m["user_id"] for m in rows(c, "SELECT user_id FROM room_members WHERE room_id=?", r["id"])]}
                 for r in rows(c, "SELECT r.* FROM rooms r JOIN room_members m ON m.room_id=r.id WHERE r.kind='call' AND m.user_id=? ORDER BY r.created DESC LIMIT 20", u["id"])]
        dms = [r["id"] for r in rows(c, "SELECT r.id FROM rooms r JOIN room_members m ON m.room_id=r.id WHERE r.kind='dm' AND m.user_id=?", u["id"])]
        ids = dms + [t["room"] for t in teams] + [s["id"] for t in teams for s in t["spaces"]] + [x["id"] for x in calls]
        unread, last = {}, {}
        if ids:
            q = ",".join("?" * len(ids))
            for r in rows(c, f"""SELECT m.room_id r, COUNT(*) n FROM messages m LEFT JOIN reads x ON x.room_id=m.room_id AND x.user_id=?
                WHERE m.room_id IN ({q}) AND m.id>MAX(COALESCE(x.last_id,0),COALESCE(x.cleared_id,0)) AND m.user_id!=? AND m.system=0 AND m.deleted=0 GROUP BY m.room_id""", u["id"], u["id"], *ids):
                unread[r["r"]] = r["n"]
            for m in rows(c, f"SELECT * FROM messages WHERE id IN (SELECT MAX(id) FROM messages WHERE room_id IN ({q}) AND deleted=0 GROUP BY room_id)", *ids):
                last[m["room_id"]] = {"text": m["text"][:80], "ts": m["ts"], "user": m["user_id"], "file": bool(m["file_id"]), "system": bool(m["system"])}
    info = {k: ws[k] for k in ("name", "location", "registration_number", "industry", "description")}
    if u["access"] == "admin":
        info.update(office_code=ws["office_code"], self_register=bool(ws["self_register"]))
    return {"me": {**pub(u), "must_change": bool(u["must_change"]), "recovery_issued": u["recovery_issued"]}, "workspace": info, "users": users,
            "teams": teams, "meetings": meetings, "calls": calls, "unread": unread, "last": last}


# ---- admin
@app.get("/api/admin/stats")
def admin_stats(a: dict = Depends(admin_only)):
    with db() as c:
        w = a["ws_id"]
        one = lambda s, *p: row(c, s, w, *p)["n"]
        days = rows(c, "SELECT date(m.ts,'unixepoch') d, COUNT(*) n FROM messages m JOIN rooms r ON r.id=m.room_id WHERE r.ws_id=? AND m.ts>? AND m.system=0 GROUP BY d ORDER BY d", w, now() - 7 * 86400)
        return {"users": one("SELECT COUNT(*) n FROM users WHERE ws_id=?"), "active": one("SELECT COUNT(*) n FROM users WHERE ws_id=? AND active=1"),
                "admins": one("SELECT COUNT(*) n FROM users WHERE ws_id=? AND access='admin' AND active=1"),
                "teams": one("SELECT COUNT(*) n FROM teams WHERE ws_id=?"), "meetings": one("SELECT COUNT(*) n FROM rooms WHERE ws_id=? AND kind='meeting'"),
                "spaces": one("SELECT COUNT(*) n FROM rooms WHERE ws_id=? AND kind='space' AND expires>?", now()),
                "messages": one("SELECT COUNT(*) n FROM messages m JOIN rooms r ON r.id=m.room_id WHERE r.ws_id=? AND m.system=0"),
                "online": len(conns), "days": days}


@app.get("/api/admin/users")
def admin_users(a: dict = Depends(admin_only)):
    with db() as c:
        return [{**pub(x), "last_login": x["last_login"], "created": x["created"], "must_change": bool(x["must_change"]), "recovery_issued": x["recovery_issued"]}
                for x in rows(c, "SELECT * FROM users WHERE ws_id=? ORDER BY active DESC, name", a["ws_id"])]


@app.get("/api/admin/users.csv")
def admin_users_csv(a: dict = Depends(admin_only)):
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["name", "email", "role", "department", "phone", "access", "active", "last_login"])
    with db() as c:
        for x in rows(c, "SELECT * FROM users WHERE ws_id=? ORDER BY name", a["ws_id"]):
            w.writerow([x["name"], x["email"], x["role"], x["department"], x["phone"], x["access"], x["active"],
                        time.strftime("%Y-%m-%d %H:%M", time.gmtime(x["last_login"])) if x["last_login"] else ""])
    return Response(out.getvalue(), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=employees.csv"})


@app.post("/api/admin/users", status_code=201)
def admin_create_user(b: AdminUserIn, a: dict = Depends(admin_only)):
    pw_ok(b.password)
    if b.access not in ACCESS:
        raise HTTPException(422, "Access must be admin, manager or member.")
    with db() as c:
        if row(c, "SELECT 1 x FROM users WHERE email=?", b.email.lower()):
            raise HTTPException(409, "This email is already registered.")
        i = uid()
        c.execute("INSERT INTO users(id,ws_id,name,email,role,department,phone,access,pw_hash,must_change,created) VALUES(?,?,?,?,?,?,?,?,?,1,?)",
                  (i, a["ws_id"], b.name.strip(), b.email.lower(), b.role.strip(), b.department.strip(), b.phone.strip(), b.access, hash_secret(b.password), now()))
        key = set_recovery(c, i)
        audit(c, a, f"Created account {b.email.lower()} ({b.access}) with credential file")
        nu = row(c, "SELECT * FROM users WHERE id=?", i)
        return {**pub(nu), "credentials_file": credential_file(c, nu, b.password, key, "admin:" + a["name"])}


@app.patch("/api/admin/users/{user_id}")
async def admin_patch_user(user_id: str, b: UserPatch, a: dict = Depends(admin_only)):
    data = b.model_dump(exclude_none=True)
    with db() as c:
        t = row(c, "SELECT * FROM users WHERE id=? AND ws_id=?", user_id, a["ws_id"])
        if not t:
            raise HTTPException(404, "User not found.")
        if t["id"] == a["id"] and (data.get("active") is False or data.get("access", "admin") != "admin"):
            raise HTTPException(400, "You cannot demote or deactivate your own admin account.")
        if "access" in data and data["access"] not in ACCESS:
            raise HTTPException(422, "Access must be admin, manager or member.")
        if "active" in data:
            data["active"] = int(data["active"])
            data["token_ver"] = t["token_ver"] + 1
        for k, v in data.items():
            c.execute(f"UPDATE users SET {k}=? WHERE id=?", (v.strip() if isinstance(v, str) else v, user_id))
        audit(c, a, f"Updated {t['email']}: " + ", ".join(k for k in data if k != "token_ver"))
        res = pub(row(c, "SELECT * FROM users WHERE id=?", user_id))
    if data.get("active") == 0:
        for s in list(conns.get(user_id, ())):
            await s.close(code=4401)
    return res


@app.post("/api/admin/users/{user_id}/reset-password")
def admin_reset_pw(user_id: str, a: dict = Depends(admin_only)):
    temp = secrets.token_urlsafe(8) + "7a"
    with db() as c:
        t = row(c, "SELECT * FROM users WHERE id=? AND ws_id=?", user_id, a["ws_id"])
        if not t:
            raise HTTPException(404, "User not found.")
        c.execute("UPDATE users SET pw_hash=?, must_change=1, token_ver=token_ver+1, fails=0, locked_until=0 WHERE id=?", (hash_secret(temp), user_id))
        key = set_recovery(c, user_id)
        audit(c, a, f"Reset password and reissued credentials for {t['email']}")
        cf = credential_file(c, row(c, "SELECT * FROM users WHERE id=?", user_id), temp, key, "admin:" + a["name"])
    return {"temporary_password": temp, "credentials_file": cf}


@app.post("/api/admin/rotate-secret")
def rotate_secret(a: dict = Depends(admin_only)):
    s = secrets.token_urlsafe(9)
    with db() as c:
        c.execute("UPDATE workspaces SET secret_hash=? WHERE id=?", (hash_secret(s), a["ws_id"]))
        audit(c, a, "Rotated office secret")
    return {"secret": s}


@app.patch("/api/admin/workspace")
def admin_workspace(b: WorkspacePatch, a: dict = Depends(admin_only)):
    data = b.model_dump(exclude_none=True)
    with db() as c:
        for k, v in data.items():
            c.execute(f"UPDATE workspaces SET {k}=? WHERE id=?", (int(v) if isinstance(v, bool) else v.strip(), a["ws_id"]))
        audit(c, a, "Updated workspace: " + ", ".join(data))
    return {"ok": True}


@app.get("/api/admin/audit")
def admin_audit(a: dict = Depends(admin_only)):
    with db() as c:
        return rows(c, "SELECT actor,action,ts FROM audit WHERE ws_id=? ORDER BY id DESC LIMIT 300", a["ws_id"])


@app.get("/api/admin/teams")
def admin_teams(a: dict = Depends(admin_only)):
    with db() as c:
        return [team_view(c, t) for t in rows(c, "SELECT * FROM teams WHERE ws_id=? ORDER BY name", a["ws_id"])]


# ---- teams
@app.post("/api/teams", status_code=201)
def create_team(b: TeamIn, u: dict = Depends(auth)):
    if u["access"] not in ("admin", "manager"):
        raise HTTPException(403, "Only admins and managers can create teams.")
    with db() as c:
        valid = {i["id"] for i in rows(c, "SELECT id FROM users WHERE ws_id=? AND active=1", u["ws_id"])}
        ids = {u["id"], *[i for i in b.member_ids if i in valid]}
        tid = uid()
        c.execute("INSERT INTO teams(id,ws_id,name,department,description,owner_id,created) VALUES(?,?,?,?,?,?,?)",
                  (tid, u["ws_id"], b.name.strip(), b.department.strip(), b.description.strip(), u["id"], now()))
        rid = new_room(c, u["ws_id"], "team", b.name.strip(), team_id=tid, owner_id=u["id"])
        c.execute("UPDATE teams SET room_id=? WHERE id=?", (rid, tid))
        c.executemany("INSERT INTO team_members VALUES(?,?)", [(tid, i) for i in ids])
        add_msg(c, rid, None, f"{u['name']} created the {b.name.strip()} team ({b.department.strip()}).", True)
        audit(c, u, f"Created team {b.name.strip()}")
        return team_view(c, get_team(c, tid, u))


@app.patch("/api/teams/{tid}")
def patch_team(tid: str, b: TeamPatch, u: dict = Depends(auth)):
    with db() as c:
        t = get_team(c, tid, u)
        if not can_manage(t, u):
            raise HTTPException(403, "Only the team owner or an admin can edit a team.")
        for k, v in b.model_dump(exclude_none=True).items():
            c.execute(f"UPDATE teams SET {k}=? WHERE id=?", (v.strip(), tid))
            if k == "name":
                c.execute("UPDATE rooms SET title=? WHERE id=?", (v.strip(), t["room_id"]))
        return team_view(c, get_team(c, tid, u))


@app.post("/api/teams/{tid}/members")
def add_member(tid: str, b: MemberIn, u: dict = Depends(auth)):
    with db() as c:
        t = get_team(c, tid, u)
        tu = row(c, "SELECT * FROM users WHERE id=? AND ws_id=? AND active=1", b.user_id, u["ws_id"])
        if not can_manage(t, u):
            raise HTTPException(403, "Only the team owner or an admin can manage members.")
        if not tu:
            raise HTTPException(404, "User not found.")
        if c.execute("INSERT OR IGNORE INTO team_members VALUES(?,?)", (tid, b.user_id)).rowcount:
            add_msg(c, t["room_id"], None, f"{tu['name']} joined the team.", True)
        return team_view(c, t)


@app.delete("/api/teams/{tid}/members/{user_id}")
def remove_member(tid: str, user_id: str, u: dict = Depends(auth)):
    with db() as c:
        t = get_team(c, tid, u)
        if not (can_manage(t, u) or user_id == u["id"]):
            raise HTTPException(403, "Only the team owner or an admin can remove members.")
        if user_id == t["owner_id"]:
            raise HTTPException(400, "The team owner cannot be removed. Delete the team instead.")
        c.execute("DELETE FROM team_members WHERE team_id=? AND user_id=?", (tid, user_id))
        return team_view(c, t)


@app.delete("/api/teams/{tid}")
def delete_team(tid: str, u: dict = Depends(auth)):
    with db() as c:
        t = get_team(c, tid, u)
        if not can_manage(t, u):
            raise HTTPException(403, "Only the team owner or an admin can delete a team.")
        drop_files(c, "team_id=? OR id=?", tid, t["room_id"])
        c.execute("DELETE FROM rooms WHERE team_id=? OR id=?", (tid, t["room_id"]))
        c.execute("DELETE FROM teams WHERE id=?", (tid,))
        audit(c, u, f"Deleted team {t['name']}")
    return {"ok": True}


@app.post("/api/teams/{tid}/spaces", status_code=201)
def create_space(tid: str, b: SpaceIn, u: dict = Depends(auth)):
    with db() as c:
        get_team(c, tid, u)
        if u["id"] not in team_ids(c, tid) and u["access"] != "admin":
            raise HTTPException(403, "Join the team to create spaces.")
        rid = new_room(c, u["ws_id"], "space", b.name.strip(), team_id=tid, owner_id=u["id"], expires=now() + b.hours * 3600)
        add_msg(c, rid, None, f"Temporary space opened by {u['name']}. It closes in {b.hours}h.", True)
        return {"id": rid}


@app.delete("/api/spaces/{rid}")
def close_space(rid: str, u: dict = Depends(auth)):
    with db() as c:
        r = get_room(c, rid, u)
        t = get_team(c, r["team_id"], u) if r["kind"] == "space" else None
        if not t or not (r["owner_id"] == u["id"] or can_manage(t, u)):
            raise HTTPException(403, "Only the space creator, team owner or an admin can close a space.")
        drop_files(c, "id=?", rid)
        c.execute("DELETE FROM rooms WHERE id=?", (rid,))
    return {"ok": True}


# ---- rooms: dm, meetings, calls, messages
@app.get("/api/dm/{other}")
def open_dm(other: str, u: dict = Depends(auth)):
    with db() as c:
        if other == u["id"] or not row(c, "SELECT 1 x FROM users WHERE id=? AND ws_id=? AND active=1", other, u["ws_id"]):
            raise HTTPException(404, "Contact not found.")
        rid = "dm_" + "_".join(sorted([u["id"], other]))
        if not row(c, "SELECT 1 x FROM rooms WHERE id=?", rid):
            new_room(c, u["ws_id"], "dm", "Direct chat", [u["id"], other], rid=rid)
    return {"id": rid}


@app.post("/api/meetings", status_code=201)
def create_meeting(b: MeetingIn, u: dict = Depends(auth)):
    with db() as c:
        rid = new_room(c, u["ws_id"], "meeting", b.title.strip(), rid=uuid.uuid4().hex[:8], owner_id=u["id"],
                       description=b.description.strip(), scheduled_at=b.scheduled_at or None)
        audit(c, u, f"Created meeting {b.title.strip()}")
    return {"id": rid}


@app.patch("/api/meetings/{rid}")
def edit_meeting(rid: str, b: MeetingIn, u: dict = Depends(auth)):
    with db() as c:
        r = get_room(c, rid, u)
        if r["kind"] != "meeting" or not (r["owner_id"] == u["id"] or u["access"] == "admin"):
            raise HTTPException(403, "Only the organiser or an admin can edit this meeting.")
        c.execute("UPDATE rooms SET title=?, description=?, scheduled_at=? WHERE id=?", (b.title.strip(), b.description.strip(), b.scheduled_at or None, rid))
    return {"ok": True}


@app.delete("/api/meetings/{rid}")
def delete_meeting(rid: str, u: dict = Depends(auth)):
    with db() as c:
        r = get_room(c, rid, u)
        if r["kind"] != "meeting" or not (r["owner_id"] == u["id"] or u["access"] == "admin"):
            raise HTTPException(403, "Only the organiser or an admin can delete this meeting.")
        drop_files(c, "id=?", rid)
        c.execute("DELETE FROM rooms WHERE id=?", (rid,))
        audit(c, u, f"Deleted meeting {r['title']}")
    return {"ok": True}


@app.post("/api/calls", status_code=201)
def create_call(b: CallIn, u: dict = Depends(auth)):
    with db() as c:
        ids = {u["id"], *b.invite_ids}
        n = row(c, f"SELECT COUNT(*) n FROM users WHERE ws_id=? AND active=1 AND id IN ({','.join('?' * len(ids))})", u["ws_id"], *ids)["n"]
        if n != len(ids):
            raise HTTPException(404, "One of the invited contacts was not found.")
        return {"id": new_room(c, u["ws_id"], "call", b.title.strip(), ids, owner_id=u["id"])}


@app.get("/api/rooms/{rid}")
def room_info(rid: str, u: dict = Depends(auth)):
    with db() as c:
        r = get_room(c, rid, u)
        r["members"] = [m["user_id"] for m in rows(c, "SELECT user_id FROM room_members WHERE room_id=?", rid)]
        return r


class ReactIn(BaseModel):
    emoji: str = Field(min_length=1, max_length=8)


class ClearIn(BaseModel):
    scope: str = "me"


@app.get("/api/rooms/{rid}/messages")
def room_messages(rid: str, before: int = 0, q: str = "", limit: int = 50, u: dict = Depends(auth)):
    with db() as c:
        r = get_room(c, rid, u)
        cl = row(c, "SELECT COALESCE(cleared_id,0) n FROM reads WHERE room_id=? AND user_id=?", rid, u["id"])
        sql, args = "SELECT * FROM messages WHERE room_id=? AND id>? AND id NOT IN (SELECT message_id FROM hidden WHERE user_id=?)", [rid, cl["n"] if cl else 0, u["id"]]
        if before:
            sql, args = sql + " AND id<?", args + [before]
        if q.strip():
            esc = q.strip().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            sql, args = sql + " AND deleted=0 AND text LIKE ? ESCAPE '\\'", args + [f"%{esc}%"]
        data = rows(c, sql + " ORDER BY id DESC LIMIT ?", *args, min(max(limit, 1), 100))
        peer = 0
        if r["kind"] == "dm":
            other = [x for x in rid[3:].split("_") if x != u["id"]]
            pr = row(c, "SELECT last_id FROM reads WHERE room_id=? AND user_id=?", rid, other[0]) if other else None
            peer = pr["last_id"] if pr else 0
        return {"messages": view_msgs(c, list(reversed(data))), "peer_read": peer}


@app.post("/api/rooms/{rid}/read")
async def mark_read(rid: str, u: dict = Depends(auth)):
    with db() as c:
        r = get_room(c, rid, u)
        last = row(c, "SELECT COALESCE(MAX(id),0) n FROM messages WHERE room_id=?", rid)["n"]
        c.execute("INSERT INTO reads(room_id,user_id,last_id) VALUES(?,?,?) ON CONFLICT(room_id,user_id) DO UPDATE SET last_id=excluded.last_id", (rid, u["id"], last))
        aud = audience(c, r)
    if r["kind"] == "dm":
        await to_many(aud, {"t": "read", "room": rid, "user": u["id"], "last": last}, exclude=u["id"])
    return {"ok": True}


@app.patch("/api/messages/{mid}")
async def edit_message(mid: int, b: MsgIn, u: dict = Depends(auth)):
    with db() as c:
        m = row(c, "SELECT * FROM messages WHERE id=?", mid)
        if not m or m["user_id"] != u["id"] or m["deleted"] or m["system"]:
            raise HTTPException(403, "You can only edit your own messages.")
        c.execute("UPDATE messages SET text=?, edited=1 WHERE id=?", (b.text.strip(), mid))
        room, view = row(c, "SELECT * FROM rooms WHERE id=?", m["room_id"]), msg_view(c, row(c, "SELECT * FROM messages WHERE id=?", mid))
        aud = audience(c, room)
    await to_many(aud, {"t": "msg_edit", "room": room["id"], "msg": view})
    return view


@app.delete("/api/messages/{mid}")
async def delete_message(mid: int, scope: str = "everyone", u: dict = Depends(auth)):
    with db() as c:
        m = row(c, "SELECT * FROM messages WHERE id=?", mid)
        room = row(c, "SELECT * FROM rooms WHERE id=?", m["room_id"]) if m else None
        if not m or not can_access(c, u, room):
            raise HTTPException(404, "Message not found.")
        if scope == "me":                                   # delete for me only
            c.execute("INSERT OR IGNORE INTO hidden VALUES(?,?)", (mid, u["id"]))
            return {"ok": True}
        team = row(c, "SELECT * FROM teams WHERE id=?", room["team_id"]) if room["team_id"] else None
        if m["system"] or (m["user_id"] != u["id"] and not (u["access"] == "admin" or (team and team["owner_id"] == u["id"]))):
            raise HTTPException(403, "You can only delete your own messages for everyone.")
        if m["file_id"]:
            f = row(c, "SELECT key FROM files WHERE id=?", m["file_id"])
            if f:
                storage.delete(f["key"])
            c.execute("DELETE FROM files WHERE id=?", (m["file_id"],))
        c.execute("UPDATE messages SET deleted=1, text='', file_id=NULL WHERE id=?", (mid,))
        aud = audience(c, room)
    await to_many(aud, {"t": "msg_del", "room": room["id"], "id": mid})
    return {"ok": True}


@app.post("/api/messages/{mid}/react")
async def react(mid: int, b: ReactIn, u: dict = Depends(auth)):
    with db() as c:
        m = row(c, "SELECT * FROM messages WHERE id=?", mid)
        room = row(c, "SELECT * FROM rooms WHERE id=?", m["room_id"]) if m else None
        if not m or m["deleted"] or not can_access(c, u, room):
            raise HTTPException(404, "Message not found.")
        ex = row(c, "SELECT emoji FROM reactions WHERE message_id=? AND user_id=?", mid, u["id"])
        if ex and ex["emoji"] == b.emoji:
            c.execute("DELETE FROM reactions WHERE message_id=? AND user_id=?", (mid, u["id"]))
        else:
            c.execute("INSERT OR REPLACE INTO reactions VALUES(?,?,?)", (mid, u["id"], b.emoji))
        view, aud = msg_view(c, m), audience(c, room)
    await to_many(aud, {"t": "msg_edit", "room": room["id"], "msg": view})
    return view


@app.post("/api/rooms/{rid}/clear")
async def clear_chat(rid: str, b: ClearIn, u: dict = Depends(auth)):
    with db() as c:
        r = get_room(c, rid, u)
        last = row(c, "SELECT COALESCE(MAX(id),0) n FROM messages WHERE room_id=?", rid)["n"]
        if b.scope == "all":                                # wipes the conversation for everyone
            team = row(c, "SELECT * FROM teams WHERE id=?", r["team_id"]) if r["team_id"] else None
            if r["kind"] == "dm" or not (u["access"] == "admin" or r["owner_id"] == u["id"] or (team and team["owner_id"] == u["id"])):
                raise HTTPException(403, "Only the owner or an admin can clear a group chat for everyone.")
            for f in rows(c, "SELECT key FROM files WHERE room_id=?", rid):
                storage.delete(f["key"])
            c.execute("DELETE FROM files WHERE room_id=?", (rid,))
            c.execute("DELETE FROM messages WHERE room_id=?", (rid,))
            audit(c, u, f"Cleared chat {r['title']} for everyone")
            aud = audience(c, r)
        else:                                               # clear for me only
            c.execute("INSERT INTO reads(room_id,user_id,last_id,cleared_id) VALUES(?,?,?,?) ON CONFLICT(room_id,user_id) DO UPDATE SET cleared_id=excluded.cleared_id, last_id=excluded.last_id",
                      (rid, u["id"], last, last))
            aud = []
    await to_many(aud, {"t": "cleared", "room": rid})
    return {"ok": True}


@app.post("/api/rooms/{rid}/upload", status_code=201)
async def upload(rid: str, request: Request, name: str, mime: str = "application/octet-stream", caption: str = "", reply_to: int = 0, u: dict = Depends(auth)):
    """Raw-body upload (no extra dependency). Streams to storage and enforces the 50 MB limit while reading."""
    with db() as c:
        r = get_room(c, rid, u)
    name = Path(name).name[:120] or "file"
    ext = re.sub(r"[^a-z0-9.]", "", Path(name).suffix.lower())[:10]
    if ext in BLOCKED_EXT:
        raise HTTPException(415, "This file type is not allowed.")
    if int(request.headers.get("content-length") or 0) > MAX_UPLOAD:
        raise HTTPException(413, "Files can be up to 50 MB.")
    if not re.match(r"^[\w.+-]+/[\w.+-]+$", mime):
        mime = "application/octet-stream"
    fid = uid()
    key, size = fid + ext, 0
    try:
        with open(storage.path(key), "wb") as fh:
            async for chunk in request.stream():
                size += len(chunk)
                if size > MAX_UPLOAD:
                    raise HTTPException(413, "Files can be up to 50 MB.")
                fh.write(chunk)
        if size == 0:
            raise HTTPException(400, "The file is empty.")
    except HTTPException:
        storage.delete(key)
        raise
    except Exception:
        storage.delete(key)
        raise HTTPException(400, "Upload failed. Try again.")
    with db() as c:
        c.execute("INSERT INTO files(id,room_id,user_id,name,size,mime,key,created) VALUES(?,?,?,?,?,?,?,?)", (fid, rid, u["id"], name, size, mime[:100], key, now()))
        rp = reply_to if row(c, "SELECT 1 x FROM messages WHERE id=? AND room_id=?", reply_to, rid) else None
        msg = add_msg(c, rid, u["id"], caption.strip()[:1000], reply_to=rp, file_id=fid)
        aud = audience(c, r)
    await to_many(aud, {"t": "chat", "room": rid, "msg": msg})
    return msg


@app.get("/api/files/{fid}")
def get_file(fid: str, token: str = "", inline: int = 0, authorization: str = Header(None)):
    u = load_user(token or (authorization or "").removeprefix("Bearer ").strip())
    if not u:
        raise HTTPException(401, "Session expired. Sign in again.")
    with db() as c:
        f = row(c, "SELECT * FROM files WHERE id=?", fid)
        r = row(c, "SELECT * FROM rooms WHERE id=?", f["room_id"]) if f else None
        if not f or not can_access(c, u, r):
            raise HTTPException(404, "File not found.")
    p = storage.path(f["key"])
    if not p.exists():
        raise HTTPException(404, "File not found.")
    safe = bool(inline) and f["mime"].startswith(INLINE_OK)   # only inert types render in the browser
    return FileResponse(p, media_type=f["mime"] if safe else "application/octet-stream", filename=f["name"],
                        content_disposition_type="inline" if safe else "attachment")


@app.get("/api/rooms/{rid}/files")
def room_files(rid: str, u: dict = Depends(auth)):
    with db() as c:
        get_room(c, rid, u)
        cl = row(c, "SELECT COALESCE(cleared_id,0) n FROM reads WHERE room_id=? AND user_id=?", rid, u["id"])
        return rows(c, """SELECT f.id,f.name,f.size,f.mime,f.created,f.user_id FROM files f JOIN messages m ON m.file_id=f.id
            WHERE f.room_id=? AND m.id>? AND m.id NOT IN (SELECT message_id FROM hidden WHERE user_id=?) ORDER BY f.created DESC LIMIT 200""",
                    rid, cl["n"] if cl else 0, u["id"])


# --------------------------------------------------------------------------- realtime
conns: dict = {}      # user_id -> set[WebSocket]
CALLS: dict = {}      # room_id -> set[user_id]
SUBS: dict = {}       # meeting room_id -> set[user_id]
SHARING: dict = {}    # room_id -> {user_id: screen stream id}


async def send(user_id, msg):
    for s in list(conns.get(user_id, ())):
        try:
            await s.send_json(msg)
        except Exception:
            conns.get(user_id, set()).discard(s)


async def to_many(ids, msg, exclude=None):
    for i in ids:
        if i != exclude:
            await send(i, msg)


def audience(c, r) -> list:
    online = set(conns)
    if r["kind"] == "meeting":
        return list((SUBS.get(r["id"], set()) | CALLS.get(r["id"], set())) & online)
    if r["team_id"]:
        ids = set(team_ids(c, r["team_id"])) | {x["id"] for x in rows(c, "SELECT id FROM users WHERE ws_id=? AND access='admin'", r["ws_id"])}
    else:
        ids = {x["user_id"] for x in rows(c, "SELECT user_id FROM room_members WHERE room_id=?", r["id"])}
    return list(ids & online)


def ws_peers(c, ws_id):
    return [i for i in list(conns) if (row(c, "SELECT ws_id FROM users WHERE id=?", i) or {}).get("ws_id") == ws_id]


async def leave_call(u, rid):
    peers = CALLS.get(rid)
    if not peers or u["id"] not in peers:
        return
    peers.discard(u["id"])
    SHARING.get(rid, {}).pop(u["id"], None)
    await to_many(list(peers), {"t": "peer_leave", "room": rid, "user": u["id"]})
    with db() as c:
        r = row(c, "SELECT * FROM rooms WHERE id=?", rid)
        if r:
            aud, m = audience(c, r), add_msg(c, rid, None, f"{u['name']} left the call.", True)
    if r:
        await to_many(aud, {"t": "call_state", "room": rid, "count": len(peers)})
        await to_many(aud, {"t": "chat", "room": rid, "msg": m})
    if not peers:
        CALLS.pop(rid, None)
        SHARING.pop(rid, None)


async def handle(u, sock, m):
    t, rid = m.get("t"), m.get("room")
    if t == "ping":
        return await sock.send_json({"t": "pong"})
    msg = None
    with db() as c:
        r = row(c, "SELECT * FROM rooms WHERE id=?", rid) if isinstance(rid, str) else None
        if not (r and can_access(c, u, r) and not (r["expires"] and r["expires"] < now())):
            return await sock.send_json({"t": "error", "msg": "That room is unavailable."})
        aud = audience(c, r)
        if t == "chat":
            text = str(m.get("text", "")).strip()[:4000]
            rp = m.get("reply_to")
            if not (isinstance(rp, int) and row(c, "SELECT 1 x FROM messages WHERE id=? AND room_id=?", rp, rid)):
                rp = None
            msg = add_msg(c, rid, u["id"], text, reply_to=rp) if text else None
        elif t == "call_join" and (u["id"] in CALLS.get(rid, ()) or len(CALLS.get(rid, ())) < MAX_CALL):
            msg = add_msg(c, rid, None, f"{u['name']} joined the call.", True)
    if t == "open":
        SUBS.setdefault(rid, set()).add(u["id"])
        await sock.send_json({"t": "call_state", "room": rid, "count": len(CALLS.get(rid, ()))})
    elif t == "chat" and msg:
        await to_many(aud, {"t": "chat", "room": rid, "msg": msg})
    elif t == "typing":
        await to_many(aud, {"t": "typing", "room": rid, "user": u["id"]}, exclude=u["id"])
    elif t == "call_join":
        if not msg:
            return await sock.send_json({"t": "error", "msg": f"Calls support up to {MAX_CALL} people."})
        peers = CALLS.setdefault(rid, set())
        others = [p for p in peers if p != u["id"]]
        peers.add(u["id"])
        await sock.send_json({"t": "peers", "room": rid, "peers": others, "sharing": SHARING.get(rid, {})})
        aud = list(set(aud) | {u["id"]})
        await to_many(aud, {"t": "call_state", "room": rid, "count": len(peers)})
        await to_many(aud, {"t": "chat", "room": rid, "msg": msg})
    elif t == "share":                                  # only the sharer toggles their own share
        on, sid = bool(m.get("on")), str(m.get("sid", ""))[:80]
        if u["id"] in CALLS.get(rid, ()):
            if on:
                SHARING.setdefault(rid, {})[u["id"]] = sid
            else:
                SHARING.get(rid, {}).pop(u["id"], None)
            await to_many(list(CALLS[rid]), {"t": "share", "room": rid, "from": u["id"], "on": on, "sid": sid}, exclude=u["id"])
    elif t == "call_leave":
        await leave_call(u, rid)
    elif t == "sig":
        if u["id"] in CALLS.get(rid, ()) and m.get("to") in CALLS.get(rid, ()):
            await send(m["to"], {"t": "sig", "room": rid, "from": u["id"], "data": m.get("data")})
    elif t == "ring":
        allowed = set(conns) if r["kind"] == "meeting" else None
        with db() as c:
            for to in [x for x in (m.get("to") or [])[:MAX_CALL] if x != u["id"] and x in conns]:
                tu = load_user_by_id(c, to)
                if tu and (allowed is not None and tu["ws_id"] == u["ws_id"] or can_access(c, tu, r)):
                    await send(to, {"t": "ring", "room": rid, "from": u["id"], "title": r["title"], "kind": r["kind"]})


def load_user_by_id(c, i):
    return row(c, "SELECT * FROM users WHERE id=? AND active=1", i)


@app.websocket("/ws")
async def ws_endpoint(sock: WebSocket, token: str = ""):
    u = load_user(token)
    if not u:
        await sock.close(code=4401)
        return
    await sock.accept()
    first = u["id"] not in conns
    conns.setdefault(u["id"], set()).add(sock)
    if first:
        with db() as c:
            peers = ws_peers(c, u["ws_id"])
        await to_many(peers, {"t": "presence", "user": u["id"], "online": True})
    try:
        while True:
            d = await sock.receive_json()
            if isinstance(d, dict):
                await handle(u, sock, d)
    except (WebSocketDisconnect, RuntimeError):
        pass
    except Exception as e:
        print("ws error:", e)
    finally:
        conns.get(u["id"], set()).discard(sock)
        if not conns.get(u["id"]):
            conns.pop(u["id"], None)
            for rid in [k for k, p in CALLS.items() if u["id"] in p]:
                await leave_call(u, rid)
            for s in SUBS.values():
                s.discard(u["id"])
            with db() as c:
                peers = ws_peers(c, u["ws_id"])
            await to_many(peers, {"t": "presence", "user": u["id"], "online": False})