
import fcntl
import hashlib, secrets, sqlite3, threading
from pathlib import Path
from fastapi import Header, HTTPException
from pydantic import BaseModel

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
DB_PATH = DATA / "app.db"
FRONTEND = ROOT / "frontend"
SESSIONS: dict[str, str] = {}


def lock_dir() -> Path:
    # 锁目录随库走：不同 SQLite 文件（含测试临时库）各用一套锁，杜绝跨库争用串扰
    return Path(DB_PATH).parent / "locks"

# 同载荷（主题+字段指纹）跨进程/跨线程串行化：两名值班同抢一条载荷时排队，后到只记争用
_PAYLOAD_LOCKS: dict[str, threading.Lock] = {}
_LOCKS_GUARD = threading.Lock()


def payload_lock(key: str) -> threading.Lock:
    with _LOCKS_GUARD:
        lk = _PAYLOAD_LOCKS.get(key)
        if lk is None:
            lk = threading.Lock()
            _PAYLOAD_LOCKS[key] = lk
        return lk


class PayloadGate:
    """跨进程排他闸：fcntl 锁文件 + 进程内线程锁，覆盖整个校验临界区。

    同载荷在所有进程/线程间互斥；非阻塞 try_acquire 失败即说明已有同载荷校验在途。
    """

    def __init__(self, key: str):
        ldir = lock_dir()
        ldir.mkdir(parents=True, exist_ok=True)
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]
        self._path = ldir / f"payload-{digest}.lock"
        self._fh = open(self._path, "a+")
        self._thread_lock = payload_lock(key)
        self._held_thread = False

    def try_acquire(self) -> bool:
        if not self._thread_lock.acquire(blocking=False):
            return False
        try:
            fcntl.flock(self._fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self._thread_lock.release()
            return False
        self._held_thread = True
        return True

    def release(self) -> None:
        if self._held_thread:
            try:
                fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)
            finally:
                self._held_thread = False
                self._thread_lock.release()

    def close(self) -> None:
        try:
            self._fh.close()
        except OSError:
            pass


def connect():
    DATA.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    # WAL + busy_timeout：跨连接写入排队，避免 SQLITE_BUSY 把失败闭合写路径打成 500
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    return conn

def sha(p: str) -> str:
    return hashlib.sha256(p.encode("utf-8")).hexdigest()

def ensure_users(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS users(
        username TEXT PRIMARY KEY, password_sha TEXT NOT NULL, role TEXT NOT NULL)""")
    if conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"] == 0:
        conn.execute("INSERT INTO users VALUES (?,?,?)", ("admin", sha("123456"), "管理员"))
        conn.execute("INSERT INTO users VALUES (?,?,?)", ("viewer", sha("view123"), "只读"))

class LoginIn(BaseModel):
    username: str
    password: str

def require_user(authorization: str | None) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "未登录")
    u = SESSIONS.get(authorization.removeprefix("Bearer ").strip())
    if not u:
        raise HTTPException(401, "登录已失效")
    return u

from datetime import datetime
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

PRODUCT = "入站契约"
SKELETON = "Schema 契约版本约束入站校验，破坏性变更进缓冲或拒收，并与落库结果对账"

app = FastAPI(title=PRODUCT)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

def init_db():
    with connect() as conn:
        ensure_users(conn)
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS contracts(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          version TEXT UNIQUE NOT NULL,
          subject TEXT NOT NULL,
          mode TEXT NOT NULL,
          track TEXT NOT NULL,
          status TEXT NOT NULL,
          required_fields TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS ingress_batches(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          subject TEXT NOT NULL,
          payload_fields TEXT NOT NULL,
          contract_version TEXT,
          result TEXT NOT NULL,
          detail TEXT NOT NULL,
          created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS buffers(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          batch_id INTEGER NOT NULL,
          reason TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS validation_contention(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          subject TEXT NOT NULL,
          payload_fields TEXT NOT NULL,
          detail TEXT NOT NULL,
          created_at TEXT NOT NULL
        );
        """)
        if conn.execute("SELECT COUNT(*) c FROM contracts").fetchone()["c"] == 0:
            conn.execute("INSERT INTO contracts(version,subject,mode,track,status,required_fields) VALUES (?,?,?,?,?,?)",
                         ("v3","订单入站","严格","正式","启用","order_id,amount,currency"))
            conn.execute("INSERT INTO contracts(version,subject,mode,track,status,required_fields) VALUES (?,?,?,?,?,?)",
                         ("v4-shadow","订单入站","兼容","影子","试跑","order_id,amount,currency,channel"))
            conn.execute("INSERT INTO contracts(version,subject,mode,track,status,required_fields) VALUES (?,?,?,?,?,?)",
                         ("v2","库存入站","严格","正式","停用","sku,qty"))

@app.on_event("startup")
def _s():
    init_db()

@app.get("/api/health")
def health():
    with connect() as c:
        n = c.execute("SELECT COUNT(*) c FROM contracts").fetchone()["c"]
    return {"ok": True, "product": PRODUCT, "skeleton": SKELETON, "contracts": n, "db": str(DB_PATH)}

@app.post("/api/login")
def login(body: LoginIn):
    with connect() as c:
        row = c.execute("SELECT username,role FROM users WHERE username=? AND password_sha=?", (body.username, sha(body.password))).fetchone()
    if not row: raise HTTPException(401, "账号或密码错误")
    tok = secrets.token_hex(16); SESSIONS[tok]=row["username"]
    return {"token": tok, "username": row["username"], "role": row["role"]}

@app.get("/api/contracts")
def contracts(authorization: str | None = Header(default=None)):
    require_user(authorization)
    with connect() as c:
        return {"items":[dict(r) for r in c.execute("SELECT * FROM contracts ORDER BY id").fetchall()]}

class IngressIn(BaseModel):
    subject: str
    payload_fields: str  # comma fields present


def _field_set(raw: str) -> set[str]:
    return {x.strip() for x in raw.split(",") if x.strip()}


@app.post("/api/ingress/validate")
def validate(body: IngressIn, authorization: str | None = Header(default=None)):
    require_user(authorization)
    fields = _field_set(body.payload_fields)
    now = datetime.now().isoformat(timespec="seconds")
    gate = PayloadGate(f"{body.subject}\x1f{body.payload_fields.strip()}")

    # 两层串行：
    # 1) 跨进程闸门(fcntl+线程锁)——同载荷两名值班同抢时只放一个进临界区，后到只记校验争用(409)；
    # 2) 持闸期间 BEGIN IMMEDIATE 冻结全部外部写——契约改窄/旧缓存无法插进读契约→算缺字段→
    #    写批次的窗口，必填口径在整个事务内一致，缺字段绝无通过态写入。
    if not gate.try_acquire():
        conn = connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "INSERT INTO ingress_batches(subject,payload_fields,contract_version,result,detail,created_at)"
                " VALUES (?,?,?,?,?,?)",
                (body.subject, body.payload_fields, None, "校验争用",
                 "同载荷并发校验争用:已排队,仅保留先到校验结论", now))
            conn.execute(
                "INSERT INTO validation_contention(subject,payload_fields,detail,created_at) VALUES (?,?,?,?)",
                (body.subject, body.payload_fields, "后到校验排队,记校验争用", now))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
            gate.close()
        raise HTTPException(409, "同载荷校验进行中，已记校验争用")

    try:
        # 取闸门后先拍校验起始契约快照（只读短事务），作为本次判决锁定的必填口径
        snap = connect()
        try:
            ctr0 = snap.execute(
                "SELECT * FROM contracts WHERE subject=? AND track='正式' AND status='启用'"
                " ORDER BY id DESC LIMIT 1", (body.subject,)).fetchone()
            if not ctr0:
                raise HTTPException(404, "无启用正式契约")
            snap_version = ctr0["version"]
            snap_mode = ctr0["mode"]
            snap_required = ctr0["required_fields"]
            missing0 = sorted(_field_set(snap_required) - fields)
        finally:
            snap.close()

        conn = connect()
        try:
            # BEGIN IMMEDIATE：在途的契约写会在此排队，提交后我们拿到的是最新值，再与快照比对
            conn.execute("BEGIN IMMEDIATE")
            ctr = conn.execute(
                "SELECT * FROM contracts WHERE subject=? AND track='正式' AND status='启用'"
                " ORDER BY id DESC LIMIT 1", (body.subject,)).fetchone()
            # 契约在本校验期间被改（版本或必填口径变化）→ 故障闭合，禁止按新口径放行
            drifted = ctr is None or ctr["version"] != snap_version or ctr["required_fields"] != snap_required

            if drifted:
                version, mode, missing = snap_version, snap_mode, missing0
                reason = "校验期间契约变更,按起始口径故障闭合;缺字段:" + (",".join(missing) if missing else "无")
            else:
                version, mode, missing = ctr["version"], ctr["mode"], missing0
                reason = ("缺字段:" + ",".join(missing)) if missing else "字段齐全"

            if missing or drifted:
                if mode == "兼容" and missing:
                    # 乙路径：缺字段先进缓冲草稿，确认前不写任何通过标记；批次与缓冲同事务
                    cur = conn.execute(
                        "INSERT INTO ingress_batches(subject,payload_fields,contract_version,result,detail,created_at)"
                        " VALUES (?,?,?,?,?,?)",
                        (body.subject, body.payload_fields, version, "缓冲", reason, now))
                    conn.execute("INSERT INTO buffers(batch_id,reason) VALUES (?,?)",
                                 (cur.lastrowid, "缺字段进双写缓冲"))
                    conn.commit()
                    return {"result": "缓冲", "version": version, "missing": missing, "batch_id": cur.lastrowid}
                # 甲路径（含故障闭合）：拒收批次与原因同一事务落库，通过态零写入
                cur = conn.execute(
                    "INSERT INTO ingress_batches(subject,payload_fields,contract_version,result,detail,created_at)"
                    " VALUES (?,?,?,?,?,?)",
                    (body.subject, body.payload_fields, version, "拒收", reason, now))
                conn.commit()
                return {"result": "拒收", "version": version, "missing": missing, "batch_id": cur.lastrowid}

            cur = conn.execute(
                "INSERT INTO ingress_batches(subject,payload_fields,contract_version,result,detail,created_at)"
                " VALUES (?,?,?,?,?,?)",
                (body.subject, body.payload_fields, version, "通过", "字段齐全", now))
            conn.commit()
            return {"result": "通过", "version": version, "batch_id": cur.lastrowid}
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
    finally:
        gate.release()
        gate.close()

@app.get("/api/ingress")
def ingress(authorization: str | None = Header(default=None)):
    require_user(authorization)
    with connect() as c:
        return {"items":[dict(r) for r in c.execute("SELECT * FROM ingress_batches ORDER BY id DESC").fetchall()]}

@app.get("/api/buffers")
def buffers(authorization: str | None = Header(default=None)):
    require_user(authorization)
    with connect() as c:
        rows = c.execute("""SELECT b.*, i.subject, i.payload_fields FROM buffers b JOIN ingress_batches i ON i.id=b.batch_id ORDER BY b.id DESC""").fetchall()
        return {"items":[dict(r) for r in rows]}

@app.get("/api/contention")
def contention(authorization: str | None = Header(default=None)):
    require_user(authorization)
    with connect() as c:
        return {"items": [dict(r) for r in
                          c.execute("SELECT * FROM validation_contention ORDER BY id DESC").fetchall()]}


@app.get("/api/reconcile")
def reconcile(authorization: str | None = Header(default=None)):
    require_user(authorization)
    with connect() as c:
        total = c.execute("SELECT COUNT(*) c FROM ingress_batches").fetchone()["c"]
        passed = c.execute("SELECT COUNT(*) c FROM ingress_batches WHERE result='通过'").fetchone()["c"]
        buffered = c.execute("SELECT COUNT(*) c FROM ingress_batches WHERE result='缓冲'").fetchone()["c"]
        rejected = c.execute("SELECT COUNT(*) c FROM ingress_batches WHERE result='拒收'").fetchone()["c"]
        contended = c.execute("SELECT COUNT(*) c FROM ingress_batches WHERE result='校验争用'").fetchone()["c"]
        buf_rows = c.execute("SELECT COUNT(*) c FROM buffers").fetchone()["c"]
        contention_rows = c.execute("SELECT COUNT(*) c FROM validation_contention").fetchone()["c"]
        # 假通过巡检：通过态批次必须字段齐全，绝不能携带缺字段说明
        false_pass = c.execute(
            "SELECT COUNT(*) c FROM ingress_batches WHERE result='通过' AND detail!='字段齐全'"
        ).fetchone()["c"]
    return {
        "ingress_total": total,
        "passed": passed,
        "buffered": buffered,
        "rejected": rejected,
        "contended": contended,
        "buffer_rows": buf_rows,
        "contention_rows": contention_rows,
        "aligned": buffered == buf_rows and contended == contention_rows,
        "false_pass": false_pass,
    }

@app.get("/")
def index():
    return FileResponse(FRONTEND / "index.html")
app.mount("/static", StaticFiles(directory=str(FRONTEND)), name="static")
