"""缺字段误通过修复：失败闭合写路径 + 同载荷并发排队记争用。

这些用例在修复前应当失败（红），修复后全绿。
"""
import sqlite3
import threading
from datetime import datetime

import pytest
from fastapi.testclient import TestClient

import app as appmod
from app import app, init_db


@pytest.fixture(autouse=True)
def _db(tmp_path, monkeypatch):
    monkeypatch.setattr(appmod, "DB_PATH", str(tmp_path / "t.db"))
    init_db()
    yield


@pytest.fixture()
def client():
    return TestClient(app)


@pytest.fixture()
def auth(client):
    tok = client.post("/api/login", json={"username": "admin", "password": "123456"}).json()["token"]
    return {"Authorization": f"Bearer {tok}"}


MISSING_PAYLOAD = {"subject": "订单入站", "payload_fields": "order_id,amount"}  # 缺 currency


def _open():
    conn = sqlite3.connect(appmod.DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def test_missing_field_never_persisted_as_pass(client, auth):
    """甲路径：严格模式缺字段拒收，原因与拒收同一事务落库，通过态零写入。"""
    r = client.post("/api/ingress/validate", headers=auth, json=MISSING_PAYLOAD)
    assert r.status_code == 200
    body = r.json()
    assert body["result"] == "拒收"
    assert "currency" in body["missing"]

    with _open() as c:
        row = c.execute("SELECT * FROM ingress_batches WHERE id=?", (body["batch_id"],)).fetchone()
        assert row["result"] == "拒收"
        assert row["detail"].startswith("缺字段:") and "currency" in row["detail"]
        # 通过态零写入：全库不得有任何缺字段载荷被记为通过
        bad = c.execute(
            "SELECT COUNT(*) n FROM ingress_batches WHERE result='通过' AND instr(detail,'缺字段')>0"
        ).fetchone()["n"]
        assert bad == 0
        passed = c.execute("SELECT COUNT(*) n FROM ingress_batches WHERE result='通过'").fetchone()["n"]
        assert passed == 0


def test_compat_mode_missing_field_goes_to_buffer_atomically(client, auth):
    """乙路径：兼容模式缺字段先进缓冲草稿，确认前禁止任何通过标记，双写同一事务。"""
    with _open() as c:
        c.execute("UPDATE contracts SET mode='兼容' WHERE version='v3'")
    r = client.post("/api/ingress/validate", headers=auth, json=MISSING_PAYLOAD)
    assert r.status_code == 200
    body = r.json()
    assert body["result"] == "缓冲"
    with _open() as c:
        row = c.execute("SELECT * FROM ingress_batches WHERE id=?", (body["batch_id"],)).fetchone()
        assert row["result"] != "通过"
        buf = c.execute("SELECT * FROM buffers WHERE batch_id=?", (body["batch_id"],)).fetchone()
        assert buf is not None and "缺字段" in buf["reason"]
        assert c.execute("SELECT COUNT(*) n FROM ingress_batches WHERE result='通过'").fetchone()["n"] == 0


def test_buffer_double_write_rolls_back_together(client, auth, monkeypatch):
    """缓冲双写任一环节失败必须整体回滚，不得留下孤儿批次或假状态。"""
    with _open() as c:
        c.execute("UPDATE contracts SET mode='兼容' WHERE version='v3'")
        c.execute("CREATE TRIGGER boom BEFORE INSERT ON buffers "
                  "BEGIN SELECT RAISE(ABORT,'buffer down'); END")
    with pytest.raises(Exception):
        client.post("/api/ingress/validate", headers=auth, json=MISSING_PAYLOAD)
    with _open() as c:
        assert c.execute("SELECT COUNT(*) n FROM ingress_batches").fetchone()["n"] == 0
        assert c.execute("SELECT COUNT(*) n FROM buffers").fetchone()["n"] == 0


def test_contract_swap_during_validation_cannot_create_false_pass(client, auth):
    """旧缓存/中途改窄契约不得放行：校验事务进行中的契约改窄必须被阻塞，缺字段仍按旧口径拒收。

    确定性场景（不靠时序碰运气）：另一连接先持有 RESERVED 写锁并改窄契约但未提交，
    此时发起校验。校验事务读到的必须是改窄前的必填口径，缺字段一律拒收、零通过。
    """
    holder = _open()
    holder.execute("BEGIN IMMEDIATE")
    holder.execute("UPDATE contracts SET required_fields='order_id' WHERE version='v3'")  # 改窄但未提交

    done = threading.Event()
    outcome = {}

    def worker():
        r = client.post("/api/ingress/validate", headers=auth, json=MISSING_PAYLOAD)
        outcome["status"] = r.status_code
        outcome["body"] = r.json()
        done.set()

    t = threading.Thread(target=worker)
    t.start()
    assert not done.wait(timeout=2), "外部写锁在持期间，校验应等待而非提前判定"

    holder.commit()  # 放行：校验此时才能拿写锁，但它必须按事务内一致口径判决
    holder.close()
    assert done.wait(timeout=5)
    t.join()

    assert outcome["status"] == 200
    assert outcome["body"]["result"] == "拒收", "缺字段不得因契约改窄而通过"
    with _open() as c:
        assert c.execute("SELECT COUNT(*) n FROM ingress_batches WHERE result='通过'").fetchone()["n"] == 0
        row = c.execute("SELECT * FROM ingress_batches WHERE result='拒收'").fetchone()
        assert row is not None and "currency" in row["detail"]
        # 改窄最终落库，但拒收批次锁定的是改窄前契约版本，入站详情与当时必填不打架
        assert c.execute("SELECT required_fields FROM contracts WHERE version='v3'").fetchone()[0] == "order_id"
        assert row["contract_version"] == "v3"


def test_same_payload_concurrent_validation_queues_and_records_contention(client, auth):
    """同载荷两名值班同时抢校验须排队：后到只记校验争用，不产生重复/假通过批次。"""
    barrier = threading.Barrier(2)
    outcomes, http_status = [], []

    def hit():
        barrier.wait()
        r = client.post("/api/ingress/validate", headers=auth, json=MISSING_PAYLOAD)
        http_status.append(r.status_code)
        outcomes.append(r.json())

    t1 = threading.Thread(target=hit)
    t2 = threading.Thread(target=hit)
    t1.start(); t2.start(); t1.join(); t2.join()

    with _open() as c:
        rows = c.execute("SELECT * FROM ingress_batches ORDER BY id").fetchall()
        contention = c.execute(
            "SELECT COUNT(*) n FROM ingress_batches WHERE result='校验争用' OR detail LIKE '%校验争用%'"
        ).fetchone()["n"]
        passed = c.execute("SELECT COUNT(*) n FROM ingress_batches WHERE result='通过'").fetchone()["n"]

    # 全部请求都得到确定答复，且没有通过态；同载荷只允许一条正式校验结论
    assert all(s in (200, 409) for s in http_status)
    assert passed == 0
    decisive = [r for r in rows if r["result"] in ("拒收", "缓冲")]
    assert len(decisive) == 1, f"同载荷应只落一条正式结论，实际 {len(decisive)}"
    assert contention >= 1, "后到的并发校验必须留下校验争用记录"


def test_init_db_is_idempotent_and_creates_contention_ledger(tmp_path, monkeypatch):
    """init_db 重复执行不报错，且争用账册表随库建立。"""
    dbp = str(tmp_path / "id.db")
    monkeypatch.setattr(appmod, "DB_PATH", dbp)
    appmod.init_db()
    appmod.init_db()  # 幂等
    with _open() as c:
        names = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert {"contracts", "ingress_batches", "buffers", "validation_contention"} <= names


def test_gate_released_after_404_so_payload_can_revalidate(client, auth):
    """无契约抛 404 后闸门必须释放：同载荷随后能正常校验，不得被永久判为争用。"""
    r = client.post("/api/ingress/validate", headers=auth,
                    json={"subject": "不存在主题", "payload_fields": "x"})
    assert r.status_code == 404
    # 同一载荷键在真实主题上再校验，应正常落拒收而非 409 争用
    r2 = client.post("/api/ingress/validate", headers=auth, json=MISSING_PAYLOAD)
    assert r2.status_code == 200 and r2.json()["result"] == "拒收"
    r3 = client.post("/api/ingress/validate", headers=auth, json=MISSING_PAYLOAD)
    # 仅当真正并发在途才争用；串行第二次（上一请求已结束）应再次正常处理
    assert r3.status_code == 200 and r3.json()["result"] == "拒收"


def test_read_views_have_no_false_pass(client, auth):
    """入站列表、详情（批次行）、版本目录、缓冲队列、对账账册五处对读均无假通过。"""
    client.post("/api/ingress/validate", headers=auth, json=MISSING_PAYLOAD)
    client.post("/api/ingress/validate", headers=auth,
                json={"subject": "订单入站", "payload_fields": "order_id,amount,currency"})

    ingress = client.get("/api/ingress", headers=auth).json()["items"]
    missing_rows = [i for i in ingress if "缺字段" in i["detail"]]
    assert missing_rows and all(i["result"] != "通过" for i in missing_rows)

    detail = next(i for i in ingress if i["result"] == "通过")
    assert detail["detail"] == "字段齐全"  # 详情与契约必填口径一致

    contracts = client.get("/api/contracts", headers=auth).json()["items"]
    assert any(x["version"] == "v3" and "currency" in x["required_fields"] for x in contracts)

    buffers = client.get("/api/buffers", headers=auth).json()["items"]
    assert all(b["batch_id"] != detail["id"] for b in buffers)

    recon = client.get("/api/reconcile", headers=auth).json()
    assert recon["passed"] == 1
    assert recon["rejected"] >= 1
    assert recon["aligned"] is True
