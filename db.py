# db.py
import os
import sqlite3
import hashlib
import secrets
from datetime import date
from typing import List, Dict, Tuple, Optional

import pandas as pd

DB_PATH = os.getenv("SPLIT_DB_PATH", "split.db")


# ------------------------
# ID helpers
# ------------------------
def new_page_id() -> str:
    """
    8 chars, URL-safe, easy to read.
    Uses [a-z0-9] only.
    """
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(secrets.choice(alphabet) for _ in range(8))


def _norm_page_id(page_id) -> str:
    if page_id is None:
        return ""
    return str(page_id).strip()


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db() -> None:
    conn = get_conn()
    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS pages (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            password_salt TEXT,
            password_hash TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            is_deleted INTEGER NOT NULL DEFAULT 0,
            deleted_at TEXT
        )
        """
    )

    # page_id must be TEXT to match pages.id
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS members (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            page_id TEXT NOT NULL,
            name TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            is_deleted INTEGER NOT NULL DEFAULT 0,
            deleted_at TEXT,
            UNIQUE(page_id, name),
            FOREIGN KEY (page_id) REFERENCES pages(id)
        )
        """
    )

    # page_id must be TEXT to match pages.id
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS expenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            page_id TEXT NOT NULL,
            expense_date TEXT NOT NULL,
            description TEXT NOT NULL,
            amount REAL NOT NULL CHECK (amount >= 0),
            currency TEXT NOT NULL CHECK (currency IN ('USD', 'JPY')),
            paid_by_member_id INTEGER NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            is_deleted INTEGER NOT NULL DEFAULT 0,
            deleted_at TEXT,
            FOREIGN KEY (page_id) REFERENCES pages(id),
            FOREIGN KEY (paid_by_member_id) REFERENCES members(id)
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS expense_shares (
            expense_id INTEGER NOT NULL,
            member_id INTEGER NOT NULL,
            is_deleted INTEGER NOT NULL DEFAULT 0,
            deleted_at TEXT,
            PRIMARY KEY (expense_id, member_id),
            FOREIGN KEY (expense_id) REFERENCES expenses(id) ON DELETE CASCADE,
            FOREIGN KEY (member_id) REFERENCES members(id)
        )
        """
    )

    conn.commit()
    conn.close()


# ------------------------
# Password helpers
# ------------------------
def _hash_password(password: str, salt_hex: str) -> str:
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(salt_hex),
        200_000,
    )
    return dk.hex()


def _make_password_record(password: str) -> Tuple[str, str]:
    salt_hex = secrets.token_hex(16)
    pw_hash = _hash_password(password, salt_hex)
    return salt_hex, pw_hash


def verify_page_password(page_id, password: str) -> Tuple[bool, str]:
    page_id = _norm_page_id(page_id)
    password = (password or "").strip()

    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "SELECT password_salt, password_hash FROM pages WHERE id = ? AND is_deleted = 0",
        (page_id,),
    )
    row = cur.fetchone()
    conn.close()

    if not row:
        return False, "Page not found"

    salt = row["password_salt"]
    pw_hash = row["password_hash"]

    if salt is None or pw_hash is None:
        return True, "No password"

    if not password:
        return False, "Password required"

    ok = _hash_password(password, salt) == pw_hash
    return (True, "OK") if ok else (False, "Wrong password")


# ------------------------
# Page ops
# ------------------------
def create_page(name: str, password: str) -> Tuple[bool, str]:
    name = (name or "").strip()
    password = (password or "").strip()
    if not name:
        return False, "Page name is empty"

    salt = None
    pw_hash = None
    if password:
        salt, pw_hash = _make_password_record(password)

    conn = get_conn()
    cur = conn.cursor()

    # id衝突は極小だけど、一応リトライ
    for _ in range(10):
        pid = new_page_id()
        try:
            cur.execute(
                """
                INSERT INTO pages (id, name, password_salt, password_hash)
                VALUES (?, ?, ?, ?)
                """,
                (pid, name, salt, pw_hash),
            )
            conn.commit()
            return True, "Created"
        except sqlite3.IntegrityError as e:
            # name の重複
            if "pages.name" in str(e) or "UNIQUE" in str(e):
                conn.rollback()
                return False, "That page name already exists"
            # id がたまたま衝突した場合はリトライ
            conn.rollback()
            continue
        finally:
            # 成功でも失敗でも close は最後にやりたいので、ここではしない
            pass

    conn.close()
    return False, "Failed to create page id. Try again."


def list_pages(include_deleted: bool = False) -> List[sqlite3.Row]:
    conn = get_conn()
    cur = conn.cursor()
    if include_deleted:
        cur.execute("SELECT id, name, password_hash, is_deleted, deleted_at FROM pages ORDER BY name COLLATE NOCASE")
    else:
        cur.execute(
            """
            SELECT id, name, password_hash
            FROM pages
            WHERE is_deleted = 0
            ORDER BY name COLLATE NOCASE
            """
        )
    rows = cur.fetchall()
    conn.close()
    return rows


def get_page(page_id) -> Optional[sqlite3.Row]:
    page_id = _norm_page_id(page_id)
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, name, password_hash FROM pages WHERE id = ? AND is_deleted = 0",
        (page_id,),
    )
    row = cur.fetchone()
    conn.close()
    return row


# ------------------------
# Member ops (page-scoped)
# ------------------------
def add_member(page_id, name: str) -> Tuple[bool, str]:
    page_id = _norm_page_id(page_id)
    name = (name or "").strip()
    if not name:
        return False, "Name is empty"

    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO members (page_id, name) VALUES (?, ?)",
            (page_id, name),
        )
        conn.commit()
        return True, "Added"
    except sqlite3.IntegrityError:
        return False, "That name already exists"
    finally:
        conn.close()


def get_members(page_id, include_deleted: bool = False) -> List[sqlite3.Row]:
    page_id = _norm_page_id(page_id)
    conn = get_conn()
    cur = conn.cursor()
    if include_deleted:
        cur.execute(
            """
            SELECT id, name, is_deleted, deleted_at
            FROM members
            WHERE page_id = ?
            ORDER BY name COLLATE NOCASE
            """,
            (page_id,),
        )
    else:
        cur.execute(
            """
            SELECT id, name
            FROM members
            WHERE page_id = ? AND is_deleted = 0
            ORDER BY name COLLATE NOCASE
            """,
            (page_id,),
        )
    rows = cur.fetchall()
    conn.close()
    return rows


def member_usage_count(page_id, member_id: int) -> int:
    page_id = _norm_page_id(page_id)
    conn = get_conn()
    cur = conn.cursor()

    cur.execute(
        """
        SELECT COUNT(*) AS c
        FROM expenses
        WHERE page_id = ? AND paid_by_member_id = ? AND is_deleted = 0
        """,
        (page_id, int(member_id)),
    )
    c1 = int(cur.fetchone()["c"])

    cur.execute(
        """
        SELECT COUNT(*) AS c
        FROM expense_shares s
        JOIN expenses e ON e.id = s.expense_id
        WHERE e.page_id = ? AND s.member_id = ? AND s.is_deleted = 0 AND e.is_deleted = 0
        """,
        (page_id, int(member_id)),
    )
    c2 = int(cur.fetchone()["c"])

    conn.close()
    return c1 + c2


def rename_member(page_id, member_id: int, new_name: str) -> Tuple[bool, str]:
    page_id = _norm_page_id(page_id)
    new_name = (new_name or "").strip()
    if not new_name:
        return False, "Name is empty"

    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            UPDATE members
            SET name = ?
            WHERE page_id = ? AND id = ? AND is_deleted = 0
            """,
            (new_name, page_id, int(member_id)),
        )
        if cur.rowcount == 0:
            conn.rollback()
            return False, "Member not found"
        conn.commit()
        return True, "Updated"
    except sqlite3.IntegrityError:
        return False, "That name already exists"
    finally:
        conn.close()


def soft_delete_member_everywhere(page_id, member_id: int) -> Tuple[bool, str]:
    page_id = _norm_page_id(page_id)
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            UPDATE expenses
            SET is_deleted = 1, deleted_at = datetime('now')
            WHERE page_id = ? AND paid_by_member_id = ? AND is_deleted = 0
            """,
            (page_id, int(member_id)),
        )

        cur.execute(
            """
            UPDATE expense_shares
            SET is_deleted = 1, deleted_at = datetime('now')
            WHERE member_id = ? AND is_deleted = 0
              AND expense_id IN (SELECT id FROM expenses WHERE page_id = ?)
            """,
            (int(member_id), page_id),
        )

        cur.execute(
            """
            UPDATE expenses
            SET is_deleted = 1, deleted_at = datetime('now')
            WHERE page_id = ? AND is_deleted = 0
              AND id IN (
                SELECT e.id
                FROM expenses e
                LEFT JOIN expense_shares s
                  ON s.expense_id = e.id AND s.is_deleted = 0
                WHERE e.page_id = ? AND e.is_deleted = 0
                GROUP BY e.id
                HAVING COUNT(s.member_id) = 0
              )
            """,
            (page_id, page_id),
        )

        cur.execute(
            """
            UPDATE members
            SET is_deleted = 1, deleted_at = datetime('now')
            WHERE page_id = ? AND id = ? AND is_deleted = 0
            """,
            (page_id, int(member_id)),
        )

        conn.commit()
        return True, "Deleted"
    except Exception as e:
        conn.rollback()
        return False, f"Delete failed: {e}"
    finally:
        conn.close()


def restore_member(page_id, member_id: int) -> Tuple[bool, str]:
    page_id = _norm_page_id(page_id)
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            UPDATE members
            SET is_deleted = 0, deleted_at = NULL
            WHERE page_id = ? AND id = ? AND is_deleted = 1
            """,
            (page_id, int(member_id)),
        )
        if cur.rowcount == 0:
            conn.rollback()
            return False, "Member not found"
        conn.commit()
        return True, "Restored"
    except Exception as e:
        conn.rollback()
        return False, f"Restore failed: {e}"
    finally:
        conn.close()


# ------------------------
# Expense ops (page-scoped)
# ------------------------
def add_expense(
    page_id,
    expense_date: date,
    description: str,
    amount: float,
    currency: str,
    paid_by_member_id: int,
    target_member_ids: List[int],
) -> Tuple[bool, str]:
    page_id = _norm_page_id(page_id)
    description = (description or "").strip()
    if not description:
        return False, "Title is empty"
    if amount is None or amount < 0:
        return False, "Invalid amount"
    if currency not in ("USD", "JPY"):
        return False, "Invalid currency"
    if not target_member_ids:
        return False, "Please select targets"

    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            "SELECT is_deleted FROM members WHERE page_id = ? AND id = ?",
            (page_id, int(paid_by_member_id)),
        )
        r = cur.fetchone()
        if not r or int(r["is_deleted"]) == 1:
            conn.rollback()
            return False, "Payer not found"

        qmarks = ",".join(["?"] * len(target_member_ids))
        cur.execute(
            f"""
            SELECT COUNT(*) AS c
            FROM members
            WHERE page_id = ? AND id IN ({qmarks}) AND is_deleted = 0
            """,
            [page_id] + [int(x) for x in target_member_ids],
        )
        if int(cur.fetchone()["c"]) != len(target_member_ids):
            conn.rollback()
            return False, "Targets include deleted members"

        cur.execute(
            """
            INSERT INTO expenses (page_id, expense_date, description, amount, currency, paid_by_member_id)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (page_id, expense_date.isoformat(), description, float(amount), currency, int(paid_by_member_id)),
        )
        expense_id = cur.lastrowid

        cur.executemany(
            "INSERT INTO expense_shares (expense_id, member_id, is_deleted, deleted_at) VALUES (?, ?, 0, NULL)",
            [(int(expense_id), int(mid)) for mid in target_member_ids],
        )

        conn.commit()
        return True, "Saved"
    except Exception as e:
        conn.rollback()
        return False, f"Save failed: {e}"
    finally:
        conn.close()


def update_expense(
    page_id,
    expense_id: int,
    expense_date: date,
    description: str,
    amount: float,
    currency: str,
    paid_by_member_id: int,
    target_member_ids: List[int],
) -> Tuple[bool, str]:
    page_id = _norm_page_id(page_id)
    description = (description or "").strip()
    if not description:
        return False, "Title is empty"
    if amount is None or amount < 0:
        return False, "Invalid amount"
    if currency not in ("USD", "JPY"):
        return False, "Invalid currency"
    if not target_member_ids:
        return False, "Please select targets"

    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            "SELECT is_deleted FROM expenses WHERE page_id = ? AND id = ?",
            (page_id, int(expense_id)),
        )
        r = cur.fetchone()
        if not r or int(r["is_deleted"]) == 1:
            conn.rollback()
            return False, "Expense not found"

        cur.execute(
            "SELECT is_deleted FROM members WHERE page_id = ? AND id = ?",
            (page_id, int(paid_by_member_id)),
        )
        rr = cur.fetchone()
        if not rr or int(rr["is_deleted"]) == 1:
            conn.rollback()
            return False, "Payer not found"

        qmarks = ",".join(["?"] * len(target_member_ids))
        cur.execute(
            f"""
            SELECT COUNT(*) AS c
            FROM members
            WHERE page_id = ? AND id IN ({qmarks}) AND is_deleted = 0
            """,
            [page_id] + [int(x) for x in target_member_ids],
        )
        if int(cur.fetchone()["c"]) != len(target_member_ids):
            conn.rollback()
            return False, "Targets include deleted members"

        cur.execute(
            """
            UPDATE expenses
            SET expense_date = ?, description = ?, amount = ?, currency = ?, paid_by_member_id = ?
            WHERE page_id = ? AND id = ? AND is_deleted = 0
            """,
            (
                expense_date.isoformat(),
                description,
                float(amount),
                currency,
                int(paid_by_member_id),
                page_id,
                int(expense_id),
            ),
        )

        cur.execute(
            """
            UPDATE expense_shares
            SET is_deleted = 1, deleted_at = datetime('now')
            WHERE expense_id = ? AND is_deleted = 0
            """,
            (int(expense_id),),
        )

        for mid in target_member_ids:
            cur.execute(
                """
                INSERT INTO expense_shares (expense_id, member_id, is_deleted, deleted_at)
                VALUES (?, ?, 0, NULL)
                ON CONFLICT(expense_id, member_id)
                DO UPDATE SET is_deleted = 0, deleted_at = NULL
                """,
                (int(expense_id), int(mid)),
            )

        cur.execute(
            "SELECT COUNT(*) AS c FROM expense_shares WHERE expense_id = ? AND is_deleted = 0",
            (int(expense_id),),
        )
        if int(cur.fetchone()["c"]) == 0:
            cur.execute(
                "UPDATE expenses SET is_deleted = 1, deleted_at = datetime('now') WHERE page_id = ? AND id = ?",
                (page_id, int(expense_id)),
            )

        conn.commit()
        return True, "Updated"
    except Exception as e:
        conn.rollback()
        return False, f"Update failed: {e}"
    finally:
        conn.close()


def soft_delete_expense(page_id, expense_id: int) -> Tuple[bool, str]:
    page_id = _norm_page_id(page_id)
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            UPDATE expenses
            SET is_deleted = 1, deleted_at = datetime('now')
            WHERE page_id = ? AND id = ? AND is_deleted = 0
            """,
            (page_id, int(expense_id)),
        )
        if cur.rowcount == 0:
            conn.rollback()
            return False, "Expense not found"

        cur.execute(
            """
            UPDATE expense_shares
            SET is_deleted = 1, deleted_at = datetime('now')
            WHERE expense_id = ? AND is_deleted = 0
            """,
            (int(expense_id),),
        )

        conn.commit()
        return True, "Deleted"
    except Exception as e:
        conn.rollback()
        return False, f"Delete failed: {e}"
    finally:
        conn.close()


def restore_expense(page_id, expense_id: int) -> Tuple[bool, str]:
    page_id = _norm_page_id(page_id)
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            SELECT paid_by_member_id
            FROM expenses
            WHERE page_id = ? AND id = ? AND is_deleted = 1
            """,
            (page_id, int(expense_id)),
        )
        row = cur.fetchone()
        if not row:
            conn.rollback()
            return False, "Expense not found"

        payer_id = int(row["paid_by_member_id"])
        cur.execute(
            "SELECT is_deleted FROM members WHERE page_id = ? AND id = ?",
            (page_id, payer_id),
        )
        payer = cur.fetchone()
        if not payer or int(payer["is_deleted"]) == 1:
            conn.rollback()
            return False, "Cannot restore: payer is deleted"

        cur.execute(
            """
            UPDATE expenses
            SET is_deleted = 0, deleted_at = NULL
            WHERE page_id = ? AND id = ? AND is_deleted = 1
            """,
            (page_id, int(expense_id)),
        )

        cur.execute(
            """
            UPDATE expense_shares
            SET is_deleted = 0, deleted_at = NULL
            WHERE expense_id = ?
              AND member_id IN (SELECT id FROM members WHERE page_id = ? AND is_deleted = 0)
            """,
            (int(expense_id), page_id),
        )

        cur.execute(
            "SELECT COUNT(*) AS c FROM expense_shares WHERE expense_id = ? AND is_deleted = 0",
            (int(expense_id),),
        )
        if int(cur.fetchone()["c"]) == 0:
            cur.execute(
                """
                UPDATE expenses
                SET is_deleted = 1, deleted_at = datetime('now')
                WHERE page_id = ? AND id = ?
                """,
                (page_id, int(expense_id)),
            )
            conn.commit()
            return False, "Cannot restore: no active targets"

        conn.commit()
        return True, "Restored"
    except Exception as e:
        conn.rollback()
        return False, f"Restore failed: {e}"
    finally:
        conn.close()


def fetch_expenses(page_id, active_only: bool = True) -> List[Dict]:
    page_id = _norm_page_id(page_id)
    conn = get_conn()
    cur = conn.cursor()

    if active_only:
        cur.execute(
            """
            SELECT
                e.id,
                e.expense_date,
                e.description,
                e.amount,
                e.currency,
                e.paid_by_member_id,
                e.created_at,
                m.name AS paid_by
            FROM expenses e
            JOIN members m ON m.id = e.paid_by_member_id
            WHERE e.page_id = ?
              AND e.is_deleted = 0
              AND m.is_deleted = 0
            ORDER BY e.expense_date DESC, e.created_at DESC, e.id DESC
            """,
            (page_id,),
        )
    else:
        cur.execute(
            """
            SELECT
                e.id,
                e.expense_date,
                e.description,
                e.amount,
                e.currency,
                e.paid_by_member_id,
                e.created_at,
                e.is_deleted,
                e.deleted_at,
                m.name AS paid_by
            FROM expenses e
            JOIN members m ON m.id = e.paid_by_member_id
            WHERE e.page_id = ?
            ORDER BY e.expense_date DESC, e.created_at DESC, e.id DESC
            """,
            (page_id,),
        )

    expenses = [dict(r) for r in cur.fetchall()]

    for ex in expenses:
        if active_only:
            cur.execute(
                """
                SELECT m.id, m.name
                FROM expense_shares s
                JOIN members m ON m.id = s.member_id
                WHERE s.expense_id = ?
                  AND s.is_deleted = 0
                  AND m.is_deleted = 0
                  AND m.page_id = ?
                ORDER BY m.name COLLATE NOCASE
                """,
                (int(ex["id"]), page_id),
            )
            rows = cur.fetchall()
            ex["target_ids"] = [r["id"] for r in rows]
            ex["targets"] = [r["name"] for r in rows]
        else:
            cur.execute(
                """
                SELECT m.id, m.name, s.is_deleted
                FROM expense_shares s
                JOIN members m ON m.id = s.member_id
                WHERE s.expense_id = ?
                  AND m.page_id = ?
                ORDER BY m.name COLLATE NOCASE
                """,
                (int(ex["id"]), page_id),
            )
            rows = cur.fetchall()
            ex["target_ids"] = [r["id"] for r in rows if int(r["is_deleted"]) == 0]
            ex["targets"] = [r["name"] for r in rows if int(r["is_deleted"]) == 0]

    conn.close()
    return expenses


def compute_net_balances(page_id) -> Dict[str, Dict[str, float]]:
    page_id = _norm_page_id(page_id)
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("SELECT id, name FROM members WHERE page_id = ? AND is_deleted = 0", (page_id,))
    members = cur.fetchall()
    id_to_name = {r["id"]: r["name"] for r in members}

    balances: Dict[str, Dict[str, float]] = {"USD": {}, "JPY": {}}
    for name in id_to_name.values():
        balances["USD"][name] = 0.0
        balances["JPY"][name] = 0.0

    cur.execute(
        """
        SELECT id, amount, currency, paid_by_member_id
        FROM expenses
        WHERE page_id = ?
          AND is_deleted = 0
          AND paid_by_member_id IN (SELECT id FROM members WHERE page_id = ? AND is_deleted = 0)
        """,
        (page_id, page_id),
    )
    expenses = cur.fetchall()

    for ex in expenses:
        ex_id = int(ex["id"])
        amount = float(ex["amount"])
        currency = ex["currency"]
        payer_id = int(ex["paid_by_member_id"])

        cur.execute(
            """
            SELECT member_id
            FROM expense_shares
            WHERE expense_id = ? AND is_deleted = 0
              AND member_id IN (SELECT id FROM members WHERE page_id = ? AND is_deleted = 0)
            """,
            (ex_id, page_id),
        )
        targets = [int(r["member_id"]) for r in cur.fetchall()]
        if not targets:
            continue

        split = amount / len(targets)

        payer_name = id_to_name.get(payer_id)
        if payer_name is None:
            continue
        balances[currency][payer_name] += amount

        for t in targets:
            t_name = id_to_name.get(t)
            if t_name is None:
                continue
            balances[currency][t_name] -= split

    conn.close()
    return balances


def build_transaction_matrix(page_id, currency: str) -> pd.DataFrame:
    page_id = _norm_page_id(page_id)
    members = get_members(page_id)
    member_names = [m["name"] for m in members]
    if not member_names:
        return pd.DataFrame()

    conn = get_conn()
    cur = conn.cursor()

    cur.execute(
        """
        SELECT
            e.id,
            e.expense_date,
            e.created_at,
            e.description,
            e.amount,
            m.name AS payer_name
        FROM expenses e
        JOIN members m ON m.id = e.paid_by_member_id
        WHERE e.page_id = ?
          AND e.currency = ?
          AND e.is_deleted = 0
          AND m.is_deleted = 0
        ORDER BY e.expense_date DESC, e.created_at DESC, e.id DESC
        """,
        (page_id, currency),
    )
    exp_rows = cur.fetchall()

    expense_ids = [int(r["id"]) for r in exp_rows]
    targets_map: Dict[int, List[str]] = {eid: [] for eid in expense_ids}

    if expense_ids:
        qmarks = ",".join(["?"] * len(expense_ids))
        cur.execute(
            f"""
            SELECT s.expense_id, m.name AS target_name
            FROM expense_shares s
            JOIN members m ON m.id = s.member_id
            WHERE s.expense_id IN ({qmarks})
              AND s.is_deleted = 0
              AND m.is_deleted = 0
              AND m.page_id = ?
            """,
            expense_ids + [page_id],
        )
        for r in cur.fetchall():
            targets_map[int(r["expense_id"])].append(r["target_name"])

    conn.close()

    data_rows: List[Dict] = []
    for r in exp_rows:
        eid = int(r["id"])
        when_str = r["expense_date"]
        created_at = r["created_at"]
        title = r["description"]
        amount = float(r["amount"])
        payer = r["payer_name"]
        targets = targets_map.get(eid, [])

        if not targets:
            continue

        split = amount / len(targets)

        row = {"When": when_str, "Created at": created_at, "Title": title}
        for name in member_names:
            row[name] = 0.0

        row[payer] += amount
        for t in targets:
            row[t] -= split

        data_rows.append(row)

    df = pd.DataFrame(data_rows)
    if df.empty:
        return df

    cols = ["When", "Created at", "Title"] + member_names
    return df[cols]


# ------------------------
# Bulk / Danger ops (page-scoped)
# ------------------------
def soft_delete_all_expenses(page_id) -> Tuple[bool, str]:
    page_id = _norm_page_id(page_id)
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            UPDATE expenses
            SET is_deleted = 1, deleted_at = datetime('now')
            WHERE page_id = ? AND is_deleted = 0
            """,
            (page_id,),
        )
        cur.execute(
            """
            UPDATE expense_shares
            SET is_deleted = 1, deleted_at = datetime('now')
            WHERE expense_id IN (SELECT id FROM expenses WHERE page_id = ?)
              AND is_deleted = 0
            """,
            (page_id,),
        )
        conn.commit()
        return True, "Deleted all history (soft delete)"
    except Exception as e:
        conn.rollback()
        return False, f"Bulk delete failed: {e}"
    finally:
        conn.close()


def soft_delete_all_members_everywhere(page_id) -> Tuple[bool, str]:
    page_id = _norm_page_id(page_id)
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            UPDATE expenses
            SET is_deleted = 1, deleted_at = datetime('now')
            WHERE page_id = ? AND is_deleted = 0
            """,
            (page_id,),
        )

        cur.execute(
            """
            UPDATE expense_shares
            SET is_deleted = 1, deleted_at = datetime('now')
            WHERE expense_id IN (SELECT id FROM expenses WHERE page_id = ?)
              AND is_deleted = 0
            """,
            (page_id,),
        )

        cur.execute(
            """
            UPDATE members
            SET is_deleted = 1, deleted_at = datetime('now')
            WHERE page_id = ? AND is_deleted = 0
            """,
            (page_id,),
        )

        conn.commit()
        return True, "Deleted all members and history (soft delete)"
    except Exception as e:
        conn.rollback()
        return False, f"Bulk delete failed: {e}"
    finally:
        conn.close()


def wipe_page(page_id) -> Tuple[bool, str]:
    """
    Delete ALL data for a single page (members, expenses, shares, and the page itself).
    This does NOT delete the whole DB file.
    """
    page_id = _norm_page_id(page_id)
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute("SELECT id FROM pages WHERE id = ? AND is_deleted = 0", (page_id,))
        if not cur.fetchone():
            conn.rollback()
            return False, "Page not found"

        # shares -> expenses -> members -> page
        cur.execute(
            """
            DELETE FROM expense_shares
            WHERE expense_id IN (SELECT id FROM expenses WHERE page_id = ?)
            """,
            (page_id,),
        )
        cur.execute("DELETE FROM expenses WHERE page_id = ?", (page_id,))
        cur.execute("DELETE FROM members WHERE page_id = ?", (page_id,))
        cur.execute("DELETE FROM pages WHERE id = ?", (page_id,))

        conn.commit()
        return True, "Deleted this page and all its data"
    except Exception as e:
        conn.rollback()
        return False, f"Wipe failed: {e}"
    finally:
        conn.close()


def delete_db_file() -> Tuple[bool, str]:
    try:
        if os.path.exists(DB_PATH):
            os.remove(DB_PATH)
        return True, "DB file deleted. Restart the app."
    except Exception as e:
        return False, f"Delete DB failed: {e}"