# db.py (Supabase API version using supabase-py)
# Notes:
# - Uses Supabase REST API (PostgREST) via supabase-py
# - No direct Postgres connections (psycopg is not used)
# - Requires Streamlit secrets:
#   [supabase]
#   url = "https://<PROJECT_REF>.supabase.co"
#   service_role_key = "<SERVICE_ROLE_KEY>"

import hashlib
import secrets
from datetime import date
from typing import List, Dict, Tuple, Optional, Any

import pandas as pd
import streamlit as st
from supabase import create_client, Client


# ------------------------
# Supabase client
# ------------------------
def _supabase_url() -> str:
    try:
        return st.secrets["supabase"]["url"]
    except Exception:
        raise RuntimeError("Missing secrets: set [supabase].url in .streamlit/secrets.toml or Streamlit Cloud Secrets")


def _supabase_service_role_key() -> str:
    try:
        return st.secrets["supabase"]["service_role_key"]
    except Exception:
        raise RuntimeError(
            "Missing secrets: set [supabase].service_role_key in .streamlit/secrets.toml or Streamlit Cloud Secrets"
        )


@st.cache_resource(show_spinner=False)
def _sb() -> Client:
    return create_client(_supabase_url(), _supabase_service_role_key())


def _ok(resp) -> Tuple[bool, Optional[str]]:
    """
    supabase-py returns objects with .data and .error in most versions
    Be defensive across versions.
    """
    err = getattr(resp, "error", None)
    if err:
        return False, str(err)
    return True, None


# ------------------------
# ID helpers
# ------------------------
def new_page_id() -> str:
    """
    8 chars, URL safe, easy to read.
    Uses [a z 0 9] only.
    """
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(secrets.choice(alphabet) for _ in range(8))


def _norm_page_id(page_id) -> str:
    if page_id is None:
        return ""
    return str(page_id).strip()


# ------------------------
# Init
# ------------------------
def init_db() -> None:
    """
    Tables are created in Supabase SQL Editor.
    This only checks that API keys and URL work.
    """
    sb = _sb()
    resp = sb.table("pages").select("id").limit(1).execute()
    ok, msg = _ok(resp)
    if not ok:
        raise RuntimeError(f"Supabase connectivity check failed: {msg}")


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
    sb = _sb()
    page_id = _norm_page_id(page_id)
    password = (password or "").strip()

    resp = (
        sb.table("pages")
        .select("password_salt,password_hash")
        .eq("id", page_id)
        .eq("is_deleted", False)
        .limit(1)
        .execute()
    )
    ok, msg = _ok(resp)
    if not ok:
        return False, f"DB error: {msg}"

    rows = resp.data or []
    if not rows:
        return False, "Page not found"

    salt = rows[0].get("password_salt")
    pw_hash = rows[0].get("password_hash")

    if salt is None or pw_hash is None:
        return True, "No password"

    if not password:
        return False, "Password required"

    ok_pw = _hash_password(password, salt) == pw_hash
    return (True, "OK") if ok_pw else (False, "Wrong password")


# ------------------------
# Page ops
# ------------------------
def create_page(name: str, password: str) -> Tuple[bool, str]:
    sb = _sb()
    name = (name or "").strip()
    password = (password or "").strip()
    if not name:
        return False, "Page name is empty"

    # fast duplicate name check
    chk = sb.table("pages").select("id").eq("name", name).eq("is_deleted", False).limit(1).execute()
    ok, msg = _ok(chk)
    if not ok:
        return False, f"DB error: {msg}"
    if chk.data:
        return False, "That page name already exists"

    salt = None
    pw_hash = None
    if password:
        salt, pw_hash = _make_password_record(password)

    # retry id collision
    for _ in range(10):
        pid = new_page_id()
        payload = {
            "id": pid,
            "name": name,
            "password_salt": salt,
            "password_hash": pw_hash,
            "is_deleted": False,
            "deleted_at": None,
        }
        resp = sb.table("pages").insert(payload).execute()
        ok, msg = _ok(resp)
        if ok:
            return True, "Created"

        # If name was inserted in parallel by someone else, detect and stop
        chk2 = sb.table("pages").select("id").eq("name", name).eq("is_deleted", False).limit(1).execute()
        ok2, _ = _ok(chk2)
        if ok2 and chk2.data:
            return False, "That page name already exists"

        # Otherwise assume id collision or transient error and retry a few times
        continue

    return False, "Failed to create page id. Try again."


def list_pages(include_deleted: bool = False) -> List[Dict]:
    sb = _sb()
    q = sb.table("pages").select("id,name,password_hash,is_deleted,deleted_at")
    if not include_deleted:
        q = q.eq("is_deleted", False)
    resp = q.order("name", desc=False).execute()
    ok, msg = _ok(resp)
    if not ok:
        raise RuntimeError(f"DB error: {msg}")
    return resp.data or []


def get_page(page_id) -> Optional[Dict]:
    sb = _sb()
    page_id = _norm_page_id(page_id)
    resp = (
        sb.table("pages")
        .select("id,name,password_hash,password_salt")
        .eq("id", page_id)
        .eq("is_deleted", False)
        .limit(1)
        .execute()
    )
    ok, msg = _ok(resp)
    if not ok:
        raise RuntimeError(f"DB error: {msg}")
    rows = resp.data or []
    return rows[0] if rows else None


# ------------------------
# Member ops (page scoped)
# ------------------------
def add_member(page_id, name: str) -> Tuple[bool, str]:
    sb = _sb()
    page_id = _norm_page_id(page_id)
    name = (name or "").strip()
    if not name:
        return False, "Name is empty"

    # duplicate check among active members
    chk = (
        sb.table("members")
        .select("id")
        .eq("page_id", page_id)
        .eq("name", name)
        .eq("is_deleted", False)
        .limit(1)
        .execute()
    )
    ok, msg = _ok(chk)
    if not ok:
        return False, f"DB error: {msg}"
    if chk.data:
        return False, "That name already exists"

    resp = sb.table("members").insert({"page_id": page_id, "name": name, "is_deleted": False, "deleted_at": None}).execute()
    ok, msg = _ok(resp)
    if not ok:
        return False, f"DB error: {msg}"
    return True, "Added"


def get_members(page_id, include_deleted: bool = False) -> List[Dict]:
    sb = _sb()
    page_id = _norm_page_id(page_id)
    q = sb.table("members").select("id,name,is_deleted,deleted_at").eq("page_id", page_id)
    if not include_deleted:
        q = q.eq("is_deleted", False)
    resp = q.order("name", desc=False).execute()
    ok, msg = _ok(resp)
    if not ok:
        raise RuntimeError(f"DB error: {msg}")
    return resp.data or []


def member_usage_count(page_id, member_id: int) -> int:
    sb = _sb()
    page_id = _norm_page_id(page_id)
    member_id = int(member_id)

    r1 = (
        sb.table("expenses")
        .select("id", count="exact")
        .eq("page_id", page_id)
        .eq("paid_by_member_id", member_id)
        .eq("is_deleted", False)
        .execute()
    )
    ok, msg = _ok(r1)
    if not ok:
        raise RuntimeError(f"DB error: {msg}")
    c1 = int(getattr(r1, "count", 0) or 0)

    # shares within page: fetch expense ids for page, then count shares for those expense ids
    ex_ids_resp = sb.table("expenses").select("id").eq("page_id", page_id).execute()
    ok, msg = _ok(ex_ids_resp)
    if not ok:
        raise RuntimeError(f"DB error: {msg}")
    ex_ids = [int(r["id"]) for r in (ex_ids_resp.data or [])]
    if not ex_ids:
        return c1

    r2 = (
        sb.table("expense_shares")
        .select("expense_id", count="exact")
        .in_("expense_id", ex_ids)
        .eq("member_id", member_id)
        .eq("is_deleted", False)
        .execute()
    )
    ok, msg = _ok(r2)
    if not ok:
        raise RuntimeError(f"DB error: {msg}")
    c2 = int(getattr(r2, "count", 0) or 0)

    return c1 + c2


def rename_member(page_id, member_id: int, new_name: str) -> Tuple[bool, str]:
    sb = _sb()
    page_id = _norm_page_id(page_id)
    member_id = int(member_id)
    new_name = (new_name or "").strip()
    if not new_name:
        return False, "Name is empty"

    # duplicate check
    chk = (
        sb.table("members")
        .select("id")
        .eq("page_id", page_id)
        .eq("name", new_name)
        .eq("is_deleted", False)
        .limit(1)
        .execute()
    )
    ok, msg = _ok(chk)
    if not ok:
        return False, f"DB error: {msg}"
    if chk.data and int(chk.data[0]["id"]) != member_id:
        return False, "That name already exists"

    resp = (
        sb.table("members")
        .update({"name": new_name})
        .eq("page_id", page_id)
        .eq("id", member_id)
        .eq("is_deleted", False)
        .execute()
    )
    ok, msg = _ok(resp)
    if not ok:
        return False, f"DB error: {msg}"
    if not resp.data:
        return False, "Member not found"
    return True, "Updated"


def soft_delete_member_everywhere(page_id, member_id: int) -> Tuple[bool, str]:
    """
    Not fully transactional via REST API.
    Best effort updates in a safe order.
    """
    sb = _sb()
    page_id = _norm_page_id(page_id)
    member_id = int(member_id)

    try:
        # 1) Delete expenses paid by this member
        r1 = (
            sb.table("expenses")
            .update({"is_deleted": True, "deleted_at": "now()"})
            .eq("page_id", page_id)
            .eq("paid_by_member_id", member_id)
            .eq("is_deleted", False)
            .execute()
        )
        ok, msg = _ok(r1)
        if not ok:
            return False, f"Delete failed: {msg}"

        # 2) Delete shares referencing this member in this page
        ex_ids_resp = sb.table("expenses").select("id").eq("page_id", page_id).execute()
        ok, msg = _ok(ex_ids_resp)
        if not ok:
            return False, f"Delete failed: {msg}"
        ex_ids = [int(r["id"]) for r in (ex_ids_resp.data or [])]
        if ex_ids:
            r2 = (
                sb.table("expense_shares")
                .update({"is_deleted": True, "deleted_at": "now()"})
                .in_("expense_id", ex_ids)
                .eq("member_id", member_id)
                .eq("is_deleted", False)
                .execute()
            )
            ok, msg = _ok(r2)
            if not ok:
                return False, f"Delete failed: {msg}"

        # 3) Delete member itself
        r3 = (
            sb.table("members")
            .update({"is_deleted": True, "deleted_at": "now()"})
            .eq("page_id", page_id)
            .eq("id", member_id)
            .eq("is_deleted", False)
            .execute()
        )
        ok, msg = _ok(r3)
        if not ok:
            return False, f"Delete failed: {msg}"
        if not r3.data:
            return False, "Member not found"

        # 4) For expenses in page that now have zero active shares, delete the expense
        active_shares = (
            sb.table("expense_shares")
            .select("expense_id")
            .in_("expense_id", ex_ids)
            .eq("is_deleted", False)
            .execute()
        )
        ok, msg = _ok(active_shares)
        if not ok:
            return False, f"Delete failed: {msg}"
        active_expense_ids = set(int(r["expense_id"]) for r in (active_shares.data or []))
        for eid in ex_ids:
            if eid not in active_expense_ids:
                _ = (
                    sb.table("expenses")
                    .update({"is_deleted": True, "deleted_at": "now()"})
                    .eq("page_id", page_id)
                    .eq("id", int(eid))
                    .eq("is_deleted", False)
                    .execute()
                )

        return True, "Deleted"
    except Exception as e:
        return False, f"Delete failed: {e}"


def restore_member(page_id, member_id: int) -> Tuple[bool, str]:
    sb = _sb()
    page_id = _norm_page_id(page_id)
    member_id = int(member_id)

    resp = (
        sb.table("members")
        .update({"is_deleted": False, "deleted_at": None})
        .eq("page_id", page_id)
        .eq("id", member_id)
        .eq("is_deleted", True)
        .execute()
    )
    ok, msg = _ok(resp)
    if not ok:
        return False, f"Restore failed: {msg}"
    if not resp.data:
        return False, "Member not found"
    return True, "Restored"


# ------------------------
# Expense ops (page scoped)
# ------------------------
def _active_member_ids(page_id: str) -> List[int]:
    sb = _sb()
    resp = sb.table("members").select("id").eq("page_id", page_id).eq("is_deleted", False).execute()
    ok, msg = _ok(resp)
    if not ok:
        raise RuntimeError(f"DB error: {msg}")
    return [int(r["id"]) for r in (resp.data or [])]


def add_expense(
    page_id,
    expense_date: date,
    description: str,
    amount: float,
    currency: str,
    paid_by_member_id: int,
    target_member_ids: List[int],
) -> Tuple[bool, str]:
    sb = _sb()
    page_id = _norm_page_id(page_id)
    description = (description or "").strip()

    if not description:
        return False, "Title is empty"
    if amount is None or float(amount) < 0:
        return False, "Invalid amount"
    if currency not in ("USD", "JPY"):
        return False, "Invalid currency"
    if not target_member_ids:
        return False, "Please select targets"

    paid_by_member_id = int(paid_by_member_id)
    target_member_ids = [int(x) for x in target_member_ids]

    # validate payer and targets are active in this page
    active_ids = set(_active_member_ids(page_id))
    if paid_by_member_id not in active_ids:
        return False, "Payer not found"
    if any(t not in active_ids for t in target_member_ids):
        return False, "Targets include deleted members"

    try:
        ex_resp = (
            sb.table("expenses")
            .insert(
                {
                    "page_id": page_id,
                    "expense_date": expense_date.isoformat(),
                    "description": description,
                    "amount": float(amount),
                    "currency": currency,
                    "paid_by_member_id": paid_by_member_id,
                    "is_deleted": False,
                    "deleted_at": None,
                }
            )
            .execute()
        )
        ok, msg = _ok(ex_resp)
        if not ok:
            return False, f"Save failed: {msg}"
        if not ex_resp.data:
            return False, "Save failed"

        expense_id = int(ex_resp.data[0]["id"])

        share_rows = [
            {"expense_id": expense_id, "member_id": int(mid), "is_deleted": False, "deleted_at": None}
            for mid in target_member_ids
        ]
        sh_resp = sb.table("expense_shares").insert(share_rows).execute()
        ok, msg = _ok(sh_resp)
        if not ok:
            return False, f"Save failed: {msg}"

        return True, "Saved"
    except Exception as e:
        return False, f"Save failed: {e}"


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
    sb = _sb()
    page_id = _norm_page_id(page_id)
    expense_id = int(expense_id)
    description = (description or "").strip()

    if not description:
        return False, "Title is empty"
    if amount is None or float(amount) < 0:
        return False, "Invalid amount"
    if currency not in ("USD", "JPY"):
        return False, "Invalid currency"
    if not target_member_ids:
        return False, "Please select targets"

    paid_by_member_id = int(paid_by_member_id)
    target_member_ids = [int(x) for x in target_member_ids]

    # validate expense exists and is active
    ex_chk = (
        sb.table("expenses")
        .select("id,is_deleted")
        .eq("page_id", page_id)
        .eq("id", expense_id)
        .limit(1)
        .execute()
    )
    ok, msg = _ok(ex_chk)
    if not ok:
        return False, f"Update failed: {msg}"
    if not ex_chk.data or bool(ex_chk.data[0].get("is_deleted", False)):
        return False, "Expense not found"

    active_ids = set(_active_member_ids(page_id))
    if paid_by_member_id not in active_ids:
        return False, "Payer not found"
    if any(t not in active_ids for t in target_member_ids):
        return False, "Targets include deleted members"

    try:
        up = (
            sb.table("expenses")
            .update(
                {
                    "expense_date": expense_date.isoformat(),
                    "description": description,
                    "amount": float(amount),
                    "currency": currency,
                    "paid_by_member_id": paid_by_member_id,
                }
            )
            .eq("page_id", page_id)
            .eq("id", expense_id)
            .eq("is_deleted", False)
            .execute()
        )
        ok, msg = _ok(up)
        if not ok:
            return False, f"Update failed: {msg}"

        # soft delete all current shares
        sd = (
            sb.table("expense_shares")
            .update({"is_deleted": True, "deleted_at": "now()"})
            .eq("expense_id", expense_id)
            .eq("is_deleted", False)
            .execute()
        )
        ok, msg = _ok(sd)
        if not ok:
            return False, f"Update failed: {msg}"

        # upsert shares back as active
        upsert_rows = [
            {"expense_id": expense_id, "member_id": int(mid), "is_deleted": False, "deleted_at": None}
            for mid in target_member_ids
        ]
        us = sb.table("expense_shares").upsert(upsert_rows, on_conflict="expense_id,member_id").execute()
        ok, msg = _ok(us)
        if not ok:
            return False, f"Update failed: {msg}"

        # if no active shares remain, delete expense
        cnt = (
            sb.table("expense_shares")
            .select("expense_id", count="exact")
            .eq("expense_id", expense_id)
            .eq("is_deleted", False)
            .execute()
        )
        ok, msg = _ok(cnt)
        if not ok:
            return False, f"Update failed: {msg}"
        c = int(getattr(cnt, "count", 0) or 0)
        if c == 0:
            _ = (
                sb.table("expenses")
                .update({"is_deleted": True, "deleted_at": "now()"})
                .eq("page_id", page_id)
                .eq("id", expense_id)
                .execute()
            )

        return True, "Updated"
    except Exception as e:
        return False, f"Update failed: {e}"


def soft_delete_expense(page_id, expense_id: int) -> Tuple[bool, str]:
    sb = _sb()
    page_id = _norm_page_id(page_id)
    expense_id = int(expense_id)

    try:
        r1 = (
            sb.table("expenses")
            .update({"is_deleted": True, "deleted_at": "now()"})
            .eq("page_id", page_id)
            .eq("id", expense_id)
            .eq("is_deleted", False)
            .execute()
        )
        ok, msg = _ok(r1)
        if not ok:
            return False, f"Delete failed: {msg}"
        if not r1.data:
            return False, "Expense not found"

        r2 = (
            sb.table("expense_shares")
            .update({"is_deleted": True, "deleted_at": "now()"})
            .eq("expense_id", expense_id)
            .eq("is_deleted", False)
            .execute()
        )
        ok, msg = _ok(r2)
        if not ok:
            return False, f"Delete failed: {msg}"

        return True, "Deleted"
    except Exception as e:
        return False, f"Delete failed: {e}"


def restore_expense(page_id, expense_id: int) -> Tuple[bool, str]:
    sb = _sb()
    page_id = _norm_page_id(page_id)
    expense_id = int(expense_id)

    try:
        ex = (
            sb.table("expenses")
            .select("paid_by_member_id")
            .eq("page_id", page_id)
            .eq("id", expense_id)
            .eq("is_deleted", True)
            .limit(1)
            .execute()
        )
        ok, msg = _ok(ex)
        if not ok:
            return False, f"Restore failed: {msg}"
        if not ex.data:
            return False, "Expense not found"

        payer_id = int(ex.data[0]["paid_by_member_id"])
        payer = (
            sb.table("members")
            .select("is_deleted")
            .eq("page_id", page_id)
            .eq("id", payer_id)
            .limit(1)
            .execute()
        )
        ok, msg = _ok(payer)
        if not ok:
            return False, f"Restore failed: {msg}"
        if not payer.data or bool(payer.data[0]["is_deleted"]):
            return False, "Cannot restore: payer is deleted"

        r1 = (
            sb.table("expenses")
            .update({"is_deleted": False, "deleted_at": None})
            .eq("page_id", page_id)
            .eq("id", expense_id)
            .eq("is_deleted", True)
            .execute()
        )
        ok, msg = _ok(r1)
        if not ok:
            return False, f"Restore failed: {msg}"

        # restore shares only for active members in this page
        active_ids = _active_member_ids(page_id)
        if active_ids:
            r2 = (
                sb.table("expense_shares")
                .update({"is_deleted": False, "deleted_at": None})
                .eq("expense_id", expense_id)
                .in_("member_id", active_ids)
                .execute()
            )
            ok, msg = _ok(r2)
            if not ok:
                return False, f"Restore failed: {msg}"

        cnt = (
            sb.table("expense_shares")
            .select("expense_id", count="exact")
            .eq("expense_id", expense_id)
            .eq("is_deleted", False)
            .execute()
        )
        ok, msg = _ok(cnt)
        if not ok:
            return False, f"Restore failed: {msg}"
        c = int(getattr(cnt, "count", 0) or 0)
        if c == 0:
            _ = (
                sb.table("expenses")
                .update({"is_deleted": True, "deleted_at": "now()"})
                .eq("page_id", page_id)
                .eq("id", expense_id)
                .execute()
            )
            return False, "Cannot restore: no active targets"

        return True, "Restored"
    except Exception as e:
        return False, f"Restore failed: {e}"


def fetch_expenses(page_id, active_only: bool = True) -> List[Dict]:
    sb = _sb()
    page_id = _norm_page_id(page_id)

    # members map
    mem_resp = sb.table("members").select("id,name,is_deleted").eq("page_id", page_id).execute()
    ok, msg = _ok(mem_resp)
    if not ok:
        raise RuntimeError(f"DB error: {msg}")
    mem_rows = mem_resp.data or []
    id_to_name = {int(r["id"]): r["name"] for r in mem_rows}
    active_member_ids = {int(r["id"]) for r in mem_rows if not bool(r.get("is_deleted", False))}

    q = sb.table("expenses").select(
        "id,expense_date,description,amount,currency,paid_by_member_id,created_at,is_deleted,deleted_at"
    ).eq("page_id", page_id)

    if active_only:
        q = q.eq("is_deleted", False)

    exp_resp = q.order("expense_date", desc=True).order("created_at", desc=True).order("id", desc=True).execute()
    ok, msg = _ok(exp_resp)
    if not ok:
        raise RuntimeError(f"DB error: {msg}")

    expenses = [dict(r) for r in (exp_resp.data or [])]
    if not expenses:
        return []

    # attach paid_by
    for ex in expenses:
        ex["paid_by"] = id_to_name.get(int(ex["paid_by_member_id"]), "Unknown")

    expense_ids = [int(r["id"]) for r in expenses]

    # fetch shares for these expenses
    sh_resp = sb.table("expense_shares").select("expense_id,member_id,is_deleted").in_("expense_id", expense_ids).execute()
    ok, msg = _ok(sh_resp)
    if not ok:
        raise RuntimeError(f"DB error: {msg}")

    shares = sh_resp.data or []
    shares_by_exp: Dict[int, List[Dict[str, Any]]] = {}
    for s in shares:
        eid = int(s["expense_id"])
        shares_by_exp.setdefault(eid, []).append(s)

    for ex in expenses:
        eid = int(ex["id"])
        rows = shares_by_exp.get(eid, [])

        if active_only:
            active_targets = [
                int(s["member_id"]) for s in rows if (not bool(s.get("is_deleted", False))) and int(s["member_id"]) in active_member_ids
            ]
        else:
            active_targets = [int(s["member_id"]) for s in rows if not bool(s.get("is_deleted", False))]

        ex["target_ids"] = active_targets
        ex["targets"] = [id_to_name.get(mid, "Unknown") for mid in active_targets]

    # In active_only mode, hide expenses whose payer is deleted
    if active_only:
        filtered = []
        for ex in expenses:
            if int(ex["paid_by_member_id"]) in active_member_ids and not bool(ex.get("is_deleted", False)):
                filtered.append(ex)
        expenses = filtered

    return expenses


def compute_net_balances(page_id) -> Dict[str, Dict[str, float]]:
    page_id = _norm_page_id(page_id)
    members = get_members(page_id)
    id_to_name = {int(r["id"]): r["name"] for r in members}

    balances: Dict[str, Dict[str, float]] = {"USD": {}, "JPY": {}}
    for name in id_to_name.values():
        balances["USD"][name] = 0.0
        balances["JPY"][name] = 0.0

    expenses = fetch_expenses(page_id, active_only=True)

    # build quick active member ids set
    active_member_ids = set(id_to_name.keys())

    for ex in expenses:
        amount = float(ex["amount"])
        currency = ex["currency"]
        payer_id = int(ex["paid_by_member_id"])
        targets = [int(t) for t in ex.get("target_ids", []) if int(t) in active_member_ids]

        if not targets:
            continue
        if payer_id not in active_member_ids:
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

    return balances


def build_transaction_matrix(page_id, currency: str) -> pd.DataFrame:
    page_id = _norm_page_id(page_id)
    members = get_members(page_id)
    member_names = [m["name"] for m in members]
    if not member_names:
        return pd.DataFrame()

    expenses = fetch_expenses(page_id, active_only=True)
    expenses = [e for e in expenses if e["currency"] == currency]

    data_rows: List[Dict[str, Any]] = []
    for ex in expenses:
        when_str = str(ex["expense_date"])
        created_at = str(ex["created_at"])
        title = ex["description"]
        amount = float(ex["amount"])
        payer = ex["paid_by"]
        targets = ex.get("targets", [])

        if not targets:
            continue
        split = amount / len(targets)

        row: Dict[str, Any] = {"When": when_str, "Created at": created_at, "Title": title}
        for name in member_names:
            row[name] = 0.0

        if payer in row:
            row[payer] += amount
        for t in targets:
            if t in row:
                row[t] -= split

        data_rows.append(row)

    df = pd.DataFrame(data_rows)
    if df.empty:
        return df

    cols = ["When", "Created at", "Title"] + member_names
    return df[cols]


# ------------------------
# Bulk and Danger ops (page scoped)
# ------------------------
def soft_delete_all_expenses(page_id) -> Tuple[bool, str]:
    sb = _sb()
    page_id = _norm_page_id(page_id)

    try:
        r1 = (
            sb.table("expenses")
            .update({"is_deleted": True, "deleted_at": "now()"})
            .eq("page_id", page_id)
            .eq("is_deleted", False)
            .execute()
        )
        ok, msg = _ok(r1)
        if not ok:
            return False, f"Bulk delete failed: {msg}"

        ex_ids_resp = sb.table("expenses").select("id").eq("page_id", page_id).execute()
        ok, msg = _ok(ex_ids_resp)
        if not ok:
            return False, f"Bulk delete failed: {msg}"
        ex_ids = [int(r["id"]) for r in (ex_ids_resp.data or [])]
        if ex_ids:
            r2 = (
                sb.table("expense_shares")
                .update({"is_deleted": True, "deleted_at": "now()"})
                .in_("expense_id", ex_ids)
                .eq("is_deleted", False)
                .execute()
            )
            ok, msg = _ok(r2)
            if not ok:
                return False, f"Bulk delete failed: {msg}"

        return True, "Deleted all history (soft delete)"
    except Exception as e:
        return False, f"Bulk delete failed: {e}"


def soft_delete_all_members_everywhere(page_id) -> Tuple[bool, str]:
    sb = _sb()
    page_id = _norm_page_id(page_id)

    try:
        # delete expenses
        r1 = (
            sb.table("expenses")
            .update({"is_deleted": True, "deleted_at": "now()"})
            .eq("page_id", page_id)
            .eq("is_deleted", False)
            .execute()
        )
        ok, msg = _ok(r1)
        if not ok:
            return False, f"Bulk delete failed: {msg}"

        # delete shares
        ex_ids_resp = sb.table("expenses").select("id").eq("page_id", page_id).execute()
        ok, msg = _ok(ex_ids_resp)
        if not ok:
            return False, f"Bulk delete failed: {msg}"
        ex_ids = [int(r["id"]) for r in (ex_ids_resp.data or [])]
        if ex_ids:
            r2 = (
                sb.table("expense_shares")
                .update({"is_deleted": True, "deleted_at": "now()"})
                .in_("expense_id", ex_ids)
                .eq("is_deleted", False)
                .execute()
            )
            ok, msg = _ok(r2)
            if not ok:
                return False, f"Bulk delete failed: {msg}"

        # delete members
        r3 = (
            sb.table("members")
            .update({"is_deleted": True, "deleted_at": "now()"})
            .eq("page_id", page_id)
            .eq("is_deleted", False)
            .execute()
        )
        ok, msg = _ok(r3)
        if not ok:
            return False, f"Bulk delete failed: {msg}"

        return True, "Deleted all members and history (soft delete)"
    except Exception as e:
        return False, f"Bulk delete failed: {e}"


def wipe_page(page_id) -> Tuple[bool, str]:
    """
    Delete ALL data for a single page (shares, expenses, members, page).
    Not fully transactional via REST API.
    """
    sb = _sb()
    page_id = _norm_page_id(page_id)

    try:
        page = sb.table("pages").select("id").eq("id", page_id).eq("is_deleted", False).limit(1).execute()
        ok, msg = _ok(page)
        if not ok:
            return False, f"Wipe failed: {msg}"
        if not page.data:
            return False, "Page not found"

        ex_ids_resp = sb.table("expenses").select("id").eq("page_id", page_id).execute()
        ok, msg = _ok(ex_ids_resp)
        if not ok:
            return False, f"Wipe failed: {msg}"
        ex_ids = [int(r["id"]) for r in (ex_ids_resp.data or [])]

        if ex_ids:
            r1 = sb.table("expense_shares").delete().in_("expense_id", ex_ids).execute()
            ok, msg = _ok(r1)
            if not ok:
                return False, f"Wipe failed: {msg}"

        r2 = sb.table("expenses").delete().eq("page_id", page_id).execute()
        ok, msg = _ok(r2)
        if not ok:
            return False, f"Wipe failed: {msg}"

        r3 = sb.table("members").delete().eq("page_id", page_id).execute()
        ok, msg = _ok(r3)
        if not ok:
            return False, f"Wipe failed: {msg}"

        r4 = sb.table("pages").delete().eq("id", page_id).execute()
        ok, msg = _ok(r4)
        if not ok:
            return False, f"Wipe failed: {msg}"

        return True, "Deleted this page and all its data"
    except Exception as e:
        return False, f"Wipe failed: {e}"


def delete_db_file() -> Tuple[bool, str]:
    return False, "Not supported in Supabase mode"