# db.py (Supabase API version using supabase-py)
#
# Notes:
# - Uses Supabase REST API (PostgREST) via supabase-py
# - No direct Postgres connections (psycopg is not used)
# - Requires Streamlit secrets:
#   [supabase]
#   url = "https://<PROJECT_REF>.supabase.co"
#   service_role_key = "<SERVICE_ROLE_KEY>"

import hashlib
import secrets
import time
import random
import json

from datetime import date
from decimal import Decimal, ROUND_DOWN
from typing import Any, Dict, List, Optional, Tuple

import httpx
import pandas as pd
import streamlit as st
from supabase import create_client, Client

# Currency choices (manual)
CURRENCY_CHOICES = ["USD","JPY","EUR","GBP","AUD","CAD","CHF","CNY","HKD","SGD","KRW","Other","none"]
NO_DECIMAL_CURRENCIES = {"JPY", "KRW"}

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
    err = getattr(resp, "error", None)
    if err:
        return False, str(err)
    return True, None


def _execute_with_retry(q, tries: int = 4, base_sleep: float = 0.35):
    last_exc = None
    for i in range(tries):
        try:
            return q.execute()
        except (
            httpx.RemoteProtocolError,
            httpx.ReadTimeout,
            httpx.ConnectTimeout,
            httpx.WriteTimeout,
            httpx.PoolTimeout,
            httpx.ConnectError,
        ) as e:
            last_exc = e
            time.sleep(base_sleep * (2**i) + random.uniform(0.0, 0.2))
            try:
                _sb.clear()
            except Exception:
                pass
        except Exception:
            raise
    raise last_exc


# ------------------------
# ID helpers
# ------------------------
def _norm_page_id(page_id) -> str:
    if page_id is None:
        return ""
    return str(page_id).strip()


def _generate_page_id() -> str:
    # Around 43 characters, URL safe
    return secrets.token_urlsafe(8)


# ------------------------
# Init
# ------------------------
def init_db() -> None:
    sb = _sb()
    resp = _execute_with_retry(sb.table("pages").select("id").limit(1))
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
    # Returns salt_hex and pw_hash
    salt_hex = secrets.token_hex(16)
    pw_hash = _hash_password(password, salt_hex)
    return salt_hex, pw_hash


def verify_page_password(page_id, password: str) -> Tuple[bool, str]:
    sb = _sb()
    page_id = _norm_page_id(page_id)
    password = (password or "").strip()

    resp = _execute_with_retry(
        sb.table("pages")
        .select("password_salt,password_hash")
        .eq("id", page_id)
        .eq("is_deleted", False)
        .limit(1)
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
def create_page(
    name: str,
    password: str | None = None,
    main_currency: str = "USD",
    sub_currency: str = "none",
) -> tuple[bool, str, str | None]:
    sb = _sb()
    name = (name or "").strip()
    if not name:
        return False, "Page name is empty", None

    password = (password or "").strip()
    salt = None
    pw_hash = None
    if password:
        salt, pw_hash = _make_password_record(password)

    # Safety loop in case of extremely unlikely collision
    for _ in range(5):
        page_id = _generate_page_id()
        resp = _execute_with_retry(
            sb.table("pages").insert(
                {
                    "id": page_id,
                    "name": name,
                    "password_salt": salt,
                    "password_hash": pw_hash,
                    "main_currency": main_currency,
                    "sub_currency": sub_currency,
                    "is_deleted": False,
                    "deleted_at": None,
                }
            )
        )
        ok, msg = _ok(resp)
        if ok:
            return True, "Page created", page_id

        if "duplicate key value violates unique constraint" in (msg or "") and "pages_pkey" in (msg or ""):
            continue
        return False, (msg or "Create failed"), None

    return False, "Failed to create page id", None


def list_pages(include_deleted: bool = False) -> List[Dict]:
    sb = _sb()
    q = sb.table("pages").select("id,name,password_hash,is_deleted,deleted_at,main_currency,sub_currency")
    if not include_deleted:
        q = q.eq("is_deleted", False)
    resp = _execute_with_retry(q.order("name", desc=False))
    ok, msg = _ok(resp)
    if not ok:
        raise RuntimeError(f"DB error: {msg}")
    return resp.data or []


def get_page(page_id) -> Optional[Dict]:
    sb = _sb()
    page_id = _norm_page_id(page_id)
    resp = _execute_with_retry(
        sb.table("pages")
        .select("id,name,password_hash,password_salt,main_currency,sub_currency")
        .eq("id", page_id)
        .eq("is_deleted", False)
        .limit(1)
    )
    ok, msg = _ok(resp)
    if not ok:
        raise RuntimeError(f"DB error: {msg}")
    rows = resp.data or []
    return rows[0] if rows else None


def update_page_settings(
    page_id: str,
    new_name: str,
    main_currency: str,
    sub_currency: str,
) -> Tuple[bool, str]:
    # Update page name and currencies
    sb = _sb()
    page_id = _norm_page_id(page_id)

    new_name = (new_name or "").strip()
    if not new_name:
        return False, "Page name is empty"

    main_currency = (main_currency or "").strip()
    sub_currency = (sub_currency or "").strip() or "none"

    if sub_currency.lower() == "none":
        sub_currency = "none"

    # Basic guard
    if main_currency.lower() == "none":
        return False, "Main currency cannot be none"
    if sub_currency == main_currency:
        return False, "Sub currency must be different from main currency"

    # Ensure page exists
    chk = _execute_with_retry(
        sb.table("pages")
        .select("id")
        .eq("id", page_id)
        .eq("is_deleted", False)
        .limit(1)
    )
    ok, msg = _ok(chk)
    if not ok:
        return False, f"DB error: {msg}"
    if not (chk.data or []):
        return False, "Page not found"

    # Update
    try:
        up = _execute_with_retry(
            sb.table("pages")
            .update(
                {
                    "name": new_name,
                    "main_currency": main_currency,
                    "sub_currency": sub_currency,
                }
            )
            .eq("id", page_id)
            .eq("is_deleted", False)
        )
        ok, msg = _ok(up)
        if not ok:
            # If name unique constraint fails, surface a friendly message
            if "duplicate key value violates unique constraint" in (msg or ""):
                return False, "Page name already exists"
            return False, f"Update failed: {msg}"
        return True, "Updated"
    except Exception as e:
        return False, f"Update failed: {e}"


def update_page_password(page_id: str, new_password: str) -> Tuple[bool, str]:
    # Set or change password for a page
    sb = _sb()
    page_id = _norm_page_id(page_id)
    new_password = (new_password or "").strip()

    if not new_password:
        return False, "Password is empty"

    salt_hex, pw_hash = _make_password_record(new_password)

    resp = _execute_with_retry(
        sb.table("pages")
        .update({"password_salt": salt_hex, "password_hash": pw_hash})
        .eq("id", page_id)
        .eq("is_deleted", False)
    )
    ok, msg = _ok(resp)
    if not ok:
        return False, f"Update failed: {msg}"
    return True, "Password updated"


def remove_page_password(page_id: str) -> Tuple[bool, str]:
    # Remove password protection for a page
    sb = _sb()
    page_id = _norm_page_id(page_id)

    resp = _execute_with_retry(
        sb.table("pages")
        .update({"password_salt": None, "password_hash": None})
        .eq("id", page_id)
        .eq("is_deleted", False)
    )
    ok, msg = _ok(resp)
    if not ok:
        return False, f"Update failed: {msg}"
    return True, "Password removed"


# ------------------------
# Member ops (page scoped)
# ------------------------
def add_member(page_id, name: str) -> Tuple[bool, str]:
    sb = _sb()
    page_id = _norm_page_id(page_id)
    name = (name or "").strip()
    if not name:
        return False, "Name is empty"

    # Duplicate check among active members
    chk = _execute_with_retry(
        sb.table("members")
        .select("id")
        .eq("page_id", page_id)
        .eq("name", name)
        .eq("is_deleted", False)
        .limit(1)
    )
    ok, msg = _ok(chk)
    if not ok:
        return False, f"DB error: {msg}"
    if chk.data:
        return False, "That name already exists"

    resp = _execute_with_retry(
        sb.table("members").insert({"page_id": page_id, "name": name, "is_deleted": False, "deleted_at": None})
    )
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
    resp = _execute_with_retry(q.order("name", desc=False))
    ok, msg = _ok(resp)
    if not ok:
        raise RuntimeError(f"DB error: {msg}")
    return resp.data or []


def member_usage_count(page_id, member_id: int) -> int:
    sb = _sb()
    page_id = _norm_page_id(page_id)
    member_id = int(member_id)

    r1 = _execute_with_retry(
        sb.table("expenses")
        .select("id", count="exact")
        .eq("page_id", page_id)
        .eq("paid_by_member_id", member_id)
        .eq("is_deleted", False)
    )
    ok, msg = _ok(r1)
    if not ok:
        raise RuntimeError(f"DB error: {msg}")
    c1 = int(getattr(r1, "count", 0) or 0)

    ex_ids_resp = _execute_with_retry(sb.table("expenses").select("id").eq("page_id", page_id))
    ok, msg = _ok(ex_ids_resp)
    if not ok:
        raise RuntimeError(f"DB error: {msg}")
    ex_ids = [int(r["id"]) for r in (ex_ids_resp.data or [])]
    if not ex_ids:
        return c1

    r2 = _execute_with_retry(
        sb.table("expense_shares")
        .select("expense_id", count="exact")
        .in_("expense_id", ex_ids)
        .eq("member_id", member_id)
        .eq("is_deleted", False)
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

    chk = _execute_with_retry(
        sb.table("members")
        .select("id")
        .eq("page_id", page_id)
        .eq("name", new_name)
        .eq("is_deleted", False)
        .limit(1)
    )
    ok, msg = _ok(chk)
    if not ok:
        return False, f"DB error: {msg}"
    if chk.data and int(chk.data[0]["id"]) != member_id:
        return False, "That name already exists"

    resp = _execute_with_retry(
        sb.table("members")
        .update({"name": new_name})
        .eq("page_id", page_id)
        .eq("id", member_id)
        .eq("is_deleted", False)
    )
    ok, msg = _ok(resp)
    if not ok:
        return False, f"DB error: {msg}"
    if not resp.data:
        return False, "Member not found"
    return True, "Updated"


def soft_delete_member_everywhere(page_id, member_id: int) -> Tuple[bool, str]:
    """
    Soft delete a member WITHOUT touching any historical expenses/shares.
    This keeps past settlements consistent and allows full restore.
    """
    sb = _sb()
    page_id = _norm_page_id(page_id)
    member_id = int(member_id)

    try:
        r = _execute_with_retry(
            sb.table("members")
            .update({"is_deleted": True, "deleted_at": None})
            .eq("page_id", page_id)
            .eq("id", member_id)
            .eq("is_deleted", False)
        )
        ok, msg = _ok(r)
        if not ok:
            return False, f"Delete failed: {msg}"
        if not r.data:
            return False, "Member not found"

        return True, "Deleted (member only). History is kept."
    except Exception as e:
        return False, f"Delete failed: {e}"


def restore_member(page_id, member_id: int) -> Tuple[bool, str]:
    """
    Restore a soft-deleted member. History was never modified, so nothing else is needed.
    """
    sb = _sb()
    page_id = _norm_page_id(page_id)
    member_id = int(member_id)

    try:
        r = _execute_with_retry(
            sb.table("members")
            .update({"is_deleted": False, "deleted_at": None})
            .eq("page_id", page_id)
            .eq("id", member_id)
            .eq("is_deleted", True)
        )
        ok, msg = _ok(r)
        if not ok:
            return False, f"Restore failed: {msg}"
        if not r.data:
            return False, "Member not found"

        return True, "Restored"
    except Exception as e:
        return False, f"Restore failed: {e}"


# ------------------------
# Expense ops (page scoped)
# ------------------------
def _active_member_ids(page_id: str) -> List[int]:
    sb = _sb()
    resp = _execute_with_retry(sb.table("members").select("id").eq("page_id", page_id).eq("is_deleted", False))
    ok, msg = _ok(resp)
    if not ok:
        raise RuntimeError(f"DB error: {msg}")
    return [int(r["id"]) for r in (resp.data or [])]


def _norm_how(how: str) -> str:
    how_norm = (how or "even").strip().lower()
    if how_norm in ["$", "amount", "number"]:
        return "$"
    if how_norm in ["%", "percent", "percentage"]:
        return "%"
    return "even"


def _allowed_currencies_for_page(page_id: str) -> List[str]:
    """
    Allowed currencies are always:
      - main_currency
      - sub_currency (if not none)
    Returned as upper-case list, unique, stable order (main then sub).
    """
    page_id = _norm_page_id(page_id)
    page = get_page(page_id)  # <- must exist in your db.py
    main = (page.get("main_currency") or "USD") if page else "USD"
    sub_raw = (page.get("sub_currency") or "none") if page else "none"

    main_u = str(main).upper().strip()

    sub_s = str(sub_raw).strip()
    sub_u = str(sub_raw).upper().strip()
    has_sub = bool(sub_s) and (sub_u != "NONE") and (sub_s.lower() != "none")

    out = [main_u]
    if has_sub and sub_u != main_u:
        out.append(sub_u)
    return out


def _ccy_scale(currency: str) -> int:
    c = (currency or "").upper().strip()
    return 0 if c in NO_DECIMAL_CURRENCIES else 2


def _quant_unit(scale: int) -> Decimal:
    # scale=2 -> 0.01, scale=0 -> 1
    return Decimal("1") if scale == 0 else Decimal("0.01")


def _quantize_down(x: Decimal, scale: int) -> Decimal:
    unit = _quant_unit(scale)
    return x.quantize(unit, rounding=ROUND_DOWN)


def _allocate_even(amount: Decimal, target_ids: List[int], scale: int) -> Dict[int, Decimal]:
    """
    Split amount evenly across targets with:
    - floor to currency unit
    - distribute remainder by +1 unit to first members (stable order)
    Ensures sum == amount.
    """
    n = len(target_ids)
    if n <= 0:
        return {}

    unit = _quant_unit(scale)
    base = _quantize_down(amount / Decimal(n), scale)
    alloc = {int(mid): base for mid in target_ids}

    used = base * Decimal(n)
    remainder = amount - used  # >= 0 and < n*unit

    # number of unit-steps to distribute
    steps = int((remainder / unit).to_integral_value(rounding=ROUND_DOWN))
    for i in range(steps):
        alloc[int(target_ids[i % n])] = alloc[int(target_ids[i % n])] + unit

    # Final safety: force exact sum by adjusting last
    s = sum(alloc.values(), Decimal("0"))
    if s != amount:
        last = int(target_ids[-1])
        alloc[last] = alloc[last] + (amount - s)

    return alloc


def _allocate_percent(amount: Decimal, target_ids: List[int], percents: Dict[int, float], scale: int) -> Dict[int, Decimal]:
    """
    Allocate by percent with:
    - raw = amount * pct/100
    - floor to unit
    - distribute remainder by +1 unit following largest fractional parts
    Ensures sum == amount.
    """
    if not target_ids:
        return {}

    unit = _quant_unit(scale)

    # raw amounts
    raw: Dict[int, Decimal] = {}
    flo: Dict[int, Decimal] = {}
    frac: List[Tuple[Decimal, int]] = []  # (fractional_part, mid)

    for mid in target_ids:
        p = Decimal(str(float(percents.get(int(mid), 0.0))))
        r = amount * p / Decimal("100")
        r_floor = _quantize_down(r, scale)

        raw[int(mid)] = r
        flo[int(mid)] = r_floor
        frac_part = r - r_floor
        frac.append((frac_part, int(mid)))

    used = sum(flo.values(), Decimal("0"))
    remainder = amount - used

    steps = int((remainder / unit).to_integral_value(rounding=ROUND_DOWN))

    # biggest fractional gets extra unit first
    frac.sort(key=lambda x: (x[0], -x[1]), reverse=True)

    alloc = dict(flo)
    for i in range(steps):
        mid = frac[i % len(frac)][1]
        alloc[mid] = alloc[mid] + unit

    # Final safety: force exact sum
    s = sum(alloc.values(), Decimal("0"))
    if s != amount:
        last = int(target_ids[-1])
        alloc[last] = alloc[last] + (amount - s)

    return alloc


def _allocate_fixed(amount: Decimal, target_ids: List[int], shares: Dict[int, float], scale: int) -> Dict[int, Decimal]:
    """
    Allocate using provided share_amounts. Must match total exactly after rounding to currency unit.
    We do NOT auto-fix here; if mismatch, return error to user.
    """
    if not target_ids:
        return {}

    q = _quant_unit(scale)

    alloc: Dict[int, Decimal] = {}
    for mid in target_ids:
        v = Decimal(str(float(shares.get(int(mid), 0.0))))
        # normalize to currency unit (half-up would be another option; here use quantize DOWN? No: user input should be respected.
        # We'll quantize to unit using normal quantize (ROUND_DOWN would bias; but user input likely already unit-safe).
        vq = v.quantize(q)  # default ROUND_HALF_EVEN; ok for user-entered unit values
        alloc[int(mid)] = vq

    s = sum(alloc.values(), Decimal("0"))
    if s != amount:
        raise ValueError(f"Share amounts do not sum to total. sum={s} total={amount}")

    return alloc


def _compute_share_amounts_for_save(
    amount_f: float,
    currency_u: str,
    how_norm: str,
    target_member_ids: List[int],
    share_amounts: Dict[int, float],
    share_percents: Dict[int, float],
) -> Dict[int, Decimal]:
    """
    Returns {member_id: Decimal share_amount} guaranteed sum == amount (except fixed which must already match).
    """
    scale = _ccy_scale(currency_u)
    amount = Decimal(str(float(amount_f))).quantize(_quant_unit(scale))  # normalize total to unit

    # Use stable order for deterministic distribution
    target_ids = [int(x) for x in target_member_ids]

    if how_norm == "even":
        return _allocate_even(amount, target_ids, scale)

    if how_norm == "%":
        return _allocate_percent(amount, target_ids, share_percents or {}, scale)

    if how_norm == "$":
        return _allocate_fixed(amount, target_ids, share_amounts or {}, scale)

    # Fallback treat as even
    return _allocate_even(amount, target_ids, scale)


# -------------------------
# REPLACE: add_expense
# -------------------------
def add_expense(
    page_id,
    expense_date: date,
    description: str,
    amount: float,
    currency: str,
    paid_by_member_id: int,
    target_member_ids: List[int],
    note: str = "",
    how: str = "even",
    share_amounts: Optional[Dict[int, float]] = None,
    share_percents: Optional[Dict[int, float]] = None,
) -> Tuple[bool, str]:
    sb = _sb()
    page_id = _norm_page_id(page_id)
    description = (description or "").strip()
    note = (note or "").strip()
    how_norm = _norm_how(how)

    currency_u = (currency or "").upper().strip()
    allowed_ccy = _allowed_currencies_for_page(page_id)

    if not description:
        return False, "Title is empty"
    if amount is None or float(amount) < 0:
        return False, "Invalid amount"
    if currency_u not in allowed_ccy:
        return False, f"Invalid currency: {currency_u} (allowed: {', '.join(allowed_ccy)})"
    if not target_member_ids:
        return False, "Please select targets"

    paid_by_member_id = int(paid_by_member_id)
    target_member_ids = [int(x) for x in target_member_ids]

    active_ids = set(_active_member_ids(page_id))
    if paid_by_member_id not in active_ids:
        return False, "Payer not found"
    if any(t not in active_ids for t in target_member_ids):
        return False, "Targets include deleted members"

    share_amounts = share_amounts or {}
    share_percents = share_percents or {}

    try:
        # 1) insert expense
        ex_resp = _execute_with_retry(
            sb.table("expenses").insert(
                {
                    "page_id": page_id,
                    "expense_date": expense_date.isoformat(),
                    "description": description,
                    "amount": float(amount),
                    "currency": currency_u,
                    "paid_by_member_id": paid_by_member_id,
                    "how": how_norm,
                    "note": note,
                    "is_deleted": False,
                    "deleted_at": None,
                }
            )
        )
        ok, msg = _ok(ex_resp)
        if not ok:
            return False, f"Save failed: {msg}"
        if not ex_resp.data:
            return False, "Save failed"

        expense_id = int(ex_resp.data[0]["id"])

        # 2) build shares (sum exact)
        alloc = _compute_share_amounts_for_save(
            amount_f=float(amount),
            currency_u=currency_u,
            how_norm=how_norm,
            target_member_ids=target_member_ids,
            share_amounts=share_amounts,
            share_percents=share_percents,
        )

        # 3) also store share_percent (informational only; not used as source of truth)
        rows_out: List[Dict[str, Any]] = []
        total = Decimal(str(float(amount)))
        for mid in target_member_ids:
            mid_i = int(mid)
            sa = alloc.get(mid_i, Decimal("0"))
            sp = (sa / Decimal(str(float(amount))) * Decimal("100")) if float(amount) > 0 else Decimal("0")

            # store numeric (float) for Supabase
            rows_out.append(
                {
                    "expense_id": expense_id,
                    "member_id": mid_i,
                    "is_deleted": False,
                    "deleted_at": None,
                    "share_amount": float(sa),
                    "share_percent": float(sp),
                }
            )

        sh_resp = _execute_with_retry(sb.table("expense_shares").insert(rows_out))
        ok, msg = _ok(sh_resp)
        if not ok:
            return False, f"Save failed: {msg}"

        return True, "Saved"
    except ValueError as ve:
        return False, f"Save failed: {ve}"
    except Exception as e:
        return False, f"Save failed: {e}"


# -------------------------
# REPLACE: update_expense
# -------------------------
def update_expense(
    page_id,
    expense_id: int,
    expense_date: date,
    description: str,
    amount: float,
    currency: str,
    paid_by_member_id: int,
    target_member_ids: List[int],
    note: str = "",
    how: str = "even",
    share_amounts: Optional[Dict[int, float]] = None,
    share_percents: Optional[Dict[int, float]] = None,
) -> Tuple[bool, str]:
    sb = _sb()
    page_id = _norm_page_id(page_id)
    expense_id = int(expense_id)
    description = (description or "").strip()
    note = (note or "").strip()
    how_norm = _norm_how(how)

    currency_u = (currency or "").upper().strip()
    allowed_ccy = _allowed_currencies_for_page(page_id)

    if not description:
        return False, "Title is empty"
    if amount is None or float(amount) < 0:
        return False, "Invalid amount"
    if currency_u not in allowed_ccy:
        return False, f"Invalid currency: {currency_u} (allowed: {', '.join(allowed_ccy)})"
    if not target_member_ids:
        return False, "Please select targets"

    paid_by_member_id = int(paid_by_member_id)
    target_member_ids = [int(x) for x in target_member_ids]

    ex_chk = _execute_with_retry(
        sb.table("expenses")
        .select("id,is_deleted")
        .eq("page_id", page_id)
        .eq("id", expense_id)
        .limit(1)
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

    share_amounts = share_amounts or {}
    share_percents = share_percents or {}

    try:
        # 1) update expense row
        up = _execute_with_retry(
            sb.table("expenses")
            .update(
                {
                    "expense_date": expense_date.isoformat(),
                    "description": description,
                    "amount": float(amount),
                    "currency": currency_u,
                    "paid_by_member_id": paid_by_member_id,
                    "how": how_norm,
                    "note": note,
                }
            )
            .eq("page_id", page_id)
            .eq("id", expense_id)
            .eq("is_deleted", False)
        )
        ok, msg = _ok(up)
        if not ok:
            return False, f"Update failed: {msg}"

        # 2) soft delete existing shares
        sd = _execute_with_retry(
            sb.table("expense_shares")
            .update({"is_deleted": True, "deleted_at": None})
            .eq("expense_id", expense_id)
            .eq("is_deleted", False)
        )
        ok, msg = _ok(sd)
        if not ok:
            return False, f"Update failed: {msg}"

        # 3) rebuild shares (sum exact)
        alloc = _compute_share_amounts_for_save(
            amount_f=float(amount),
            currency_u=currency_u,
            how_norm=how_norm,
            target_member_ids=target_member_ids,
            share_amounts=share_amounts,
            share_percents=share_percents,
        )

        rows_out: List[Dict[str, Any]] = []
        for mid in target_member_ids:
            mid_i = int(mid)
            sa = alloc.get(mid_i, Decimal("0"))
            sp = (sa / Decimal(str(float(amount))) * Decimal("100")) if float(amount) > 0 else Decimal("0")

            rows_out.append(
                {
                    "expense_id": expense_id,
                    "member_id": mid_i,
                    "is_deleted": False,
                    "deleted_at": None,
                    "share_amount": float(sa),
                    "share_percent": float(sp),
                }
            )

        us = _execute_with_retry(
            sb.table("expense_shares").upsert(rows_out, on_conflict="expense_id,member_id")
        )
        ok, msg = _ok(us)
        if not ok:
            return False, f"Update failed: {msg}"

        # 4) keep safety behavior: if no active shares, delete expense
        cnt = _execute_with_retry(
            sb.table("expense_shares")
            .select("expense_id", count="exact")
            .eq("expense_id", expense_id)
            .eq("is_deleted", False)
        )
        ok, msg = _ok(cnt)
        if not ok:
            return False, f"Update failed: {msg}"
        c = int(getattr(cnt, "count", 0) or 0)
        if c == 0:
            _ = _execute_with_retry(
                sb.table("expenses")
                .update({"is_deleted": True, "deleted_at": None})
                .eq("page_id", page_id)
                .eq("id", expense_id)
            )

        return True, "Updated"
    except ValueError as ve:
        return False, f"Update failed: {ve}"
    except Exception as e:
        return False, f"Update failed: {e}"


def soft_delete_expense(page_id, expense_id: int) -> Tuple[bool, str]:
    sb = _sb()
    page_id = _norm_page_id(page_id)
    expense_id = int(expense_id)

    try:
        r1 = _execute_with_retry(
            sb.table("expenses")
            .update({"is_deleted": True, "deleted_at": None})
            .eq("page_id", page_id)
            .eq("id", expense_id)
            .eq("is_deleted", False)
        )
        ok, msg = _ok(r1)
        if not ok:
            return False, f"Delete failed: {msg}"
        if not r1.data:
            return False, "Expense not found"

        r2 = _execute_with_retry(
            sb.table("expense_shares")
            .update({"is_deleted": True, "deleted_at": None})
            .eq("expense_id", expense_id)
            .eq("is_deleted", False)
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
        ex = _execute_with_retry(
            sb.table("expenses")
            .select("paid_by_member_id")
            .eq("page_id", page_id)
            .eq("id", expense_id)
            .eq("is_deleted", True)
            .limit(1)
        )
        ok, msg = _ok(ex)
        if not ok:
            return False, f"Restore failed: {msg}"
        if not ex.data:
            return False, "Expense not found"

        payer_id = int(ex.data[0]["paid_by_member_id"])
        payer = _execute_with_retry(
            sb.table("members").select("is_deleted").eq("page_id", page_id).eq("id", payer_id).limit(1)
        )
        ok, msg = _ok(payer)
        if not ok:
            return False, f"Restore failed: {msg}"
        if not payer.data or bool(payer.data[0]["is_deleted"]):
            return False, "Cannot restore: payer is deleted"

        r1 = _execute_with_retry(
            sb.table("expenses")
            .update({"is_deleted": False, "deleted_at": None})
            .eq("page_id", page_id)
            .eq("id", expense_id)
            .eq("is_deleted", True)
        )
        ok, msg = _ok(r1)
        if not ok:
            return False, f"Restore failed: {msg}"

        active_ids = _active_member_ids(page_id)
        if active_ids:
            r2 = _execute_with_retry(
                sb.table("expense_shares")
                .update({"is_deleted": False, "deleted_at": None})
                .eq("expense_id", expense_id)
                .in_("member_id", active_ids)
            )
            ok, msg = _ok(r2)
            if not ok:
                return False, f"Restore failed: {msg}"

        cnt = _execute_with_retry(
            sb.table("expense_shares")
            .select("expense_id", count="exact")
            .eq("expense_id", expense_id)
            .eq("is_deleted", False)
        )
        ok, msg = _ok(cnt)
        if not ok:
            return False, f"Restore failed: {msg}"
        c = int(getattr(cnt, "count", 0) or 0)
        if c == 0:
            _ = _execute_with_retry(
                sb.table("expenses")
                .update({"is_deleted": True, "deleted_at": None})
                .eq("page_id", page_id)
                .eq("id", expense_id)
            )
            return False, "Cannot restore: no active targets"

        return True, "Restored"
    except Exception as e:
        return False, f"Restore failed: {e}"


def fetch_expenses(page_id, active_only: bool = True) -> List[Dict]:
    sb = _sb()
    page_id = _norm_page_id(page_id)

    # Members (for names + active filter)
    mem_resp = _execute_with_retry(sb.table("members").select("id,name,is_deleted").eq("page_id", page_id))
    ok, msg = _ok(mem_resp)
    if not ok:
        raise RuntimeError(f"DB error: {msg}")

    mem_rows = mem_resp.data or []
    id_to_name = {int(r["id"]): r["name"] for r in mem_rows}
    active_member_ids = {int(r["id"]) for r in mem_rows if not bool(r.get("is_deleted", False))}

    # Expenses (ADD: note)
    q = (
        sb.table("expenses")
        .select(
            "id,expense_date,description,amount,currency,paid_by_member_id,how,note,created_at,is_deleted,deleted_at"
        )
        .eq("page_id", page_id)
    )

    if active_only:
        q = q.eq("is_deleted", False)

    exp_resp = _execute_with_retry(
        q.order("expense_date", desc=True).order("created_at", desc=True).order("id", desc=True)
    )
    ok, msg = _ok(exp_resp)
    if not ok:
        raise RuntimeError(f"DB error: {msg}")

    expenses = [dict(r) for r in (exp_resp.data or [])]
    if not expenses:
        return []

    for ex in expenses:
        ex["paid_by"] = id_to_name.get(int(ex["paid_by_member_id"]), "Unknown")
        ex["how"] = ex.get("how") or "even"
        ex["note"] = (ex.get("note") or "").strip()

    expense_ids = [int(r["id"]) for r in expenses]

    # Shares (used for target_ids + shares)
    sh_resp = _execute_with_retry(
        sb.table("expense_shares")
        .select("expense_id,member_id,is_deleted,share_amount,share_percent")
        .in_("expense_id", expense_ids)
    )
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

        # target member ids
        if active_only:
            active_targets = [
                int(s["member_id"])
                for s in rows
                if (not bool(s.get("is_deleted", False))) and int(s["member_id"]) in active_member_ids
            ]
        else:
            active_targets = [int(s["member_id"]) for s in rows if not bool(s.get("is_deleted", False))]

        ex["target_ids"] = active_targets
        ex["targets"] = [id_to_name.get(mid, "Unknown") for mid in active_targets]

        # share dicts
        ex_share_amounts: Dict[int, float] = {}
        ex_share_percents: Dict[int, float] = {}
        for s in rows:
            if bool(s.get("is_deleted", False)):
                continue
            mid = int(s["member_id"])
            sa = s.get("share_amount", None)
            sp = s.get("share_percent", None)
            if sa is not None:
                ex_share_amounts[mid] = float(sa)
            if sp is not None:
                ex_share_percents[mid] = float(sp)

        ex["share_amounts"] = ex_share_amounts
        ex["share_percents"] = ex_share_percents

        # ---- fallback: legacy rows may have NULL share_amount/share_percent ----
        if (not ex_share_amounts) and (not ex_share_percents) and ex.get("target_ids"):
            how0 = ex.get("how") or "even"
            amt0 = float(ex.get("amount") or 0.0)
            t0 = [int(x) for x in (ex.get("target_ids") or [])]
            n0 = len(t0)

            fb_amounts: Dict[int, float] = {}
            fb_percents: Dict[int, float] = {}

            if n0 <= 0:
                pass

            elif how0 == "even":
                each_amt = amt0 / n0
                each_pct = 100.0 / n0
                for mid in t0:
                    fb_amounts[mid] = round(float(each_amt), 2)
                    fb_percents[mid] = round(float(each_pct), 2)

            elif how0 == "$":
                # legacy: no per member amounts stored -> cannot infer correctly
                # fall back to even split rather than all zero
                each_amt = amt0 / n0
                each_pct = 100.0 / n0
                for mid in t0:
                    fb_amounts[mid] = round(float(each_amt), 2)
                    fb_percents[mid] = round(float(each_pct), 2)

            elif how0 == "%":
                # legacy: no per member percents stored -> cannot infer correctly
                # fall back to even split rather than all zero
                each_amt = amt0 / n0
                each_pct = 100.0 / n0
                for mid in t0:
                    fb_amounts[mid] = round(float(each_amt), 2)
                    fb_percents[mid] = round(float(each_pct), 2)

            ex["share_amounts"] = fb_amounts
            ex["share_percents"] = fb_percents

    # final filter: payer must be active (when active_only)
    if active_only:
        expenses = [
            ex
            for ex in expenses
            if int(ex["paid_by_member_id"]) in active_member_ids and not bool(ex.get("is_deleted", False))
        ]

    return expenses


def compute_net_balances(page_id) -> Dict[str, Dict[str, float]]:
    """
    Compute net balances by aggregating build_transaction_matrix_net.
    This guarantees consistency between Summary and Transaction detail (net matrix).
    """
    page_id = _norm_page_id(page_id)

    page = get_page(page_id)
    main_ccy = (page.get("main_currency") or "USD") if page else "USD"
    sub_raw = (page.get("sub_currency") or "none") if page else "none"

    MAIN = str(main_ccy).upper().strip()
    sub_s = str(sub_raw).strip()
    SUB = str(sub_raw).upper().strip()
    HAS_SUB = bool(sub_s) and (SUB != "NONE") and (sub_s.lower() != "none")

    ccy_choices = [MAIN] + ([SUB] if HAS_SUB and SUB != MAIN else [])

    out: Dict[str, Dict[str, float]] = {}

    for ccy in ccy_choices:
        df = build_transaction_matrix_net(page_id, ccy)

        if df is None or df.empty:
            out[ccy] = {}
            continue

        # member columns = all except meta columns
        meta_cols = {"Expense ID", "Date", "Title", "Note"}
        member_cols = [c for c in df.columns if c not in meta_cols]

        out_ccy: Dict[str, float] = {}
        for col in member_cols:
            out_ccy[str(col)] = -float(pd.to_numeric(df[col], errors="coerce").fillna(0).sum())

        out[ccy] = out_ccy

    return out


def build_transaction_matrix(page_id: str, currency: str) -> pd.DataFrame:
    """
    Share matrix (legacy / compatibility):
    - Member columns show how much each member consumed (share_amount)
    """
    return build_transaction_matrix_share(page_id, currency)


def build_transaction_matrix_share(page_id: str, currency: str) -> pd.DataFrame:
    """
    Share matrix:
    - Member columns show how much each member consumed (share_amount)
    - Amount: total expense amount
    - Paid by: payer name
    - NG: "!" if sum(member amounts) != Amount, else blank
    """
    page_id = _norm_page_id(page_id)

    currency = (currency or "").strip()
    if not currency or currency.lower() == "none":
        return pd.DataFrame()
    currency = currency.upper()

    # ---- formatting rule ----
    no_decimal = currency in NO_DECIMAL_CURRENCIES

    members = get_members(page_id) or []

    # sort by name (case-insensitive, trimmed) to keep UI consistent
    members = sorted(
        [m for m in members if m.get("id") is not None],
        key=lambda m: str(m.get("name") or "").strip().lower(),
    )

    member_ids = [int(m["id"]) for m in members]
    member_names = [str(m.get("name") or "") for m in members]
    id_to_name = {int(m["id"]): str(m.get("name") or "") for m in members}

    expenses = fetch_expenses(page_id, active_only=True) or []
    expenses = [
        e for e in expenses
        if str(e.get("currency") or "").upper() == currency
    ]

    cols = (
        ["Expense ID", "Date", "Title", "Amount", "Paid by"]
        + member_names
        + ["Note", "NG"]
    )
    if not expenses:
        return pd.DataFrame(columns=cols)

    # ---- fetch shares ----
    expense_ids = [int(e["id"]) for e in expenses if e.get("id") is not None]

    sb = _sb()
    sh_resp = _execute_with_retry(
        sb.table("expense_shares")
        .select("expense_id,member_id,share_amount,is_deleted")
        .in_("expense_id", expense_ids)
        .eq("is_deleted", False)
    )
    ok, msg = _ok(sh_resp)
    if not ok:
        raise RuntimeError(f"DB error: {msg}")

    shares = sh_resp.data or []
    shares_by_exp: dict[int, dict[int, float]] = {}
    for s in shares:
        eid = int(s["expense_id"])
        mid = int(s["member_id"])
        sa = s.get("share_amount")
        if sa is None:
            continue
        shares_by_exp.setdefault(eid, {})[mid] = float(sa)

    def _even_split_map(e: dict) -> dict[int, float]:
        if (e.get("how") or "even") != "even":
            return {}
        amt = float(e.get("amount") or 0.0)
        targets = [int(x) for x in (e.get("target_ids") or [])]
        if not targets:
            return {}
        each = amt / len(targets)
        return {mid: float(each) for mid in targets}

    def _mmdd(d) -> str:
        s = str(d or "")
        if len(s) >= 10 and s[4] == "-" and s[7] == "-":
            return f"{int(s[5:7])}/{int(s[8:10])}"
        return s

    rows = []
    for e in expenses:
        eid = int(e["id"])
        amount_raw = float(e.get("amount") or 0.0)
        amount_disp = int(round(amount_raw, 0)) if no_decimal else round(amount_raw, 2)

        payer_id = e.get("paid_by_member_id")
        payer_name = id_to_name.get(int(payer_id)) if payer_id is not None else ""

        row = {
            "Expense ID": eid,
            "Date": _mmdd(e.get("expense_date")),
            "Title": e.get("description"),
            "Amount": amount_disp,
            "Paid by": payer_name,
            "Note": e.get("note") or "",
        }

        # 1) expense_shares
        share_map = dict(shares_by_exp.get(eid, {}))

        # 2) fallback: fetch_expenses share_amounts
        if not share_map:
            sa2 = e.get("share_amounts") or {}
            share_map = {int(k): float(v) for k, v in sa2.items()}

        # 3) legacy even split
        if not share_map:
            share_map = _even_split_map(e)

        # fill member columns
        member_sum = 0.0
        for mid, name in zip(member_ids, member_names):
            v_raw = float(share_map.get(int(mid), 0.0))
            v_disp = int(round(v_raw, 0)) if no_decimal else round(v_raw, 2)
            row[name] = v_disp
            member_sum += float(v_disp)

        # NG check (compare displayed values)
        tol = 0.0 if no_decimal else 1e-9
        row["NG"] = "!" if abs(member_sum - float(amount_disp)) > tol else ""

        rows.append(row)

    df = pd.DataFrame(rows).reindex(columns=cols)

    # ensure numeric for member columns
    for name in member_names:
        df[name] = pd.to_numeric(df[name], errors="coerce").fillna(0)

    df["Expense ID"] = pd.to_numeric(df["Expense ID"], errors="coerce").fillna(0).astype(int)

    return df


def build_transaction_matrix_net(page_id: str, currency: str) -> pd.DataFrame:
    """
    Net matrix:
    - Member columns show +share_amount for targets
    - Payer column additionally gets -amount (so each row sums to 0)
    """
    page_id = _norm_page_id(page_id)

    currency = (currency or "").strip()
    if not currency or currency.lower() == "none":
        return pd.DataFrame()
    currency = currency.upper()

    no_decimal = currency in NO_DECIMAL_CURRENCIES

    members = get_members(page_id) or []

    # sort by name (case-insensitive, trimmed) to keep UI consistent
    members = sorted(
        [m for m in members if m.get("id") is not None],
        key=lambda m: str(m.get("name") or "").strip().lower(),
    )

    member_ids = [int(m["id"]) for m in members]
    member_names = [str(m.get("name") or "") for m in members]
    id_to_name = {int(m["id"]): str(m.get("name") or "") for m in members}

    expenses = fetch_expenses(page_id, active_only=True) or []
    expenses = [e for e in expenses if str(e.get("currency") or "").upper() == currency]

    cols = ["Expense ID", "Date", "Title"] + member_names + ["Note"]
    if not expenses:
        return pd.DataFrame(columns=cols)

    # ---- fetch shares ----
    expense_ids = [int(e["id"]) for e in expenses if e.get("id") is not None]

    sb = _sb()
    sh_resp = _execute_with_retry(
        sb.table("expense_shares")
        .select("expense_id,member_id,share_amount,is_deleted")
        .in_("expense_id", expense_ids)
        .eq("is_deleted", False)
    )
    ok, msg = _ok(sh_resp)
    if not ok:
        raise RuntimeError(f"DB error: {msg}")

    shares = sh_resp.data or []
    shares_by_exp: dict[int, dict[int, float]] = {}
    for s in shares:
        eid = int(s["expense_id"])
        mid = int(s["member_id"])
        sa = s.get("share_amount")
        if sa is None:
            continue
        shares_by_exp.setdefault(eid, {})[mid] = float(sa)

    def _even_split_map(e: dict) -> dict[int, float]:
        if (e.get("how") or "even") != "even":
            return {}
        amt = float(e.get("amount") or 0.0)
        targets = [int(x) for x in (e.get("target_ids") or [])]
        if not targets:
            return {}
        each = amt / len(targets)
        return {mid: float(each) for mid in targets}

    def _mmdd(d) -> str:
        s = str(d or "")
        if len(s) >= 10 and s[4] == "-" and s[7] == "-":
            return f"{int(s[5:7])}/{int(s[8:10])}"
        return s

    rows = []
    for e in expenses:
        eid = int(e["id"])
        amount = float(e.get("amount") or 0.0)
        payer_id = e.get("paid_by_member_id")
        payer_id = int(payer_id) if payer_id is not None else None
        payer_name = id_to_name.get(payer_id) if payer_id is not None else None

        row = {
            "Expense ID": eid,
            "Date": _mmdd(e.get("expense_date")),
            "Title": e.get("description"),
            "Note": e.get("note") or "",
        }

        # start all members at 0
        for name in member_names:
            row[name] = 0

        # 1) expense_shares
        share_map = dict(shares_by_exp.get(eid, {}))

        # 2) fallback: fetch_expenses share_amounts
        if not share_map:
            sa2 = e.get("share_amounts") or {}
            share_map = {int(k): float(v) for k, v in sa2.items()}

        # 3) legacy even split
        if not share_map:
            share_map = _even_split_map(e)

        # + share for each member
        for mid, name in zip(member_ids, member_names):
            v = float(share_map.get(int(mid), 0.0))
            row[name] = (int(round(v, 0)) if no_decimal else round(v, 2))

        # payer gets -amount (so row sum becomes 0 if shares sum to amount)
        if payer_name and payer_name in row:
            payer_delta = -amount
            if no_decimal:
                row[payer_name] = int(round(float(row[payer_name]) + payer_delta, 0))
            else:
                row[payer_name] = round(float(row[payer_name]) + payer_delta, 2)

        rows.append(row)

    df = pd.DataFrame(rows).reindex(columns=cols)

    # ensure numeric
    for name in member_names:
        df[name] = pd.to_numeric(df[name], errors="coerce").fillna(0)

    df["Expense ID"] = pd.to_numeric(df["Expense ID"], errors="coerce").fillna(0).astype(int)

    return df


# ------------------------
# Bulk and Danger ops (page scoped)
# ------------------------
def soft_delete_all_expenses(page_id) -> Tuple[bool, str]:
    sb = _sb()
    page_id = _norm_page_id(page_id)

    try:
        r1 = _execute_with_retry(
            sb.table("expenses")
            .update({"is_deleted": True, "deleted_at": "now()"})
            .eq("page_id", page_id)
            .eq("is_deleted", False)
        )
        ok, msg = _ok(r1)
        if not ok:
            return False, f"Bulk delete failed: {msg}"

        ex_ids_resp = _execute_with_retry(sb.table("expenses").select("id").eq("page_id", page_id))
        ok, msg = _ok(ex_ids_resp)
        if not ok:
            return False, f"Bulk delete failed: {msg}"
        ex_ids = [int(r["id"]) for r in (ex_ids_resp.data or [])]
        if ex_ids:
            r2 = _execute_with_retry(
                sb.table("expense_shares")
                .update({"is_deleted": True, "deleted_at": "now()"})
                .in_("expense_id", ex_ids)
                .eq("is_deleted", False)
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
        r1 = _execute_with_retry(
            sb.table("expenses")
            .update({"is_deleted": True, "deleted_at": "now()"})
            .eq("page_id", page_id)
            .eq("is_deleted", False)
        )
        ok, msg = _ok(r1)
        if not ok:
            return False, f"Bulk delete failed: {msg}"

        ex_ids_resp = _execute_with_retry(sb.table("expenses").select("id").eq("page_id", page_id))
        ok, msg = _ok(ex_ids_resp)
        if not ok:
            return False, f"Bulk delete failed: {msg}"
        ex_ids = [int(r["id"]) for r in (ex_ids_resp.data or [])]
        if ex_ids:
            r2 = _execute_with_retry(
                sb.table("expense_shares")
                .update({"is_deleted": True, "deleted_at": "now()"})
                .in_("expense_id", ex_ids)
                .eq("is_deleted", False)
            )
            ok, msg = _ok(r2)
            if not ok:
                return False, f"Bulk delete failed: {msg}"

        r3 = _execute_with_retry(
            sb.table("members")
            .update({"is_deleted": True, "deleted_at": "now()"})
            .eq("page_id", page_id)
            .eq("is_deleted", False)
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
        page = _execute_with_retry(sb.table("pages").select("id").eq("id", page_id).eq("is_deleted", False).limit(1))
        ok, msg = _ok(page)
        if not ok:
            return False, f"Wipe failed: {msg}"
        if not page.data:
            return False, "Page not found"

        ex_ids_resp = _execute_with_retry(sb.table("expenses").select("id").eq("page_id", page_id))
        ok, msg = _ok(ex_ids_resp)
        if not ok:
            return False, f"Wipe failed: {msg}"
        ex_ids = [int(r["id"]) for r in (ex_ids_resp.data or [])]

        if ex_ids:
            r1 = _execute_with_retry(sb.table("expense_shares").delete().in_("expense_id", ex_ids))
            ok, msg = _ok(r1)
            if not ok:
                return False, f"Wipe failed: {msg}"

        r2 = _execute_with_retry(sb.table("expenses").delete().eq("page_id", page_id))
        ok, msg = _ok(r2)
        if not ok:
            return False, f"Wipe failed: {msg}"

        r3 = _execute_with_retry(sb.table("members").delete().eq("page_id", page_id))
        ok, msg = _ok(r3)
        if not ok:
            return False, f"Wipe failed: {msg}"

        r4 = _execute_with_retry(sb.table("pages").delete().eq("id", page_id))
        ok, msg = _ok(r4)
        if not ok:
            return False, f"Wipe failed: {msg}"

        return True, "Deleted this page and all its data"
    except Exception as e:
        return False, f"Wipe failed: {e}"


def delete_db_file() -> Tuple[bool, str]:
    return False, "Not supported in Supabase mode"


# Settlement
def fetch_settle_input_checks(page_id: str) -> dict[int, bool]:
    page_id = _norm_page_id(page_id)
    sb = _sb()
    resp = _execute_with_retry(
        sb.table("settle_input_checks")
        .select("member_id,is_done")
        .eq("page_id", page_id)
    )
    ok, msg = _ok(resp)
    if not ok:
        raise RuntimeError(f"DB error: {msg}")

    out: dict[int, bool] = {}
    for r in (resp.data or []):
        out[int(r["member_id"])] = bool(r.get("is_done", False))
    return out


def set_settle_input_check(page_id: str, member_id: int, is_done: bool) -> tuple[bool, str]:
    page_id = _norm_page_id(page_id)
    sb = _sb()
    payload = {"page_id": page_id, "member_id": int(member_id), "is_done": bool(is_done)}
    resp = _execute_with_retry(
        sb.table("settle_input_checks").upsert(payload, on_conflict="page_id,member_id")
    )
    ok, msg = _ok(resp)
    return ok, ("Updated" if ok else msg)


def save_settlement_result_df(page_id: str, df: pd.DataFrame) -> tuple[bool, str]:
    page_id = _norm_page_id(page_id)
    sb = _sb()
    payload = {
        "page_id": page_id,
        "result_json": df.to_json(orient="records"),
    }
    resp = _execute_with_retry(
        sb.table("settlement_results").upsert(payload, on_conflict="page_id")
    )
    ok, msg = _ok(resp)
    return ok, ("Saved" if ok else msg)


def fetch_settlement_result_df(page_id: str):
    page_id = _norm_page_id(page_id)
    sb = _sb()
    resp = _execute_with_retry(
        sb.table("settlement_results")
        .select("result_json")
        .eq("page_id", page_id)
        .limit(1)
    )
    ok, msg = _ok(resp)
    if not ok:
        raise RuntimeError(f"DB error: {msg}")
    rows = resp.data or []
    if not rows:
        return None
    j = rows[0].get("result_json")
    if not j:
        return None
    return pd.DataFrame(json.loads(j))


def fetch_settlement_done_map(page_id: str) -> dict[str, bool]:
    page_id = _norm_page_id(page_id)
    sb = _sb()
    resp = _execute_with_retry(
        sb.table("settlement_done_flags")  # <- changed
        .select("row_key,is_done")
        .eq("page_id", page_id)
    )
    ok, msg = _ok(resp)
    if not ok:
        raise RuntimeError(f"DB error: {msg}")

    return {str(r["row_key"]): bool(r.get("is_done", False)) for r in (resp.data or [])}


def set_settlement_done(page_id: str, row_key: str, is_done: bool) -> tuple[bool, str]:
    page_id = _norm_page_id(page_id)
    sb = _sb()
    payload = {"page_id": page_id, "row_key": str(row_key), "is_done": bool(is_done)}
    resp = _execute_with_retry(
        sb.table("settlement_done_flags")  # <- changed
        .upsert(payload, on_conflict="page_id,row_key")
    )
    ok, msg = _ok(resp)
    return ok, ("Updated" if ok else msg)