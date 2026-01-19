# pages/1_App.py

# ----------------------------------------
# Imports
# ----------------------------------------
from datetime import date
from io import BytesIO

import pandas as pd
import streamlit as st

import db

# ----------------------------------------
# Pandas display settings
# ----------------------------------------
pd.options.display.float_format = "{:,.2f}".format

# ----------------------------------------
# Streamlit page config + DB init
# ----------------------------------------
st.set_page_config(page_title="SplitWiser", layout="wide")
db.init_db()

# ----------------------------------------
# Restore page_id from URL (so /App?page_id=... works)
# ----------------------------------------
qp_page_id = st.query_params.get("page_id", None)

if ("page_id" not in st.session_state or st.session_state["page_id"] is None) and qp_page_id:
    try:
        st.session_state["page_id"] = str(qp_page_id)  # TEXT id
    except Exception:
        st.session_state["page_id"] = None

if "page_id" not in st.session_state or st.session_state["page_id"] is None:
    st.warning("No page selected. Go back to the main page.")
    if st.button("Back to main"):
        st.switch_page("main.py")
    st.stop()

PAGE_ID = str(st.session_state["page_id"])

# Keep URL in sync for refresh / revisit
st.query_params["page_id"] = PAGE_ID

page_row = db.get_page(PAGE_ID)
page_name = page_row["name"] if page_row else "Unknown"

# ----------------------------------------
# Page currency settings (main/sub)
# ----------------------------------------
# Currency choices
CURRENCY_CHOICES = list(db.CURRENCY_CHOICES)
NO_DECIMAL_CURRENCIES = set(db.NO_DECIMAL_CURRENCIES)


def _norm_ccy(x: str | None) -> str:
    # Normalize currency code:
    # - None/empty -> "none"
    # - "none" (case-insensitive) -> "none"
    # - otherwise -> uppercase currency code
    if not x:
        return "none"
    s = str(x).strip().lower()
    if s == "none":
        return "none"
    return s.upper()


MAIN_CCY = _norm_ccy(page_row.get("main_currency") if page_row else None)
if MAIN_CCY == "none":
    MAIN_CCY = "USD"  # Fallback safeguard

SUB_CCY = _norm_ccy(page_row.get("sub_currency") if page_row else None)

# Whether this page uses a secondary currency
HAS_SUB = (SUB_CCY != "none") and (SUB_CCY != MAIN_CCY)

# Currency choices used across the app
CCY_CHOICES = [MAIN_CCY] + ([SUB_CCY] if HAS_SUB else [])

# ----------------------------------------
# Page title
# ----------------------------------------
# Title: page name only
st.title(f"{page_name}")

# ----------------------------------------
# Session state helpers
# ----------------------------------------
def _ss_get(key: str, default=None):
    # Get a session_state value with default initialization
    if key not in st.session_state:
        st.session_state[key] = default
    return st.session_state[key]


def _clear_keys(keys):
    # Delete keys from session_state if they exist
    for k in keys:
        if k in st.session_state:
            del st.session_state[k]


def _calc_even_amounts(total: float, member_ids: list[int]) -> dict[int, float]:
    # Split "total" evenly across member_ids (rounded to 2 decimals)
    if not member_ids:
        return {}
    n = len(member_ids)
    base = round(float(total) / n, 2)
    return {int(mid): base for mid in member_ids}


def _calc_even_percents(member_ids: list[int]) -> dict[int, float]:
    # Split 100% evenly across member_ids (rounded to 2 decimals)
    if not member_ids:
        return {}
    n = len(member_ids)
    base = round(100.0 / n, 2)
    return {int(mid): base for mid in member_ids}


def _fmt_money(x: float, ccy: str) -> str:
    # Format currency amount:
    # - No-decimal currencies -> integer with commas
    # - Others -> 2 decimals with commas
    if (ccy or "").upper() in NO_DECIMAL_CURRENCIES:
        return f"{int(round(float(x or 0.0), 0)):,}"
    return f"{float(x or 0.0):,.2f}"


def _reset_add_expense_form(page_id: str):
    # Reset add-expense widgets (legacy helper; not used in hard reset approach)
    keys = [
        f"add_d_{page_id}",
        f"add_title_{page_id}",
        f"add_amount_{page_id}",
        f"add_currency_{page_id}",
        f"add_payer_{page_id}",
        f"add_targets_{page_id}",
        f"add_note_{page_id}",
    ]
    _clear_keys(keys)


def _reset_edit_step1_keys(page_id: str, expense_id: int):
    # Reset edit-step1 widget keys for a specific expense
    keys = [
        f"edit_d_{page_id}_{expense_id}",
        f"edit_title_{page_id}_{expense_id}",
        f"edit_amount_{page_id}_{expense_id}",
        f"edit_currency_{page_id}_{expense_id}",
        f"edit_payer_{page_id}_{expense_id}",
        f"edit_targets_{page_id}_{expense_id}",
        f"edit_note_{page_id}_{expense_id}",
    ]
    _clear_keys(keys)


def _reset_edit_step2_keys(page_id: str, expense_id: int, target_ids: list[int]):
    # Reset edit-step2 widget keys (shares) for a specific expense/targets
    keys = []
    for mid in target_ids:
        keys.append(f"hist_share_amt_{page_id}_{expense_id}_{mid}")
        keys.append(f"hist_share_pct_{page_id}_{expense_id}_{mid}")
    _clear_keys(keys)


def _fmt_shares_line(ex: dict, id_to_name: dict[int, str]) -> str:
    # Build a human-readable "shares" line for a transaction
    how = ex.get("how") or "even"
    targets = [int(x) for x in (ex.get("target_ids") or [])]
    amount = float(ex.get("amount") or 0.0)
    ccy = (ex.get("currency") or MAIN_CCY).upper()

    if not targets:
        return ""

    if how == "even":
        per = amount / len(targets) if len(targets) > 0 else 0.0
        parts = [f"{id_to_name.get(t, 'Unknown')}: {_fmt_money(per, ccy)}" for t in targets]
        return " | ".join(parts)

    if how == "$":
        shares = ex.get("share_amounts") or {}
        parts = [
            f"{id_to_name.get(t, 'Unknown')}: {_fmt_money(float(shares.get(t, 0.0)), ccy)}"
            for t in targets
        ]
        return " | ".join(parts)

    if how == "%":
        shares = ex.get("share_percents") or {}
        parts = [f"{id_to_name.get(t, 'Unknown')}: {float(shares.get(t, 0.0)):.2f}%" for t in targets]
        return " | ".join(parts)

    return ""


# ----------------------------------------
# Export buttons (transaction matrix)
# - Always fetch from DB (source of truth)
# - Exports BOTH Share and Net as separate sheets:
#   MAIN, MAIN(net), (optional) SUB, SUB(net)
# ----------------------------------------
c1, c2 = st.columns([1, 1], gap="small")

with c1:
    st.caption("")

with c2:
    # MAIN
    df_main_share = db.build_transaction_matrix_share(PAGE_ID, MAIN_CCY)
    df_main_net = db.build_transaction_matrix_net(PAGE_ID, MAIN_CCY)

    # SUB (optional)
    df_sub_share = pd.DataFrame()
    df_sub_net = pd.DataFrame()
    if HAS_SUB and (SUB_CCY or "").lower() != "none":
        df_sub_share = db.build_transaction_matrix_share(PAGE_ID, SUB_CCY)
        df_sub_net = db.build_transaction_matrix_net(PAGE_ID, SUB_CCY)

    # Build an Excel file in memory
    bio = BytesIO()
    with pd.ExcelWriter(bio, engine="openpyxl") as writer:
        # MAIN share
        if df_main_share is None or df_main_share.empty:
            pd.DataFrame({"Info": [f"No {MAIN_CCY} transactions"]}).to_excel(
                writer, sheet_name=MAIN_CCY, index=False
            )
        else:
            df_main_share.to_excel(writer, sheet_name=MAIN_CCY, index=False)

        # MAIN net
        main_net_sheet = f"{MAIN_CCY}(net)"
        if df_main_net is None or df_main_net.empty:
            pd.DataFrame({"Info": [f"No {MAIN_CCY} net rows"]}).to_excel(
                writer, sheet_name=main_net_sheet[:31], index=False
            )
        else:
            df_main_net.to_excel(writer, sheet_name=main_net_sheet[:31], index=False)

        # SUB share + net
        if HAS_SUB and (SUB_CCY or "").lower() != "none":
            if df_sub_share is None or df_sub_share.empty:
                pd.DataFrame({"Info": [f"No {SUB_CCY} transactions"]}).to_excel(
                    writer, sheet_name=SUB_CCY, index=False
                )
            else:
                df_sub_share.to_excel(writer, sheet_name=SUB_CCY, index=False)

            sub_net_sheet = f"{SUB_CCY}(net)"
            if df_sub_net is None or df_sub_net.empty:
                pd.DataFrame({"Info": [f"No {SUB_CCY} net rows"]}).to_excel(
                    writer, sheet_name=sub_net_sheet[:31], index=False
                )
            else:
                df_sub_net.to_excel(writer, sheet_name=sub_net_sheet[:31], index=False)

    # Make the filename filesystem-safe
    safe_page_name = "".join([c for c in (page_name or "") if c not in r'\/:*?"<>|']).strip() or "page"

    st.download_button(
        label="Download Transaction Matrix (Excel)",
        data=bio.getvalue(),
        file_name=f"{safe_page_name}_transaction_matrix.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )

# ----------------------------------------
# Layout columns
# ----------------------------------------
left, right = st.columns([1, 2], gap="large")

# ----------------------------------------
# Left: Members + Add member + Add expense
# ----------------------------------------
with left:
    st.subheader("Members")

    # ------------------------
    # Members list: rename / delete
    # ------------------------
    members = db.get_members(PAGE_ID)
    if not members:
        st.info("No members yet. Add members below.")
    else:
        for m in members:
            mid = int(m["id"])
            usage = db.member_usage_count(PAGE_ID, mid)

            with st.expander(f'{m["name"]} (usage {usage})', expanded=False):
                with st.form(f"member_form_{mid}"):
                    new_name = st.text_input("Name", value=m["name"], key=f"member_name_{mid}")

                    b1, b2 = st.columns([1, 1])
                    with b1:
                        save_clicked = st.form_submit_button("Save")
                    with b2:
                        delete_clicked = st.form_submit_button("Delete")

                    if save_clicked:
                        ok, msg = db.rename_member(PAGE_ID, mid, new_name)
                        if ok:
                            st.success(msg)
                            st.rerun()
                        else:
                            st.error(msg)

                    if delete_clicked:
                        ok, msg = db.soft_delete_member_everywhere(PAGE_ID, mid)
                        if ok:
                            st.success(msg)
                            st.rerun()
                        else:
                            st.error(msg)

    # ------------------------
    # Add member
    # ------------------------
    st.divider()
    st.subheader("Add member")

    with st.form("add_member_form", clear_on_submit=True):
        new_name = st.text_input("Name")
        submitted = st.form_submit_button("Add")

        if submitted:
            ok, msg = db.add_member(PAGE_ID, new_name)
            if ok:
                st.success(msg)
                st.rerun()
            else:
                st.error(msg)

    # ------------------------
    # Add expense
    # ------------------------
    st.divider()
    st.subheader("Add expense")

    members = db.get_members(PAGE_ID)
    if not members:
        st.info("Add members first.")
    else:
        # ID/name maps
        id_name = [(int(m["id"]), m["name"]) for m in members]
        names = [x[1] for x in id_name]
        name_to_id = {n: i for i, n in id_name}
        id_to_name = {i: n for i, n in id_name}

        # Draft state keys
        draft_key = f"draft_add_{PAGE_ID}"
        mode_key = f"draft_add_mode_{PAGE_ID}"
        form_ver_key = f"add_form_ver_{PAGE_ID}"

        # Init keys if missing
        if draft_key not in st.session_state:
            st.session_state[draft_key] = None
        if mode_key not in st.session_state:
            st.session_state[mode_key] = None
        if form_ver_key not in st.session_state:
            st.session_state[form_ver_key] = 0

        form_ver = int(st.session_state[form_ver_key])

        def _hard_reset_add_form():
            # Fully reset the add form on next rerun by changing widget keys
            st.session_state[draft_key] = None
            st.session_state[mode_key] = None
            st.session_state[form_ver_key] += 1

            # Clean up Step2 keys as well
            try:
                for mid, _nm in id_name:
                    _clear_keys(
                        [
                            f"add_share_amt_{PAGE_ID}_{mid}",
                            f"add_share_pct_{PAGE_ID}_{mid}",
                        ]
                    )
            except Exception:
                pass

        # ------------------------
        # Step 1: base fields + choose mode + Clear
        # ------------------------
        with st.form("add_expense_step1", clear_on_submit=False):
            d = st.date_input("When", value=date.today(), key=f"add_d_{PAGE_ID}_{form_ver}")
            title = st.text_input("Title", key=f"add_title_{PAGE_ID}_{form_ver}")
            amount = st.number_input(
                "Amount",
                min_value=0.0,
                value=0.0,
                step=1.0,
                key=f"add_amount_{PAGE_ID}_{form_ver}",
            )

            # Currency: page-defined main/sub
            currency = st.selectbox(
                "Currency",
                CCY_CHOICES,
                index=0,
                key=f"add_currency_{PAGE_ID}_{form_ver}",
            )

            payer_name = st.selectbox("Paid by", names, index=0, key=f"add_payer_{PAGE_ID}_{form_ver}")
            payer_id = name_to_id[payer_name]

            target_names = st.multiselect(
                "For",
                options=names,
                default=names,
                key=f"add_targets_{PAGE_ID}_{form_ver}",
            )
            target_ids = [name_to_id[n] for n in target_names]

            note = st.text_input("Note", key=f"add_note_{PAGE_ID}_{form_ver}")

            # Mode buttons
            cA, cB, cC, cD = st.columns(4)
            with cA:
                go_even = st.form_submit_button("Even")
            with cB:
                go_dollar = st.form_submit_button("Enter $")
            with cC:
                go_percent = st.form_submit_button("Enter %")
            with cD:
                clear_add = st.form_submit_button("Clear")

            # Clear: hard reset + rerun
            if clear_add:
                _hard_reset_add_form()
                st.rerun()

            # Validation + save (Even) or proceed to Step2 ($/%)
            if go_even or go_dollar or go_percent:
                if not (title or "").strip():
                    st.error("Title is empty")
                elif float(amount) < 0:
                    st.error("Invalid amount")
                elif not target_ids:
                    st.error("Please select targets")
                else:
                    if go_even:
                        ok, msg = db.add_expense(
                            PAGE_ID,
                            d,
                            (title or "").strip(),
                            float(amount),
                            currency,
                            int(payer_id),
                            [int(x) for x in target_ids],
                            note=(note or "").strip(),
                            how="even",
                            share_amounts=None,
                            share_percents=None,
                        )
                        if ok:
                            st.success(msg)
                            _hard_reset_add_form()
                            st.rerun()
                        else:
                            st.error(msg)
                    else:
                        # Save Step1 fields into draft and move to Step2
                        st.session_state[draft_key] = {
                            "d": d,
                            "title": (title or "").strip(),
                            "amount": float(amount),
                            "currency": currency,
                            "payer_id": int(payer_id),
                            "target_ids": [int(x) for x in target_ids],
                            "note": (note or "").strip(),
                        }
                        st.session_state[mode_key] = "$" if go_dollar else "%"

                        # Reset Step2 widget values for targets
                        for mid in target_ids:
                            _clear_keys([f"add_share_amt_{PAGE_ID}_{mid}", f"add_share_pct_{PAGE_ID}_{mid}"])

                        st.rerun()

        # ------------------------
        # Step 2: mode specific inputs + Save/Clear (only for $ and %)
        # ------------------------
        draft = st.session_state.get(draft_key)
        mode = st.session_state.get(mode_key)

        if draft and mode in ("$", "%"):
            st.divider()

            # Mode title
            try:
                st.markdown(
                    f"<div style='font-size:20px; font-weight:600;'>Mode: {mode}</div>",
                    unsafe_allow_html=True,
                )
            except Exception:
                st.write(f"Mode: {mode}")

            targets = list(draft["target_ids"])

            # ---- Mode: $ ----
            if mode == "$":
                total = float(draft["amount"])
                defaults = _calc_even_amounts(total, targets)

                # Per-target amount inputs
                share_amounts: dict[int, float] = {}
                for mid in targets:
                    nm = id_to_name.get(int(mid), f"member {mid}")
                    v = st.number_input(
                        nm,
                        min_value=0.0,
                        value=float(defaults.get(int(mid), 0.0)),
                        step=0.01,
                        key=f"add_share_amt_{PAGE_ID}_{mid}",
                    )
                    share_amounts[int(mid)] = float(v)

                # Sum check must match total
                s = round(sum(share_amounts.values()), 2)
                dff = round(s - total, 2)
                st.caption(f"sum: {s:.2f}   amount: {total:.2f}   diff: {dff:+.2f}")

                c1, c2 = st.columns([1, 1])
                with c1:
                    can_save = abs(float(dff)) <= 1e-9
                    save_clicked = st.button("Save", key=f"add_save_dollar_{PAGE_ID}", disabled=(not can_save))
                with c2:
                    clear_clicked = st.button("Clear", key=f"add_clear_dollar_{PAGE_ID}")

                if save_clicked:
                    if abs(float(dff)) > 1e-9:
                        st.error("diff must be 0.00 before saving.")
                    else:
                        ok, msg = db.add_expense(
                            PAGE_ID,
                            draft["d"],
                            draft["title"],
                            draft["amount"],
                            draft["currency"],
                            draft["payer_id"],
                            draft["target_ids"],
                            note=(draft.get("note") or "").strip(),
                            how="$",
                            share_amounts=share_amounts,
                            share_percents=None,
                        )
                        if ok:
                            st.success(msg)
                            _hard_reset_add_form()
                            st.rerun()
                        else:
                            st.error(msg)

                if clear_clicked:
                    _hard_reset_add_form()
                    st.rerun()

            # ---- Mode: % ----
            elif mode == "%":
                defaults = _calc_even_percents(targets)

                # Per-target percent inputs
                share_percents: dict[int, float] = {}
                for mid in targets:
                    nm = id_to_name.get(int(mid), f"member {mid}")
                    v = st.number_input(
                        nm,
                        min_value=0.0,
                        max_value=100.0,
                        value=float(defaults.get(int(mid), 0.0)),
                        step=0.01,
                        key=f"add_share_pct_{PAGE_ID}_{mid}",
                    )
                    share_percents[int(mid)] = float(v)

                # Sum check must be 100%
                s = round(sum(share_percents.values()), 2)
                dff = round(s - 100.0, 2)
                st.caption(f"sum: {s:.2f}%   diff: {dff:+.2f}%")

                c1, c2 = st.columns([1, 1])
                with c1:
                    can_save = abs(float(dff)) <= 1e-9
                    save_clicked = st.button("Save", key=f"add_save_percent_{PAGE_ID}", disabled=(not can_save))
                with c2:
                    clear_clicked = st.button("Clear", key=f"add_clear_percent_{PAGE_ID}")

                if save_clicked:
                    if abs(float(dff)) > 1e-9:
                        st.error("diff must be 0.00% before saving.")
                    else:
                        ok, msg = db.add_expense(
                            PAGE_ID,
                            draft["d"],
                            draft["title"],
                            draft["amount"],
                            draft["currency"],
                            draft["payer_id"],
                            draft["target_ids"],
                            note=(draft.get("note") or "").strip(),
                            how="%",
                            share_amounts=None,
                            share_percents=share_percents,
                        )
                        if ok:
                            st.success(msg)
                            _hard_reset_add_form()
                            st.rerun()
                        else:
                            st.error(msg)

                if clear_clicked:
                    _hard_reset_add_form()
                    st.rerun()

# ----------------------------------------
# Right: Summary -> Transaction detail -> History -> Deleted history -> Deleted members
# ----------------------------------------
with right:
    # ------------------------
    # Summary
    # ------------------------
    st.subheader("Summary")
    st.caption("Positive = receive, negative = pay")

    members = db.get_members(PAGE_ID)
    if not members:
        st.write("No members.")
    else:
        balances = db.compute_net_balances(PAGE_ID)

        # Build tabs from main/sub
        tab_labels = [MAIN_CCY] + ([SUB_CCY] if HAS_SUB else [])
        tabs = st.tabs(tab_labels)

        # Map tabs to balances keys and display
        for idx, ccy in enumerate(tab_labels):
            with tabs[idx]:
                net_map = balances.get(ccy, {}) if isinstance(balances, dict) else {}
                rows = []
                for k, v in (net_map or {}).items():
                    rows.append({"Member": k, "Net": _fmt_money(float(v or 0.0), ccy)})
                st.dataframe(rows, use_container_width=True, hide_index=True)

        # ------------------------
        # Settle up UI
        # ------------------------
        st.divider()
        st.subheader("Settle up")

        # Current members snapshot
        members_now = db.get_members(PAGE_ID) or []
        id_name = [
            (int(m["id"]), (m.get("name") or "").strip())
            for m in members_now
            if m.get("id") is not None and (m.get("name") or "").strip()
        ]
        member_ids_now = [mid for mid, _ in id_name]
        id_to_name = {mid: nm for mid, nm in id_name}
        names_now = [nm for _, nm in id_name]

        # ------------------------
        # Persisted input check (DB)
        # ------------------------
        with st.expander("Input check", expanded=False):
            st.caption("Mark everyone as done to compute.")

            # Load persisted status
            check_map = db.fetch_settle_input_checks(PAGE_ID) or {}  # {member_id: bool}

            done_ids = [mid for mid in member_ids_now if bool(check_map.get(mid, False))]
            undone_ids = [mid for mid in member_ids_now if not bool(check_map.get(mid, False))]

            done_names = [id_to_name.get(mid, str(mid)) for mid in done_ids]
            undone_names = [id_to_name.get(mid, str(mid)) for mid in undone_ids]

            st.markdown(f"**Done:** {' / '.join(done_names) if done_names else 'None'}")
            st.markdown(f"**Not done:** {' / '.join(undone_names) if undone_names else 'None'}")

            # Form: multiselect + bulk update
            if names_now:
                with st.form(f"settle_input_check_form_{PAGE_ID}", clear_on_submit=False):
                    picked_names = st.multiselect(
                        "Members",
                        options=names_now,
                        default=[],
                        key=f"settle_input_pick_multi_{PAGE_ID}",
                    )

                    c1, c2 = st.columns(2)
                    with c1:
                        done_clicked = st.form_submit_button("Done")
                    with c2:
                        undone_clicked = st.form_submit_button("Undone")

                    if (done_clicked or undone_clicked) and picked_names:
                        name_to_id = {nm: mid for mid, nm in id_name}
                        is_done = bool(done_clicked)

                        ok_all = True
                        last_msg = ""
                        for nm in picked_names:
                            mid = int(name_to_id[nm])
                            ok, msg = db.set_settle_input_check(
                                page_id=PAGE_ID,
                                member_id=mid,
                                is_done=is_done,
                            )
                            ok_all = ok_all and ok
                            last_msg = msg

                        if ok_all:
                            st.success("Updated.")
                            st.rerun()
                        else:
                            st.error(last_msg or "Failed to update.")
            else:
                st.write("No members.")

        # Re-check whether all members are confirmed
        check_map_now = db.fetch_settle_input_checks(PAGE_ID) or {}
        all_confirmed = all(bool(check_map_now.get(mid, False)) for mid in member_ids_now) if member_ids_now else False

        # ------------------------
        # Consistency check before mode selection (MAIN + SUB)
        # ------------------------
        def _get_tx_summary_for_ccy(ccy: str) -> tuple[int, int]:
            """
            Returns:
                total_rows, ng_count
            """
            if not ccy:
                return 0, 0

            dfc = db.build_transaction_matrix(PAGE_ID, ccy)
            if dfc is None or dfc.empty:
                return 0, 0

            total = len(dfc)
            ng = int((dfc["NG"] == "!").sum()) if "NG" in dfc.columns else 0
            return total, ng


        total_main, ng_main = _get_tx_summary_for_ccy(MAIN_CCY)
        total_sub, ng_sub = _get_tx_summary_for_ccy(SUB_CCY) if HAS_SUB else (0, 0)

        total_tx = total_main + total_sub
        total_ng = ng_main + ng_sub

        if total_tx == 0:
            pass

        elif total_ng == 0:
            st.success("All transactions are consistent.")

        else:
            st.warning(
                f"{total_ng} transaction(s) do not match "
                f"({MAIN_CCY}: {ng_main}"
                f"{', ' + SUB_CCY + ': ' + str(ng_sub) if HAS_SUB else ''}). "
                f"Check the transaction table and fix them."
            )


        # ------------------------
        # Mode selection (after checklist) - MAIN/SUB aware
        # ------------------------
        mode_key = f"settle_mode_{PAGE_ID}"

        # Build mode options dynamically from page currencies
        mode_options = [MAIN_CCY]
        if HAS_SUB:
            mode_options += [SUB_CCY, "Convert"]

        # Initialize default mode safely
        if mode_key not in st.session_state or st.session_state[mode_key] not in mode_options:
            st.session_state[mode_key] = MAIN_CCY

        mode = st.radio(
            "Mode",
            options=mode_options,
            horizontal=True,
            key=mode_key,
            disabled=(not all_confirmed),
        )

        st.caption("Use Convert if you have multiple currencies.")

        # ------------------------
        # Convert UI (only when selected)
        # - MAIN/SUB aware
        # - NO_DECIMAL_CURRENCIES aware
        # ------------------------
        fx_key = f"fx_{PAGE_ID}"
        if fx_key not in st.session_state:
            st.session_state[fx_key] = 150.0  # default; label adapts

        conv_dir_key = f"conv_dir_{PAGE_ID}"

        # Direction options depend on MAIN/SUB
        conv_options = []
        if HAS_SUB:
            conv_options = [f"{SUB_CCY} to {MAIN_CCY}", f"{MAIN_CCY} to {SUB_CCY}"]

        if conv_dir_key not in st.session_state or st.session_state[conv_dir_key] not in conv_options:
            st.session_state[conv_dir_key] = conv_options[0] if conv_options else ""

        converted_unit_label = None
        converted_unit_ccy = None
        converted_net_map = None

        def _round_by_ccy(x: float, ccy: str) -> float:
            # Round by currency: integer for no-decimal currencies, else 2 decimals
            ccy = (ccy or "").upper()
            return float(round(x, 0) if ccy in db.NO_DECIMAL_CURRENCIES else round(x, 2))

        def _adjust_net_map_to_zero(net_map: dict, ccy: str) -> dict:
            """
            Round nets to currency unit then adjust by minimal steps to make total sum == 0.
            step = 1 for no-decimal currencies, else 0.01
            """
            ccy_u = (ccy or "").upper()
            step = 1.0 if ccy_u in db.NO_DECIMAL_CURRENCIES else 0.01

            raw = {k: float(v) for k, v in (net_map or {}).items()}
            rounded = {k: _round_by_ccy(v, ccy_u) for k, v in raw.items()}

            s = float(sum(rounded.values()))
            if abs(s) < (step / 2):
                return rounded

            residual = -s
            steps = int(round(residual / step))
            if steps == 0 or len(rounded) == 0:
                return rounded

            # rounding errors: rounded - raw
            errs = {k: rounded[k] - raw[k] for k in rounded.keys()}

            if steps > 0:
                # need to increase total: prefer those rounded down (more negative error)
                order = sorted(errs.keys(), key=lambda k: errs[k])
                for i in range(steps):
                    k = order[i % len(order)]
                    rounded[k] = _round_by_ccy(rounded[k] + step, ccy_u)
            else:
                # need to decrease total: prefer those rounded up (more positive error)
                order = sorted(errs.keys(), key=lambda k: errs[k], reverse=True)
                for i in range(-steps):
                    k = order[i % len(order)]
                    rounded[k] = _round_by_ccy(rounded[k] - step, ccy_u)

            return rounded

        if mode == "Convert" and HAS_SUB:
            with st.expander("Convert", expanded=True):
                conv_dir = st.radio(
                    "Direction",
                    options=conv_options,
                    horizontal=True,
                    key=conv_dir_key,
                )

                # Store fx as "1 MAIN = ? SUB" always (invert internally for SUB->MAIN)
                fx_label = f"1 {MAIN_CCY} = ? {SUB_CCY}"
                fx = st.number_input(
                    fx_label,
                    min_value=0.000001,
                    value=float(st.session_state[fx_key]),
                    step=0.1,
                    key=fx_key,
                )

                converted_rows = []
                converted_net_map = {}

                for name in names_now:
                    main_net = float(balances.get(MAIN_CCY, {}).get(name, 0.0))
                    sub_net = float(balances.get(SUB_CCY, {}).get(name, 0.0))

                    if conv_dir == f"{SUB_CCY} to {MAIN_CCY}":
                        # sub -> main:
                        # 1 MAIN = fx SUB  =>  1 SUB = 1/fx MAIN
                        main_equiv = sub_net / float(fx)
                        main_total = main_net + main_equiv

                        converted_unit_ccy = MAIN_CCY
                        converted_unit_label = f"Amount ({MAIN_CCY})"

                        converted_rows.append(
                            {
                                "Member": name,
                                MAIN_CCY: _round_by_ccy(main_net, MAIN_CCY),
                                f"{MAIN_CCY} equiv": _round_by_ccy(main_equiv, MAIN_CCY),
                                # net is filled after adjustment
                                f"{MAIN_CCY} net": None,
                            }
                        )
                        converted_net_map[name] = float(main_total)

                    else:
                        # main -> sub:
                        # 1 MAIN = fx SUB
                        sub_equiv = main_net * float(fx)
                        sub_total = sub_net + sub_equiv

                        converted_unit_ccy = SUB_CCY
                        converted_unit_label = f"Amount ({SUB_CCY})"

                        converted_rows.append(
                            {
                                "Member": name,
                                SUB_CCY: _round_by_ccy(sub_net, SUB_CCY),
                                f"{SUB_CCY} equiv": _round_by_ccy(sub_equiv, SUB_CCY),
                                # net is filled after adjustment
                                f"{SUB_CCY} net": None,
                            }
                        )
                        converted_net_map[name] = float(sub_total)

                # ---- adjust so that sum(net) == 0 in currency unit ----
                if converted_unit_ccy and converted_net_map:
                    converted_net_map = _adjust_net_map_to_zero(converted_net_map, converted_unit_ccy)

                    net_col = f"{converted_unit_ccy} net"
                    for row in converted_rows:
                        nm = row.get("Member")
                        if nm in converted_net_map:
                            row[net_col] = converted_net_map[nm]

                st.dataframe(pd.DataFrame(converted_rows), use_container_width=True, hide_index=True)

        # Convert-ready flag (needs converted_net_map when mode == Convert)
        convert_ready = bool(converted_net_map) if (mode == "Convert") else True
        can_compute = all_confirmed and convert_ready

        # ------------------------
        # Build settle table (internal numeric col "_amt_num" for persistence)
        # - NO_DECIMAL_CURRENCIES aware
        # ------------------------
        def _unit_ccy_from_label(unit_label: str) -> str:
            # unit_label expected like "Amount (USD)" or "Amount (KRW)" etc.
            s = str(unit_label or "")
            if "(" in s and ")" in s:
                return s.split("(")[-1].split(")")[0].strip().upper()
            return ""

        def _build_settle_table_from_net(net_map: dict[str, float], unit_label: str) -> pd.DataFrame:
            # Greedy matching: debtors pay creditors
            creditors = []
            debtors = []
            for name, v in (net_map or {}).items():
                amt = float(v or 0.0)
                if amt > 0:
                    creditors.append([name, amt])
                elif amt < 0:
                    debtors.append([name, -amt])

            # Deterministic order
            creditors.sort(key=lambda x: x[0])
            debtors.sort(key=lambda x: x[0])

            i = 0
            j = 0
            rows = []
            eps = 1e-9

            # Safety guard against infinite loops
            max_iter = (len(creditors) + 1) * (len(debtors) + 1) * 50
            it = 0

            while i < len(debtors) and j < len(creditors):
                it += 1
                if it > max_iter:
                    break

                d_name, d_amt = debtors[i]
                c_name, c_amt = creditors[j]

                x_raw = min(d_amt, c_amt)
                if x_raw <= eps:
                    break

                rows.append({"From": d_name, "To": c_name, unit_label: float(x_raw)})

                # Decrease remaining amounts
                d_amt -= x_raw
                c_amt -= x_raw

                if d_amt <= eps:
                    i += 1
                else:
                    debtors[i][1] = d_amt

                if c_amt <= eps:
                    j += 1
                else:
                    creditors[j][1] = c_amt

            df = pd.DataFrame(rows)
            if df.empty:
                return df

            unit_ccy = _unit_ccy_from_label(unit_label)
            no_decimal = unit_ccy in db.NO_DECIMAL_CURRENCIES

            # Format display + store numeric in "_amt_num"
            if no_decimal:
                df["_amt_num"] = df[unit_label].round(0)
                df = df[df["_amt_num"] != 0].reset_index(drop=True)
                df[unit_label] = df["_amt_num"].astype(int).map(lambda x: f"{x:,}")
            else:
                df["_amt_num"] = df[unit_label].round(2)
                df = df[df["_amt_num"] != 0].reset_index(drop=True)
                df[unit_label] = df["_amt_num"].map(lambda x: f"{x:,.2f}")

            return df

        # ------------------------
        # Compute button + persistence (result)
        # - MAIN/SUB aware
        # - Always show section after the compute button
        # - If DB has saved rows -> show them (refresh proof)
        # ------------------------
        result_key = f"settle_result_{PAGE_ID}"
        compute_key = f"btn_compute_settle_{PAGE_ID}"

        def _pick_amount_col(df: pd.DataFrame) -> str | None:
            # Amount col is the first column other than From/To/_amt_num/RowKey
            if df is None or not isinstance(df, pd.DataFrame) or df.empty:
                return None
            amt_cols = [c for c in df.columns if c not in ("From", "To", "RowKey", "_amt_num")]
            return amt_cols[0] if amt_cols else None

        def _ensure_settle_cols(df: pd.DataFrame | None) -> pd.DataFrame:
            # Ensure RowKey exists. Never returns None.
            if df is None or not isinstance(df, pd.DataFrame):
                return pd.DataFrame()

            df2 = df.copy()

            if "RowKey" not in df2.columns:
                amt_col = _pick_amount_col(df2)
                if amt_col:
                    df2["RowKey"] = df2.apply(
                        lambda r: (
                            f'{str(r.get("From","")).strip()}|'
                            f'{str(r.get("To","")).strip()}|'
                            f'{str(r.get(amt_col,"")).strip()}'
                        ),
                        axis=1,
                    )
                else:
                    df2["RowKey"] = df2.apply(
                        lambda r: f'{str(r.get("From","")).strip()}|{str(r.get("To","")).strip()}|',
                        axis=1,
                    )

            return df2

        # Initialize session_state (never None)
        if result_key not in st.session_state or st.session_state[result_key] is None:
            st.session_state[result_key] = pd.DataFrame()

        # Load saved result from DB (do NOT overwrite with None)
        df_db = None
        try:
            df_db = db.fetch_settlement_result_df(PAGE_ID)  # DataFrame or None
        except Exception:
            df_db = None

        if isinstance(df_db, pd.DataFrame) and (not df_db.empty):
            st.session_state[result_key] = _ensure_settle_cols(df_db)

        # Compute button
        compute_clicked = st.button("Compute settlement", key=compute_key, disabled=(not can_compute))

        if compute_clicked:
            # Compute settlement table based on mode
            if mode == "Convert":
                unit_label = converted_unit_label or "Amount"
                df_settle = _build_settle_table_from_net(converted_net_map or {}, unit_label)
            else:
                # mode is either MAIN_CCY or SUB_CCY
                unit_label = f"Amount ({mode})"
                net_map = {k: float(v) for k, v in (balances.get(mode, {}) or {}).items()}
                df_settle = _build_settle_table_from_net(net_map, unit_label)

            df_settle = _ensure_settle_cols(df_settle)

            # Rebuild RowKey deterministically from displayed amount string
            if not df_settle.empty:
                amt_col = _pick_amount_col(df_settle) or unit_label
                df_settle["RowKey"] = df_settle.apply(
                    lambda r: (
                        f'{str(r.get("From","")).strip()}|'
                        f'{str(r.get("To","")).strip()}|'
                        f'{str(r.get(amt_col,"")).strip()}'
                    ),
                    axis=1,
                )

            st.session_state[result_key] = df_settle

            # Persist result table to DB (refresh proof)
            ok, msg = db.save_settlement_result_df(PAGE_ID, df_settle)
            if ok:
                st.success("Saved.")
            else:
                st.error(msg)

        # Always show result area after compute button:
        # Show only if DB (or session) has rows.
        df_saved = _ensure_settle_cols(st.session_state.get(result_key))

        if not df_saved.empty:
            st.subheader("Who pays whom")

            # Hide internal columns but keep them in DF
            st.dataframe(
                df_saved,
                use_container_width=True,
                hide_index=True,
                column_config={
                    "RowKey": None,
                    "_amt_num": None,
                },
            )

            # ------------------------
            # Payment record (DB)
            # - Below "Who pays whom"
            # - Show Done/Not done
            # - Form: multi select -> Done / Undone (bulk)
            # ------------------------
            def _label_for_row(r: dict, amt_col: str | None) -> str:
                # Build a display label for a settlement row
                fr = str(r.get("From", "")).strip()
                to = str(r.get("To", "")).strip()
                a = (str(r.get(amt_col, "")).strip() if amt_col else "").strip()
                return f"{fr} -> {to}  {a}".strip()

            # Load Done flags from DB (source of truth)
            try:
                done_map = db.fetch_settlement_done_map(PAGE_ID) or {}
            except Exception:
                done_map = {}

            # Build selectable labels (label -> rowkey)
            amt_col = _pick_amount_col(df_saved)
            rows = df_saved.to_dict(orient="records")

            seen = {}
            labels = []
            label_to_rowkey = {}

            for r in rows:
                rk = str(r.get("RowKey", "")).strip()
                if not rk:
                    continue

                base = _label_for_row(r, amt_col)
                k = seen.get(base, 0) + 1
                seen[base] = k
                lbl = base if k == 1 else f"{base} ({k})"

                labels.append(lbl)
                label_to_rowkey[lbl] = rk

            # Done / Not done display
            done_labels = []
            undone_labels = []
            for lbl in labels:
                rk = str(label_to_rowkey.get(lbl, "")).strip()
                if not rk:
                    continue
                if bool(done_map.get(rk, False)):
                    done_labels.append(lbl)
                else:
                    undone_labels.append(lbl)

            st.markdown(f"**Done:** {' / '.join(done_labels) if done_labels else 'None'}")
            st.markdown(f"**Not done:** {' / '.join(undone_labels) if undone_labels else 'None'}")

            # Form: multiselect + bulk set
            with st.form(f"settle_payment_form_{PAGE_ID}", clear_on_submit=True):
                picked = st.multiselect(
                    "Select payments",
                    options=labels,
                    default=[],
                    key=f"settle_payment_pick_{PAGE_ID}",
                )

                c1, c2 = st.columns([1, 1])
                with c1:
                    set_done = st.form_submit_button("Done")
                with c2:
                    set_undone = st.form_submit_button("Undone")

                if set_done or set_undone:
                    if not picked:
                        st.error("Please select at least one payment.")
                    else:
                        is_done = bool(set_done)

                        ok_all = True
                        last_msg = ""
                        for lbl in picked:
                            rk = str(label_to_rowkey.get(lbl, "")).strip()
                            if not rk:
                                continue
                            ok, msg = db.set_settlement_done(PAGE_ID, rk, is_done)
                            ok_all = ok_all and ok
                            last_msg = msg

                        if ok_all:
                            st.success("Saved.")
                            st.rerun()
                        else:
                            st.error(last_msg or "Failed to save.")

    # ----------------------------------------
    # Transaction detail (View + Editor)
    # ----------------------------------------
    st.divider()
    st.subheader("Transaction detail")

    # Fetch once
    expenses_all = db.fetch_expenses(PAGE_ID, active_only=True) or []
    expense_by_id = {int(e["id"]): e for e in expenses_all if e.get("id") is not None}

    members = db.get_members(PAGE_ID)
    id_name = [(int(m["id"]), m["name"]) for m in members]
    names = [x[1] for x in id_name]
    name_to_id = {n: i for i, n in id_name}
    id_to_name = {i: n for i, n in id_name}

    # ------------------------
    # Session state for editor
    # ------------------------
    edit_id_key = f"td_edit_id_{PAGE_ID}"
    edit_draft_key = f"td_edit_draft_{PAGE_ID}"
    edit_mode_key = f"td_edit_mode_{PAGE_ID}"
    _ss_get(edit_id_key, None)
    _ss_get(edit_draft_key, None)
    _ss_get(edit_mode_key, None)

    def _td_clear():
        # Clear the current editor state
        st.session_state[edit_id_key] = None
        st.session_state[edit_draft_key] = None
        st.session_state[edit_mode_key] = None

    def _fmt_mmdd(dstr: str) -> str:
        # Format a date string like "YYYY-MM-DD" into "M/D" for labels
        try:
            if isinstance(dstr, str) and len(dstr) >= 10:
                mm = dstr[5:7]
                dd = dstr[8:10]
                if mm.isdigit() and dd.isdigit():
                    return f"{int(mm)}/{int(dd)}"
        except Exception:
            pass
        return str(dstr or "").strip()

    def _to_sort_date(dstr: str) -> int:
        # Convert "YYYY-MM-DD" into int YYYYMMDD for sorting (fallback 0)
        try:
            if isinstance(dstr, str) and len(dstr) >= 10:
                y = dstr[0:4]
                m = dstr[5:7]
                d = dstr[8:10]
                if y.isdigit() and m.isdigit() and d.isdigit():
                    return int(y + m + d)
        except Exception:
            pass
        return 0

    def _to_sort_created_at(v) -> float:
        # Accept ISO string or numeric for created_at sort key (fallback 0.0)
        try:
            if v is None:
                return 0.0
            if isinstance(v, (int, float)):
                return float(v)
            if isinstance(v, str):
                try:
                    from datetime import datetime
                    return datetime.fromisoformat(v.replace("Z", "+00:00")).timestamp()
                except Exception:
                    return float(int("".join(ch for ch in v if ch.isdigit())[:14] or "0"))
        except Exception:
            pass
        return 0.0

    def _td_open_by_expense_id(expense_id: int):
        # Load an expense into the inline editor (draft + mode)
        ex = expense_by_id.get(int(expense_id))
        if not ex:
            st.error("Transaction not found.")
            return

        eid = int(ex["id"])
        target_ids = [int(x) for x in (ex.get("target_ids") or [])]

        # Clear old widget keys for this expense
        _reset_edit_step1_keys(PAGE_ID, eid)
        _reset_edit_step2_keys(PAGE_ID, eid, target_ids)

        how0 = ex.get("how") or "even"

        st.session_state[edit_id_key] = eid
        st.session_state[edit_draft_key] = {
            "expense_id": eid,
            "d": date.fromisoformat(ex["expense_date"]) if isinstance(ex["expense_date"], str) else ex["expense_date"],
            "title": (ex.get("description") or "").strip(),
            "amount": float(ex.get("amount") or 0.0),
            "currency": (ex.get("currency") or MAIN_CCY).upper(),
            "payer_id": int(ex.get("paid_by_member_id") or 0),
            "target_ids": [int(x) for x in (ex.get("target_ids") or [])],
            "how": how0,
            "share_amounts": dict(ex.get("share_amounts") or {}),
            "share_percents": dict(ex.get("share_percents") or {}),
            "note": (ex.get("note") or "").strip(),
        }
        st.session_state[edit_mode_key] = how0

    # Tabs per currency
    tab_labels_td = [MAIN_CCY] + ([SUB_CCY] if HAS_SUB else [])
    tabs_td = st.tabs(tab_labels_td)

    for idx, ccy in enumerate(tab_labels_td):
        with tabs_td[idx]:
            # ------------------------
            # 1) Table view (hide Expense ID)
            # ------------------------
            df_td = db.build_transaction_matrix(PAGE_ID, ccy)

            # Build NG markers by expense id (for picker display)
            ng_by_eid = {}
            if df_td is not None and not df_td.empty and "Expense ID" in df_td.columns and "NG" in df_td.columns:
                tmp = df_td[["Expense ID", "NG"]].copy()
                tmp["Expense ID"] = pd.to_numeric(tmp["Expense ID"], errors="coerce").fillna(0).astype(int)
                ng_by_eid = {
                    int(r["Expense ID"]): (str(r["NG"]) if r["NG"] is not None else "")
                    for _, r in tmp.iterrows()
                }

            if df_td.empty:
                st.write(f"No {ccy} transactions.")
            else:
                df_view = df_td.copy()
                if "Expense ID" in df_view.columns:
                    # Hide from display but keep for internal use
                    st.dataframe(
                        df_view,
                        use_container_width=True,
                        hide_index=True,
                        column_config={"Expense ID": None},
                    )
                else:
                    st.dataframe(df_view, use_container_width=True, hide_index=True)

            # ------------------------
            # 2) Picker (form) under table:
            #    select by MM/DD + Title (no ID displayed)
            # ------------------------
            expenses_ccy = [e for e in expenses_all if (e.get("currency") or MAIN_CCY).upper() == ccy]
            if not expenses_ccy:
                continue

            opts = []
            for e in expenses_ccy:
                eid0 = int(e["id"])
                d_raw = e.get("expense_date") or ""
                t = (e.get("description") or "").strip()
                d_mmdd = _fmt_mmdd(d_raw)

                ng_mark = str(ng_by_eid.get(eid0, "") or "").strip()  # "!" or ""
                ng_suffix = f"  {ng_mark}" if ng_mark else ""
                label = f"{d_mmdd}  {t}{ng_suffix}".strip()

                # NG first: "!" -> rank 0, else 1
                ng_rank = 0 if ng_mark == "!" else 1

                opts.append(
                    {
                        "label_base": label,
                        "eid": eid0,
                        "date_key": _to_sort_date(d_raw),
                        "created_key": _to_sort_created_at(e.get("created_at")),
                        "ng_rank": ng_rank,
                    }
                )

            # Sort: NG first -> expense_date desc -> created_at desc
            opts.sort(key=lambda x: (x["ng_rank"], -x["date_key"], -x["created_key"]))

            # Make labels unique (without showing ID)
            seen = {}
            labels = []
            label_to_id = {}
            for o in opts:
                base = o["label_base"]
                k = seen.get(base, 0) + 1
                seen[base] = k
                lbl = base if k == 1 else f"{base} ({k})"
                labels.append(lbl)
                label_to_id[lbl] = int(o["eid"])

            pick_key = f"td_pick_{PAGE_ID}_{ccy}"

            # Preselect current editing item if it belongs to this currency tab
            default_label = labels[0] if labels else None
            current_edit_id = st.session_state.get(edit_id_key)
            if current_edit_id is not None:
                ex0 = expense_by_id.get(int(current_edit_id))
                if ex0 and (ex0.get("currency") or MAIN_CCY).upper() == ccy:
                    d0 = _fmt_mmdd(ex0.get("expense_date") or "")
                    t0 = (ex0.get("description") or "").strip()
                    base0 = f"{d0}  {t0}".strip()
                    for lbl in labels:
                        if lbl == base0 or lbl.startswith(base0 + " ("):
                            default_label = lbl
                            break

            with st.form(f"td_pick_form_{PAGE_ID}_{ccy}", clear_on_submit=False):
                pick_label = st.selectbox(
                    "Select",
                    options=labels,
                    index=(labels.index(default_label) if (default_label in labels) else 0),
                    key=pick_key,
                )

                c1, c2, c3 = st.columns([1, 2, 1])
                with c1:
                    open_clicked = st.form_submit_button("Edit")
                with c2:
                    confirm_delete = st.checkbox(
                        "Confirm delete",
                        value=False,
                        key=f"td_pick_confirm_delete_{PAGE_ID}_{ccy}",
                    )
                with c3:
                    delete_clicked = st.form_submit_button("Delete")

                if open_clicked:
                    _td_open_by_expense_id(int(label_to_id[pick_label]))
                    st.rerun()

                if delete_clicked:
                    if not confirm_delete:
                        st.error("Please check Confirm delete.")
                    else:
                        del_id = int(label_to_id[pick_label])
                        ok, msg = db.soft_delete_expense(PAGE_ID, del_id)
                        if ok:
                            st.success(msg)
                            _td_clear()
                            st.rerun()
                        else:
                            st.error(msg)

            # ------------------------
            # 3) Inline editor UI
            # ------------------------
            current_edit_id = st.session_state.get(edit_id_key)
            if current_edit_id is None:
                continue

            draft = st.session_state.get(edit_draft_key) or {}
            mode = st.session_state.get(edit_mode_key) or (draft.get("how") or "even")

            editing_ex = expense_by_id.get(int(current_edit_id))
            editing_ccy = (editing_ex.get("currency") or MAIN_CCY).upper() if editing_ex else None
            if editing_ccy != ccy:
                continue

            if int(draft.get("expense_id", 0)) != int(current_edit_id):
                continue

            eid = int(current_edit_id)

            # ------------------------
            # Step 1 (form): base fields + mode buttons
            # ------------------------
            with st.form(f"td_edit_step1_{PAGE_ID}_{eid}", clear_on_submit=False):
                d = st.date_input("When", value=draft["d"], key=f"edit_d_{PAGE_ID}_{eid}")
                title = st.text_input("Title", value=draft["title"], key=f"edit_title_{PAGE_ID}_{eid}")
                amount = st.number_input(
                    "Amount",
                    min_value=0.0,
                    value=float(draft["amount"]),
                    step=1.0,
                    key=f"edit_amount_{PAGE_ID}_{eid}",
                )
                currency = st.selectbox(
                    "Currency",
                    CCY_CHOICES,
                    index=(CCY_CHOICES.index(draft["currency"]) if draft.get("currency") in CCY_CHOICES else 0),
                    key=f"edit_currency_{PAGE_ID}_{eid}",
                )

                payer_default_name = id_to_name.get(int(draft["payer_id"]), names[0] if names else "")
                payer_name = st.selectbox(
                    "Paid by",
                    names,
                    index=(names.index(payer_default_name) if payer_default_name in names else 0),
                    key=f"edit_payer_{PAGE_ID}_{eid}",
                )
                payer_id = int(name_to_id[payer_name])

                default_targets = [id_to_name.get(int(t)) for t in (draft.get("target_ids") or [])]
                default_targets = [x for x in default_targets if x in names]
                if not default_targets:
                    default_targets = names

                target_names = st.multiselect(
                    "For",
                    options=names,
                    default=default_targets,
                    key=f"edit_targets_{PAGE_ID}_{eid}",
                )
                target_ids = [int(name_to_id[n]) for n in target_names]

                note = st.text_input(
                    "Note",
                    value=(draft.get("note") or ""),
                    key=f"edit_note_{PAGE_ID}_{eid}",
                )

                # Main actions
                a1, a2, a3 = st.columns([1, 1, 1])
                with a1:
                    go_even = st.form_submit_button("Even")
                with a2:
                    go_dollar = st.form_submit_button("Enter $")
                with a3:
                    go_percent = st.form_submit_button("Enter %")

                if go_even or go_dollar or go_percent:
                    # Validate
                    if not (title or "").strip():
                        st.error("Title is empty")
                    elif float(amount) < 0:
                        st.error("Invalid amount")
                    elif not target_ids:
                        st.error("Please select targets")
                    else:
                        # Update draft
                        draft["d"] = d
                        draft["title"] = (title or "").strip()
                        draft["amount"] = float(amount)
                        draft["currency"] = currency
                        draft["payer_id"] = int(payer_id)
                        draft["target_ids"] = [int(x) for x in target_ids]
                        draft["note"] = (note or "").strip()

                        # Keep only targets' shares in draft
                        sa = dict(draft.get("share_amounts") or {})
                        sp = dict(draft.get("share_percents") or {})
                        keep = set(draft["target_ids"])
                        draft["share_amounts"] = {int(k): float(v) for k, v in sa.items() if int(k) in keep}
                        draft["share_percents"] = {int(k): float(v) for k, v in sp.items() if int(k) in keep}

                        st.session_state[edit_draft_key] = draft

                        if go_even:
                            # Save as even immediately
                            ok, msg = db.update_expense(
                                PAGE_ID,
                                eid,
                                draft["d"],
                                draft["title"],
                                draft["amount"],
                                draft["currency"],
                                draft["payer_id"],
                                draft["target_ids"],
                                note=(draft.get("note") or "").strip(),
                                how="even",
                                share_amounts=None,
                                share_percents=None,
                            )
                            if ok:
                                st.success(msg)
                                _reset_edit_step1_keys(PAGE_ID, eid)
                                _reset_edit_step2_keys(PAGE_ID, eid, draft["target_ids"])
                                _td_clear()
                                st.rerun()
                            else:
                                st.error(msg)
                        else:
                            # Switch to Step2 mode (no save here)
                            draft["how"] = "$" if go_dollar else "%"
                            st.session_state[edit_draft_key] = draft
                            st.session_state[edit_mode_key] = draft["how"]
                            _reset_edit_step2_keys(PAGE_ID, eid, draft["target_ids"])
                            st.rerun()

            # ------------------------
            # Step 2: mode specific inputs + Save/Cancel
            # ------------------------
            draft = st.session_state.get(edit_draft_key) or {}
            mode = st.session_state.get(edit_mode_key) or (draft.get("how") or "even")

            if int(draft.get("expense_id", 0)) == eid and mode in ("$", "%"):
                st.markdown("**Edit shares**")

                targets = [int(x) for x in (draft.get("target_ids") or [])]
                if not targets:
                    st.warning("No targets selected.")
                else:
                    # ---- Edit shares: $ ----
                    if mode == "$":
                        total = float(draft.get("amount") or 0.0)
                        existing = dict(draft.get("share_amounts") or {})
                        defaults = _calc_even_amounts(total, targets)

                        share_amounts: dict[int, float] = {}
                        for mid in targets:
                            nm = id_to_name.get(int(mid), f"member {mid}")
                            default_v = float(existing.get(int(mid), defaults.get(int(mid), 0.0)))
                            v = st.number_input(
                                nm,
                                min_value=0.0,
                                value=default_v,
                                step=0.01,
                                key=f"td_share_amt_{PAGE_ID}_{eid}_{mid}",
                            )
                            share_amounts[int(mid)] = float(v)

                        s = round(sum(share_amounts.values()), 2)
                        dff = round(s - total, 2)
                        st.caption(f"sum: {s:.2f}   amount: {total:.2f}   diff: {dff:+.2f}")

                        b1, b2 = st.columns([1, 1])
                        with b1:
                            can_save = abs(float(dff)) <= 1e-9
                            save_clicked = st.button(
                                "Save changes",
                                key=f"td_save_dollar_{PAGE_ID}_{eid}",
                                disabled=(not can_save),
                            )
                        with b2:
                            cancel_clicked = st.button("Cancel", key=f"td_cancel_dollar_{PAGE_ID}_{eid}")

                        if save_clicked:
                            ok, msg = db.update_expense(
                                PAGE_ID,
                                eid,
                                draft["d"],
                                draft["title"],
                                draft["amount"],
                                draft["currency"],
                                draft["payer_id"],
                                draft["target_ids"],
                                note=(draft.get("note") or "").strip(),
                                how="$",
                                share_amounts=share_amounts,
                                share_percents=None,
                            )
                            if ok:
                                st.success(msg)
                                _reset_edit_step1_keys(PAGE_ID, eid)
                                _reset_edit_step2_keys(PAGE_ID, eid, targets)
                                _td_clear()
                                st.rerun()
                            else:
                                st.error(msg)

                        if cancel_clicked:
                            _td_clear()
                            st.rerun()

                    # ---- Edit shares: % ----
                    elif mode == "%":
                        existing = dict(draft.get("share_percents") or {})
                        defaults = _calc_even_percents(targets)

                        share_percents: dict[int, float] = {}
                        for mid in targets:
                            nm = id_to_name.get(int(mid), f"member {mid}")
                            default_v = float(existing.get(int(mid), defaults.get(int(mid), 0.0)))
                            v = st.number_input(
                                nm,
                                min_value=0.0,
                                max_value=100.0,
                                value=default_v,
                                step=0.01,
                                key=f"td_share_pct_{PAGE_ID}_{eid}_{mid}",
                            )
                            share_percents[int(mid)] = float(v)

                        s = round(sum(share_percents.values()), 2)
                        dff = round(s - 100.0, 2)
                        st.caption(f"sum: {s:.2f}%   diff: {dff:+.2f}%")

                        b1, b2 = st.columns([1, 1])
                        with b1:
                            can_save = abs(float(dff)) <= 1e-9
                            save_clicked = st.button(
                                "Save changes",
                                key=f"td_save_percent_{PAGE_ID}_{eid}",
                                disabled=(not can_save),
                            )
                        with b2:
                            cancel_clicked = st.button("Cancel", key=f"td_cancel_percent_{PAGE_ID}_{eid}")

                        if save_clicked:
                            ok, msg = db.update_expense(
                                PAGE_ID,
                                eid,
                                draft["d"],
                                draft["title"],
                                draft["amount"],
                                draft["currency"],
                                draft["payer_id"],
                                draft["target_ids"],
                                note=(draft.get("note") or "").strip(),
                                how="%",
                                share_amounts=None,
                                share_percents=share_percents,
                            )
                            if ok:
                                st.success(msg)
                                _reset_edit_step1_keys(PAGE_ID, eid)
                                _reset_edit_step2_keys(PAGE_ID, eid, targets)
                                _td_clear()
                                st.rerun()
                            else:
                                st.error(msg)

                        if cancel_clicked:
                            _td_clear()
                            st.rerun()

    # ----------------------------------------
    # Deleted history
    # ----------------------------------------
    st.divider()
    st.subheader("Deleted history")

    all_expenses = db.fetch_expenses(PAGE_ID, active_only=False)
    deleted_expenses = [e for e in (all_expenses or []) if int(e.get("is_deleted", 0)) == 1]

    if not deleted_expenses:
        st.write("No deleted history.")
    else:
        for ex in deleted_expenses:
            ex_id = int(ex["id"])
            ccy = (ex.get("currency") or MAIN_CCY).upper()
            label = (
                f'{ex["expense_date"]}  {ex["description"]}  {_fmt_money(float(ex["amount"]), ccy)} {ccy}  '
                f'paid by {ex["paid_by"]}  (deleted {ex.get("deleted_at")})'
            )
            cA, cB = st.columns([3, 1])
            with cA:
                st.write(label)
            with cB:
                if st.button("Restore", key=f"restore_expense_{PAGE_ID}_{ex_id}"):
                    ok, msg = db.restore_expense(PAGE_ID, ex_id)
                    if ok:
                        st.success(msg)
                        st.rerun()
                    else:
                        st.error(msg)

    # ----------------------------------------
    # Deleted members
    # ----------------------------------------
    st.divider()
    st.subheader("Deleted members")

    deleted_members = [r for r in db.get_members(PAGE_ID, include_deleted=True) if int(r["is_deleted"]) == 1]
    if not deleted_members:
        st.write("No deleted members.")
    else:
        for dm in deleted_members:
            dm_id = int(dm["id"])
            cA, cB = st.columns([3, 1])
            with cA:
                st.write(f'{dm["name"]} (deleted {dm["deleted_at"]})')
            with cB:
                if st.button("Restore", key=f"restore_member_{PAGE_ID}_{dm_id}"):
                    ok, msg = db.restore_member(PAGE_ID, dm_id)
                    if ok:
                        st.success(msg)
                        st.rerun()
                    else:
                        st.error(msg)

# ----------------------------------------
# Danger zone (BOTTOM)
# ----------------------------------------
with st.expander("Danger zone", expanded=False):
    st.caption("These actions are destructive. Some are irreversible.")

    dz1, dz2, dz3 = st.columns([1, 1, 1], gap="small")

    with dz1:
        confirm_hist = st.checkbox("Confirm delete all history (this page)", value=False, key=f"confirm_hist_{PAGE_ID}")
        if st.button("Delete all history (this page)", key=f"btn_del_hist_{PAGE_ID}"):
            if not confirm_hist:
                st.error("Please check confirmation first.")
            else:
                ok, msg = db.soft_delete_all_expenses(PAGE_ID)
                if ok:
                    st.success(msg)
                    st.rerun()
                else:
                    st.error(msg)

    with dz2:
        confirm_members = st.checkbox(
            "Confirm delete all members (this page)", value=False, key=f"confirm_members_{PAGE_ID}"
        )
        if st.button("Delete all members (this page)", key=f"btn_del_members_{PAGE_ID}"):
            if not confirm_members:
                st.error("Please check confirmation first.")
            else:
                ok, msg = db.soft_delete_all_members_everywhere(PAGE_ID)
                if ok:
                    st.success(msg)
                    st.rerun()
                else:
                    st.error(msg)

    with dz3:
        st.caption("Deletes this page and ALL data in it. Other pages are not affected.")
        confirm_wipe = st.checkbox(
            "Confirm delete this page (irreversible)",
            value=False,
            key=f"confirm_wipe_page_{PAGE_ID}",
        )

        if st.button("Delete this page and all data", key=f"btn_wipe_page_{PAGE_ID}"):
            if not confirm_wipe:
                st.error("Please check confirmation first.")
            else:
                ok, msg = db.wipe_page(PAGE_ID)
                if ok:
                    st.session_state["page_id"] = None
                    st.session_state["authed_pages"] = set()
                    st.error(msg)
                    st.switch_page("main.py")
                else:
                    st.error(msg)

# ----------------------------------------
# Settings (BOTTOM)
# ----------------------------------------
st.divider()
st.subheader("Settings")

# Current values from DB
page_row = db.get_page(PAGE_ID)
current_name = (page_row.get("name") if page_row else page_name) or "Unknown"
current_main = (page_row.get("main_currency") if page_row else "USD") or "USD"
current_sub = (page_row.get("sub_currency") if page_row else "none") or "none"

# Normalize
current_sub = "none" if str(current_sub).lower() == "none" else str(current_sub)

# ------------------------
# Settings form (name + currencies only)
# ------------------------
with st.form(f"settings_form_{PAGE_ID}", clear_on_submit=False):
    # Page name
    new_page_name = st.text_input("Page name", value=current_name, key=f"set_name_{PAGE_ID}")

    c1, c2 = st.columns(2)
    with c1:
        main_opts = [c for c in CURRENCY_CHOICES if c != "none"]
        main_currency = st.selectbox(
            "Main currency",
            options=main_opts,
            index=(main_opts.index(current_main) if current_main in main_opts else 0),
            key=f"set_main_{PAGE_ID}",
        )
    with c2:
        sub_currency = st.selectbox(
            "Sub currency",
            options=CURRENCY_CHOICES,
            index=(
                CURRENCY_CHOICES.index(current_sub)
                if current_sub in CURRENCY_CHOICES
                else CURRENCY_CHOICES.index("none")
            ),
            key=f"set_sub_{PAGE_ID}",
        )

    save_settings = st.form_submit_button("Save settings")

    if save_settings:
        # Persist: store None when "none" is selected
        sub_to_save = None if (str(sub_currency).lower() == "none") else sub_currency

        ok, msg = db.update_page_settings(
            PAGE_ID,
            new_page_name,
            main_currency,
            sub_to_save,  # store None for "none"
        )
        if ok:
            st.success(msg)
            st.rerun()
        else:
            st.error(msg)

# ------------------------
# Password form (separate)
# ------------------------
st.subheader("Password")

with st.form(f"password_form_{PAGE_ID}", clear_on_submit=True):
    new_pw = st.text_input(
        "New password",
        value="",
        type="password",
        key=f"pw_new_{PAGE_ID}",
    )

    c3, c4 = st.columns([1, 1])
    with c3:
        save_pw = st.form_submit_button("Update password")
    with c4:
        remove_pw = st.form_submit_button("Remove password")

    if save_pw:
        if not (new_pw or "").strip():
            st.error("Password is empty")
        else:
            ok, msg = db.update_page_password(PAGE_ID, new_pw)
            if ok:
                st.success(msg)
                st.rerun()
            else:
                st.error(msg)

    if remove_pw:
        ok, msg = db.remove_page_password(PAGE_ID)
        if ok:
            st.success(msg)
            st.rerun()
        else:
            st.error(msg)

# ----------------------------------------
# Back to main page
# ----------------------------------------
st.divider()
if st.button("Back to Main"):
    st.switch_page("main.py")
if st.button("Go to Readme"):
    st.switch_page("pages/2_Readme.py")