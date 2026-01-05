# pages/1_App.py
from datetime import date
from io import BytesIO

import pandas as pd
import streamlit as st

import db

st.set_page_config(page_title="Split App", layout="wide")
db.init_db()

# ------------------------
# Restore page_id from URL (so /App?page_id=... works)
# ------------------------
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

st.title(f"Split App: {page_name}")

# ------------------------
# Backup buttons (page-scoped export is only transaction detail; DB file is global)
# ------------------------
c1, c2 = st.columns([1, 1], gap="small")

with c1:
    try:
        with open(db.DB_PATH, "rb") as f:
            db_bytes = f.read()
    except FileNotFoundError:
        db_bytes = b""

    st.download_button(
        label="Download DB backup (split.db)",
        data=db_bytes,
        file_name="split_backup.db",
        mime="application/octet-stream",
        disabled=(len(db_bytes) == 0),
    )

with c2:
    df_usd = db.build_transaction_matrix(PAGE_ID, "USD")
    df_jpy = db.build_transaction_matrix(PAGE_ID, "JPY")

    bio = BytesIO()
    with pd.ExcelWriter(bio, engine="openpyxl") as writer:
        if df_usd.empty:
            pd.DataFrame({"Info": ["No USD transactions"]}).to_excel(writer, sheet_name="USD", index=False)
        else:
            df_usd.to_excel(writer, sheet_name="USD", index=False)

        if df_jpy.empty:
            pd.DataFrame({"Info": ["No JPY transactions"]}).to_excel(writer, sheet_name="JPY", index=False)
        else:
            df_jpy.to_excel(writer, sheet_name="JPY", index=False)

    st.download_button(
        label="Download Transaction Detail (Excel)",
        data=bio.getvalue(),
        file_name="transaction_detail.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )

left, right = st.columns([1, 2], gap="large")

# ------------------------
# Members
# ------------------------
with left:
    st.subheader("Members")

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

    st.divider()
    st.subheader("Add expense")

    members = db.get_members(PAGE_ID)
    if not members:
        st.info("Add members first.")
    else:
        id_name = [(int(m["id"]), m["name"]) for m in members]
        names = [x[1] for x in id_name]
        name_to_id = {n: i for i, n in id_name}

        with st.form("add_expense_form", clear_on_submit=True):
            d = st.date_input("When", value=date.today())
            title = st.text_input("Title")
            amount = st.number_input("Amount", min_value=0.0, value=0.0, step=1.0)
            currency = st.selectbox("Currency", ["USD", "JPY"], index=0)

            payer_name = st.selectbox("Paid by", names, index=0)
            payer_id = name_to_id[payer_name]

            target_names = st.multiselect("For", options=names, default=names)
            target_ids = [name_to_id[n] for n in target_names]

            submitted2 = st.form_submit_button("Save")
            if submitted2:
                ok, msg = db.add_expense(PAGE_ID, d, title, float(amount), currency, payer_id, target_ids)
                if ok:
                    st.success(msg)
                    st.rerun()
                else:
                    st.error(msg)

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

# ------------------------
# History + Summary + Detail
# ------------------------
with right:
    st.subheader("History")
    expenses = db.fetch_expenses(PAGE_ID, active_only=True)
    members = db.get_members(PAGE_ID)

    if not expenses:
        st.write("No expenses yet.")
    else:
        id_name = [(int(m["id"]), m["name"]) for m in members]
        names = [x[1] for x in id_name]
        name_to_id = {n: i for i, n in id_name}
        id_to_name = {i: n for i, n in id_name}

        for ex in expenses:
            ex_id = int(ex["id"])
            with st.expander(
                f'{ex["expense_date"]}  {ex["description"]}  {float(ex["amount"]):.2f} {ex["currency"]}  paid by {ex["paid_by"]}',
                expanded=False,
            ):
                with st.form(f"edit_form_{ex_id}"):
                    d = st.date_input("When", value=date.fromisoformat(ex["expense_date"]), key=f"d_{ex_id}")
                    title = st.text_input("Title", value=ex["description"], key=f"title_{ex_id}")
                    amount = st.number_input(
                        "Amount",
                        min_value=0.0,
                        value=float(ex["amount"]),
                        step=1.0,
                        key=f"amt_{ex_id}",
                    )
                    currency = st.selectbox(
                        "Currency",
                        ["USD", "JPY"],
                        index=0 if ex["currency"] == "USD" else 1,
                        key=f"ccy_{ex_id}",
                    )

                    payer_name = st.selectbox(
                        "Paid by",
                        names,
                        index=names.index(ex["paid_by"]) if ex["paid_by"] in names else 0,
                        key=f"payer_{ex_id}",
                    )
                    payer_id = name_to_id[payer_name]

                    default_targets = [id_to_name[i] for i in ex["target_ids"] if i in id_to_name]
                    target_names = st.multiselect(
                        "For",
                        options=names,
                        default=default_targets if default_targets else names,
                        key=f"targets_{ex_id}",
                    )
                    target_ids = [name_to_id[n] for n in target_names]

                    b1, b2 = st.columns([1, 1])
                    with b1:
                        save_clicked = st.form_submit_button("Save changes")
                    with b2:
                        delete_clicked = st.form_submit_button("Delete")

                    if save_clicked:
                        ok, msg = db.update_expense(
                            PAGE_ID, ex_id, d, title, float(amount), currency, payer_id, target_ids
                        )
                        if ok:
                            st.success(msg)
                            st.rerun()
                        else:
                            st.error(msg)

                    if delete_clicked:
                        ok, msg = db.soft_delete_expense(PAGE_ID, ex_id)
                        if ok:
                            st.success(msg)
                            st.rerun()
                        else:
                            st.error(msg)

    st.divider()
    st.subheader("Summary")

    members = db.get_members(PAGE_ID)
    if not members:
        st.write("No members.")
    else:
        balances = db.compute_net_balances(PAGE_ID)

        cA, cB = st.columns(2)
        with cA:
            st.markdown("**USD**")
            usd_rows = [{"Member": k, "Net": round(v, 2)} for k, v in balances["USD"].items()]
            st.dataframe(usd_rows, use_container_width=True, hide_index=True)

        with cB:
            st.markdown("**JPY**")
            jpy_rows = [{"Member": k, "Net": round(v, 0)} for k, v in balances["JPY"].items()]
            st.dataframe(jpy_rows, use_container_width=True, hide_index=True)

        st.divider()
        st.markdown("**Convert JPY net to USD**")

        fx = st.number_input(
            "1 USD = ? JPY",
            min_value=0.000001,
            value=150.0,
            step=0.1,
            key=f"fx_{PAGE_ID}",
        )

        member_rows = [m["name"] for m in db.get_members(PAGE_ID)]

        usd_equiv_rows = []
        for member in member_rows:
            usd_net = float(balances["USD"].get(member, 0.0))
            jpy_net = float(balances["JPY"].get(member, 0.0))
            jpy_in_usd = jpy_net / float(fx)
            total_usd_net = usd_net + jpy_in_usd

            usd_equiv_rows.append(
                {
                    "Member": member,
                    "USD": round(usd_net, 2),
                    "USD equiv": round(jpy_in_usd, 2),
                    "USD net": round(total_usd_net, 2),
                }
            )

        st.dataframe(pd.DataFrame(usd_equiv_rows), use_container_width=True, hide_index=True)

        st.divider()
        st.subheader("Transaction detail")

        tab_usd, tab_jpy = st.tabs(["USD", "JPY"])

        with tab_usd:
            df_usd = db.build_transaction_matrix(PAGE_ID, "USD")
            if df_usd.empty:
                st.write("No USD transactions.")
            else:
                st.dataframe(df_usd, use_container_width=True, hide_index=True)

        with tab_jpy:
            df_jpy = db.build_transaction_matrix(PAGE_ID, "JPY")
            if df_jpy.empty:
                st.write("No JPY transactions.")
            else:
                st.dataframe(df_jpy, use_container_width=True, hide_index=True)

    st.divider()
    st.subheader("Deleted history")
    all_expenses = db.fetch_expenses(PAGE_ID, active_only=False)
    deleted_expenses = [e for e in all_expenses if int(e.get("is_deleted", 0)) == 1]

    if not deleted_expenses:
        st.write("No deleted history.")
    else:
        for ex in deleted_expenses:
            ex_id = int(ex["id"])
            label = (
                f'{ex["expense_date"]}  {ex["description"]}  {float(ex["amount"]):.2f} {ex["currency"]}  '
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

# ------------------------
# Danger zone (BOTTOM)
# ------------------------
st.divider()
st.subheader("Danger zone")
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
                # Clear session and go back to main
                st.session_state["page_id"] = None
                st.session_state["authed_pages"] = set()
                st.error(msg)
                st.switch_page("main.py")
            else:
                st.error(msg)