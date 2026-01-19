# main.py
import streamlit as st
import db

# --------------------------------------------------
# App configuration and DB initialization
# --------------------------------------------------
st.set_page_config(page_title="SplitWiser", layout="wide")
db.init_db()

st.title("SplitWiser")

if st.button("Readme"):
    st.switch_page("pages/2_Readme.py")

# --------------------------------------------------
# Session state initialization
# --------------------------------------------------
if "page_id" not in st.session_state:
    st.session_state["page_id"] = None

if "authed_pages" not in st.session_state:
    st.session_state["authed_pages"] = set()

# --------------------------------------------------
# Currency choices
# Single source of truth (from db)
# --------------------------------------------------
CURRENCY_CHOICES = list(db.CURRENCY_CHOICES)

# ==================================================
# Create a new page
# ==================================================
st.subheader("Create a page")

with st.form("create_page_form", clear_on_submit=True):
    name = st.text_input("Page name")
    password = st.text_input("Password (optional)", type="password")
    st.caption(
        "This page is public. Set a password if you want to keep your data private. Anyone with the link can access it without a password."
    )

    st.markdown("### Currencies")

    # Main currency
    # - must not be 'none'
    main_options = [c for c in CURRENCY_CHOICES if c != "none"]
    main_currency = st.selectbox(
        "Main currency",
        options=main_options,
        index=main_options.index("USD") if "USD" in main_options else 0,
        key="create_main_ccy",
    )

    # Sub currency
    # - optional
    # - can be 'none'
    sub_currency = st.selectbox(
        "Sub currency (optional)",
        options=["none"] + main_options,
        index=0,
        key="create_sub_ccy",
    )

    submitted = st.form_submit_button("Create")

    if submitted:
        if not (name or "").strip():
            st.error("Page name is empty")
        elif sub_currency != "none" and sub_currency == main_currency:
            st.error("Main and sub currencies must be different (or set sub to none).")
        else:
            ok, msg, new_page_id = db.create_page(
                name=(name or "").strip(),
                password=password,
                main_currency=main_currency,
                sub_currency=sub_currency,
            )

            if ok and new_page_id:
                st.session_state["authed_pages"].add(new_page_id)
                st.session_state["page_id"] = new_page_id
                st.query_params["page_id"] = str(new_page_id)
                st.switch_page("pages/1_App.py")
            else:
                st.error(msg)

# ==================================================
# Open an existing page
# ==================================================
st.divider()
st.subheader("Open a page")

pages = db.list_pages()
if not pages:
    st.info("No pages yet. Create one above.")
    st.stop()

# --------------------------------------------------
# Build page label list for selectbox
# --------------------------------------------------
page_label_to_id = {}
labels = []

for p in pages:
    pid = str(p["id"])
    has_pw = (p.get("password_hash") is not None)

    mc = (p.get("main_currency") or "USD").upper()
    sc = (p.get("sub_currency") or "none").upper()

    label = f'{p["name"]} ({mc}, {sc}){" (password)" if has_pw else ""}'
    labels.append(label)
    page_label_to_id[label] = pid

selected_label = st.selectbox("Select page", labels)
selected_id = page_label_to_id[selected_label]

# --------------------------------------------------
# Password check and navigation
# --------------------------------------------------
page_row = db.get_page(selected_id)
has_password = (page_row is not None and page_row.get("password_hash") is not None)

if has_password and selected_id not in st.session_state["authed_pages"]:
    st.warning("Password required.")
    with st.form("unlock_form"):
        pw = st.text_input("Enter password", type="password")
        unlock = st.form_submit_button("Unlock")
        if unlock:
            ok, msg = db.verify_page_password(selected_id, pw)
            if ok:
                st.session_state["authed_pages"].add(selected_id)
                st.success("Unlocked")
                st.rerun()
            else:
                st.error(msg)
else:
    if st.button("Go to app"):
        st.session_state["page_id"] = selected_id
        st.query_params["page_id"] = str(selected_id)
        st.switch_page("pages/1_App.py")