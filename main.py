# main.py
import streamlit as st
import db

st.set_page_config(page_title="Split App", layout="wide")
db.init_db()

st.title("Split App")

if "page_id" not in st.session_state:
    st.session_state["page_id"] = None
if "authed_pages" not in st.session_state:
    st.session_state["authed_pages"] = set()

st.subheader("Create a page")
with st.form("create_page_form", clear_on_submit=True):
    name = st.text_input("Page name")
    password = st.text_input("Password (optional)", type="password")
    submitted = st.form_submit_button("Create")
    if submitted:
        ok, msg = db.create_page(name, password)
        if ok:
            st.success(msg)
            st.rerun()
        else:
            st.error(msg)

st.divider()
st.subheader("Open a page")

pages = db.list_pages()
if not pages:
    st.info("No pages yet. Create one above.")
    st.stop()

page_label_to_id = {}
labels = []
for p in pages:
    pid = str(p["id"])  # TEXT id
    has_pw = (p["password_hash"] is not None)
    label = f'{p["name"]}{" (password)" if has_pw else ""}'
    labels.append(label)
    page_label_to_id[label] = pid

selected_label = st.selectbox("Select page", labels)
selected_id = str(page_label_to_id[selected_label])  # keep as TEXT

page_row = db.get_page(selected_id)
has_password = (page_row is not None and page_row["password_hash"] is not None)

if has_password and selected_id not in st.session_state["authed_pages"]:
    st.warning("Password required.")
    pw = st.text_input("Enter password", type="password")
    if st.button("Unlock"):
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
        st.query_params["page_id"] = selected_id
        st.switch_page("pages/1_App.py")