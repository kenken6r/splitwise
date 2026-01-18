# pages/2_Readme.py
import streamlit as st

# Page config
st.set_page_config(page_title="Readme", layout="wide")

st.title("Readme")

# Language tabs (default: English)
tab_en, tab_ja = st.tabs(["English", "日本語"])

with tab_en:
    st.markdown(
        """
### What this app does
- Create a page with a main currency and an optional sub currency
- Add members and transactions
- Compute balances automatically
- Convert balances using an FX rate

### Notes
- This is a lightweight Splitwise style tool.
- Data is stored locally by the app.
- If you delete or restore members, you may need to update existing transactions
  to keep balances consistent.
- **This page is publicly accessible.**  
  If you do not want others to see your data, please set a password.
  - When a password is set, access from the main page requires authentication.
  - Anyone who knows the direct URL can access the page without a password.
- **If you want to delete all information after use**, run **Delete page**
  in the *Danger Zone*.  
  This action permanently deletes all data and **cannot be undone**.

### How to use
1. Create a page (or open an existing one)
2. Add members and transactions
3. Check balances and settle up
"""
    )

with tab_ja:
    st.markdown(
        """
### このアプリについて
- メイン通貨とサブ通貨を設定したページを作成できます
- メンバーと取引を追加できます
- 残高は自動で計算されます
- 為替レートを使って通貨換算ができます

### 注意
- このアプリは簡易的な Splitwise 風ツールです
- データはアプリ内に保存されます
- **メンバーを削除・復元した場合、取引データを更新しないと
  残高が正しく計算されないことがあります**
- **このページは一般公開されます。**  
  他の人に見られたくない場合は、必ずパスワードを設定してください。
  - パスワードを設定すると、メインページからのアクセスには認証が必要になります
  - URL を直接知っている人は、パスワードなしでアクセスできます
- **使い終わって情報を消したい場合**は、*Danger Zone* にある
  **Delete page** を実行してください。  
  この操作はすべてのデータを完全に削除し、**復元できません**。

### 使い方
1. ページを作成する（または既存ページを開く）
2. メンバーと取引を追加する
3. 残高を確認して精算する
"""
    )

# Back to main
if st.button("Back to Main"):
    st.switch_page("main.py")