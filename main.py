import streamlit as st
import hashlib
import sqlite3
from cryptography.fernet import Fernet

# Setup Fernet Encryption
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# Connect to SQLite
conn = sqlite3.connect('secure_data.db', check_same_thread=False)
cursor = conn.cursor()

# Create table if not exists
cursor.execute('''
CREATE TABLE IF NOT EXISTS data_store (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    encrypted_text TEXT NOT NULL,
    hashed_passkey TEXT NOT NULL
)
''')
conn.commit()

# Global session state for failed attempts
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0

# Hashing function
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Encrypt function
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# Decrypt function
def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)
    cursor.execute("SELECT encrypted_text FROM data_store WHERE encrypted_text = ? AND hashed_passkey = ?", 
                   (encrypted_text, hashed_passkey))
    result = cursor.fetchone()
    
    if result:
        st.session_state.failed_attempts = 0
        return cipher.decrypt(encrypted_text.encode()).decode()
    else:
        st.session_state.failed_attempts += 1
        return None

# Store data into DB
def store_data_sql(encrypted_text, hashed_passkey):
    cursor.execute("INSERT INTO data_store (encrypted_text, hashed_passkey) VALUES (?, ?)",
                   (encrypted_text, hashed_passkey))
    conn.commit()

# ---------------- Streamlit UI -------------------

st.title("🔒 Secure Data Encryption System (with SQLite3)")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("🏠 Welcome")
    st.write("Securely store and retrieve encrypted data using passkeys.")

elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            hashed_passkey = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data)
            store_data_sql(encrypted_text, hashed_passkey)
            st.success("✅ Data stored securely!")
            st.code(encrypted_text, language="text")
        else:
            st.error("⚠️ Both fields are required!")

elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")
    encrypted_text = st.text_area("Enter Encrypted Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            decrypted_text = decrypt_data(encrypted_text, passkey)

            if decrypted_text:
                st.success(f"✅ Decrypted Data: {decrypted_text}")
            else:
                attempts_left = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect passkey! Attempts remaining: {attempts_left}")

                if st.session_state.failed_attempts >= 3:
                    st.warning("🔒 Too many failed attempts! Redirecting to Login Page.")
                    st.rerun()
        else:
            st.error("⚠️ Both fields are required!")

elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    login_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":
            st.session_state.failed_attempts = 0
            st.success("✅ Reauthorized successfully! Redirecting to Retrieve Data...")
            st.rerun()
        else:
            st.error("❌ Incorrect password!")
