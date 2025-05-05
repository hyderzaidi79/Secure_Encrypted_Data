import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet

# Paths
KEY_FILE = "secret.key"
USER_DB = "users.json"
DATA_DB = "data_store.json"
ATTEMPT_DB = "login_attempts.json"

# Load/generate encryption key
def load_or_create_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
        return key

cipher = Fernet(load_or_create_key())

# Hash passwords and passkeys
def hash_text(text):
    return hashlib.sha256(text.encode()).hexdigest()

# Load/save JSON
def load_json(path):
    if os.path.exists(path):
        with open(path, "r") as f:
            return json.load(f)
    return {}

def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=4)

# User management
def register_user(username, password):
    users = load_json(USER_DB)
    if username in users:
        return False
    users[username] = hash_text(password)
    save_json(USER_DB, users)
    return True

def authenticate_user(username, password):
    users = load_json(USER_DB)
    return users.get(username) == hash_text(password)

# Track login attempts
def record_failed_attempt(username):
    attempts = load_json(ATTEMPT_DB)
    now = time.time()
    if username not in attempts:
        attempts[username] = {"count": 1, "last_attempt": now}
    else:
        attempts[username]["count"] += 1
        attempts[username]["last_attempt"] = now
    save_json(ATTEMPT_DB, attempts)

def reset_attempts(username):
    attempts = load_json(ATTEMPT_DB)
    if username in attempts:
        del attempts[username]
    save_json(ATTEMPT_DB, attempts)

def is_locked_out(username):
    attempts = load_json(ATTEMPT_DB)
    if username in attempts:
        count = attempts[username]["count"]
        last_time = attempts[username]["last_attempt"]
        if count >= 3 and time.time() - last_time < 60:
            return True, int(60 - (time.time() - last_time))
    return False, 0

# Store user-specific encrypted data
def save_user_data(username, encrypted_text, hashed_passkey):
    all_data = load_json(DATA_DB)
    if username not in all_data:
        all_data[username] = []
    all_data[username].append({
        "encrypted_text": encrypted_text,
        "passkey": hashed_passkey
    })
    save_json(DATA_DB, all_data)

def get_user_data(username):
    all_data = load_json(DATA_DB)
    return all_data.get(username, [])

# Session state init
if "user" not in st.session_state:
    st.session_state.user = None

# UI
st.title("🔒 Secure Encrypted Data Vault")

menu = ["Home", "Login", "Register", "Store Data", "Retrieve Data", "Export Data"]
with st.sidebar:
    st.markdown("## 🔧 Navigation")
    choice = st.radio("Go to", menu, label_visibility="collapsed")  # Clean look

    st.markdown("---")  # Divider line for visual separation

    # Displaying login/logout info
    if st.session_state.user:
        st.markdown(f"**👤 Logged in as:** `{st.session_state.user}`")
        if st.button("🚪 Logout"):
            st.session_state.user = None
            st.success("👋 Logged out successfully.")
    else:
        st.markdown("🔑 **Not logged in**")
        st.info("Please login or register to continue.")

    # Optional custom CSS for vertical radio buttons (in case it stacks horizontally on some themes)
    st.markdown("""
        <style>
            div[data-baseweb="radio"] > div {
                flex-direction: column;
            }
        </style>
    """, unsafe_allow_html=True)

# Main content
if choice == "Home":
    st.subheader("🏠 Welcome")
    st.write("Register or login to securely store and retrieve encrypted data.")

elif choice == "Register":
    st.subheader("📝 Register New Account")
    new_user = st.text_input("Username")
    new_pass = st.text_input("Password", type="password")
    if st.button("Register"):
        if new_user and new_pass:
            if register_user(new_user, new_pass):
                st.success("✅ Registered successfully! You can now login.")
            else:
                st.error("⚠️ Username already exists.")
        else:
            st.error("Both fields are required.")

elif choice == "Login":
    st.subheader("🔐 Login")
    user = st.text_input("Username")
    pwd = st.text_input("Password", type="password")

    if st.button("Login"):
        if not user or not pwd:
            st.error("Both fields required.")
        else:
            locked, wait = is_locked_out(user)
            if locked:
                st.warning(f"🚫 Too many failed attempts. Try again in {wait} seconds.")
            elif authenticate_user(user, pwd):
                st.session_state.user = user
                reset_attempts(user)
                st.success(f"✅ Logged in as {user}")
            else:
                record_failed_attempt(user)
                locked, wait = is_locked_out(user)
                if locked:
                    st.warning(f"🚫 Account locked. Try again in {wait} seconds.")
                else:
                    st.error("❌ Invalid credentials.")

elif choice == "Store Data":
    if not st.session_state.user:
        st.warning("🔑 Please login first.")
    else:
        st.subheader("📂 Store Data")
        data = st.text_area("Enter your secret data:")
        passkey = st.text_input("Enter a passkey to encrypt:", type="password")
        if st.button("Encrypt & Save"):
            if data and passkey:
                hashed_pass = hash_text(passkey)
                encrypted = cipher.encrypt(data.encode()).decode()
                save_user_data(st.session_state.user, encrypted, hashed_pass)
                st.success("✅ Encrypted and saved!")
                st.code(encrypted, language="text")
            else:
                st.error("Both fields required.")

elif choice == "Retrieve Data":
    if not st.session_state.user:
        st.warning("🔑 Please login first.")
    else:
        st.subheader("🔍 Retrieve Data")
        encrypted_input = st.text_area("Enter your encrypted text:")
        passkey_input = st.text_input("Enter your passkey:", type="password")

        if st.button("Decrypt"):
            if encrypted_input and passkey_input:
                user_data = get_user_data(st.session_state.user)
                hashed_input = hash_text(passkey_input)
                for item in user_data:
                    if item["encrypted_text"] == encrypted_input and item["passkey"] == hashed_input:
                        try:
                            decrypted = cipher.decrypt(encrypted_input.encode()).decode()
                            st.success(f"✅ Decrypted Data: {decrypted}")
                        except Exception:
                            st.error("⚠️ Decryption failed.")
                        break
                else:
                    st.error("❌ Incorrect passkey or encrypted text.")
            else:
                st.error("Both fields required.")

elif choice == "Export Data":
    if not st.session_state.user:
        st.warning("🔑 Please login first.")
    else:
        st.subheader("⬇️ Export Your Encrypted Data")
        user_data = get_user_data(st.session_state.user)
        if user_data:
            json_str = json.dumps(user_data, indent=4)
            st.download_button("📁 Download JSON", json_str, file_name=f"{st.session_state.user}_data.json")
        else:
            st.info("You have no saved data.")
