import streamlit as st
import json
import os
import uuid
import time
from cryptography.fernet import Fernet
from hashlib import pbkdf2_hmac
import base64

DATA_FILE = "data_store.json"
LOCKOUT_TIME = 60

def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

def generate_key():
    if "fernet_key" not in st.session_state:
        key = Fernet.generate_key()
        st.session_state.fernet_key = key
    return st.session_state.fernet_key

def hash_passkey(passkey, salt=None):
    if not salt:
        salt = os.urandom(16)
    hashed = pbkdf2_hmac("sha256", passkey.encode(), salt, 100000)
    return base64.b64encode(salt + hashed).decode()

def verify_passkey(stored_hash, passkey):
    raw = base64.b64decode(stored_hash.encode())
    salt, stored = raw[:16], raw[16:]
    hashed = pbkdf2_hmac("sha256", passkey.encode(), salt, 100000)
    return hashed == stored

def encrypt_data(text):
    return Fernet(generate_key()).encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    return Fernet(generate_key()).decrypt(encrypted_text.encode()).decode()

if "data" not in st.session_state:
    st.session_state.data = load_data()

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = {}

if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = {}

if "current_user" not in st.session_state:
    st.session_state.current_user = None

st.title("🔐 Multi-User Secure Data Vault")

menu = ["Register", "Login", "Store Data", "Retrieve Data", "Logout"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Register":
    st.subheader("🆕 Register")
    username = st.text_input("Username")
    passkey = st.text_input("Passkey", type="password")
    if st.button("Register"):
        if username in st.session_state.data:
            st.error("Username already exists.")
        else:
            st.session_state.data[username] = {"auth": hash_passkey(passkey), "entries": {}}
            save_data(st.session_state.data)
            st.success("Registration successful.")

elif choice == "Login":
    st.subheader("🔑 Login")
    username = st.text_input("Username")
    passkey = st.text_input("Passkey", type="password")

    if st.button("Login"):
        if username not in st.session_state.data:
            st.error("User not found.")
        elif username in st.session_state.lockout_time and time.time() < st.session_state.lockout_time[username]:
            st.warning("Temporarily locked out. Try again later.")
        elif verify_passkey(st.session_state.data[username]["auth"], passkey):
            st.session_state.current_user = username
            st.session_state.failed_attempts[username] = 0
            st.success("Logged in.")
        else:
            st.session_state.failed_attempts[username] = st.session_state.failed_attempts.get(username, 0) + 1
            attempts = st.session_state.failed_attempts[username]
            if attempts >= 3:
                st.session_state.lockout_time[username] = time.time() + LOCKOUT_TIME
                st.warning("Too many attempts. Locked for 60 seconds.")
            else:
                st.error(f"Incorrect passkey. Attempts left: {3 - attempts}")

elif choice == "Store Data":
    if not st.session_state.current_user:
        st.warning("Please log in.")
    else:
        st.subheader("📥 Store Secure Data")
        user_data = st.text_area("Enter data")
        if st.button("Encrypt & Save"):
            enc = encrypt_data(user_data)
            uid = str(uuid.uuid4())
            st.session_state.data[st.session_state.current_user]["entries"][uid] = enc
            save_data(st.session_state.data)
            st.success(f"Data stored. ID:\n{uid}")

elif choice == "Retrieve Data":
    if not st.session_state.current_user:
        st.warning("Please log in.")
    else:
        st.subheader("🔍 Retrieve Encrypted Data")
        user_entries = st.session_state.data[st.session_state.current_user]["entries"]
        if not user_entries:
            st.info("No data stored yet.")
        else:
            entry_id = st.selectbox("Select Entry ID", list(user_entries.keys()))
            if st.button("Decrypt"):
                decrypted = decrypt_data(user_entries[entry_id])
                st.success(f"Decrypted Data:\n{decrypted}")

elif choice == "Logout":
    st.session_state.current_user = None
    st.success("Logged out.")
