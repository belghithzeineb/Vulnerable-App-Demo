# app.py
import os
import sqlite3
import hashlib
import requests

# 🚨 VULNERABILITY 1: Hardcoded Root Credentials (Critical)
AWS_ROOT_KEY = "AKIAIOSFODNN7EXAMPLEKEY"
DB_PASSWORD = "admin_super_secret_password_123"

def login_user(username, password):
    # 🚨 VULNERABILITY 2: Insecure Hashing MD5 (Warning)
    hashed_password = hashlib.md5(password.encode()).hexdigest()
    
    # 🚨 VULNERABILITY 3: SQL Injection (Critical)
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM accounts WHERE user='{username}' AND pass='{hashed_password}'"
    cursor.execute(query)
    return cursor.fetchone()

def run_backup(backup_server):
    # 🚨 VULNERABILITY 4: Command Injection (Critical)
    # Untrusted user input is directly passed to the OS shell
    os.system(f"scp -r /data/ {backup_server}")

def fetch_config():
    # 🚨 VULNERABILITY 5: Disabled SSL Verification (Warning)
    response = requests.get("https://internal.conf/api", verify=False)
    return response.json()