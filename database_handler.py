import sqlite3
import os
import json
import hmac

APP_DIR = os.path.join(os.getenv("APPDATA"), "PasswordManager")
os.makedirs(APP_DIR, exist_ok=True)
db_path = os.path.join(APP_DIR, "vault.db")

def init_db():
    conn=sqlite3.connect(db_path)
    cur=conn.cursor()
    cur.execute('''CREATE TABLE IF NOT EXISTS users(
                user_id INTEGER PRIMARY KEY,
                login_salt BLOB NOT NULL,
                verifier BLOB NOT NULL,
                key_salt BLOB NOT NULL,
                enc_vault BLOB NOT NULL,
                KDF_param TEXT NOT NULL
                )
    ''')
    cur.execute('''CREATE TABLE IF NOT EXISTS translation(
                username TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(user_id)
                )
    ''')
    conn.commit()
    conn.close()

def create_user(username,login_salt,verifier,key_salt,enc_vault,KDF_param):
    conn=sqlite3.connect(db_path)
    cur=conn.cursor()
    cur.execute('INSERT INTO users (login_salt,verifier,key_salt,enc_vault,KDF_param) VALUES (?,?,?,?,?)',
                (login_salt,verifier,key_salt,enc_vault,json.dumps(KDF_param)))
    user_id=cur.lastrowid
    cur.execute('INSERT INTO translation (username,user_id) VALUES (?,?)',
                (username,user_id))
    conn.commit()
    conn.close()

def ask(user_id,field):
    conn=sqlite3.connect(db_path)
    cur=conn.cursor()
    query=f'SELECT {field} FROM users WHERE user_id=?'
    cur.execute(query,(user_id,))
    result=cur.fetchone()
    conn.close()
    if(result is not None):
        result=result[0]
    else:
        return None
    if(field=="KDF_param"):
        result=json.loads(result)
    return result

def translate(username):
    conn=sqlite3.connect(db_path)
    cur=conn.cursor()
    cur.execute('SELECT user_id FROM translation WHERE username=?',(username,))
    result=cur.fetchone()
    conn.close()
    if result is None:
        return None
    return result[0]

def verify(user_id,verifier):
    conn=sqlite3.connect(db_path)
    cur=conn.cursor()
    cur.execute('SELECT verifier FROM users WHERE user_id=?',(user_id,))
    stored_verifier=cur.fetchone()
    if(stored_verifier is None):
        conn.close()
        return False
    stored_verifier=stored_verifier[0]
    conn.close()
    return hmac.compare_digest(verifier, stored_verifier)

def update_vault(user_id,enc_vault):
    conn=sqlite3.connect(db_path)
    cur=conn.cursor()
    cur.execute('UPDATE users SET enc_vault=? WHERE user_id=?',(enc_vault,user_id))
    conn.commit()
    conn.close()

init_db()