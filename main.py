from password_gen import generate_password
from argon2.low_level import hash_secret_raw, Type
from key_gen import gen_key, encrypt, decrypt
from database_handler import create_user, ask, translate, verify, update_vault,init_db
import os
import json
import getpass

argon2_type_map={
    "argon2id":Type.ID,
    "argon2i":Type.I,
    "argon2d":Type.D
}


def login():
    username=input("Enter your username: ")
    master_password = getpass.getpass("Enter your master password: ")
    user_id=translate(username)
    if(user_id is None):
        print("Username not found")
        return False,
    login_salt=ask(user_id,"login_salt")
    KDF_param=ask(user_id,"KDF_param")
    verifier=hash_secret_raw(
        secret=master_password.encode(),
        salt=login_salt,
        time_cost=KDF_param["time_cost"],
        memory_cost=KDF_param["memory_cost"],
        parallelism=KDF_param["parallelism"],
        type=argon2_type_map[KDF_param["type"]],
        hash_len=KDF_param["hash_len"]
    )
    key=gen_key(master_password,ask(user_id,"key_salt"),KDF_param)
    master_password=None
    if(verify(user_id,verifier)):
        print("Login successful")
        return True,user_id,key
    else:
        print("Incorrect password")
        return False,

    

def signup():

    username=input("Create a username: ")
    master_password = getpass.getpass("Enter your master password: ")
    user_id=translate(username)

    if(user_id is not None):
        print("Username already exists")
        return
    
    login_salt=os.urandom(16)
    key_salt=os.urandom(16)
    KDF_param={
        "time_cost":5,
        "memory_cost":1024*128,
        "parallelism":2,
        "type":"argon2id",
        "hash_len":32
    }

    if KDF_param["type"] not in argon2_type_map:
        raise ValueError("Unsupported KDF type")
    
    verifier=hash_secret_raw(
        secret=master_password.encode(),
        salt=login_salt,
        time_cost=KDF_param["time_cost"],
        memory_cost=KDF_param["memory_cost"],
        parallelism=KDF_param["parallelism"],
        type=argon2_type_map[KDF_param["type"]],
        hash_len=KDF_param["hash_len"]
    )
    
    encrypted_vault=encrypt(json.dumps({"version":1,"entries":[]}).encode(),gen_key(master_password,key_salt,KDF_param))
    master_password=None
    create_user(username,login_salt,verifier,key_salt,encrypted_vault,KDF_param)
    print("Signup successful")


def decrypt_vault(user_id,key):
    encrypted_vault=ask(user_id,"enc_vault")
    if encrypted_vault is None:
        return {}
    decrypted_data=decrypt(encrypted_vault,key)
    vault=json.loads(decrypted_data.decode())
    return vault

def find_password(user_id,key):
    site_name=input("Enter the site name: ")
    vault=decrypt_vault(user_id,key)
    for entry in vault["entries"]:
        if entry["site_name"]==site_name:
            print(f"Username: {entry['username']}")
            print(f"Password: {entry['password']}")
            vault={}
            return
    print("No entry found for the given site name")
    vault={}

def add_password(user_id,key):
    site_name=input("Enter the site name: ")
    username=input("Enter the username: ")
    choice=input("Do you want to generate a password? (y/n): ")
    if choice.lower()=='y':
        length=int(input("Enter the length of the password: "))
        password=generate_password(length)
        if(password=="minimum length 4 required"):
            print(password)
            return
        print(f"Generated password: {password}")
    else:
        password=getpass.getpass("Enter the password: ")
    vault=decrypt_vault(user_id,key)
    vault["entries"].append({
        "site_name":site_name,
        "username":username,
        "password":password
    })
    encrypted_vault=encrypt(json.dumps(vault).encode(),key)
    update_vault(user_id,encrypted_vault)
    vault={}

def logout():
    print("Logged out successfully")
    return False, None, None

def main():
    LOGGED_IN=False
    print("Welcome to the Password Manager")
    user_id=None
    key=None
    while(True):
        while not LOGGED_IN:
            choice=input("Do you want to (1) Login or (2) Signup or (3) Exit? ")
            if choice=='1':
                result=login()
                if result[0]:
                    LOGGED_IN=True
                    user_id=result[1]
                    key=result[2]
            elif choice=='2':
                signup()
            elif choice=='3':
                print("Exiting...")
                return
            else:
                print("Invalid choice")
        while LOGGED_IN:
            choice=input("Do you want to (1) Find a password or (2) Add a password or (3) Logout? ")
            if choice=='1':
                find_password(user_id,key)
            elif choice=='2':
                add_password(user_id,key)
            elif choice=='3':
                LOGGED_IN, user_id, key = logout()
            else:
                print("Invalid choice")

init_db()
main()