# Password Manager

A simple, command line password manager written in python.

## features

-Encrypted Vault Storage
-SQLite backend
-Command Line Interface
-Argon2 key derivation

## Setup

pip install -r requirements.txt
python main.py

### To make an exe file,run these commands in the directory containing the files:
pip install pyinstaller

pyinstaller --onefile --name PasswordManager main.py


## Security Warning
This project is a **learning project**.
Do not store real passwords.
