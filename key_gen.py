from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

argon2_type_map={
    "argon2id":Type.ID,
    "argon2i":Type.I,
    "argon2d":Type.D
}

def gen_key(master_password:str,salt:bytes,KDF_param:dict)->bytes:
    return hash_secret_raw(
        secret=master_password.encode(),
        salt=salt,
        time_cost=KDF_param["time_cost"],
        memory_cost=KDF_param["memory_cost"],
        parallelism=KDF_param["parallelism"],
        type=argon2_type_map[KDF_param["type"]],
        hash_len=KDF_param["hash_len"]
    )

def encrypt(data: bytes, key: bytes) -> bytes:
    nonce = os.urandom(12)
    aes = AESGCM(key)
    return nonce + aes.encrypt(nonce, data, None)

def decrypt(ciphertext: bytes, key: bytes) -> bytes:
    nonce = ciphertext[:12]
    aes = AESGCM(key)
    return aes.decrypt(nonce, ciphertext[12:], None)

# salt=os.urandom(16)
# key=gen_key("horse is the biggest dawg ive ever seen",salt)
# data=b"lotm is the best thing ive ever read period"
# cipher=encrypt(data,key)
# print(cipher)
# message=decrypt(cipher,key)
# print(message)