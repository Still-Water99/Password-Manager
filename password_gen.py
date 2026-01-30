import secrets


def generate_password(length):
    if(length<4):
        return "minimum length 4 required"
    password=[
        secrets.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        secrets.choice("abcdefghijklmnopqrstuvwxyz"),
        secrets.choice("0123456789"),
        secrets.choice("!@#$%&*_-+")
    ]
    all_chars="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%&*_-+"
    for _ in range(length-4):
        password+=secrets.choice(all_chars)
    secrets.SystemRandom().shuffle(password)

    return "".join(password)



# print(generate_password(17))