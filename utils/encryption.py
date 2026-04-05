from cryptography.fernet import Fernet

def load_key():
    with open("secret.key", "rb") as f:
        return f.read()

key = load_key()
cipher = Fernet(key)


def encrypt_file(input_path, output_path):
    with open(input_path, 'rb') as file:
        data = file.read()

    encrypted_data = cipher.encrypt(data)

    with open(output_path, 'wb') as file:
        file.write(encrypted_data)


def decrypt_file(input_path, output_path):
    with open(input_path, 'rb') as file:
        encrypted_data = file.read()

    decrypted_data = cipher.decrypt(encrypted_data)

    with open(output_path, 'wb') as file:
        file.write(decrypted_data)