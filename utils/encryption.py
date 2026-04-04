from cryptography.fernet import Fernet

# Generate key (run once and store it)
key = Fernet.generate_key()
print("key:",key)
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