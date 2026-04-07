import os
import uuid
from werkzeug.utils import secure_filename


def ensure_directories(upload_folder, encrypted_folder, temp_decrypted_folder):
    os.makedirs(upload_folder, exist_ok=True)
    os.makedirs(encrypted_folder, exist_ok=True)
    os.makedirs(temp_decrypted_folder, exist_ok=True)


def save_uploaded_file(file, upload_folder):
    original_filename = secure_filename(file.filename)
    unique_name = f"{uuid.uuid4().hex}_{original_filename}"
    temp_input_path = os.path.join(upload_folder, unique_name)
    file.save(temp_input_path)
    return temp_input_path, original_filename


def build_encrypted_output_path(original_filename, encrypted_folder):
    safe_name = secure_filename(original_filename)
    unique_name = f"{uuid.uuid4().hex}_{safe_name}.enc"
    return os.path.join(encrypted_folder, unique_name)


def build_decrypted_output_path(original_filename, temp_decrypted_folder):
    safe_name = secure_filename(original_filename)
    # Create a unique subdirectory so the file keeps its original name
    unique_dir = os.path.join(temp_decrypted_folder, uuid.uuid4().hex)
    os.makedirs(unique_dir, exist_ok=True)
    return os.path.join(unique_dir, safe_name)


def remove_file_if_exists(path):
    if os.path.exists(path):
        os.remove(path)