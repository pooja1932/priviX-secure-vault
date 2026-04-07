from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, after_this_request, make_response
import mimetypes
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
from urllib.parse import quote
from werkzeug.security import generate_password_hash, check_password_hash
import db
import os

from datetime import datetime, timezone, timedelta
try:
    from zoneinfo import ZoneInfo
except ImportError:
    from pytz import timezone
    def ZoneInfo(tz): return timezone(tz)

from file_handler import (
    ensure_directories,
    save_uploaded_file,
    build_encrypted_output_path,
    build_decrypted_output_path,
    remove_file_if_exists
)

from utils.encryption import encrypt_file, decrypt_file
from utils.hashing import generate_hash, verify_hash

load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'privix_secure_vault_secret_key_2026')

# Session safety to prevent MismatchingStateError
app.config['SESSION_COOKIE_NAME'] = 'privix_google_auth_session'
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Allow HTTP for local development (Google requires this for redirect_uri)
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
os.environ['AUTHLIB_INSECURE_TRANSPORT'] = 'true'

# Debug credentials loading (masked for privacy)
client_id = os.getenv('GOOGLE_CLIENT_ID')
client_secret = os.getenv('GOOGLE_CLIENT_SECRET')

oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=client_id,
    client_secret=client_secret,
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'},
    issuer='https://accounts.google.com'
)

@app.template_filter('format_ist_date')
def format_ist_date_filter(utc_str):
    if not utc_str:
        return ''
    try:
        utc_dt = datetime.strptime(utc_str, '%Y-%m-%d %H:%M:%S')
        utc_dt = utc_dt.replace(tzinfo=timezone.utc)
        ist_tz = timezone(timedelta(hours=5, minutes=30))
        ist_dt = utc_dt.astimezone(ist_tz)
        return ist_dt.strftime('%b %d, %Y')
    except Exception:
        return utc_str

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
ENCRYPTED_FOLDER = os.path.join(BASE_DIR, "encrypted_files")
TEMP_DECRYPTED_FOLDER = os.path.join(BASE_DIR, "temp_decrypted")

ensure_directories(UPLOAD_FOLDER, ENCRYPTED_FOLDER, TEMP_DECRYPTED_FOLDER)
db.init_db()


@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()

        if not username or not password:
            flash('Username and password are required!', 'danger')
            return redirect(url_for('signup'))

        password_hash = generate_password_hash(password)

        user_id = db.create_user(username, password_hash)
        if user_id:
            db.log_action(user_id, 'signup')
            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Username already exists. Please choose a different one.', 'danger')
            return redirect(url_for('signup'))

    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()

        user = db.get_user_by_username(username)

        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            db.log_action(user['id'], 'login')
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/logout')
def logout():
    if 'user_id' in session:
        db.log_action(session['user_id'], 'logout')
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/auth/google')
def google_login():
    # Dynamic redirect URI based on how you access the site
    redirect_uri = url_for('google_callback', _external=True)
    return google.authorize_redirect(redirect_uri)


@app.route('/login/google/authorized')
def google_callback():
    token = google.authorize_access_token()
    userinfo = google.get('https://openidconnect.googleapis.com/v1/userinfo').json()
    
    email = userinfo.get('email')
    google_id = userinfo.get('id') or userinfo.get('sub')
    name = userinfo.get('name') or userinfo.get('given_name') or email.split('@')[0]
    
    user = db.get_user_by_google_id(google_id)
    if not user:
        # Check if user with this email exists (link if so)
        existing_user = db.get_user_by_email(email)
        if existing_user:
            db.update_google_user_id(existing_user['id'], google_id)
            user = db.get_user_by_id(existing_user['id'])
            db.log_action(user['id'], 'link_google')
        else:
            # Create new user
            user_id = db.create_google_user(name, email, google_id)
            if not user_id:
                # Fallback for username collisions
                import random
                name = f"{name}_{random.getrandbits(16)}"
                user_id = db.create_google_user(name, email, google_id)
            
            if user_id:
                user = db.get_user_by_id(user_id)
                db.log_action(user_id, 'signup_google')
            else:
                flash('Authentication failed: Could not create user profile.', 'danger')
                return redirect(url_for('login'))
    
    if user:
        session['user_id'] = user['id']
        session['username'] = user['username']
        db.log_action(user['id'], 'login_google')
        flash(f'Welcome back, {user["username"]}!', 'success')
        return redirect(url_for('dashboard'))
    else:
        flash('Authentication failed: User record not found.', 'danger')
        return redirect(url_for('login'))


MAX_STORAGE_MB = 10240  # 10GB Per-user storage cap in MB

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please log in to access your files.', 'warning')
        return redirect(url_for('login'))

    user_id = session['user_id']
    username = session['username']

    uploaded_files = db.get_user_files(user_id)
    shared_files = db.get_shared_files(user_id)
    recent_logs = db.get_recent_logs(user_id, limit=3)

    # Calculate real storage usage from actual file sizes on disk
    total_bytes = 0
    all_files = uploaded_files + shared_files
    for f in all_files:
        filepath = f['filepath']
        if filepath and os.path.exists(filepath):
            total_bytes += os.path.getsize(filepath)

    used_mb = round(total_bytes / (1024 * 1024), 2)
    used_pct = min(round((used_mb / MAX_STORAGE_MB) * 100, 1), 100)

    return render_template(
        'dashboard.html',
        username=username,
        upload_count=len(uploaded_files),
        share_count=len(shared_files),
        used_mb=used_mb,
        total_mb=MAX_STORAGE_MB,
        used_pct=used_pct,
        recent_logs=recent_logs
    )



@app.route('/upload', methods=['POST'])
def upload_file():
    if 'user_id' not in session:
        flash('Please log in first.', 'warning')
        return redirect(url_for('login'))

    if 'file' not in request.files:
        flash('No file part found.', 'danger')
        return redirect(url_for('dashboard'))

    file = request.files['file']

    if file.filename == '':
        flash('No file selected.', 'danger')
        return redirect(url_for('dashboard'))

    try:
        # Step 1: save original uploaded file temporarily
        temp_input_path, original_filename = save_uploaded_file(file, UPLOAD_FOLDER)

        # Step 2: generate integrity hash from original file
        file_hash = generate_hash(temp_input_path)

        # Step 3: decide encrypted output path
        encrypted_output_path = build_encrypted_output_path(original_filename, ENCRYPTED_FOLDER)

        # Step 4: encrypt file
        encrypt_file(temp_input_path, encrypted_output_path)

        # Step 5: save metadata in database
        file_id = db.store_file_metadata(
            session['user_id'],
            original_filename,
            encrypted_output_path,
            file_hash
        )

        # Step 6: log action
        db.log_action(session['user_id'], f'upload:file_id={file_id}')

        # Step 7: remove temporary plain file
        remove_file_if_exists(temp_input_path)

        flash('File uploaded and encrypted successfully!', 'success')

    except Exception as e:
        flash(f'Upload failed: {str(e)}', 'danger')

    return redirect(url_for('dashboard'))


@app.route('/my-files')
def my_files():
    if 'user_id' not in session:
        flash('Please log in to access your files.', 'warning')
        return redirect(url_for('login'))

    user_id = session['user_id']
    uploaded_files = db.get_user_files(user_id)

    return render_template('my_files.html', uploaded_files=uploaded_files)


@app.route('/shared-files')
def shared_files():
    if 'user_id' not in session:
        flash('Please log in to access shared files.', 'warning')
        return redirect(url_for('login'))

    user_id = session['user_id']
    shared_files_data = db.get_shared_files(user_id)

    return render_template('shared_files.html', shared_files=shared_files_data)


@app.route('/share/<int:file_id>', methods=['POST'])
def share_file(file_id):
    if 'user_id' not in session:
        flash('Please log in first.', 'warning')
        return redirect(url_for('login'))

    target_usernames_str = request.form.get('target_username', '').strip()

    if not target_usernames_str:
        flash('Please enter a username to share with.', 'danger')
        return redirect(url_for('my_files'))
        
    target_usernames = [u.strip() for u in target_usernames_str.split(',') if u.strip()]
    if len(target_usernames) > 5:
        flash('You can only share with up to 5 users at a time.', 'warning')
        return redirect(url_for('my_files'))

    file_record = db.get_file_by_id(file_id)

    if not file_record:
        flash('File not found.', 'danger')
        return redirect(url_for('my_files'))

    if file_record['owner_id'] != session['user_id']:
        flash('You can only share your own files.', 'danger')
        return redirect(url_for('my_files'))

    shared_users = []
    not_found = []
    
    for target_username in target_usernames:
        target_user = db.get_user_by_username(target_username)

        if not target_user:
            not_found.append(target_username)
            continue

        if target_user['id'] == session['user_id']:
            continue

        if not db.is_file_already_shared(file_id, target_user['id']):
            import shutil
            new_filepath = build_encrypted_output_path(file_record['filename'], ENCRYPTED_FOLDER)
            shutil.copy(file_record['filepath'], new_filepath)
            
            db.share_file_with_user(
                shared_with_user_id=target_user['id'],
                original_owner_id=session['user_id'],
                original_file_id=file_id,
                filename=file_record['filename'],
                filepath=new_filepath,
                file_hash=file_record['hash']
            )
            db.log_action(session['user_id'], f'share:file_id={file_id}:to_user={target_user["id"]}')
            shared_users.append(target_username)
            
    msg = []
    if shared_users:
        msg.append(f"File shared successfully with {', '.join(shared_users)}.")
    if not_found:
        msg.append(f"Users not found: {', '.join(not_found)}")
        
    if not msg:
        flash('Could not share file (perhaps already shared or invalid user).', 'warning')
    else:
        flash(" ".join(msg), 'info' if not_found else 'success')
        
    return redirect(url_for('my_files'))


@app.route('/unshare/<int:shared_file_id>', methods=['POST'])
def unshare_file(shared_file_id):
    if 'user_id' not in session:
        flash('Please log in first.', 'warning')
        return redirect(url_for('login'))
        
    user_id = session['user_id']
    file_record = db.get_shared_file_by_id(shared_file_id)
    
    if file_record and file_record['shared_with_user_id'] == user_id:
        try:
            if os.path.exists(file_record['filepath']):
                os.remove(file_record['filepath'])
        except Exception:
            pass
        db.remove_shared_access(shared_file_id, user_id)
        db.log_action(user_id, f'unshare:shared_file_id={shared_file_id}')
        flash('Removed file from your view successfully.', 'success')
    else:
        flash('File not found or not shared with you.', 'danger')
        
    return redirect(url_for('shared_files'))


@app.route('/delete/<int:file_id>', methods=['POST'])
def delete_file_route(file_id):
    if 'user_id' not in session:
        flash('Please log in first.', 'warning')
        return redirect(url_for('login'))
        
    user_id = session['user_id']
    file_record = db.get_file_by_id(file_id)
    
    if not file_record or file_record['owner_id'] != user_id:
        flash('Cannot delete this file.', 'danger')
        return redirect(url_for('my_files'))
        
    try:
        if os.path.exists(file_record['filepath']):
            os.remove(file_record['filepath'])
    except Exception as e:
        pass
        
    db.delete_file(file_id, user_id)
    db.log_action(user_id, f'delete:file_id={file_id}')
    flash('File deleted successfully.', 'success')
    return redirect(url_for('my_files'))


@app.route('/download/<int:file_id>')
def download_file(file_id):
    if 'user_id' not in session:
        flash('Please log in first.', 'warning')
        return redirect(url_for('login'))

    user_id = session['user_id']
    file_record = db.get_file_by_id(file_id)

    if not file_record:
        flash('File not found.', 'danger')
        return redirect(url_for('dashboard'))

    has_access = (file_record['owner_id'] == user_id)

    if not has_access:
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    encrypted_path = file_record['filepath']
    original_filename = file_record['filename']
    original_hash = file_record['hash']

    if not os.path.exists(encrypted_path):
        flash('Stored file is missing.', 'danger')
        return redirect(url_for('dashboard'))

    try:
        decrypted_output_path = build_decrypted_output_path(original_filename, TEMP_DECRYPTED_FOLDER)

        decrypt_file(encrypted_path, decrypted_output_path)

        if not verify_hash(decrypted_output_path, original_hash):
            remove_file_if_exists(decrypted_output_path)
            flash('File integrity verification failed.', 'danger')
            return redirect(url_for('dashboard'))

        db.log_action(user_id, f'download:file_id={file_id}')

        # Read file into memory and clean up temp files
        with open(decrypted_output_path, 'rb') as f:
            file_data = f.read()

        # Clean up the temp UUID directory
        import shutil
        temp_dir = os.path.dirname(decrypted_output_path)
        shutil.rmtree(temp_dir, ignore_errors=True)

        # Send response with explicit headers
        response = make_response(file_data)
        mime_type = mimetypes.guess_type(original_filename)[0] or 'application/octet-stream'
        response.headers.set('Content-Type', mime_type)
        response.headers.set('Content-Disposition', 'attachment', filename=original_filename)
        response.headers.set('Content-Length', len(file_data))
        return response

    except Exception as e:
        flash(f'Download failed: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))


@app.route('/download_shared/<int:shared_file_id>')
def download_shared_file(shared_file_id):
    if 'user_id' not in session:
        flash('Please log in first.', 'warning')
        return redirect(url_for('login'))

    user_id = session['user_id']
    file_record = db.get_shared_file_by_id(shared_file_id)

    if not file_record or file_record['shared_with_user_id'] != user_id:
        flash('Access denied or file not found.', 'danger')
        return redirect(url_for('dashboard'))

    encrypted_path = file_record['filepath']
    original_filename = file_record['filename']
    original_hash = file_record['hash']

    if not os.path.exists(encrypted_path):
        flash('Stored file is missing.', 'danger')
        return redirect(url_for('dashboard'))

    try:
        decrypted_output_path = build_decrypted_output_path(original_filename, TEMP_DECRYPTED_FOLDER)
        decrypt_file(encrypted_path, decrypted_output_path)
        if not verify_hash(decrypted_output_path, original_hash):
            remove_file_if_exists(decrypted_output_path)
            flash('File integrity verification failed.', 'danger')
            return redirect(url_for('dashboard'))

        db.log_action(user_id, f'download_shared:shared_file_id={shared_file_id}')

        # Read file into memory and clean up temp files
        with open(decrypted_output_path, 'rb') as f:
            file_data = f.read()

        import shutil
        temp_dir = os.path.dirname(decrypted_output_path)
        shutil.rmtree(temp_dir, ignore_errors=True)

        # Send response with explicit headers
        response = make_response(file_data)
        mime_type = mimetypes.guess_type(original_filename)[0] or 'application/octet-stream'
        response.headers.set('Content-Type', mime_type)
        response.headers.set('Content-Disposition', 'attachment', filename=original_filename)
        response.headers.set('Content-Length', len(file_data))
        return response
    except Exception as e:
        flash(f'Download failed: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))


if __name__ == '__main__':
    app.run(debug=True, port=5000)
