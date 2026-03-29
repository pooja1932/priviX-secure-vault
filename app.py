from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
import db
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Initialize database
db.init_db()

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
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
        username = request.form['username']
        password = request.form['password']
        
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

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please log in to access your files.', 'warning')
        return redirect(url_for('login'))
        
    user_id = session['user_id']
    username = session['username']
    
    # Fetch file counts for stats
    uploaded_files = db.get_user_files(user_id)
    shared_files = db.get_shared_files(user_id)
    
    return render_template('dashboard.html', 
                           username=username, 
                           upload_count=len(uploaded_files), 
                           share_count=len(shared_files))

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
    shared_files = db.get_shared_files(user_id)
    
    return render_template('shared_files.html', shared_files=shared_files)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
