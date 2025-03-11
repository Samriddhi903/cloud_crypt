from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file
from encryption_service import EncryptionService, UserRole
from file_storage import FileStorage, FileMetadata
import os
import io
from datetime import datetime
from werkzeug.utils import secure_filename
import bcrypt

app = Flask(__name__)
app.secret_key = 'your-super-secret-key'  # Static secret key for session management

encryption_service = EncryptionService()
file_storage = FileStorage()

# Setup initial users
encryption_service.add_user("boss", UserRole.BOSS)
encryption_service.add_user("manager1", UserRole.MANAGER, "boss")
encryption_service.add_user("user1", UserRole.USER, "manager1")

def load_credentials():
    credentials = {}
    with open('credentials.txt', 'r') as f:
        for line in f:
            username, hashed_password = line.strip().split(':')
            credentials[username] = hashed_password
    return credentials

@app.route('/')
def index():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    username = session['username']
    user = encryption_service.users.get(username)
    if not user:
        return redirect(url_for('login'))
    
    # Get all files from storage
    files = file_storage.list_files()
    accessible_files = []
    
    # Filter files based on user's role and permissions
    for filename, metadata in files.items():
        # Check if user can decrypt the file based on role hierarchy
        if encryption_service.can_decrypt(username, filename):
            accessible_files.append({
                'name': filename,
                'metadata': metadata
            })
    
    # Sort files by creation date (newest first)
    accessible_files.sort(key=lambda x: x['metadata'].created_at, reverse=True)
    return render_template('index.html', files=accessible_files)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        credentials = load_credentials()
        if username in credentials:
            stored_hash = credentials[username]
            if password==stored_hash:
                session.clear()
                session['username'] = username
                flash('Logged in successfully!', 'success')
                return redirect(url_for('index'))
        flash('Invalid username or password!', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    if 'file' not in request.files:
        flash('No file selected', 'error')
        return redirect(url_for('index'))
    
    file = request.files['file']
    if not file or not hasattr(file, 'filename') or not file.filename:
        flash('No file selected or invalid file', 'error')
        return redirect(url_for('index'))
    
    filename = secure_filename(file.filename)
    file_data = file.read()
    
    try:
        encrypted_data = encryption_service.encrypt_file(
            filename, file_data, session['username']
        )
        
        metadata = FileMetadata(
            filename=filename,
            owner=session['username'],
            encrypted_key=encryption_service.file_keys[filename],
            created_at=datetime.now().isoformat()
        )
        
        if file_storage.save_file(filename, encrypted_data, metadata):
            flash('File uploaded and encrypted successfully!', 'success')
        else:
            flash('Failed to save file', 'error')
    except Exception as e:
        flash(f'Error: {str(e)}', 'error')
    
    return redirect(url_for('index'))

@app.route('/download/<filename>')
def download_file(filename):
    if 'username' not in session:
        return redirect(url_for('login'))
    
    try:
        result = file_storage.get_file(filename)
        if not result:
            flash('File not found', 'error')
            return redirect(url_for('index'))
        
        encrypted_data, metadata = result
        
        try:
            decrypted_data = encryption_service.decrypt_file(
                filename, encrypted_data, session['username']
            )
            return send_file(
                io.BytesIO(decrypted_data),
                download_name=filename,
                as_attachment=True
            )
        except ValueError as e:
            flash(f'Access denied: {str(e)}', 'error')
    except Exception as e:
        flash(f'Error: {str(e)}', 'error')
    
    return redirect(url_for('index'))

@app.route('/delete/<filename>')
def delete_file(filename):
    if 'username' not in session:
        return redirect(url_for('login'))
    
    result = file_storage.get_file(filename)
    if not result:
        flash('File not found', 'error')
        return redirect(url_for('index'))
    
    _, metadata = result
    if metadata.owner != session['username']:
        flash('You can only delete your own files', 'error')
        return redirect(url_for('index'))
    
    if file_storage.delete_file(filename):
        flash('File deleted successfully', 'success')
    else:
        flash('Failed to delete file', 'error')
    
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)