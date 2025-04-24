from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file
from encryption_service import EncryptionService, UserRole
from file_storage import FileStorage, FileMetadata
from access_request import AccessRequestManager, AccessRequest
import os
import io
from datetime import datetime
from werkzeug.utils import secure_filename
import bcrypt
import logging
# Initialize access request manager first (needs to be available globally)
access_request_manager = AccessRequestManager()

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY')  # Better to use env var

# Get cloud storage configuration from environment variables
use_cloud = os.getenv('USE_CLOUD_STORAGE', 'false').lower() == 'true'
bucket_name = os.getenv('CLOUD_STORAGE_BUCKET')
credentials_path = os.getenv('GOOGLE_APPLICATION_CREDENTIALS')
change_made=os.getenv("CHANGE_MADE","1")
# Initialize services
file_storage = FileStorage(
    use_cloud=use_cloud,
    bucket_name=bucket_name,
    credentials_path=credentials_path
)
encryption_service = EncryptionService(file_storage=file_storage)
encryption_service.set_access_request_manager(access_request_manager)
if change_made=="1" and file_storage.use_cloud:
    file_storage.sync_with_cloud()

def register_existing_files_with_encryption_service():
    """Register existing files from storage with the encryption service"""
    files = file_storage.list_files()
    for filename, metadata in files.items():
        # Only register if not already registered
        if filename not in encryption_service.file_keys and hasattr(metadata, 'encrypted_key'):
            try:
                # Register the encrypted key with the encryption service
                encryption_service.file_keys[filename] = metadata.encrypted_key
                print(f"Registered existing file: {filename}")
            except Exception as e:
                print(f"Error registering file {filename} with encryption service: {e}")

register_existing_files_with_encryption_service()

# Setup initial users
encryption_service.add_user("boss", UserRole.BOSS)
encryption_service.add_user("manager1", UserRole.MANAGER, "boss")
encryption_service.add_user("user1", UserRole.USER, "manager1")
encryption_service.add_user("user2", UserRole.USER, "manager1")  # Add an extra user for testing

def load_credentials():
    credentials = {}
    try:
        with open('credentials.txt', 'r') as f:
            for line in f:
                if ':' in line:
                    username, hashed_password = line.strip().split(':')
                    credentials[username] = hashed_password
    except Exception as e:
        print(f"Error loading credentials: {e}")
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
    
    # Process all files for display
    accessible_files = []
    
    for filename, metadata in files.items():
        # Register key with encryption service if not already registered
        if filename not in encryption_service.file_keys and hasattr(metadata, 'encrypted_key') and metadata.encrypted_key:
            encryption_service.file_keys[filename] = metadata.encrypted_key
        
        # Determine if current user can decrypt the file
        can_decrypt = encryption_service.can_decrypt(username, filename)
        
        # Check if there's a pending access request
        has_pending_request = encryption_service.has_pending_access_request(username, filename)
        
        # Add to the accessible_files list with permission info
        accessible_files.append({
            'name': filename,
            'metadata': metadata,
            'can_decrypt': can_decrypt,
            'has_pending_request': has_pending_request
        })
    
    # Sort files by creation date (newest first)
    accessible_files.sort(key=lambda x: x['metadata'].created_at if hasattr(x['metadata'], 'created_at') else '', reverse=True)
    
    # Add storage info for the template
    storage_info = {
        'using_cloud': use_cloud,
        'bucket_name': bucket_name if use_cloud else None,
        'using_kms': os.getenv('USE_GOOGLE_KMS', 'false').lower() == 'true'
    }
    
    # Get pending approval count for display in menu
    pending_count = 0
    if user.role in [UserRole.MANAGER, UserRole.BOSS]:
        pending_count = access_request_manager.get_pending_request_count(username)
    
    return render_template('index.html', 
                          files=accessible_files, 
                          storage_info=storage_info,
                          user=user,
                          pending_count=pending_count,
                          access_request_manager=access_request_manager,
                          encryption_service=encryption_service)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        credentials = load_credentials()
        if username in credentials:
            stored_hash = credentials[username]
            if bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')):
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
        
        # Save file and check if cloud upload was successful if enabled
        save_result = file_storage.save_file(filename, encrypted_data, metadata)
        
        if save_result:
            if file_storage.use_cloud:
                flash('File uploaded and encrypted successfully to cloud storage!', 'success')
            else:
                flash('File uploaded and encrypted successfully to local storage!', 'success')
        else:
            if file_storage.use_cloud:
                flash('File saved locally but cloud upload failed', 'warning')
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
        
        # Check if this is a cloud-discovered file without proper key
        if not hasattr(metadata, 'encrypted_key') or not metadata.encrypted_key:
            flash('This file was discovered in cloud storage but cannot be decrypted because the encryption key is missing.', 'error')
            return redirect(url_for('index'))
        
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

@app.route('/storage-info')
def storage_info():
    """Display storage configuration information"""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    info = {
        'using_cloud': use_cloud,
        'bucket_name': bucket_name if use_cloud else None,
        'using_kms': os.getenv('USE_GOOGLE_KMS', 'false').lower() == 'true',
        'project_id': os.getenv('GOOGLE_CLOUD_PROJECT', 'Not configured'),
        'local_storage_path': str(file_storage.storage_dir)
    }
    
    return render_template('storage_info.html', info=info)

@app.route('/refresh-files')
def refresh_files():
    if 'username' not in session:
        return redirect(url_for('login'))
    logger = logging.getLogger(__name__)
    try:
        # Force a refresh of files from cloud storage
        if file_storage.use_cloud and file_storage.bucket:
            blobs = list(file_storage.bucket.list_blobs())
            all_metadata = file_storage.load_metadata()
            
            # Create set of cloud files (excluding metadata.json)
            cloud_files = set(blob.name for blob in blobs if blob.name != 'metadata.json')
            
            # Update metadata with files from cloud
            updated = False
            for blob in blobs:
                if blob.name != 'metadata.json' and blob.name not in all_metadata:
                    # For files found in cloud but not in metadata
                    all_metadata[blob.name] = FileMetadata(
                        filename=blob.name,
                        owner=session['username'],  # Assign to current user
                        encrypted_key="",  # This needs special handling
                        created_at=blob.time_created.isoformat() if hasattr(blob, 'time_created') else datetime.now().isoformat()
                    ).to_dict()
                    updated = True
            
            # Remove files from metadata that don't exist in cloud
            metadata_files = set(all_metadata.keys())
            files_to_remove = metadata_files - cloud_files
            
            removed_files = False
            for filename in files_to_remove:
                if filename in all_metadata:
                    logger.info(f"Removing {filename} from metadata as it no longer exists in cloud")
                    del all_metadata[filename]
                    updated = True
                    removed_files = True
                    
                    # Also remove local copy if it exists
                    file_path = file_storage.storage_dir / filename
                    if os.path.exists(file_path):
                        os.remove(file_path)
                        logger.info(f"Removed local copy of {filename}")
            
            if updated:
                file_storage.save_metadata(all_metadata)
                if removed_files:
                    flash('File list updated: added new files and removed files no longer in cloud storage', 'success')
                else:
                    flash('File list refreshed from cloud storage', 'success')
            else:
                flash('No changes needed - file list is already in sync with cloud storage', 'info')
        else:
            flash('Cloud storage is not enabled', 'warning')
    except Exception as e:
        logger.error(f"Error refreshing files: {e}")
        flash(f'Error refreshing files: {str(e)}', 'error')
    
    return redirect(url_for('index'))

@app.route('/request-access/<filename>')
def request_access(filename):
    """Request access to a file"""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # Get the current user
    requestor = session['username']
    requestor_user = encryption_service.users.get(requestor)
    if not requestor_user:
        flash('User not found', 'error')
        return redirect(url_for('index'))
    
    # First check if user already has access
    if encryption_service.can_decrypt(requestor, filename):
        flash('You already have access to this file', 'warning')
        return redirect(url_for('index'))
    
    # Check if there's already a pending request
    if encryption_service.has_pending_access_request(requestor, filename):
        flash('You already have a pending request for this file', 'warning')
        return redirect(url_for('index'))
    
    # Get all files to check existence
    files = file_storage.list_files()
    if filename not in files:
        flash('File not found', 'error')
        return redirect(url_for('index'))
    
    # Get file metadata
    metadata = files[filename]
    
    # Determine who should approve this request
    approver = None
    
    # If the file has an owner, check if they're a manager or boss
    file_owner = metadata.owner if hasattr(metadata, 'owner') else None
    owner_user = encryption_service.users.get(file_owner) if file_owner else None
    
    if owner_user and owner_user.role in [UserRole.MANAGER, UserRole.BOSS]:
        approver = file_owner
    # If the file owner is a regular user, go to their manager
    elif owner_user and owner_user.manager:
        approver = owner_user.manager
    # If no suitable approver found yet, use the requestor's manager
    elif requestor_user.manager:
        approver = requestor_user.manager
    # If still no approver, use any available boss
    else:
        for username, user in encryption_service.users.items():
            if user.role == UserRole.BOSS:
                approver = username
                break
    
    if not approver:
        flash('No approver available for this request', 'error')
        return redirect(url_for('index'))
    
    # Create the access request
    success, result = access_request_manager.create_request(filename, requestor, approver)
    
    if success:
        flash(f'Access request sent to {approver}', 'success')
    else:
        flash(f'Failed to create request: {result}', 'error')
    
    return redirect(url_for('index'))

@app.route('/my-requests')
def my_requests():
    """View my access requests"""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    username = session['username']
    requests = access_request_manager.get_requests_from_requestor(username)
    
    # Get file details for each request
    request_details = []
    for req in requests:
        file_info = None
        result = file_storage.get_file(req.filename)
        if result:
            _, metadata = result
            file_info = {
                'name': req.filename,
                'owner': metadata.owner,
                'created_at': metadata.created_at if hasattr(metadata, 'created_at') else 'Unknown'
            }
        
        request_details.append({
            'request': req,
            'file': file_info
        })
    
    # Sort by creation date (newest first)
    request_details.sort(key=lambda x: x['request'].created_at, reverse=True)
    
    return render_template('my_requests.html', 
                          requests=request_details, 
                          encryption_service=encryption_service,
                          access_request_manager=access_request_manager)

@app.route('/pending-approvals')
def pending_approvals():
    """View requests pending my approval"""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    username = session['username']
    user = encryption_service.users.get(username)
    if not user or user.role not in [UserRole.MANAGER, UserRole.BOSS]:
        flash('You do not have permission to approve requests', 'error')
        return redirect(url_for('index'))
    
    pending = access_request_manager.get_requests_for_approver(username)
    
    # Get file details for each request
    request_details = []
    for req in pending:
        file_info = None
        result = file_storage.get_file(req.filename)
        if result:
            _, metadata = result
            file_info = {
                'name': req.filename,
                'owner': metadata.owner,
                'created_at': metadata.created_at if hasattr(metadata, 'created_at') else 'Unknown'
            }
        
        # Get requestor details
        requestor_info = encryption_service.users.get(req.requestor)
        
        request_details.append({
            'request': req,
            'file': file_info,
            'requestor': requestor_info
        })
    
    # Sort by creation date (newest first)
    request_details.sort(key=lambda x: x['request'].created_at, reverse=True)
    
    return render_template('pending_approvals.html',
                          requests=request_details,
                          access_request_manager=access_request_manager)  # Add this line

@app.route('/approve-request/<request_id>')
def approve_request(request_id):
    """Approve an access request"""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    username = session['username']
    user = encryption_service.users.get(username)
    if not user or user.role not in [UserRole.MANAGER, UserRole.BOSS]:
        flash('You do not have permission to approve requests', 'error')
        return redirect(url_for('index'))
    
    # Get the request
    request = access_request_manager.get_request_by_id(request_id)
    if not request:
        flash('Request not found', 'error')
        return redirect(url_for('pending_approvals'))
    
    # Check if this user is the approver
    if request.approver != username:
        flash('You are not authorized to approve this request', 'error')
        return redirect(url_for('pending_approvals'))
    
    # Update request status
    success, message = access_request_manager.update_request_status(request_id, "approved")
    
    if success:
        flash(f'Request approved successfully', 'success')
    else:
        flash(f'Failed to approve request: {message}', 'error')
    
    return redirect(url_for('pending_approvals'))

@app.route('/reject-request/<request_id>')
def reject_request(request_id):
    """Reject an access request"""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    username = session['username']
    user = encryption_service.users.get(username)
    if not user or user.role not in [UserRole.MANAGER, UserRole.BOSS]:
        flash('You do not have permission to reject requests', 'error')
        return redirect(url_for('index'))
    
    # Get the request
    request = access_request_manager.get_request_by_id(request_id)
    if not request:
        flash('Request not found', 'error')
        return redirect(url_for('pending_approvals'))
    
    # Check if this user is the approver
    if request.approver != username:
        flash('You are not authorized to reject this request', 'error')
        return redirect(url_for('pending_approvals'))
    
    # Update request status
    success, message = access_request_manager.update_request_status(request_id, "rejected")
    
    if success:
        flash(f'Request rejected successfully', 'success')
    else:
        flash(f'Failed to reject request: {message}', 'error')
    
    return redirect(url_for('pending_approvals'))

@app.route('/user-management')
def user_management():
    """User management page for bosses and managers"""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    username = session['username']
    user = encryption_service.users.get(username)
    if not user or user.role not in [UserRole.MANAGER, UserRole.BOSS]:
        flash('You do not have permission to access user management', 'error')
        return redirect(url_for('index'))
    
    # Get users under management
    managed_users = []
    if user.role == UserRole.BOSS:
        # Boss can see all users
        managed_users = list(encryption_service.users.values())
    else:
        # Manager can see direct reports
        user_list = encryption_service.get_users_under_manager(username)
        managed_users = [encryption_service.users[u] for u in user_list if u in encryption_service.users]
    
    # Sort users by role (boss first, then managers, then users)
    managed_users.sort(key=lambda u: u.role.value)
    
    return render_template('user_management.html', 
                          users=managed_users,
                          current_user=user)

@app.route('/add-user', methods=['POST'])
def add_user():
    """Add a new user"""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    username = session['username']
    current_user = encryption_service.users.get(username)
    if not current_user or current_user.role not in [UserRole.MANAGER, UserRole.BOSS]:
        flash('You do not have permission to add users', 'error')
        return redirect(url_for('index'))
    
    # Get form data
    new_username = request.form.get('username')
    password = request.form.get('password')
    role_str = request.form.get('role')
    
    if not new_username or not password or not role_str:
        flash('All fields are required', 'error')
        return redirect(url_for('user_management'))
    
    # Validate role
    try:
        role = UserRole(role_str)
    except ValueError:
        flash('Invalid role', 'error')
        return redirect(url_for('user_management'))
    
    # Check permissions (only boss can add managers)
    if role == UserRole.MANAGER and current_user.role != UserRole.BOSS:
        flash('Only bosses can add managers', 'error')
        return redirect(url_for('user_management'))
    
    # Add user
    try:
        # Add to encryption service
        manager = username if role == UserRole.USER else None
        encryption_service.add_user(new_username, role, manager)
        
        # Add to credentials
        credentials = load_credentials()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        credentials[new_username] = hashed_password
        
        with open('credentials.txt', 'w') as f:
            for user, pwd in credentials.items():
                f.write(f"{user}:{pwd}\n")
        
        flash(f'User {new_username} added successfully', 'success')
    except Exception as e:
        flash(f'Failed to add user: {str(e)}', 'error')
    
    return redirect(url_for('user_management'))

@app.route('/activity-log')
def activity_log():
    """View system activity log"""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    username = session['username']
    user = encryption_service.users.get(username)
    if not user or user.role != UserRole.BOSS:
        flash('Only bosses can view the activity log', 'error')
        return redirect(url_for('index'))
    
    # In a real application, you would have proper logging
    # For now, we'll show access requests as our "log"
    all_requests = list(access_request_manager.requests.values())
    
    # Sort by updated_at (newest first)
    all_requests.sort(key=lambda x: x.updated_at, reverse=True)
    
    return render_template('activity_log.html', 
                          requests=all_requests,
                          users=encryption_service.users)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        role = request.form['role']
        manager = request.form.get('manager', None)

        # Basic validation
        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return redirect(url_for('login'))

        # Load existing credentials
        credentials = load_credentials()

        # Check if username exists
        if username in credentials:
            flash('Username already exists!', 'error')
            return redirect(url_for('login'))

        try:
            # Hash the password
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            
            # Save to credentials file
            with open('credentials.txt', 'a') as f:
                f.write(f"{username}:{hashed_password}\n")

            # Add user to encryption service
            user_role = UserRole[role.upper()]
            encryption_service.add_user(username, user_role, manager)

            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash(f'Registration failed: {str(e)}', 'error')
            return redirect(url_for('login'))

    return redirect(url_for('login'))


def load_credentials():
    credentials = {}
    try:
        with open('credentials.txt', 'r') as f:
            for line in f:
                if ':' in line:
                    username, hashed_password = line.strip().split(':')
                    credentials[username] = hashed_password
    except FileNotFoundError:
        # Create file if it doesn't exist
        open('credentials.txt', 'w').close()
    except Exception as e:
        print(f"Error loading credentials: {e}")
    
    return credentials

if __name__ == '__main__':
    app.run(debug=os.getenv('FLASK_DEBUG', 'false').lower() == 'true')