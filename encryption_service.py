import os
import base64
from cryptography.fernet import Fernet
from enum import Enum
from typing import Dict, List
from google.cloud import kms
from google.cloud.kms import KeyManagementServiceClient

class UserRole(Enum):
    BOSS = "boss"
    MANAGER = "manager"
    USER = "user"

class User:
    def __init__(self, username: str, role: UserRole, manager=None):
        self.username = username
        self.role = role
        self.manager = manager
        self.key = Fernet.generate_key()
        self.encrypted_files: List[str] = []

class EncryptionService:
    def __init__(self,file_storage=None):
        self.users: Dict[str, User] = {}
        self.file_keys: Dict[str, bytes] = {}
        self.access_request_manager = None
        self.file_storage = file_storage
        # Check if KMS should be used
        self.use_kms = os.getenv('USE_GOOGLE_KMS', 'false').lower() == 'true'
        
        if self.use_kms:
            try:
                self.kms_client = KeyManagementServiceClient()
                self.project_id = os.getenv("GOOGLE_CLOUD_PROJECT")
                if not self.project_id:
                    raise ValueError("GOOGLE_CLOUD_PROJECT environment variable not set")
                self.location_id = os.getenv("KMS_LOCATION", "global")
                self.key_ring_id = os.getenv("KMS_KEYRING", "cloud-storage-keyring")
                self.crypto_key_id = os.getenv("KMS_KEY", "file-encryption-key")
                self.key_name = self.kms_client.crypto_key_path(
                    self.project_id, self.location_id, self.key_ring_id, self.crypto_key_id
                )
                # Verify KMS configuration by attempting a test encryption
                test_data = b"test"
                self.kms_client.encrypt(request={'name': self.key_name, 'plaintext': test_data})
                print("Successfully initialized Google Cloud KMS")
            except Exception as e:
                print(f"Warning: KMS initialization failed, falling back to local key management: {e}")
                self.use_kms = False
    
    def add_user(self, username: str, role: UserRole, manager=None) -> User:
        if username in self.users:
            raise ValueError(f"User {username} already exists")
        
        user = User(username, role, manager)
        self.users[username] = user
        return user
    
    def encrypt_file(self, filename: str, data: bytes, owner: str) -> bytes:
        if owner not in self.users:
            raise ValueError(f"User {owner} does not exist")
        
        user = self.users[owner]
        dek = Fernet.generate_key()
        
        if self.use_kms:
            try:
                # Encrypt the data encryption key with Cloud KMS
                encrypt_response = self.kms_client.encrypt(
                    request={
                        'name': self.key_name,
                        'plaintext': dek,
                    }
                )
                encrypted_key = encrypt_response.ciphertext
            except Exception as e:
                raise ValueError(f"Failed to encrypt key using KMS: {e}")
        else:
            encrypted_key = dek
        
        # Encrypt the file with the data encryption key
        fernet = Fernet(dek)
        encrypted_data = fernet.encrypt(data)
        
        # Store the encrypted key
        self.file_keys[filename] = base64.b64encode(encrypted_key)
        user.encrypted_files.append(filename)
        
        return encrypted_data

    def decrypt_file(self, filename: str, encrypted_data: bytes, username: str) -> bytes:
        if not self.can_decrypt(username, filename):
            raise ValueError(f"User {username} does not have permission to decrypt this file")
        
        if filename not in self.file_keys:
            raise ValueError(f"No encryption key found for file {filename}")
        
        encrypted_key = base64.b64decode(self.file_keys[filename])
        
        if self.use_kms:
            try:
                # Decrypt the data encryption key using Cloud KMS
                decrypt_response = self.kms_client.decrypt(
                    request={
                        'name': self.key_name,
                        'ciphertext': encrypted_key,
                    }
                )
                dek = decrypt_response.plaintext
            except Exception as e:
                raise ValueError(f"Failed to decrypt key using KMS: {e}")
        else:
            dek = encrypted_key
        
        # Use the decrypted key to decrypt the file
        try:
            fernet = Fernet(dek)
            return fernet.decrypt(encrypted_data)
        except Exception as e:
            raise ValueError(f"Failed to decrypt file: {e}")
    
    def _is_subordinate(self, user: User, potential_manager: User) -> bool:
        """Check if a user is a subordinate of a potential manager at any level"""
        current = user
        while current and current.manager:
            if current.manager == potential_manager.username:
                return True
            current = self.users.get(current.manager)
        return False
    
    def check_access_grant(self, username, filename):
        """Check if user has been granted access to a file via an approved request"""
        if not self.access_request_manager:
            return False
        
        try:
            # Get all requests from this user
            requests = self.access_request_manager.get_requests_from_requestor(username)
            
            # Check if there's an approved request for this file
            for req in requests:
                if req.filename == filename and req.status == "approved":
                    # You could add an expiration check here if needed
                    return True
        except Exception as e:
            print(f"Error checking access grants: {e}")
            
        return False

    def can_decrypt(self, username, filename):
        """Check if a user can decrypt a file based on role hierarchy or access grants"""
        user = self.users.get(username)
        if not user:
            return False
        
        # Check if file exists in keys
        if filename not in self.file_keys:
            return False
        
        # Get file owner
        file_owner = self._get_file_owner(filename)
        
        # User can access their own files
        if file_owner and file_owner == username:
            return True
        
        # Boss can access everything
        if user.role == UserRole.BOSS:
            return True
        
        # Managers can access files from their subordinates
        if user.role == UserRole.MANAGER:
            owner_user = self.users.get(file_owner) if file_owner else None
            if owner_user:
                # Check if owner is a direct subordinate
                if owner_user.manager == username:
                    return True
                # Check if owner is in the manager's hierarchy (any level below)
                if self._is_subordinate(owner_user, user):
                    return True
        
        # Check for approved access requests
        if self.check_access_grant(username, filename):
            return True
        
        return False

    def _get_file_owner(self, filename):
        """Helper to get file owner from file metadata"""
        # Check all users' encrypted_files lists first
        for username, user in self.users.items():
            if filename in user.encrypted_files:
                return username
        
        # If not found in users, check file storage metadata
        try:
            result = self.file_storage.get_file(filename)
            if result:
                _, metadata = result
                if hasattr(metadata, 'owner'):
                    return metadata.owner
        except Exception as e:
            print(f"Error getting file owner: {e}")
        
        return None

    def get_users_under_manager(self, manager_username):
        """Get all users that report to this manager"""
        users_under = []
        for username, user in self.users.items():
            if user.manager == manager_username:
                users_under.append(username)
        return users_under

    def set_access_request_manager(self, manager):
        """Set the access request manager instance"""
        self.access_request_manager = manager
        print("Access Request Manager successfully registered")
        return True

    def has_pending_access_request(self, username, filename):
        """Check if a user already has a pending access request for a file"""
        if not self.access_request_manager:
            return False
            
        try:
            requests = self.access_request_manager.get_requests_from_requestor(username)
            for req in requests:
                if req.filename == filename and req.status == "pending":
                    return True
        except Exception as e:
            print(f"Error checking pending requests: {e}")
            
        return False