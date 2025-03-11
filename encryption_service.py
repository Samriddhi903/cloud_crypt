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
    def __init__(self):
        self.users: Dict[str, User] = {}
        self.file_keys: Dict[str, bytes] = {}
        try:
            self.kms_client = KeyManagementServiceClient()
            self.project_id = os.getenv("GOOGLE_CLOUD_PROJECT")
            if not self.project_id:
                raise ValueError("GOOGLE_CLOUD_PROJECT environment variable not set")
            self.location_id = "global"
            self.key_ring_id = "cloud-storage-keyring"
            self.crypto_key_id = "file-encryption-key"
            self.key_name = self.kms_client.crypto_key_path(
                self.project_id, self.location_id, self.key_ring_id, self.crypto_key_id
            )
            # Verify KMS configuration by attempting a test encryption
            test_data = b"test"
            self.kms_client.encrypt(request={'name': self.key_name, 'plaintext': test_data})
            self.use_kms = True
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
    
    def can_decrypt(self, username: str, filename: str) -> bool:
        if username not in self.users or filename not in self.file_keys:
            return False
        
        user = self.users[username]
        file_owner = next(
            (u for u in self.users.values() if filename in u.encrypted_files),
            None
        )
        
        if not file_owner:
            return False
        
        if user.role == UserRole.BOSS:
            return True
        
        if user.role == UserRole.MANAGER:
            return file_owner.username == username or self._is_subordinate(file_owner, user)
        
        return file_owner.username == username
    
    def _is_subordinate(self, user: User, manager: User) -> bool:
        current = user
        while current and current.manager:
            if current.manager == manager.username:
                return True
            current = self.users.get(current.manager)
        return False

# Example usage
def main():
    service = EncryptionService()
    
    # Create users with different roles
    boss = service.add_user("boss", UserRole.BOSS)
    manager1 = service.add_user("manager1", UserRole.MANAGER, "boss")
    user1 = service.add_user("user1", UserRole.USER, "manager1")
    user2 = service.add_user("user2", UserRole.USER, "manager1")
    
    # Example file encryption
    test_data = b"This is a secret message"
    encrypted_data = service.encrypt_file("secret.txt", test_data, "user1")
    
    # Test decryption permissions
    try:
        # Boss can decrypt
        decrypted_boss = service.decrypt_file("secret.txt", encrypted_data, "boss")
        print(f"Boss decrypted: {decrypted_boss.decode()}")
        
        # Manager can decrypt subordinate's file
        decrypted_manager = service.decrypt_file("secret.txt", encrypted_data, "manager1")
        print(f"Manager decrypted: {decrypted_manager.decode()}")
        
        # User1 can decrypt their own file
        decrypted_user = service.decrypt_file("secret.txt", encrypted_data, "user1")
        print(f"User1 decrypted: {decrypted_user.decode()}")
        
        # User2 cannot decrypt User1's file
        service.decrypt_file("secret.txt", encrypted_data, "user2")
    except ValueError as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
