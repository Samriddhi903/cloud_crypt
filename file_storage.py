import os
import json
import base64
from typing import Dict, Optional
from dataclasses import dataclass, asdict
from pathlib import Path

@dataclass
class FileMetadata:
    filename: str
    owner: str
    encrypted_key: str  # Store as base64 string
    created_at: str

    def __init__(self, filename: str, owner: str, encrypted_key: bytes | str, created_at: str):
        self.filename = filename
        self.owner = owner
        # Convert bytes to base64 string if needed
        self.encrypted_key = encrypted_key if isinstance(encrypted_key, str) else base64.b64encode(encrypted_key).decode('utf-8')
        self.created_at = created_at

    def to_dict(self):
        return {
            'filename': self.filename,
            'owner': self.owner,
            'encrypted_key': self.encrypted_key,
            'created_at': self.created_at
        }

class FileStorage:
    def __init__(self, storage_dir: str | None = None):
        if storage_dir is None:
            # Use absolute path in the current directory
            storage_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "storage")
        self.storage_dir = Path(storage_dir)
        self.metadata_file = self.storage_dir / "metadata.json"
        self.initialize_storage()

    def initialize_storage(self):
        """Create storage directory and metadata file if they don't exist"""
        os.makedirs(self.storage_dir, exist_ok=True)
        if not self.metadata_file.exists():
            self.save_metadata({})
        else:
            # Validate existing metadata file
            try:
                self.load_metadata()
            except Exception:
                # Backup corrupted file and create new one
                backup_path = str(self.metadata_file) + ".backup"
                os.rename(self.metadata_file, backup_path)
                self.save_metadata({})

    def save_metadata(self, metadata: Dict):
        """Save metadata to JSON file with proper error handling and atomic operations"""
        temp_file = None
        try:
            # First write to a temporary file
            temp_file = self.metadata_file.with_name(self.metadata_file.name + '.tmp')
            with open(temp_file, 'w') as f:
                json.dump(metadata, f, indent=4)
                f.flush()
                os.fsync(f.fileno())  # Ensure data is written to disk
            
            # Then atomically rename it to the actual metadata file
            os.replace(temp_file, self.metadata_file)
            return True
        except Exception as e:
            print(f"Error saving metadata: {e}")
            if temp_file and os.path.exists(temp_file):
                try:
                    os.remove(temp_file)  # Clean up temp file if it exists
                except Exception as cleanup_error:
                    print(f"Error cleaning up temp file: {cleanup_error}")
            return False

    def load_metadata(self) -> Dict:
        """Safely load metadata from JSON file"""
        if not self.metadata_file.exists():
            return {}
        try:
            with open(self.metadata_file, 'r') as f:
                metadata = json.load(f)
                # Convert metadata dict to FileMetadata objects
                for filename, file_data in metadata.items():
                    metadata[filename] = FileMetadata(
                        filename=file_data['filename'],
                        owner=file_data['owner'],
                        encrypted_key=file_data['encrypted_key'],
                        created_at=file_data.get('created_at', '')
                    ).to_dict()
                print(f"Loaded metadata: {metadata}")
                return metadata
        except json.JSONDecodeError as e:
            print(f"Error loading metadata (malformed JSON): {e}")
            return {}

    def save_file(self, filename: str, encrypted_data: bytes, metadata: FileMetadata) -> bool:
        """Save encrypted file and its metadata"""
        try:
            # Save encrypted file
            file_path = self.storage_dir / filename
            with open(file_path, 'wb') as f:
                f.write(encrypted_data)

            # Update metadata
            all_metadata = self.load_metadata()
            all_metadata[filename] = asdict(metadata)
            self.save_metadata(all_metadata)
            return True
        except Exception as e:
            print(f"Error saving file: {e}")
            return False

    def get_file(self, filename: str) -> Optional[tuple[bytes, FileMetadata]]:
        """Retrieve encrypted file and its metadata"""
        try:
            all_metadata = self.load_metadata()
            if filename not in all_metadata:
                return None

            file_path = self.storage_dir / filename
            if not file_path.exists():
                return None

            with open(file_path, 'rb') as f:
                encrypted_data = f.read()

            metadata = FileMetadata(**all_metadata[filename])
            return encrypted_data, metadata

        except Exception as e:
            print(f"Error retrieving file: {e}")
            return None

    def delete_file(self, filename: str) -> bool:
        """Delete file and its metadata"""
        try:
            file_path = self.storage_dir / filename
            if file_path.exists():
                os.remove(file_path)

            all_metadata = self.load_metadata()
            if filename in all_metadata:
                del all_metadata[filename]
                self.save_metadata(all_metadata)

            return True
        except Exception as e:
            print(f"Error deleting file: {e}")
            return False

    def list_files(self, owner: Optional[str] = None) -> Dict[str, FileMetadata]:
        """List all files or files owned by specific user"""
        all_metadata = self.load_metadata()
        try:
            if owner is None:
                return {k: FileMetadata(**v) for k, v in all_metadata.items()}
            return {k: FileMetadata(**v) for k, v in all_metadata.items() if v['owner'] == owner}
        except Exception as e:
            print(f"Error listing files: {e}")
            return {}
