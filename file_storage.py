import os
import json
import base64
from typing import Dict, Optional, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
from google.cloud import storage
import logging
import datetime
# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

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
    def __init__(self, storage_dir: str | None = None, use_cloud: bool = False, 
                 bucket_name: str | None = None, credentials_path: str | None = None):
        # Local storage setup
        if storage_dir is None:
            storage_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "storage")
        self.storage_dir = Path(storage_dir)
        self.metadata_file = self.storage_dir / "metadata.json"
        
        # Cloud storage setup
        self.use_cloud = use_cloud
        self.bucket_name = bucket_name
        self.credentials_path = credentials_path
        self.storage_client = None
        self.bucket = None
        
        # Initialize storage
        self.initialize_storage()
        
    def initialize_storage(self):
        """Create storage directory and metadata file if they don't exist"""
        # Initialize local storage
        os.makedirs(self.storage_dir, exist_ok=True)
        
        # Initialize metadata file if it doesn't exist
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
        
        # Initialize cloud storage if enabled
        if self.use_cloud:
            try:
                if self.credentials_path:
                    self.storage_client = storage.Client.from_service_account_json(self.credentials_path)
                else:
                    self.storage_client = storage.Client()
                
                if self.bucket_name:
                    try:
                        self.bucket = self.storage_client.get_bucket(self.bucket_name)
                        logger.info(f"Connected to existing bucket: {self.bucket_name}")
                        
                        # Now that bucket is initialized, sync with cloud storage
                        self.sync_with_cloud()
                        
                    except Exception:
                        # Bucket doesn't exist, create it
                        self.bucket = self.storage_client.create_bucket(self.bucket_name)
                        logger.info(f"Created new bucket: {self.bucket_name}")
                else:
                    logger.warning("No bucket name provided for cloud storage")
                    self.use_cloud = False
            except Exception as e:
                logger.error(f"Error initializing cloud storage: {e}")
                self.use_cloud = False
                logger.info("Falling back to local storage only")


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
            
            # If using cloud storage, also upload metadata to cloud
            if self.use_cloud and self.bucket:
                try:
                    metadata_blob = self.bucket.blob('metadata.json')
                    metadata_blob.upload_from_string(
                        json.dumps(metadata, indent=4),
                        content_type='application/json'
                    )
                except Exception as e:
                    logger.error(f"Failed to save metadata to cloud: {e}")
            
            return True
        except Exception as e:
            logger.error(f"Error saving metadata: {e}")
            if temp_file and os.path.exists(temp_file):
                try:
                    os.remove(temp_file)  # Clean up temp file if it exists
                except Exception as cleanup_error:
                    logger.error(f"Error cleaning up temp file: {cleanup_error}")
            return False

    def load_metadata(self) -> Dict:
        """Safely load metadata from JSON file or cloud storage"""
        metadata = {}
        
        # Try to load from cloud first if enabled
        if self.use_cloud and self.bucket:
            try:
                metadata_blob = self.bucket.blob('metadata.json')
                if metadata_blob.exists():
                    metadata_content = metadata_blob.download_as_string()
                    metadata = json.loads(metadata_content)
                    logger.info("Successfully loaded metadata from cloud storage")
                    
                    # Save cloud metadata to local file for backup
                    with open(self.metadata_file, 'w') as f:
                        json.dump(metadata, f, indent=4)
            except Exception as e:
                logger.error(f"Error loading metadata from cloud: {e}")
                logger.info("Falling back to local metadata")
        
        # If cloud metadata loading failed or not enabled, load from local file
        if not metadata and self.metadata_file.exists():
            try:
                with open(self.metadata_file, 'r') as f:
                    metadata = json.load(f)
            except json.JSONDecodeError as e:
                logger.error(f"Error loading metadata (malformed JSON): {e}")
                return {}
        
        # Convert metadata dict to FileMetadata objects
        formatted_metadata = {}
        for filename, file_data in metadata.items():
            try:
                formatted_metadata[filename] = FileMetadata(
                    filename=file_data['filename'],
                    owner=file_data['owner'],
                    encrypted_key=file_data['encrypted_key'],
                    created_at=file_data.get('created_at', '')
                ).to_dict()
            except Exception as e:
                logger.error(f"Error processing metadata for file {filename}: {e}")
        
        return formatted_metadata

    def save_file(self, filename: str, encrypted_data: bytes, metadata: FileMetadata) -> bool:
        """Save encrypted file and its metadata to local storage and/or cloud"""
        try:
            # Update metadata first
            all_metadata = self.load_metadata()
            all_metadata[filename] = asdict(metadata)
            
            # Always save to local storage first as a backup
            file_path = self.storage_dir / filename
            with open(file_path, 'wb') as f:
                f.write(encrypted_data)
            
            # Save to cloud if enabled (after successful local save)
            cloud_success = True
            if self.use_cloud and self.bucket:
                try:
                    blob = self.bucket.blob(filename)
                    blob.upload_from_string(
                        encrypted_data, 
                        content_type='application/octet-stream'
                    )
                    logger.info(f"File {filename} uploaded to cloud storage")
                    
                    # Also upload the updated metadata
                    metadata_blob = self.bucket.blob('metadata.json')
                    metadata_blob.upload_from_string(
                        json.dumps(all_metadata, indent=4),
                        content_type='application/json'
                    )
                except Exception as e:
                    logger.error(f"Error saving file to cloud: {e}")
                    cloud_success = False
                    # Don't return False here - we still have the local copy
            
            # Update metadata (both local and cloud if successful)
            self.save_metadata(all_metadata)
            
            return cloud_success if self.use_cloud else True
                
        except Exception as e:
            logger.error(f"Error saving file: {e}")
            return False

    def get_file(self, filename: str) -> Optional[Tuple[bytes, FileMetadata]]:
        """Retrieve encrypted file and its metadata from local storage or cloud"""
        try:
            all_metadata = self.load_metadata()
            if filename not in all_metadata:
                logger.warning(f"File {filename} not found in metadata")
                return None
            
            encrypted_data = None
            
            # Try to get from cloud first if enabled
            if self.use_cloud and self.bucket:
                try:
                    blob = self.bucket.blob(filename)
                    if blob.exists():
                        encrypted_data = blob.download_as_bytes()
                        logger.info(f"Retrieved file {filename} from cloud storage")
                    else:
                        logger.warning(f"File {filename} not found in cloud storage")
                except Exception as e:
                    logger.error(f"Error retrieving file from cloud: {e}")
                    logger.info("Falling back to local storage")
            
            # If cloud retrieval failed or not enabled, try local
            if encrypted_data is None:
                file_path = self.storage_dir / filename
                if not file_path.exists():
                    logger.warning(f"File {filename} not found in local storage")
                    return None
                
                with open(file_path, 'rb') as f:
                    encrypted_data = f.read()
                logger.info(f"Retrieved file {filename} from local storage")
            
            metadata = FileMetadata(**all_metadata[filename])
            return encrypted_data, metadata

        except Exception as e:
            logger.error(f"Error retrieving file: {e}")
            return None

    def delete_file(self, filename: str) -> bool:
        """Delete file and its metadata from local storage and/or cloud"""
        try:
            # Delete from cloud if enabled
            if self.use_cloud and self.bucket:
                try:
                    blob = self.bucket.blob(filename)
                    if blob.exists():
                        blob.delete()
                        logger.info(f"Deleted file {filename} from cloud storage")
                    else:
                        logger.warning(f"File {filename} not found in cloud storage")
                except Exception as e:
                    logger.error(f"Error deleting file from cloud: {e}")
            
            # Delete from local storage
            file_path = self.storage_dir / filename
            if file_path.exists():
                os.remove(file_path)
                logger.info(f"Deleted file {filename} from local storage")
            
            # Update metadata
            all_metadata = self.load_metadata()
            if filename in all_metadata:
                del all_metadata[filename]
                self.save_metadata(all_metadata)
                logger.info(f"Removed {filename} from metadata")
            
            return True
            
        except Exception as e:
            logger.error(f"Error deleting file: {e}")
            return False

    def list_files(self, owner: Optional[str] = None) -> Dict[str, FileMetadata]:
        """List all files or files owned by specific user"""
        all_metadata = self.load_metadata()
        
        # If using cloud storage, refresh the file list from the bucket
        if self.use_cloud and self.bucket:
            try:
                blobs = list(self.bucket.list_blobs())
                
                # Update metadata with files from cloud
                updated = False
                for blob in blobs:
                    # Skip metadata.json file
                    if blob.name == 'metadata.json':
                        continue
                        
                    if blob.name not in all_metadata:
                        logger.info(f"Found file in cloud not in metadata: {blob.name}")
                        # For files found in cloud but not in metadata, add basic metadata
                        all_metadata[blob.name] = FileMetadata(
                            filename=blob.name,
                            owner=owner or "unknown",  # Default owner if not specified
                            encrypted_key="",  # This will need special handling for decryption
                            created_at=blob.time_created.isoformat()
                        ).to_dict()
                        updated = True
                
                # Save updated metadata if changes were made
                if updated:
                    self.save_metadata(all_metadata)
                    logger.info("Updated metadata with files found in cloud storage")
            except Exception as e:
                logger.error(f"Error listing files from cloud: {e}")
        
        try:
            if owner is None:
                return {k: FileMetadata(**v) for k, v in all_metadata.items()}
            return {k: FileMetadata(**v) for k, v in all_metadata.items() if v['owner'] == owner}
        except Exception as e:
            logger.error(f"Error listing files: {e}")
            return {}


    def sync_with_cloud(self) -> bool:
        """Synchronize local metadata with cloud storage bucket contents"""
        # Logger should be defined at the class level, but we'll ensure it's accessible
        logger = logging.getLogger(__name__)
        
        if not self.use_cloud or not self.bucket:
            logger.warning("Cloud storage not enabled, cannot sync")
            return False
            
        try:
            # First try to get metadata from cloud
            try:
                metadata_blob = self.bucket.blob('metadata.json')
                if metadata_blob.exists():
                    metadata_content = metadata_blob.download_as_string()
                    cloud_metadata = json.loads(metadata_content)
                    # Use cloud metadata as our source of truth
                    all_metadata = cloud_metadata
                    logger.info("Successfully loaded metadata from cloud storage")
                else:
                    # If no cloud metadata, use local metadata
                    all_metadata = self.load_metadata()
            except Exception as e:
                logger.error(f"Error loading metadata from cloud: {e}")
                all_metadata = self.load_metadata()

            # List all blobs in the bucket
            blobs = list(self.bucket.list_blobs())
            
            # Get list of files in cloud (excluding metadata.json)
            cloud_files = set(blob.name for blob in blobs if blob.name != 'metadata.json')
            
            # Check for files in cloud that aren't in metadata
            updated = False
            for blob in blobs:
                # Skip metadata.json file
                if blob.name == 'metadata.json':
                    continue
                    
                # If file exists in cloud but not in metadata, add placeholder metadata
                if blob.name not in all_metadata:
                    logger.info(f"Found new file in cloud: {blob.name}")
                    all_metadata[blob.name] = FileMetadata(
                        filename=blob.name,
                        owner="unknown",  # You might want to handle this differently
                        encrypted_key="",  # This will need to be handled for decryption
                        created_at=blob.time_created.isoformat() if hasattr(blob, 'time_created') else datetime.datetime.now().isoformat()
                    ).to_dict()
                    updated = True
            
            # Now check for files in metadata that no longer exist in cloud
            metadata_files = set(all_metadata.keys())
            files_to_remove = metadata_files - cloud_files
            
            for filename in files_to_remove:
                logger.info(f"File {filename} exists in metadata but not in cloud, removing from metadata")
                del all_metadata[filename]
                updated = True
                
                # Also remove local copy if it exists
                file_path = self.storage_dir / filename
                if file_path.exists():
                    os.remove(file_path)
                    logger.info(f"Removed local copy of {filename} that no longer exists in cloud")
            
            # Save updated metadata if changes were made
            if updated:
                self.save_metadata(all_metadata)
                logger.info("Metadata synchronized with cloud storage")
                return True
            else:
                logger.info("No changes needed during cloud synchronization")
                return False
        except Exception as e:
            logger.error(f"Error syncing with cloud: {e}")
            return False