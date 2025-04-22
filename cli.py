import argparse
import datetime
import os
import logging
from pathlib import Path
from encryption_service import EncryptionService, UserRole
from file_storage import FileStorage, FileMetadata
# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)



class CLI:
    def __init__(self):
        # Get cloud storage configuration from environment variables
        use_cloud = os.getenv('USE_CLOUD_STORAGE', 'false').lower() == 'true'
        bucket_name = os.getenv('CLOUD_STORAGE_BUCKET')
        credentials_path = os.getenv('GOOGLE_APPLICATION_CREDENTIALS')
        
        self.encryption_service = EncryptionService()
        self.file_storage = FileStorage(
            use_cloud=use_cloud,
            bucket_name=bucket_name,
            credentials_path=credentials_path
        )
        self.current_user = None
        
        # Add a flag to indicate if cloud storage is being used
        self.using_cloud = use_cloud and bucket_name is not None
        self.using_kms = os.getenv('USE_GOOGLE_KMS', 'false').lower() == 'true'

    def show_storage_status(self):
        """Display current storage configuration"""
        print("\n=== Storage Configuration ===")
        if self.using_cloud:
            print(f"Storage Type: Google Cloud Storage")
            print(f"Bucket: {os.getenv('CLOUD_STORAGE_BUCKET')}")
            print(f"Project: {os.getenv('GOOGLE_CLOUD_PROJECT', 'Not configured')}")
        else:
            print("Storage Type: Local File System")
            print(f"Storage Directory: {self.file_storage.storage_dir}")
        
        print(f"KMS Enabled: {self.using_kms}")
        if self.using_kms:
            print(f"KMS Location: {os.getenv('KMS_LOCATION', 'global')}")
            print(f"KMS Keyring: {os.getenv('KMS_KEYRING', 'cloud-storage-keyring')}")
            print(f"KMS Key: {os.getenv('KMS_KEY', 'file-encryption-key')}")
        print("=============================\n")

    def setup_users(self):
        """Setup initial users for testing"""
        self.encryption_service.add_user("boss", UserRole.BOSS)
        self.encryption_service.add_user("manager1", UserRole.MANAGER, "boss")
        self.encryption_service.add_user("user1", UserRole.USER, "manager1")
        logger.info("Initial users set up: boss, manager1, user1")

    def login(self, username: str) -> bool:
        """Login as a user"""
        if username in self.encryption_service.users:
            self.current_user = username
            logger.info(f"Logged in as {username}")
            print(f"Logged in as {username}")
            return True
        logger.warning(f"Login failed: User {username} does not exist")
        print(f"User {username} does not exist")
        return False

    def upload_file(self, filepath: str):
        """Upload and encrypt a file"""
        if not self.current_user:
            logger.warning("Upload failed: No user logged in")
            print("Please login first")
            return

        try:
            file_path = Path(filepath)
            if not file_path.exists():
                logger.warning(f"Upload failed: File {filepath} does not exist")
                print(f"File {filepath} does not exist")
                return

            with open(file_path, 'rb') as f:
                data = f.read()

            filename = file_path.name
            logger.info(f"Encrypting file: {filename}")
            encrypted_data = self.encryption_service.encrypt_file(filename, data, self.current_user)

            if filename not in self.encryption_service.file_keys:
                logger.error(f"Failed to retrieve encrypted key for {filename}")
                print(f"Failed to retrieve encrypted key for {filename}")
                return

            encrypted_key = self.encryption_service.file_keys[filename]
            metadata = FileMetadata(
                filename=filename,
                owner=self.current_user,
                encrypted_key=encrypted_key,
                created_at=datetime.datetime.now().isoformat()
            )

            logger.info(f"Saving file: {filename}")
            if self.file_storage.save_file(filename, encrypted_data, metadata):
                storage_type = "cloud storage" if self.using_cloud else "local storage"
                logger.info(f"File {filename} uploaded successfully to {storage_type}")
                print(f"File {filename} uploaded successfully to {storage_type}")
            else:
                logger.error(f"Failed to upload file {filename}")
                print(f"Failed to upload file {filename}")

        except Exception as e:
            logger.exception(f"Error uploading file: {e}")
            print(f"Error uploading file: {e}")

    def download_file(self, filename: str, output_path: str):
        """Download and decrypt a file"""
        if not self.current_user:
            logger.warning("Download failed: No user logged in")
            print("Please login first")
            return

        try:
            logger.info(f"Retrieving file: {filename}")
            result = self.file_storage.get_file(filename)
            if not result:
                logger.warning(f"File {filename} not found")
                print(f"File {filename} not found")
                return

            encrypted_data, metadata = result

            try:
                logger.info(f"Decrypting file: {filename}")
                decrypted_data = self.encryption_service.decrypt_file(
                    filename, encrypted_data, self.current_user
                )

                output_dir = Path(output_path)
                output_dir.mkdir(exist_ok=True, parents=True)
                output_file = output_dir / filename
                
                with open(output_file, 'wb') as f:
                    f.write(decrypted_data)
                
                logger.info(f"File {filename} downloaded to {output_file}")
                print(f"File {filename} downloaded to {output_file}")

            except ValueError as e:
                logger.error(f"Access denied: {e}")
                print(f"Access denied: {e}")

        except Exception as e:
            logger.exception(f"Error downloading file: {e}")
            print(f"Error downloading file: {e}")

    def list_files(self):
        """List all accessible files"""
        if not self.current_user:
            logger.warning("List files failed: No user logged in")
            print("Please login first")
            return

        logger.info("Listing accessible files")
        files = self.file_storage.list_files()
        
        if not files:
            print("\nNo files found")
            return
            
        print("\nAccessible files:")
        accessible_count = 0
        
        for filename, metadata in files.items():
            if self.encryption_service.can_decrypt(self.current_user, filename):
                storage_location = "cloud" if self.using_cloud else "local"
                print(f"- {filename} (Owner: {metadata.owner}, Created: {metadata.created_at}, Storage: {storage_location})")
                accessible_count += 1
                
        if accessible_count == 0:
            print("No files accessible with your current permissions")

    def delete_file(self, filename: str):
        """Delete a file"""
        if not self.current_user:
            logger.warning("Delete failed: No user logged in")
            print("Please login first")
            return

        logger.info(f"Attempting to delete file: {filename}")
        result = self.file_storage.get_file(filename)
        if not result:
            logger.warning(f"File {filename} not found")
            print(f"File {filename} not found")
            return

        _, metadata = result
        if metadata.owner != self.current_user:
            logger.warning(f"Delete failed: User {self.current_user} does not own file {filename}")
            print("You can only delete your own files")
            return

        if self.file_storage.delete_file(filename):
            storage_type = "cloud storage" if self.using_cloud else "local storage"
            logger.info(f"File {filename} deleted successfully from {storage_type}")
            print(f"File {filename} deleted successfully from {storage_type}")
        else:
            logger.error(f"Failed to delete file {filename}")
            print(f"Failed to delete file {filename}")

def main():
    cli = CLI()
    cli.setup_users()

    parser = argparse.ArgumentParser(description="Secure File Storage CLI")
    parser.add_argument('--login', help='Login as user')
    parser.add_argument('--upload', help='Upload and encrypt a file')
    parser.add_argument('--download', help='Download and decrypt a file')
    parser.add_argument('--output', help='Output directory for downloaded files')
    parser.add_argument('--list', action='store_true', help='List accessible files')
    parser.add_argument('--delete', help='Delete a file')
    parser.add_argument('--status', action='store_true', help='Show storage configuration status')

    args = parser.parse_args()

    if args.status:
        cli.show_storage_status()
    elif args.login:
        cli.login(args.login)
    elif args.upload:
        cli.upload_file(args.upload)
    elif args.download:
        if not args.output:
            print("Please specify output directory with --output")
        else:
            cli.download_file(args.download, args.output)
    elif args.list:
        cli.list_files()
    elif args.delete:
        cli.delete_file(args.delete)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
