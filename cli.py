import argparse
import datetime
from pathlib import Path
from encryption_service import EncryptionService, UserRole
from file_storage import FileStorage, FileMetadata

class CLI:
    def __init__(self):
        self.encryption_service = EncryptionService()
        self.file_storage = FileStorage()
        self.current_user = None

    def setup_users(self):
        """Setup initial users for testing"""
        self.encryption_service.add_user("boss", UserRole.BOSS)
        self.encryption_service.add_user("manager1", UserRole.MANAGER, "boss")
        self.encryption_service.add_user("user1", UserRole.USER, "manager1")

    def login(self, username: str) -> bool:
        """Login as a user"""
        if username in self.encryption_service.users:
            self.current_user = username
            print(f"Logged in as {username}")
            return True
        print(f"User {username} does not exist")
        return False

    def upload_file(self, filepath: str):
        """Upload and encrypt a file"""
        if not self.current_user:
            print("Please login first")
            return

        try:
            file_path = Path(filepath)
            if not file_path.exists():
                print(f"File {filepath} does not exist")
                return

            with open(file_path, 'rb') as f:
                data = f.read()

            filename = file_path.name
            encrypted_data = self.encryption_service.encrypt_file(filename, data, self.current_user)

            if filename not in self.encryption_service.file_keys:
                print(f"Failed to retrieve encrypted key for {filename}")
                return

            encrypted_key = self.encryption_service.file_keys[filename]
            metadata = FileMetadata(
                filename=filename,
                owner=self.current_user,
                encrypted_key=encrypted_key,
                created_at=datetime.datetime.now().isoformat()
            )

            if self.file_storage.save_file(filename, encrypted_data, metadata):
                print(f"File {filename} uploaded successfully")
            else:
                print(f"Failed to upload file {filename}")

        except Exception as e:
            print(f"Error uploading file: {e}")

    def download_file(self, filename: str, output_path: str):
        """Download and decrypt a file"""
        if not self.current_user:
            print("Please login first")
            return

        try:
            result = self.file_storage.get_file(filename)
            if not result:
                print(f"File {filename} not found")
                return

            encrypted_data, metadata = result

            try:
                decrypted_data = self.encryption_service.decrypt_file(
                    filename, encrypted_data, self.current_user
                )

                output_file = Path(output_path) / filename
                with open(output_file, 'wb') as f:
                    f.write(decrypted_data)
                print(f"File {filename} downloaded to {output_file}")

            except ValueError as e:
                print(f"Access denied: {e}")

        except Exception as e:
            print(f"Error downloading file: {e}")

    def list_files(self):
        """List all accessible files"""
        if not self.current_user:
            print("Please login first")
            return

        files = self.file_storage.list_files()
        print("\nAccessible files:")
        for filename, metadata in files.items():
            if self.encryption_service.can_decrypt(self.current_user, filename):
                print(f"- {filename} (Owner: {metadata.owner}, Created: {metadata.created_at})")

    def delete_file(self, filename: str):
        """Delete a file"""
        if not self.current_user:
            print("Please login first")
            return

        result = self.file_storage.get_file(filename)
        if not result:
            print(f"File {filename} not found")
            return

        _, metadata = result
        if metadata.owner != self.current_user:
            print("You can only delete your own files")
            return

        if self.file_storage.delete_file(filename):
            print(f"File {filename} deleted successfully")
        else:
            print(f"Failed to delete file {filename}")

def main():
    cli = CLI()
    cli.setup_users()

    parser = argparse.ArgumentParser(description="Secure File Storage CLI")
    # parser.add_argument('--login', help='Login as user')
    # parser.add_argument('--upload', help='Upload and encrypt a file')
    # parser.add_argument('--download', help='Download and decrypt a file')
    # parser.add_argument('--output', help='Output directory for downloaded files')
    # parser.add_argument('--list', action='store_true', help='List accessible files')
    # parser.add_argument('--delete', help='Delete a file')

    args = parser.parse_args()

    if args.login:
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
