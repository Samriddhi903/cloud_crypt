import bcrypt

password = 'boss123'
hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(12))
print(f"Password: {password}")
print(f"Generated hash: {hashed.decode('utf-8')}")

# Verify the hash
stored_hash = '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY.0DQJbG7.gsYe'
print(f"\nVerifying against stored hash: {stored_hash}")
print(f"Verification result: {bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))}")