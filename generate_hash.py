import bcrypt

# For manager1
password = 'manager123'
hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(12))
with open('credentials.txt', 'w') as f:
    f.write(f"manager1:{hashed.decode('utf-8')}\n")

# For boss
password = 'boss123'
hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(12))
with open('credentials.txt', 'a') as f:
    f.write(f"boss:{hashed.decode('utf-8')}\n")

# For user1
password = 'user123'
hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(12))
with open('credentials.txt', 'a') as f:
    f.write(f"user1:{hashed.decode('utf-8')}\n")

print("Default credentials generated in credentials.txt")