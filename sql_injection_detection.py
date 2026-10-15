import sqlite3
import re

# Create database
connection = sqlite3.connect("security.db")
cursor = connection.cursor()

# Create users table
cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    password TEXT NOT NULL
)
""")

# Insert sample users only once
cursor.execute("SELECT COUNT(*) FROM users")
if cursor.fetchone()[0] == 0:
    cursor.executemany(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        [
            ("rahul", "rahul123"),
            ("amit", "amit123")
        ]
    )
    connection.commit()


def detect_suspicious_input(value):
    patterns = [
        r"'\s*OR\s+'?\w+'?\s*=\s*'?\w+",
        r"\bUNION\s+SELECT\b",
        r";\s*DROP\s+TABLE\b",
        r"--"
    ]

    for pattern in patterns:
        if re.search(pattern, value, re.IGNORECASE):
            return True

    return False


def login(username, password):
    print("\nChecking input for suspicious patterns...")

    if detect_suspicious_input(username) or detect_suspicious_input(password):
        print("Warning: Possible SQL Injection detected!")
        print("Login rejected for security.")
        return

    # Parameterized query helps prevent SQL injection
    cursor.execute(
        "SELECT username FROM users WHERE username = ? AND password = ?",
        (username, password)
    )

    result = cursor.fetchone()

    if result:
        print("Login successful. Welcome,", result[0])
    else:
        print("Invalid username or password.")


print("=== SQL Injection Detection System ===")
print("Sample users: rahul / rahul123 or amit / amit123")

while True:
    username = input("\nEnter username (or type exit): ")

    if username.lower() == "exit":
        break

    password = input("Enter password: ")
    login(username, password)

connection.close()
print("\nSystem completed successfully.")