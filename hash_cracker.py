import argparse
import hashlib
import os
import logging
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes


# Set up logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


# Save result to a specified file
def save_result_to_file(filename, content):
    """Save the result to a specified file."""
    try:
        with open(filename, "w") as file:
            file.write(content)
        print(f"Result saved to {filename}")
    except Exception as e:
        logging.error(f"Failed to save result to {filename}: {e}")


# Generate a key from the password using PBKDF2
def generate_key(password, salt, iterations=100000):
    """Generates a PBKDF2 key using a password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),   # Using SHA256 as the hash function
        length=32,                    # Length of the key (256 bits)
        salt=salt,                    # Salt value (should be random for each session)
        iterations=iterations,        # Number of iterations to slow down the key derivation
        backend=default_backend()     # Using the default cryptographic backend
    )
    key = kdf.derive(password.encode())  # Derives the key from the password and salt
    return key


# AES encryption function
def encrypt_key(plain_text, password):
    """Encrypt the plain text using AES and the provided password."""
    # Generate a random salt and IV
    salt = os.urandom(16)
    iv = os.urandom(16)

    # Generate AES key from password
    key = generate_key(password, salt)

    # Pad the plain text to make its length a multiple of 16 bytes
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plain_text.encode()) + padder.finalize()

    # Encrypt using AES (CBC mode)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Return the encrypted data as base64, including salt and IV
    encrypted_result = salt + iv + encrypted_data
    return base64.b64encode(encrypted_result).decode()


# AES decryption function
def decrypt_key(encrypted_data, password):
    """Decrypt the AES-encrypted data using the provided password."""
    # Convert base64 to bytes
    encrypted_data_bytes = base64.b64decode(encrypted_data)

    # Extract salt and IV from the encrypted data
    salt = encrypted_data_bytes[:16]
    iv = encrypted_data_bytes[16:32]
    encrypted_key = encrypted_data_bytes[32:]

    # Generate AES key from password and salt
    key = generate_key(password, salt)

    # Decrypt using AES (CBC mode)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_key) + decryptor.finalize()

    # Unpad the decrypted data
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

    # Return the decrypted plain text
    return unpadded_data.decode()


# Hash a password using SHA256 (example)
def hash_password(password):
    """Hashes the password using SHA256."""
    hashed = hashlib.sha256(password.encode()).hexdigest()
    return hashed


# Interactive function for handling tasks
def interactive_menu():
    while True:
        print("\nChoose an option:")
        print("1. Encrypt a message")
        print("2. Decrypt a message")
        print("3. Hash a password")
        print("4. Generate a Key")
        print("5. Return to main menu")
        choice = input("\nEnter your choice (1-5): ").strip()

        if choice == "1":
            # Encrypt option
            password = input("Enter the password to use: ").strip()
            plain_text = input("Enter the message to encrypt: ").strip()
            encrypted_message = encrypt_key(plain_text, password)
            print(f"Encrypted message: {encrypted_message}")

            # Ask the user if they want to save the result
            while True:
                save_file = input("Would you like to save the result to a file? (y/n): ").strip().lower()
                if save_file == 'y':
                    filename = input("Enter the filename: ").strip()
                    save_result_to_file(filename, encrypted_message)
                    break
                elif save_file == 'n':
                    print("Result not saved.")
                    break
                else:
                    print("Invalid choice, choose 'y' for yes or 'n' for no.")

        elif choice == "2":
            # Decrypt option
            password = input("Enter the password for decryption: ").strip()
            encrypted_message = input("Enter the encrypted message: ").strip()
            decrypted_message = decrypt_key(encrypted_message, password)
            print(f"Decrypted message: {decrypted_message}")

        elif choice == "3":
            # Hash option
            password = input("Enter the password to hash: ").strip()
            hashed_password = hash_password(password)
            print(f"Hashed password (SHA256): {hashed_password}")

        elif choice == "4":
            # Generate Key option
            password = input("Enter the password to generate a key: ").strip()
            salt = os.urandom(16)  # Random salt for each key generation
            key = generate_key(password, salt)
            print(f"Generated key (hex): {base64.b64encode(key).decode()}")

        elif choice == "5":
            print("Returning to main menu...")
            break  # This will exit the loop and return to the main menu

        else:
            print("Invalid choice. Please choose a valid option.")

# Main function
def main():
    # Setup the argument parser
    parser = argparse.ArgumentParser(description="Encryption, Decryption, and Hashing Tool")

    # Define the arguments
    parser.add_argument("-e", "--encrypt", help="Encrypt a plaintext message", type=str)
    parser.add_argument("-d", "--decrypt", help="Decrypt an encrypted message", type=str)
    parser.add_argument("-p", "--password", help="Password to use for encryption/decryption", type=str)
    parser.add_argument("-H", "--hash", help="Hash a password (SHA256)", type=str)
    parser.add_argument("--generate-key", help="Generate a key from a password", action="store_true")

    # Parse the arguments
    args = parser.parse_args()

    # If no argument is passed, ask the user for input interactively
    if not any(vars(args).values()):
        interactive_menu()  # Enter interactive menu for user input
    else:
        # If --generate-key argument is provided, generate the key
        if args.generate_key:
            if not args.password:
                # If password isn't provided via argument, ask interactively
                password = input("Enter the password to generate a key: ").strip()
            salt = os.urandom(16)  # Random salt for each key generation
            key = generate_key(password, salt)
            print(f"Generated key (base64): {base64.b64encode(key).decode()}")

        # Encrypt a message
        elif args.encrypt:
            if not args.password:
                # If password isn't provided via argument, ask interactively
                password = input("Enter the password for encryption: ").strip()
            encrypted_message = encrypt_key(args.encrypt, password)
            print(f"Encrypted message: {encrypted_message}")

        # Decrypt a message
        elif args.decrypt:
            if not args.password:
                # If password isn't provided via argument, ask interactively
                password = input("Enter the password for decryption: ").strip()
            decrypted_message = decrypt_key(args.decrypt, password)
            print(f"Decrypted message: {decrypted_message}")

        # Hash a password
        elif args.hash:
            hashed_password = hash_password(args.hash)
            print(f"Hashed password (SHA256): {hashed_password}")

        else:
            print("Please specify an action to perform (encryption, decryption, or hashing).")
            return


if __name__ == "__main__":
    main()
