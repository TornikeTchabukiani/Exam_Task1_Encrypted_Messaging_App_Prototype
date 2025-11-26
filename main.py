"""
Mini Encrypted Messaging System
Implements hybrid encryption using RSA and AES-256
"""

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os


class UserA:
    """User A: Generates RSA key pair and decrypts messages"""

    def __init__(self):
        self.private_key = None
        self.public_key = None

    def generate_rsa_keypair(self):
        """Generate RSA-2048 key pair"""
        print("[User A] Generating RSA key pair...")
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        print("[User A] RSA key pair generated successfully!")

    def get_public_key(self):
        """Export public key in PEM format for sharing"""
        pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem

    def decrypt_aes_key(self, encrypted_aes_key):
        """Decrypt AES key using RSA private key"""
        print("[User A] Decrypting AES key with RSA private key...")
        aes_key = self.private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print("[User A] AES key decrypted successfully!")
        return aes_key

    def decrypt_message(self, encrypted_message, aes_key, iv):
        """Decrypt message using AES key"""
        print("[User A] Decrypting message with AES key...")
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded_message = decryptor.update(encrypted_message) + decryptor.finalize()

        # Remove PKCS7 padding
        padding_length = padded_message[-1]
        message = padded_message[:-padding_length]

        print("[User A] Message decrypted successfully!")
        return message.decode('utf-8')


class UserB:
    """User B: Encrypts messages using AES and RSA"""

    def __init__(self, public_key_pem):
        self.public_key = serialization.load_pem_public_key(
            public_key_pem,
            backend=default_backend()
        )
        self.aes_key = None
        self.iv = None

    def generate_aes_key(self):
        """Generate random AES-256 key"""
        print("[User B] Generating random AES-256 key...")
        self.aes_key = os.urandom(32)  # 256 bits
        self.iv = os.urandom(16)  # 128 bits for CBC mode
        print("[User B] AES key generated successfully!")

    def encrypt_message(self, message):
        """Encrypt message using AES-256-CBC"""
        print("[User B] Encrypting message with AES-256...")

        # Add PKCS7 padding
        message_bytes = message.encode('utf-8')
        padding_length = 16 - (len(message_bytes) % 16)
        padded_message = message_bytes + bytes([padding_length] * padding_length)

        cipher = Cipher(
            algorithms.AES(self.aes_key),
            modes.CBC(self.iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        encrypted_message = encryptor.update(padded_message) + encryptor.finalize()

        print("[User B] Message encrypted successfully!")
        return encrypted_message

    def encrypt_aes_key(self):
        """Encrypt AES key using RSA public key"""
        print("[User B] Encrypting AES key with RSA public key...")
        encrypted_aes_key = self.public_key.encrypt(
            self.aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print("[User B] AES key encrypted successfully!")
        return encrypted_aes_key


def main():
    """Main encryption/decryption workflow"""

    print("=" * 60)
    print("MINI ENCRYPTED MESSAGING SYSTEM")
    print("=" * 60)
    print()

    # Step 1: User A generates RSA key pair
    print("STEP 1: User A Setup")
    print("-" * 60)
    user_a = UserA()
    user_a.generate_rsa_keypair()
    public_key_pem = user_a.get_public_key()
    print()

    # Step 2: User B receives public key and encrypts message
    print("STEP 2: User B Encryption")
    print("-" * 60)

    # Read original message
    with open('message.txt', 'r') as f:
        original_message = f.read()
    print(f"[User B] Original message: '{original_message}'")

    user_b = UserB(public_key_pem)
    user_b.generate_aes_key()

    # Encrypt message with AES
    encrypted_message = user_b.encrypt_message(original_message)

    # Encrypt AES key with RSA
    encrypted_aes_key = user_b.encrypt_aes_key()

    # Save encrypted data
    with open('encrypted_message.bin', 'wb') as f:
        f.write(user_b.iv + encrypted_message)  # Store IV with encrypted message

    with open('aes_key_encrypted.bin', 'wb') as f:
        f.write(encrypted_aes_key)

    print("[User B] Encrypted files saved!")
    print()

    # Step 3: User A decrypts message
    print("STEP 3: User A Decryption")
    print("-" * 60)

    # Read encrypted data
    with open('aes_key_encrypted.bin', 'rb') as f:
        encrypted_aes_key = f.read()

    with open('encrypted_message.bin', 'rb') as f:
        data = f.read()
        iv = data[:16]
        encrypted_message = data[16:]

    # Decrypt AES key
    aes_key = user_a.decrypt_aes_key(encrypted_aes_key)

    # Decrypt message
    decrypted_message = user_a.decrypt_message(encrypted_message, aes_key, iv)

    # Save decrypted message
    with open('decrypted_message.txt', 'w') as f:
        f.write(decrypted_message)

    print(f"[User A] Decrypted message: '{decrypted_message}'")
    print()

    # Verification
    print("VERIFICATION")
    print("-" * 60)
    print(f"Original:  '{original_message}'")
    print(f"Decrypted: '{decrypted_message}'")
    print(f"Match: {original_message == decrypted_message}")
    print()
    print("=" * 60)
    print("ENCRYPTION/DECRYPTION COMPLETE!")
    print("=" * 60)


if __name__ == "__main__":
    # Create sample message file
    with open('message.txt', 'w') as f:
        f.write("This is a secret message from User B to User A!")

    main()