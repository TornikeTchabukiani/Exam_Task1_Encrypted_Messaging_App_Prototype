# MINI ENCRYPTED MESSAGING SYSTEM DOCUMENTATION

## OVERVIEW

This system implements hybrid encryption combining RSA (asymmetric) and AES (symmetric) encryption to securely transmit messages between two users. This approach leverages the security of RSA for key exchange and the efficiency of AES for message encryption.

---

## ARCHITECTURE

User A generates an RSA keypair and shares the public key with User B. User B then generates a random AES-256 key, encrypts the message with AES, and encrypts the AES key with User A's RSA public key. User A receives the encrypted AES key and message, decrypts the AES key using their RSA private key, and finally decrypts the message using the recovered AES key.

---

## ENCRYPTION FLOW

### PHASE 1: USER A SETUP

Action: User A generates an RSA-2048 key pair

- Private Key: Kept secret by User A (2048 bits)
- Public Key: Shared with User B (2048 bits)
- Algorithm: RSA with public exponent 65537

Purpose: The RSA key pair enables asymmetric encryption where anyone with the public key can encrypt data, but only User A with the private key can decrypt it.

### PHASE 2: USER B ENCRYPTION

#### Step 2.1: Generate AES Key

Action: User B generates a random AES-256 key

- Key Size: 256 bits (32 bytes)
- IV (Initialization Vector): 128 bits (16 bytes)
- Mode: CBC (Cipher Block Chaining)

Purpose: AES encryption is much faster than RSA and suitable for encrypting large messages. The random key ensures each message is encrypted with a unique key.

#### Step 2.2: Encrypt Message with AES

Process:
1. Convert message to bytes using UTF-8 encoding
2. Apply PKCS7 padding to make message length a multiple of 16 bytes
3. Encrypt using AES-256-CBC with the generated key and IV
4. Save IV plus encrypted message to encrypted_message.bin

Algorithm Details:
- Cipher: AES-256
- Mode: CBC (provides semantic security)
- Padding: PKCS7 (ensures proper block alignment)

#### Step 2.3: Encrypt AES Key with RSA

Process:
1. Take the 256-bit AES key
2. Encrypt it using User A's RSA public key
3. Use OAEP padding with SHA-256
4. Save encrypted AES key to aes_key_encrypted.bin

Algorithm Details:
- Padding: OAEP (Optimal Asymmetric Encryption Padding)
- Hash: SHA-256
- MGF: MGF1 with SHA-256

Purpose: This securely transmits the AES key to User A. Only User A can decrypt this with their private key.

### PHASE 3: USER A DECRYPTION

#### Step 3.1: Decrypt AES Key

Process:
1. Read aes_key_encrypted.bin
2. Decrypt using RSA private key with OAEP padding
3. Recover the original 256-bit AES key

Security: Only User A's private key can decrypt this, ensuring the AES key remains confidential.

#### Step 3.2: Decrypt Message

Process:
1. Read encrypted_message.bin
2. Extract IV (first 16 bytes)
3. Extract encrypted message (remaining bytes)
4. Decrypt using AES-256-CBC with the recovered key and IV
5. Remove PKCS7 padding
6. Convert bytes back to text using UTF-8
7. Save to decrypted_message.txt

---

## SECURITY FEATURES

### 1. Hybrid Encryption Benefits

- Key Exchange Security: RSA ensures secure transmission of the AES key
- Message Encryption Efficiency: AES provides fast encryption and decryption
- Perfect Forward Secrecy (per session): Each message uses a unique AES key

### 2. Algorithm Strengths

Asymmetric Encryption:
- Component: RSA-2048
- Security Level: 112-bit equivalent

Symmetric Encryption:
- Component: AES-256
- Security Level: 256-bit

RSA Padding:
- Component: OAEP with SHA-256
- Protection: Prevents padding oracle attacks

AES Padding:
- Component: PKCS7
- Purpose: Standard block padding

Encryption Mode:
- Component: CBC (Cipher Block Chaining)
- Security: Provides semantic security

### 3. Randomness

- AES Key: Cryptographically secure random (32 bytes)
- Initialization Vector: Cryptographically secure random (16 bytes)
- Purpose: Prevents pattern analysis and replay attacks

---

## FILE STRUCTURE

The system generates four files:

1. message.txt - Original plaintext message
2. encrypted_message.bin - Contains IV (first 16 bytes) followed by AES-encrypted message
3. aes_key_encrypted.bin - Contains RSA-encrypted AES key
4. decrypted_message.txt - Final decrypted message (should match original)

---

## USAGE INSTRUCTIONS

### Installation

Install the required Python library:
pip install cryptography

### Running the System

Execute the main script:
python encrypted_messaging.py

### Expected Output

The script will perform the following operations:
1. Create message.txt with a sample message
2. Generate all encrypted files
3. Decrypt and verify the message
4. Display the complete workflow with status messages

---

## ATTACK RESISTANCE

### What This System Protects Against

1. Eavesdropping: Encrypted data is unreadable without the private key
2. Man-in-the-Middle (partial): RSA encryption prevents key interception
3. Replay Attacks: Random AES key and IV prevent message reuse
4. Padding Oracle Attacks: OAEP padding prevents RSA padding attacks

### Limitations

1. No Authentication: System does not verify sender identity
2. No Integrity Check: No HMAC or signature to detect tampering
3. No Key Verification: Public key authenticity is not verified
4. Single Use: Each encryption requires new key exchange

### Production Enhancements

For real-world use, consider adding:
- Digital Signatures: Verify message authenticity
- Key Fingerprinting: Verify public key authenticity
- GCM Mode: Use AES-GCM for authenticated encryption
- Key Management: Implement secure key storage and rotation
- Certificate Authority: Verify public key ownership

---

## MATHEMATICAL FOUNDATION

### RSA Encryption and Decryption

RSA encryption works by raising the message to the power of the public exponent modulo the modulus. The formula is: ciphertext equals message raised to the power of e, modulo n, where e is the public exponent and n is the modulus.

RSA decryption works by raising the ciphertext to the power of the private exponent modulo the modulus. The formula is: message equals ciphertext raised to the power of d, modulo n, where d is the private exponent.

### AES Operation

AES encryption takes three inputs: a key K, an initialization vector IV, and plaintext P. It produces ciphertext C through the encryption function E.

AES decryption takes the same key K and initialization vector IV, along with ciphertext C, and produces the original plaintext P through the decryption function D.


## DETAILED WORKFLOW

### Step-by-Step Process

Step 1: User A generates an RSA keypair consisting of a public key and a private key. The private key is kept secret while the public key is shared with User B.

Step 2: User B receives User A's public key and prepares to send a secure message.

Step 3: User B generates a random AES-256 key (32 bytes) and a random initialization vector (16 bytes).

Step 4: User B encrypts their message using AES-256 in CBC mode with the generated key and IV. The message is first padded using PKCS7 to ensure it is a multiple of the block size.

Step 5: User B encrypts the AES key using User A's RSA public key with OAEP padding. This encrypted key can only be decrypted by User A's private key.

Step 6: User B sends two files to User A: the encrypted message (with IV prepended) and the encrypted AES key.

Step 7: User A receives both files and begins the decryption process.

Step 8: User A decrypts the AES key using their RSA private key with OAEP padding.

Step 9: User A extracts the IV from the encrypted message file (first 16 bytes).

Step 10: User A decrypts the message using AES-256 in CBC mode with the recovered key and IV.

Step 11: User A removes the PKCS7 padding and converts the decrypted bytes back to text.

Step 12: The original message is successfully recovered and saved to decrypted_message.txt.


## CRYPTOGRAPHIC SPECIFICATIONS

### RSA Key Generation

- Key Size: 2048 bits
- Public Exponent: 65537 (standard value)
- Format: PEM encoding
- Private Key Protection: Should be encrypted at rest in production

### AES Encryption

- Algorithm: Advanced Encryption Standard
- Key Size: 256 bits (maximum security)
- Block Size: 128 bits
- Mode: CBC (Cipher Block Chaining)
- Padding Scheme: PKCS7

### RSA Encryption

- Padding Scheme: OAEP (Optimal Asymmetric Encryption Padding)
- Hash Function: SHA-256
- Mask Generation Function: MGF1 with SHA-256
- Label: None (optional parameter not used)

### Key Management

- AES Key Generation: Cryptographically secure random number generator
- IV Generation: Cryptographically secure random number generator
- Key Storage: Keys should never be stored in plain text
- Key Transmission: Only encrypted keys should be transmitted


## SECURITY CONSIDERATIONS

### Threat Model

This system assumes:
- The adversary can intercept all communications
- The adversary cannot break AES-256 or RSA-2048
- The adversary does not have access to User A's private key
- The adversary cannot tamper with messages (integrity not guaranteed)

### Key Security

RSA Private Key:
- Must be kept absolutely secret
- Should be stored encrypted when not in use
- Should never be transmitted over networks
- Compromise of private key compromises all past and future messages

AES Session Key:
- Generated fresh for each message
- Never reused between messages
- Destroyed after message decryption
- Only transmitted in encrypted form

### Implementation Security

The implementation uses well-established cryptographic libraries:
- Python cryptography library
- Standard cryptographic algorithms
- Proper padding schemes
- Secure random number generation


## COMPARISON WITH OTHER SYSTEMS

### Similar Systems

This hybrid encryption approach is used in:
- TLS/SSL: Secures web communications
- PGP/GPG: Email encryption
- SSH: Secure shell connections
- Signal Protocol: Messaging apps

### Advantages of Hybrid Encryption

Performance: Symmetric encryption (AES) is much faster than asymmetric encryption (RSA) for large data.

Security: Asymmetric encryption (RSA) provides secure key exchange without requiring a pre-shared secret.

Scalability: Each recipient only needs to know the sender's public key.

### Why Not Use Only RSA

RSA is computationally expensive and has message size limitations. RSA-2048 can only encrypt messages up to 245 bytes with OAEP padding. Messages longer than this would need to be broken into chunks, which is inefficient.

### Why Not Use Only AES

AES requires both parties to share a secret key. Without a secure channel, sharing this key is problematic. RSA solves the key distribution problem.


## CONCLUSION

This hybrid encryption system demonstrates how modern cryptography combines different algorithms to achieve both security and efficiency. RSA handles the key exchange securely, while AES handles message encryption efficiently. This is the same fundamental approach used in TLS/SSL, PGP, and many other secure communication protocols.

The system provides confidentiality through strong encryption algorithms, but does not provide authentication or integrity guarantees. For production use, additional security measures such as digital signatures and message authentication codes should be implemented.

