# Import necessary libraries
import os
import pyotp
import qrcode
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes

# -------------------------------------------
# 1. RSA Key Generation
# -------------------------------------------

# Generate an RSA private key
private_key = rsa.generate_private_key(
    public_exponent=65537,  # Commonly used public exponent
    key_size=2048,          # Key size in bits
    backend=default_backend()
)

# Derive the public key from the private key
public_key = private_key.public_key()

# Serialize the private key to PEM format without encryption
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,  # PEM format
    format=serialization.PrivateFormat.TraditionalOpenSSL,  # Traditional OpenSSL format
    encryption_algorithm=serialization.NoEncryption(),        # No encryption
)

# Serialize the public key to PEM format
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,  # PEM format
    format=serialization.PublicFormat.SubjectPublicKeyInfo,  # Subject Public Key Info format
)

# Print the serialized private and public keys
print(f"Private Key:\n{private_pem.decode()}")
print(f"Public Key:\n{public_pem.decode()}")

# -------------------------------------------
# 2. OTP Generation
# -------------------------------------------

# Generate a random 10-byte secret, encode it in base32, and create a TOTP object
otp_secret = base64.b32encode(os.urandom(10)).decode("utf-8")
totp = pyotp.TOTP(otp_secret)

# Generate the current OTP
otp = totp.now()
print(f"Generated OTP: {otp}")

# -------------------------------------------
# 3. Encryption of OTP
# -------------------------------------------

# Generate a random 32-byte shared secret for AES encryption
shared_secret = os.urandom(32)

# Generate a random 16-byte Initialization Vector (IV) for AES
iv = os.urandom(16)

# Create an AES cipher object in CFB mode with the shared secret and IV
cipher = Cipher(
    algorithms.AES(shared_secret),
    modes.CFB(iv),
    backend=default_backend()
)

# Create an encryptor object from the cipher
encryptor = cipher.encryptor()

# Encrypt the OTP by updating the encryptor with the OTP bytes and finalizing
encrypted_otp = encryptor.update(otp.encode()) + encryptor.finalize()

# Concatenate IV and encrypted OTP, then encode them in base64 for safe storage/transmission
encrypted_data = base64.b64encode(iv + encrypted_otp).decode("utf-8")
# Uncomment the following line to print the encrypted data
# print(f"Encrypted OTP: {encrypted_data}")

# -------------------------------------------
# 4. QR Code Generation
# -------------------------------------------

# Initialize a QRCode object with specific parameters
qr = qrcode.QRCode(
    version=1,  # Controls the size of the QR Code; 1 is the smallest
    error_correction=qrcode.constants.ERROR_CORRECT_L,  # Error correction level
    box_size=10,  # Size of each box in pixels
    border=4,     # Thickness of the border (default is 4)
)

# Add the encrypted data to the QR code
qr.add_data(encrypted_data)

# Compile the QR code data into a QR Code array
qr.make(fit=True)

# Create an image from the QR Code
img = qr.make_image(fill="black", back_color="white")

# Save the QR Code image to a file
img.save("qrcode.png")
print("QR code saved as 'qrcode.png'.")

# -------------------------------------------
# 5. Decryption of OTP
# -------------------------------------------

# Decode the base64 encrypted data back to bytes
encrypted_data_bytes = base64.b64decode(encrypted_data)

# Extract the IV (first 16 bytes) and the encrypted OTP (remaining bytes)
iv = encrypted_data_bytes[:16]
encrypted_otp = encrypted_data_bytes[16:]

# Recreate the AES cipher object for decryption using the same shared secret and extracted IV
cipher = Cipher(
    algorithms.AES(shared_secret),
    modes.CFB(iv),
    backend=default_backend()
)

# Create a decryptor object from the cipher
decryptor = cipher.decryptor()

# Decrypt the OTP by updating the decryptor with the encrypted OTP bytes and finalizing
decrypted_otp = decryptor.update(encrypted_otp) + decryptor.finalize()

# Print the decrypted OTP
print(f"Decrypted OTP: {decrypted_otp.decode()}")

# -------------------------------------------
# 6. Signing the Decrypted OTP
# -------------------------------------------

# Sign the decrypted OTP using the RSA private key with PSS padding and SHA256 hashing
signature = private_key.sign(
    decrypted_otp,  # Data to be signed (bytes)
    asym_padding.PSS(
        mgf=asym_padding.MGF1(hashes.SHA256()),  # Mask Generation Function
        salt_length=asym_padding.PSS.MAX_LENGTH   # Maximum salt length
    ),
    hashes.SHA256(),  # Hash algorithm
)

# Encode the signature in base64 for safe storage/transmission and print it
print(f"Signature: {base64.b64encode(signature).decode()}")

# -------------------------------------------
# 7. Verifying the Signature
# -------------------------------------------

try:
    # Verify the signature using the RSA public key
    public_key.verify(
        signature,  # The signature to verify
        decrypted_otp,  # The original data that was signed
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),  # Mask Generation Function
            salt_length=asym_padding.PSS.MAX_LENGTH   # Salt length
        ),
        hashes.SHA256(),  # Hash algorithm
    )
    print("Signature verified successfully!")
except Exception as e:
    # If verification fails, print the error
    print(f"Signature verification failed: {e}")