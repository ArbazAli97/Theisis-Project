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

private_key = rsa.generate_private_key(
    public_exponent=65537, key_size=2048, backend=default_backend()
)
public_key = private_key.public_key()

private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption(),
)
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)
print(f"Private Key:{private_pem.decode()}")
print(f"Public Key:{public_pem.decode()}")


otp = pyotp.TOTP(base64.b32encode(os.urandom(10)).decode("utf-8")).now()
print(f"Generated OTP: {otp}")


shared_secret = os.urandom(32)
iv = os.urandom(16)
cipher = Cipher(algorithms.AES(shared_secret), modes.CFB(iv), backend=default_backend())
encryptor = cipher.encryptor()

encrypted_otp = encryptor.update(otp.encode()) + encryptor.finalize()

encrypted_data = base64.b64encode(iv + encrypted_otp).decode("utf-8")
# print("Encrypted OTP: {encrypted_data}")

qr = qrcode.QRCode(
    version=1,
    error_correction=qrcode.constants.ERROR_CORRECT_L,
    box_size=10,
    border=4,
)
qr.add_data(encrypted_data)
qr.make(fit=True)

img = qr.make_image(fill="black", back_color="white")
img.save("qrcode.png")


encrypted_data_bytes = base64.b64decode(encrypted_data)
iv = encrypted_data_bytes[:16]
encrypted_otp = encrypted_data_bytes[16:]

cipher = Cipher(algorithms.AES(shared_secret), modes.CFB(iv), backend=default_backend())
decryptor = cipher.decryptor()


decrypted_otp = decryptor.update(encrypted_otp) + decryptor.finalize()
print(f"Decrypted OTP: {decrypted_otp.decode()}")


signature = private_key.sign(
    decrypted_otp,
    asym_padding.PSS(
        mgf=asym_padding.MGF1(hashes.SHA256()), salt_length=asym_padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256(),
)
print(f"Signature: {base64.b64encode(signature).decode()}")


try:
    public_key.verify(
        signature,
        decrypted_otp,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    print("Signature verified successfully!")
except Exception as e:
    print(f"Signature verification failed: {e}")
