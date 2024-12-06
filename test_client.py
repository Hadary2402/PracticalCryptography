import unittest
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad
import hashlib
from client import aes_encrypt, aes_decrypt, rsa_encrypt, rsa_decrypt, hash_password, generate_session_key


class TestClientFunctions(unittest.TestCase):
    def setUp(self):
        """Set up test data."""
        self.test_message = "Hello, this is a test message!"
        self.session_key = generate_session_key()

        # Generate RSA keys for testing
        self.rsa_key = RSA.generate(2048)
        self.public_key = self.rsa_key.publickey()
        self.rsa_cipher = PKCS1_OAEP.new(self.public_key)
        self.rsa_decipher = PKCS1_OAEP.new(self.rsa_key)

    def test_aes_encryption_decryption(self):
        """Test AES encryption and decryption."""
        encrypted = aes_encrypt(self.test_message.encode(), self.session_key)
        decrypted = aes_decrypt(encrypted, self.session_key).decode()

        self.assertEqual(self.test_message, decrypted, "AES encryption/decryption failed.")

    def test_rsa_encryption_decryption(self):
        """Test RSA encryption and decryption."""
        encrypted = self.rsa_cipher.encrypt(self.test_message.encode())
        decrypted = self.rsa_decipher.decrypt(encrypted).decode()

        self.assertEqual(self.test_message, decrypted, "RSA encryption/decryption failed.")

    def test_hash_password(self):
        """Test password hashing."""
        password = "securepassword123"
        hashed = hash_password(password)
        hashed_again = hash_password(password)

        self.assertEqual(hashed, hashed_again, "Password hashing should be deterministic.")
        self.assertNotEqual(password, hashed, "Hashed password should not equal the original password.")

    def test_generate_session_key(self):
        """Test session key generation."""
        key1 = generate_session_key()
        key2 = generate_session_key()

        self.assertEqual(len(key1), 16, "AES key length should be 16 bytes.")
        self.assertNotEqual(key1, key2, "Generated session keys should be unique.")

if __name__ == "__main__":
    unittest.main()
