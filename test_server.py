import unittest
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad
from server import rsa_encrypt, rsa_decrypt, aes_encrypt, aes_decrypt, generate_or_load_keys

class TestServerFunctions(unittest.TestCase):
    def setUp(self):
        """Set up test data."""
        self.test_message = "Hello from the server!"

        # Generate or load RSA keys
        global server_key
        server_key = generate_or_load_keys()

        # Use server's RSA keys for testing
        self.rsa_cipher = PKCS1_OAEP.new(server_key.publickey())
        self.rsa_decipher = PKCS1_OAEP.new(server_key)

        # Generate a valid AES session key (16 bytes)
        self.session_key = b"thisis16byteskey"

    def test_rsa_encryption_decryption(self):
        """Test RSA encryption and decryption."""
        encrypted = self.rsa_cipher.encrypt(self.test_message.encode())
        decrypted = self.rsa_decipher.decrypt(encrypted).decode()

        self.assertEqual(self.test_message, decrypted, "RSA encryption/decryption failed.")

    def test_aes_encryption_decryption(self):
        """Test AES encryption and decryption."""
        encrypted = aes_encrypt(self.test_message.encode(), self.session_key)
        decrypted = aes_decrypt(encrypted, self.session_key).decode()

        self.assertEqual(self.test_message, decrypted, "AES encryption/decryption failed.")

    def test_generate_or_load_keys(self):
        """Test key generation or loading."""
        private_key = generate_or_load_keys()

        self.assertIsNotNone(private_key, "Private key should not be None.")
        self.assertTrue(private_key.has_private(), "Loaded key should include a private key.")

if __name__ == "__main__":
    unittest.main()
