import pkcs11
from pkcs11.util.x509 import decode_x509_certificate
from pathlib import Path

# Path to your PKCS#11 library, typically provided by the smart card vendor
PKCS11_LIBRARY_PATH = '/path/to/your/pkcs11/library.so'

# Initialize PKCS#11 library
lib = pkcs11.lib(PKCS11_LIBRARY_PATH)

# Set your slot number or enumerate the slots
slot = lib.get_slots(token_present=True)[0]  # Assumes the first slot with a token

# Open session
with slot.open(user_pin='your_pin') as session:
    # Choose a private key object for signing
    private_key = session.get_key(pkcs11.constants.ObjectClass.PRIVATE_KEY, label='YourKeyLabel')

    # Load the document
    document_path = Path('path/to/your/document.txt')
    document_content = document_path.read_bytes()

    # Sign the document
    signature = private_key.sign(document_content, mechanism=pkcs11.Mechanism.SHA256_RSA_PKCS)

    # Save signature
    signature_path = document_path.with_suffix('.sig')
    signature_path.write_bytes(signature)

print(f"Document signed successfully! Signature saved to {signature_path}")
