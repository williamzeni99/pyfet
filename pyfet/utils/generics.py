import base64
import binascii
import subprocess
from pathlib import Path
import re
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.hazmat.primitives.asymmetric import padding

from asn1crypto import cms, pem

def is_valid_email(email: str) -> bool:
    # Simple regex for validating an email
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def find_json_file(directory:Path):
    dir_path = Path(directory)

    if not dir_path.is_dir():
        return None

    for json_file in dir_path.glob('*.json'):
        return json_file
    
    return None

def count_eml_files_in_directory(directory:Path):
    dir_path = Path(directory)

    eml_file_count = sum(1 for file in dir_path.glob('*.eml') if file.is_file())
    return eml_file_count



def sign_pkcs7(input_file_path: Path, private_key_path: Path, cert_path: Path) -> None:
    
    with open(private_key_path, "rb") as file_reader:
        pv_key_file=file_reader.read()

    with open(input_file_path, "rb") as file_reader:
        in_file=file_reader.read()

    with open(cert_path, "rb") as file_reader:
        cert_file=file_reader.read()
    

    cert = x509.load_pem_x509_certificate(cert_file)
    key = serialization.load_pem_private_key(pv_key_file, None)
    pkcs7
    signature = pkcs7.PKCS7SignatureBuilder().set_data(
            in_file
        ).add_signer(
            certificate=cert, 
            private_key=key, 
            hash_algorithm= hashes.SHA256()
        ).sign(
            encoding=serialization.Encoding.PEM,
            options=[]
        )

    out_file_path= input_file_path.with_suffix(".p7m")
    with open(out_file_path, "wb") as file_writer:
        file_writer.write(signature)


def verify_pkcs7(signed_file_path: Path, cert_path: Path):
    """
    Verify a PKCS7 file using OpenSSL.
    
    Args:
        signed_file_path (Path): The path to the PKCS7 file to verify.
        cert_path (Path): The path to the PEM-encoded certificate file.
    """
    # Load the certificate
    with open(cert_path, 'rb') as cert_file:
        cert_pem = cert_file.read()

    cert = x509.load_pem_x509_certificate(cert_pem)

    # Set up the command for OpenSSL
    command = [
        'openssl', 'smime', '-verify',
        '-in', str(signed_file_path),
        '-inform', 'PEM',  # Assuming the file is in PEM format
        '-certfile', str(cert_path), 
        '-out', str(signed_file_path.with_suffix(".json"))
    ]


    # Check if the certificate is self-signed
    if cert.subject == cert.issuer:
        print("  -> Warning: certificate is self-signed")
        command.append('-noverify')

    subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    

    

# def verify_pkcs7(signed_file_path: Path, cert_path: Path):
    
#     with open(signed_file_path, "rb") as file:
#         signed= file.read()

#     certs= pkcs7.load_pem_pkcs7_certificates(signed)
#     data = extract_pkcs7_data(signed)

#     if data==None:
#         raise Exception("impossible to retrieve file data")
    
    
#     for cert in certs:
#         print(cert.signature)
        
#         cert.public_key().verify(
#             signature=cert.signature, 
#             data=data, 
#             padding= padding.PKCS1v15(), 
#             algorithm= hashes.SHA256()
#         )
    

# def verify_pkcs7(signed_file_path: Path, cert_path: Path) -> None:
#     """
#     Verify the signature of a PKCS7 file using a certificate.

#     Args:
#         signed_file_path (Path): Path to the signed PKCS7 (.p7m) file.
#         cert_path (Path): Path to the PEM-encoded certificate file used to verify the signature.
#     """
#     # Load the certificate from the specified path
#     with open(cert_path, 'rb') as cert_file:
#         cert_pem = cert_file.read()

#     # Load the .p7m file
#     with open(signed_file_path, 'rb') as f:
#         p7m_data = f.read()

#     # Check if the data is PEM encoded, decode it if necessary
#     if pem.detect(p7m_data):
#         _, _, p7m_data = pem.unarmor(p7m_data)

#     # Parse the PKCS7 data using asn1crypto
#     pkcs7_obj = cms.ContentInfo.load(p7m_data)

#     if pkcs7_obj['content_type'].native == 'signed_data':
#         signed_data = pkcs7_obj['content']

#         # Load the certificate using the cryptography library
#         cert = x509.load_pem_x509_certificate(cert_pem)

#         # Extract the public key from the certificate
#         public_key = cert.public_key()

#         # Verify each signer
#         for signer_info in signed_data['signer_infos']:
#             signature = signer_info['signature'].native

#             # Get the signed content
#             signed_content = signed_data['encap_content_info']['content'].native

#             try:
#                 # Verify the signature
#                 public_key.verify(
#                     signature,
#                     signed_content,
#                     padding.PKCS1v15(),
#                     hashes.SHA256()
#                 )
#                 print("Signature is valid.")
#             except Exception as e:
#                 if cert.subject == cert.issuer:
#                     raise Exception("certr")
#     else:
#         print("No signed data found in the PKCS7 structure.")

# def verify_self_signed_certificate(cert) -> bool:
#     """
#     Verifies whether a self-signed certificate is valid.

#     Args:
#         cert (x509.Certificate): The certificate to verify.

#     Returns:
#         bool: True if the self-signed certificate is valid, False otherwise.
#     """
#     public_key = cert.public_key()
#     try:
#         # Verify the certificate's signature using its own public key
#         public_key.verify(
#             cert.signature,
#             cert.tbs_certificate_bytes,
#             padding.PKCS1v15(),
#             cert.signature_hash_algorithm
#         )
#         return True
#     except Exception as e:
#         print(f"Self-signed certificate validation failed: {e}")
#         return False

# def verify_pkcs7(signed_file_path: Path, cert_path: Path) -> None:
#     """
#     Verify the signature of a PKCS7 file using a certificate.

#     Args:
#         signed_file_path (Path): Path to the signed PKCS7 (.p7m) file.
#         cert_path (Path): Path to the PEM-encoded certificate file used to verify the signature.
#         content (bytes, optional): Original content if the PKCS7 signature is detached.
#     """
#     # Load the certificate
#     with open(cert_path, 'rb') as cert_file:
#         cert_pem = cert_file.read()
#     cert = x509.load_pem_x509_certificate(cert_pem)

#     # Check if the certificate is self-signed
#     if cert.subject == cert.issuer:
#         print("Warning: The certificate is self-signed.")
#         if not verify_self_signed_certificate(cert):
#             print("The self-signed certificate is not valid.")
#             return
#         else:
#             print("The self-signed certificate is valid.")

#     # Load the PKCS7 data
#     with open(signed_file_path, 'rb') as f:
#         p7m_data = f.read()

#     # Decode PEM if necessary
#     if pem.detect(p7m_data):
#         _, _, p7m_data = pem.unarmor(p7m_data)

#     # Parse PKCS7 data
#     pkcs7_obj = cms.ContentInfo.load(p7m_data)
#     if pkcs7_obj['content_type'].native != 'signed_data':
#         print("No signed data found.")
#         return

#     signed_data = pkcs7_obj['content']

#     # Extract public key
#     public_key = cert.public_key()

#     # Verify each signer
#     for signer_info in signed_data['signer_infos']:
#         # Use the digest algorithm specified in the SignerInfo
#         digest_algo = signer_info['digest_algorithm']['algorithm'].native
#         if digest_algo == 'sha256':
#             hash_alg = hashes.SHA256()
#         elif digest_algo == 'sha1':
#             hash_alg = hashes.SHA1()
#         else:
#             print(f"Unsupported digest algorithm: {digest_algo}")
#             continue

#         # Handle signed attributes if present
#         if 'signed_attrs' in signer_info:
#             signed_attrs = signer_info['signed_attrs'].dump()
#             signature = signer_info['signature'].native

#             try:
#                 public_key.verify(
#                     signature,
#                     signed_attrs,
#                     padding.PKCS1v15(),
#                     hash_alg
#                 )
#                 print("Signature is valid.")
#             except Exception as e:
#                 print(f"Signature verification failed: {e}")
#         else:
#             # Use the encapsulated content if present
#             signed_content = signed_data['encap_content_info']['content'].native if 'content' in signed_data['encap_content_info'] else content

#             if signed_content is None:
#                 print("No content available for verification.")
#                 return

#             signature = signer_info['signature'].native

#             try:
#                 public_key.verify(
#                     signature,
#                     signed_content,
#                     padding.PKCS1v15(),
#                     hash_alg
#                 )
#                 print("Signature is valid.")
#             except Exception as e:
#                 print(f"Signature verification failed: {e}")

def extract_pkcs7_data(p7m_data: bytes):

    # Check if the data is PEM encoded, decode it if necessary
    if pem.detect(p7m_data):
        _, _, p7m_data = pem.unarmor(p7m_data)

    # Parse the PKCS7 data using asn1crypto
    pkcs7_obj = cms.ContentInfo.load(p7m_data)

    # Extract the signed data (if it exists)
    if pkcs7_obj['content_type'].native == 'signed_data':
        signed_data = pkcs7_obj['content']
        
        # Check if there's an embedded file
        if signed_data['encap_content_info']['content_type'].native == 'data':
            embedded_data = signed_data['encap_content_info']['content'].native
            
            return embedded_data
    
    return None
        

