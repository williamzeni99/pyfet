import subprocess
from pathlib import Path
import re
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.hazmat.primitives.asymmetric import padding

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
    
    command = [
        'openssl', 'smime', '-verify', 
        '-in', signed_file_path, 
        '-inform', 'PEM', 
        '-certfile', cert_path
    ]
    
    subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    