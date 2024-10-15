from pathlib import Path
import re



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

