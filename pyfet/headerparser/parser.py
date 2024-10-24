import ipaddress
from pathlib import Path
import re
from lark import Lark


grammar__lark_path = Path(__file__).parent / "grammar_spf.lark"

# Carica la grammatica Lark
with open(grammar__lark_path, "r") as file:
    grammar_lark = file.read()


spf_parser = Lark(grammar=grammar_lark, regex=True)

def validate_received_spf_header_RFC7208(header: str) -> bool:
    try:
        spf_parser.parse(header)
        return True
    except:
        return False

def extract_client_ip(header: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    # Regex per trovare l'IP dopo 'client-ip='
    match = re.search(r'client-ip=([0-9a-fA-F:.]+)', header)
    try:
        if match:
            return ipaddress.ip_address(match.group(1))
    except:
        pass
    
    return None
