import ipaddress
from pathlib import Path
import re
from lark import Lark


grammar__lark_path = Path(__file__).parent / "grammar_spf.lark"

# Carica la grammatica Lark
with open(grammar__lark_path, "r") as file:
    grammar_lark = file.read()


spf_parser = Lark(grammar=grammar_lark, start="header_spf", regex=True)
return_path_parser = Lark(grammar=grammar_lark, start="header_return_path", regex=True)
recevied_parser = Lark(grammar=grammar_lark, start="header_received", regex=True)

def validate_received_spf_header_RFC7208(header: str) -> bool:
    """
    This method validates the header RFC7208. Unfortunately the standard does not accept 
    Ipv6 addresses in the optional keys. So I added an additional rule in the grammar to 
    avoid false negatives. 
    """
    try:
        spf_parser.parse(header)
        return True
    except:
        return False

def validate_return_path_header_RFC5321(header:str)-> bool:
    try:
        return_path_parser.parse(header)
        return True
    except:
        return False
    
def validate_received_header_RFC5322(header:str)-> bool:
    try:
        recevied_parser.parse(header)
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
