import ipaddress
from pathlib import Path
import re
from typing import List, Optional, Tuple
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

def find_all_public_ips(header:str) -> List[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    # Regex per trovare un ip
    ipv4_6 = r'((?:[0-9]{1,3}(?:[.][0-9]{1,3}){3})|(?:(?:(?:[a-fA-F0-9]{0,4})(?:[:][a-fA-F0-9]{0,4}){0,7})[:](?:(?:[:][a-fA-F0-9]{0,4})|(?:[0-9]{1,3}(?:[.][0-9]{1,3}){3}))))'
    
    matches = re.findall(ipv4_6, header)
    ips=[]
    for match in matches:
        try:
            ip = ipaddress.ip_address(match)
            if ip.is_global:
                ips.append(ip)    
        except:
            pass
    
    return ips


def extract_email_and_domain(header: str) -> Tuple[str|None, str|None]:

    try:
        header = header.replace(">", "").replace("<", "").strip()
        return header, header.split("@")[1]
    except:
        return None, None


def find_domain_in_header(domain:str, header:str)->bool:
    domain= domain.strip().split(".")
    domain= f"{domain[-2]}.{domain[-1]}"
    return domain in header
