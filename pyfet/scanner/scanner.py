import re
from typing import List, Tuple
import email
import dns
from ipaddress import ip_address, ip_network

from pyfet.headerparser import parser


class IpLocation:
    def __init__(self, ip):
        self.ip = ip
    
    def get_location(self)->str:
        pass

    def get_owner(self)->str:
        pass
        


def ip_in_spf(ip:str, domain:str)->bool:
    def get_spf_record(domain)->str|None:
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            for record in answers:
                record_text = record.to_text()
                if record_text.startswith('"v=spf1'):
                    return record_text.strip()
        except Exception:
            return None
        return None

    spf=get_spf_record(domain=domain)
    if spf is None:
        return False
    
    if spf.split(" ")[-1]=="+all":
        return True
    
    for part in spf.split(" "):
        if part.startswith('ip4:') or part.startswith('ip6:'):
            cidr= part.split(':')[1]
            if ip_address(ip) in ip_network(cidr):
                return True
        
        elif part.startswith('include:'):
            included_domain= part.split(':')[1]
            if ip_in_spf(ip, included_domain):
                return True

    return False
    





class FET:

    def __init__(self, raw:bytes, mail_id:str):
        self.raw = raw
        self.id=mail_id
        self.parsed=email.message_from_bytes(raw)
        

    def check_spf(self)->Tuple[bool, List[str]]:
        logs=[]

        is_well_formatted = True
        is_pass = False
        manual_check=False

        spf=self.parsed.get('Received-SPF')
        logs.append(f"is present: {spf!=None}")
        if spf is not None:
            spf=spf.lower()
            is_well_formatted = parser.validate_received_spf_header_RFC7208(spf)
            logs.append(f"is well formatted: {is_well_formatted}")
            result=spf.strip().split(" ")
            result=result[0].strip() if len(result)>0 and result[0].strip()!="" else None
            is_pass= result == "pass"
            logs.append(f"found result: {result}")
            sender_ip = parser.extract_client_ip(spf)
            logs.append(f"found sender-ip in spf record: {sender_ip}")
            #THIS PART IS THE SEARCH OF THE IPOTETICAL SENDER IP


        # arc_message_auth=self.parsed.get('ARC-Authentication-Results')
        # arc_spf=False
        # if arc_message_auth is not None:
        #     infos= [info.strip() for info in arc_message_auth.split(";")]
        #     spf=[info for info in infos if re.match(r'^spf=pass.*', info)]
        #     if len(spf)>0:
        #         spf=spf[0]
        #         arc_spf = spf!=None and spf.split(" ")[0]=="spf=pass"
        #         logs.append(f"ARC-SPF: {'found' if spf!=None else 'not found'} {' ,'+spf.split(' ')[0] if spf is not None else ''}")
        #     else:
        #         logs.append(f"ARC-SPF: not found")
        # else:
        #     logs.append(f"ARC-SPF: not found")

        # manual_check= False


        return is_well_formatted and is_pass, logs

        
        



                
        



    def check_dkmi(self)->Tuple[bool, str]:
        pass
    
    def check_dmarc(self)->Tuple[bool, str]:
        pass

    def has_malware(self)->Tuple[bool, str]:
        #check with external api
        pass

    def build_location_history(self)->List[IpLocation]:
        pass

    def is_phishing(self)->Tuple[bool,str]:
        #check with external api
        pass

    def extract_attachments(self)->List[object]:
        pass
