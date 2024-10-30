import re
from typing import List, Tuple
import email
import dns
from ipaddress import ip_address, ip_network
import spf as pyspf

from pyfet.headerparser import parser


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

        sender_ips=[]
        email=None
        domain=None

        spf=self.parsed.get('Received-SPF')
        logs.append(f"is present: {spf!=None}")

        receiveds = self.parsed.get_all("Received")

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

            found=False
            if sender_ip is not None:
                sender_ips.append(sender_ip)
                for received in receiveds:
                    if parser.validate_received_header_RFC5322(received):
                        public_ips= parser.find_all_public_ips(received)
                        if sender_ip in public_ips:
                            found = True
                            break
                
                logs.append(f"found spf-ip in received header: {found}")

        return_path = self.parsed.get('Return-Path')  
        logs.append(f"return path is present: {return_path!=None}")
        if return_path:     
            logs.append(f"return-path is well formatted: {parser.validate_return_path_header_RFC5321(return_path)}")
            email, domain = parser.extract_email_and_domain(return_path)

        
        if len(sender_ips)==0 and email and domain:
            #trying to find the sender_ip
            ips=[]
            for received in receiveds:
                if parser.find_domain_in_header(domain=domain, header=received):
                    ips=parser.find_all_public_ips(header=received)
                    sender_ips.extend(ips)
                    break
            logs.append(f"manual inspection - found possible ips (do not trust this process): {[ip.__str__() for ip in ips] if len(ips)>0 else None }")

            
        
        if len(sender_ips)>0 and email and domain:
            for sender_ip in sender_ips:
                (result, comment) = pyspf.check2(i=sender_ip.__str__(), s=email, h=domain)
                logs.append(f"tested spf now [{sender_ip}][{email}]: {result}, {comment}")
                if result=="pass":
                    manual_check=True
                    break

        
                
                



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


        return is_well_formatted and is_pass and manual_check, logs

        
        



                
        



    def check_dkmi(self)->Tuple[bool, str]:
        pass
    
    def check_dmarc(self)->Tuple[bool, str]:
        pass

    def has_malware(self)->Tuple[bool, str]:
        #check with external api
        pass


    def is_phishing(self)->Tuple[bool,str]:
        #check with external api
        pass

    def extract_attachments(self)->List[object]:
        pass
