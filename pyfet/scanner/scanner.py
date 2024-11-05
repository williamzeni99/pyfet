from email.utils import parsedate_to_datetime
from logging import Logger
from typing import List, Tuple
import email
import dns
from ipaddress import ip_address, ip_network
import spf as pyspf

from pyfet.headerparser import parser
import dkim as dkimpy

from pyfet.headerparser.utils import my_validate_signature_fields


class FET:

    def __init__(self, raw:bytes, mail_id:str):
        self.raw = raw
        self.id=mail_id
        self.parsed=email.message_from_bytes(raw)
        
    def scan(self)->Tuple[bool, List[str]]:

        def check_spf(fet:FET)->Tuple[bool, List[str]]:
            logs=[]

            is_well_formatted = True
            is_pass = False

            sender_ips=[]
            email=None
            domain=None

            spf=fet.parsed.get('Received-SPF')
            logs.append(f"spf present: {spf!=None}")

            receiveds = fet.parsed.get_all("Received")

            if spf is not None:
                spf=spf.lower()
                is_well_formatted = parser.validate_received_spf_header_RFC7208(spf)
                logs.append(f"spf well formatted: {is_well_formatted}")
                result=spf.strip().split(" ")
                result=result[0].strip() if len(result)>0 and result[0].strip()!="" else None
                is_pass= result == "pass"
                logs.append(f"spf result: {result}")
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

            return_path = fet.parsed.get('Return-Path')  
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
                logs.append(f"spf - manual inspection - found possible ips (do not trust this process): {[ip.__str__() for ip in ips] if len(ips)>0 else None }")

                
            
            if len(sender_ips)>0 and email and domain:
                for sender_ip in sender_ips:
                    (result, comment) = pyspf.check2(i=sender_ip.__str__(), s=email, h=domain)
                    logs.append(f"tested spf now (this is not a digital evidence)\n        [{sender_ip}][{email}]: {result}, {comment}")
                    if result=="pass":
                        break

            return is_well_formatted and is_pass, logs

            
        def check_dkim(fet:FET)->Tuple[bool, List[str]]:

            dkim=fet.parsed.get('DKIM-Signature')
            logs=[]
            logs.append(f"dkim present: {dkim!=None}")

            if not dkim:
                return False, logs
            
            result=parser.validate_dkim_signature_header_RFC8616(dkim)
            logs.append(f"dkim is well formatted: {result}")

            if not result:
                return False, logs
            
            tag_list = dkimpy.parse_tag_value(bytes(dkim, "utf-8"))

            last_received_date=None
            if b'x' in tag_list:
                receiveds = fet.parsed.get_all("Received")
                if len(receiveds)==0:
                    logs.append("impossible to verify the dkim signature, no received header found")
                    return False, logs
                
                last_received=None
                for receive in receiveds:
                    if parser.validate_received_header_RFC5322(receive):
                        last_received=receive
                        break
                
                if last_received is None:
                    logs.append("impossible to verify the dkim signature, no received is well formatted")
                    return False, logs

                last_received_date = int(parsedate_to_datetime(last_received.split(';')[-1].strip()).timestamp())

                try:
                    my_validate_signature_fields(sig=tag_list, now=last_received_date) is None
                    logs.append(f"dkim tags well formatted: {True}")
                except Exception as e:
                    logs.append(f"dkim tags well formatted: {False} - {e}")
                    return False, logs
            
                dkimpy.validate_signature_fields= lambda x: None

            result=dkimpy.verify(message=fet.raw)
            logs.append(f"dkim is passed: {result} {'with date ' + str(last_received_date) if last_received_date else ''}")


            return result, logs
        

        def check_dmarc(fet:FET)->Tuple[bool, List[str]]:
            return False, []
        
        
        logs=[]
        spf_check, spf_logs= check_spf(fet=self)
        dkim_check, dkim_logs=check_dkim(fet=self)
        dmarc_check, dmarc_logs = check_dmarc(fet=self)
        logs.extend(spf_logs)
        logs.extend(dkim_logs)
        logs.extend(dmarc_logs)

        return spf_check and dkim_check and dmarc_check, logs


    def has_malware(self)->Tuple[bool, str]:
        #check with external api
        pass


    def is_phishing(self)->Tuple[bool,str]:
        #check with external api
        pass

    def extract_attachments(self)->List[object]:
        pass
