from email.utils import parsedate_to_datetime
from logging import Logger
import re
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
            """
            It checks the first spf starting from the top, making some extra analisys
            """
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

            original_validate_signature_fields = dkimpy.validate_signature_fields


            dkims=fet.parsed.get_all('DKIM-Signature')
            logs=[]
            logs.append(f"dkims present: {dkims!=None}")

            if not dkims:
                return False, logs
            
            results=[]
            for index, dkim in enumerate(dkims):
                result=parser.validate_dkim_signature_header_RFC8616(dkim)
                logs.append(f"dkim-{index} is well formatted: {result}")

                if not result:
                    results.append(result)
                    break
                
                tag_list = dkimpy.parse_tag_value(bytes(dkim, "utf-8"))

                last_received_date=None
                if b'x' in tag_list:
                    receiveds = fet.parsed.get_all("Received")
                    if len(receiveds)==0:
                        logs.append(f"impossible to verify the dkim-{index} signature, no received header found")
                        results.append(False)
                        break
                    
                    last_received=None
                    for receive in receiveds:
                        if parser.validate_received_header_RFC5322(receive):
                            last_received=receive
                            break
                    
                    if last_received is None:
                        logs.append(f"impossible to verify the dkim-{index} signature, no received is well formatted")
                        results.append(False)
                        break

                    last_received_date = int(parsedate_to_datetime(last_received.split(';')[-1].strip()).timestamp())

                    try:
                        my_validate_signature_fields(sig=tag_list, now=last_received_date) is None
                        logs.append(f"dkim-{index} tags well formatted: {True}")
                    except Exception as e:
                        logs.append(f"dkim-{index} tags well formatted: {False} - {e}")
                        results.append(False)
                        break
                
                    dkimpy.validate_signature_fields= lambda x: None

                result=dkimpy.verify(message=fet.raw)
                logs.append(f"dkim-{index} is passed: {result} {'with date ' + str(last_received_date) if last_received_date else ''}")
                results.append(result)
                dkimpy.validate_signature_fields = original_validate_signature_fields

            return all(results), logs
        

        def check_dmarc(fet:FET)->Tuple[bool, List[str]]:
            dmarcs=fet.parsed.get_all('Authentication-Results')
            logs=[]
            logs.append(f"dmarcs present: {dmarcs!=None}")

            if not dmarcs:
                return False, logs
            
            results=[]
            for index, dmarc in enumerate(dmarcs):
                result=parser.validate_authentication_results_header_RFC8601(dmarc)
                logs.append(f"dmarc-{index} is well formatted: {result}")

                if not result:
                    results.append(result)
                    break
                
                result = "dmarc=pass" in dmarc.lower()
                logs.append(f"dmarc-{index} is passed: {result}")
                results.append(result)
                match = re.search(r"dkim=(\w+)", dmarc)
                logs.append(f"dmarc-{index} dkim tag: {match.group(1)}")
                match = re.search(r"spf=(\w+)", dmarc)
                logs.append(f"dmarc-{index} spf tag: {match.group(1)}")
                
            return all(results), logs
        
        def check_arc_chain(fet:FET)->Tuple[bool, List[str]]:
            ispass, _ ,reason= dkimpy.arc_verify(message=fet.raw)
            result= ispass == b'pass'
            logs=[]
            logs.append(f"arc-chain validation result: {ispass.decode('utf-8')}, {reason}")
            if reason=="Most recent ARC-Message-Signature did not validate":
                logs.append("arc-chain WARNING: this fail reason is common for microsoft emails. Microsoft usually breaks dkim signatures.")

            return result, logs
        
        
        logs=[]
        spf_check, spf_logs= check_spf(fet=self)
        dkim_check, dkim_logs=check_dkim(fet=self)
        dmarc_check, dmarc_logs = check_dmarc(fet=self)
        arc_check, arc_logs = check_arc_chain(fet=self)
        logs.extend(spf_logs)
        logs.extend(dkim_logs)
        logs.extend(dmarc_logs)
        logs.extend(arc_logs)

        return spf_check and dkim_check and dmarc_check and arc_check, logs


    def has_malware(self)->Tuple[bool, str]:
        #check with external api
        pass


    def is_phishing(self)->Tuple[bool,str]:
        #check with external api
        pass

    def extract_attachments(self)->List[object]:
        pass
