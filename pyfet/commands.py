
from datetime import date, datetime
from email import policy
from email.parser import BytesParser
import hashlib
from io import TextIOWrapper
import json
import os
import re
import shutil
from typing import IO, Any, List, Tuple
import regex
import typer
from pyfet.headerparser import parser
from pyfet.oauth.login_interface import ForensicEmail
from pyfet.scanner.scanner import FET
import pyfet.utils.mail as mail
from pathlib import Path
import pyfet.utils.generics as tools
from ipaddress import IPv6Address
from pyfet.sniffer.utils import ForensicSniffer 


def log(message:str, use_log:bool=False, log_file:IO[Any]=None):
    typer.echo(message=message)
    if use_log and log_file is not None:
        typer.echo(message=message, file=log_file)

def initiate_log_file(path:Path, command:str,  params:List[Tuple[str, str]])->IO[Any]:
    log_path=path/f"log_{command}_{datetime.utcnow()}.txt"
    log_file= open(log_path, "w")

    x=f"LOG command {command} {datetime.utcnow()}\n"
    x+="Params:\n"

    for (name, value) in params:
        if isinstance(value, Path):
            x+=f"  ->{name}: {value.absolute()}\n"
        else:  
            x+=f"  ->{name}: {value}\n"

    x+="\n\n"
    log(x, True, log_file)
    return log_file 


def get_cli(save_path:Path, config_path:Path, q:bool, use_log:bool, traffic:bool):
    try:
        log_file=None
        if use_log:
            log_file = initiate_log_file(save_path, "get", [
                ("save_path", save_path), 
                ("config_path", config_path), 
                ("q", q),
                ("traffic", traffic)
                ])

        domains= mail.load_supported_domain(config_path=config_path)
        domains.append("IMAP")

        log("Currently supported authentication method:")
        for x in domains:
            log(f"  {x}")
        
        log("\n")

        while True:
            domain = typer.prompt("> insert a method for login")

            if domain in domains:
                break

            log("[!] method not supported")
    
        log("[-] Searching OAuth internal config", use_log, log_file)
        (oauth, err)=mail.getAuth_from_domain(domain=domain, config_path=config_path)
        if err!=None:
            log(f"[!] Some error occurred: {err}", use_log, log_file)
            return
    except Exception as e:
        log("[!!!] Something went wrong. Configuration file not found or bad formatting.", use_log, log_file)
        log(f"More info: {e}", use_log, log_file)
        return

    sniffer=None
    if traffic:
        sniffer = ForensicSniffer(save_path=save_path)
        log("[-] Traffic recording: start")
        sniffer.start_sniff()

    try:
        log("[-] Starting login phase", use_log, log_file)
        oauth.login()
        log("[-] Login successfull", use_log, log_file)
    except Exception as e:
        log(f"[!] Login Failed:{e}", use_log, log_file)
        sniffer.abort_sniff() if traffic else None
        return
    
    query=""
    if q:
        query=typer.prompt("> insert search query")
        log(f"  -> search query: {query}", use_log, log_file)

    log("[-] Searching for emails", use_log, log_file)

    try:
        email=oauth.getMe()
    except Exception as e:
        log("[!!!] something strage happend: impossible to read basic data", use_log, log_file)
        log(f"more info: {e}", use_log, log_file)
        sniffer.abort_sniff() if traffic else None
        return

    try:
        emails = oauth.search_emails(query=query)
        log(f"  -> downloaded {len(emails)} emails", use_log, log_file)
    except Exception as e:
        log("[!] search email failed", use_log, log_file)
        log(f"more info: {e}",use_log, log_file)
        sniffer.abort_sniff() if traffic else None
        return
    
    if traffic:
        sniffer.stop_sniff()
        log(f"[-] Traffic recording: stop", use_log, log_file)

    log(f"[-] Saving emails on device", use_log, log_file)
    extraction_name = mail.save_emails(path=save_path, emails=emails)
    
    log(f"[-] Generating report", use_log, log_file)
    mail.generate_report(
        extraction_name=extraction_name, 
        user_email=email,
        query=query, 
        save_path= save_path, 
        forensic_emails=emails, 
        sniffer=sniffer
        )
    
    log("\n[!!!] REMEMBER TO MANUALLY SIGN YOUR REPORT", use_log, log_file)
    log("  -> you can sign the report using 'pyfet sign' ", use_log, log_file)
    log_path= Path(log_file.name).resolve()
    shutil.move(log_path, save_path/extraction_name)
    if traffic:
        shutil.move(sniffer.save_file.path, save_path/extraction_name)
        shutil.move(sniffer.session_keys_file.path, save_path/extraction_name)
    

def check_cli(path:Path, use_log:bool):
    
    report_path = path.joinpath(path.name+"_report.json")
    
    log_file = None
    if use_log:
        log_file=initiate_log_file(path=path, command="check", params=[
            ("path", path)
        ])

    log("[-] Searching for report", use_log, log_file)

    try:
        with open(report_path) as report_file:
            report = json.load(report_file)
    except FileNotFoundError:
        log(f"  -> file {report_path} not found", use_log, log_file)
        log(f"  -> searching a json in the folder", use_log, log_file)

        jsonfile= tools.find_json_file(path)
        if jsonfile==None:
            log("[!] No report found, verify aborted", use_log, log_file)
            return
        log(f"  -> found {jsonfile.name}", use_log, log_file)

        try:
            with open(jsonfile) as x:
                report= json.load(x)
        except Exception as e:
            log(f"[!!] Something strange happend: {e}", use_log, log_file)
            return

    except Exception as e:
        log(f"[!!] Something strange happend: {e}", use_log, log_file)
        return

    log("[-] Loading data from report", use_log, log_file)

    traffic_status= True
    if ("session_keys" in report and "recorded_pcap" not in report) or ("session_keys" not in report and "recorded_pcap" in report):
        log("[!] Report not well formatted: one between session_keys and recorded_pcap is missing. If one of them is present the other one must be present too. The check of the traffic will be ignored, but this is strong warning", use_log, log_file)
        traffic_status=False
    
    if "session_keys" in report and "recorded_pcap" in report:
        recorded_pcap = report["recorded_pcap"]
        session_keys = report["session_keys"]
        try:
            pcap_path = path/recorded_pcap["path"]
            with open(pcap_path, "rb") as file:
                raw = file.read()
                sha256 = hashlib.sha256(raw).hexdigest()
                sha1 = hashlib.sha1(raw).hexdigest()
                md5 = hashlib.md5(raw).hexdigest()
                
                sha256_ok=False
                sha1_ok=False
                md5_ok= False
                if "sha256" in recorded_pcap and sha256==recorded_pcap["sha256"]:
                    sha256_ok=True
                if "sha1" in recorded_pcap and sha1==recorded_pcap["sha1"]:
                    sha1_ok=True
                if "md5" in recorded_pcap and md5==recorded_pcap["md5"]:
                    md5_ok=True
                    
                if sha1_ok and sha256_ok and md5_ok:
                    log("[-] Recorded Pcap file: PASS", use_log, log_file)
                else:
                    traffic_status=False
                    log("[!] Recorded Pcap file: NOT PASS (one of the signatures is not verified)", use_log, log_file)

        except:
            log("[!] Recorded Pcap file not found: file is missing or path not found in report", use_log, log_file)
            traffic_status= False

        try:
            session_keys_path = path/session_keys["path"]
            with open(session_keys_path, "rb") as file:
                raw = file.read()
                sha256 = hashlib.sha256(raw).hexdigest()
                sha1 = hashlib.sha1(raw).hexdigest()
                md5 = hashlib.md5(raw).hexdigest()
                
                sha256_ok=False
                sha1_ok=False
                md5_ok= False
                if "sha256" in session_keys and sha256==session_keys["sha256"]:
                    sha256_ok=True
                if "sha1" in session_keys and sha1==session_keys["sha1"]:
                    sha1_ok=True
                if "md5" in session_keys and md5==session_keys["md5"]:
                    md5_ok=True
                
                if sha1_ok and sha256_ok and md5_ok:
                    log("[-] Session keys file: PASS", use_log, log_file)
                else:
                    traffic_status=False
                    log("[!] Session keys file: NOT PASS (one of the signatures is not verified)", use_log, log_file)

        except:
            log("[!] Session keys file not found: file is missing or path not found in report", use_log, log_file)
            traffic_status= False


    if "emails" not in report:
        log("[!] Report not well formatted: emails missing", use_log, log_file)
        return
    
    emails = report["emails"]
    emails_path = path / "emails"
    count_emails = tools.count_eml_files_in_directory(emails_path)
    if len(emails)!= count_emails:
        log(f"  -> WARNING: number of emails missmatch (report {len(emails)}/{count_emails} folder)", use_log, log_file)
    
    missing_emails=[]
    email_tampered=[]
    email_notwell_formatted=[]
    email_ok=[]
    log("[-] Analyzing emails", use_log, log_file)
    with typer.progressbar(length=len(emails), label="  -> loading") as progress:
        for email in emails:
            progress.update(1)
            try:
                saved_at = email["save_timestamp"]
                requested_at = email["request_timestamp"]
                filename = email["filename"]
                id= email["id"]
                sha256 = email["sha256"]
                sha1 = email["sha1"]
                md5 = email["md5"]
            except Exception as e:
                email_notwell_formatted.append(email)
                continue

            email_path = emails_path / filename

            if not email_path.is_file():
                missing_emails.append(filename)
                continue

            with open(email_path, 'rb') as y:
                x=y.read()
                if(ForensicEmail.calculate_sha256(x)!=sha256):
                    email_tampered.append({
                        "filename":filename, 
                        "error": "sha256 missmatch"
                        })
                    continue

                if(ForensicEmail.calculate_sha1(x)!=sha1):
                    email_tampered.append({
                        "filename":filename,
                        "error": "sha1 missmatch"
                        })
                    continue

                if(ForensicEmail.calculate_md5(x)!=md5):
                    email_tampered.append({
                        "filename":filename,
                        "error": "md5 missmatch"
                        })
                    continue

            email_ok.append(filename)
        
        
        log("\n\n[-] RECAP", use_log, log_file)
        log(f"  -> email missing: {len(missing_emails)}", use_log, log_file)
        for x in missing_emails:
            log(f"     {x}", use_log, log_file)

        log(f"  -> email not well formatted in report (positional referiment): {len(email_notwell_formatted)}", use_log, log_file)
        for x in email_notwell_formatted:
            pretty = json.dumps(x, indent=4)
            indented_json = "\n".join("    " + line for line in pretty.splitlines())
            log(f"{indented_json}", use_log, log_file)
        
        log(f"  -> email tampered: {len(email_tampered)}", use_log, log_file)
        for x in email_tampered:
            log(f"     {x['filename']}  {x['error']}")
        
        eml_files=[]
        for file in path.glob('*.eml'):
            if file.is_file():
                eml_files.append(file.name)
        
        set_ok=set(email_ok)
        set_tampered =set([entry["filename"] for entry in email_tampered])
        set_eml_files= set(eml_files)

        missmatch = set_eml_files - set_ok.union(set_tampered)
        missmatch = list(missmatch)
        log(f"  -> email in folder but not in the report: {len(missmatch)}", use_log, log_file)
        for x in missmatch:
            log(f"     {x}", use_log, log_file)

        
        if traffic_status and len(missmatch)+len(missing_emails)+len(email_tampered)+len(email_notwell_formatted)==0:
            log("\n\n[-] RESULT: Verification successful", use_log, log_file)
        else:
            log("\n\n[!] RESULT: Verification failed", use_log, log_file)


def sign_cli(file:Path,pkey:Path, cert:Path, use_log:bool ):
    
    try:
        log_file = None
        if use_log:
            log_file= initiate_log_file(path=file.parent, command="sign", params=[
                ("file", file), 
                ("pkey", pkey), 
                ("cert", cert)
            ] )
        log("[-] Signing", use_log, log_file)
        tools.sign_pkcs7(input_file_path=file, private_key_path=pkey, cert_path=cert)
        os.remove(file)
        log("[-] Sign successful: old file deleted and new signed one generated", use_log, log_file)
    except Exception as e:
        log("[!] Signing failed", use_log, log_file)
        log(f"  -> more info: {e}", use_log, log_file)
        

def verify_cli(signed_file: Path, cert: Path, use_log:bool):

    log_file = None
    if use_log:
        log_file = initiate_log_file(path=signed_file.parent, command="verify", params=[
            ("signed_file", signed_file), 
            ("cert", cert)
        ])

    log("[-] Verifing", use_log, log_file)

    try:
        tools.verify_pkcs7(signed_file_path=signed_file, cert_path=cert)
        log("[-] Verification successful", use_log, log_file)
    except Exception as e:
        log("[!] Verification not passed", use_log, log_file)
        log(f"  -> more info: {e}", use_log, log_file)
    

def scan_cli(path: Path, use_log: bool):

    log_file=None
    if use_log:
        log_path=path
        if path.is_file():
            log_path = path.parent

        log_file=initiate_log_file(path=log_path, command="scan", params=[
            ("path", path)
        ])

    emails:List[FET]=[]

    if path.is_file():
        log("[-] Loading eml file", use_log, log_file)
        with path.open("rb") as f:
                eml = f.read()
                emails.append(FET(raw=eml, mail_id= path.name))
    else:
        log("[-] Loading eml files", use_log, log_file)
        eml_files = list(path.glob("*.eml"))
        log(f"  -> found {len(eml_files)} emails",use_log, log_file)
        if len(eml_files)==0:
            log("[!] No emails found: scan aborted", use_log, log_file)
            return
        
        with typer.progressbar(length=len(eml_files), label="  -> loading") as progress:
            for eml_file in eml_files:
                with eml_file.open("rb") as f:
                    eml = f.read()
                    emails.append(FET(raw=eml, mail_id=eml_file.name))
                progress.update(1)

    log("\n[-] Scan started", use_log, log_file)
    final_result = True
    not_pass:List[FET]=[]
    with typer.progressbar(length=len(emails), label="  -> scanning") as progress:
        for email in emails:
            result, logs = email.scan()
            final_result = final_result and result
            print(f"\r", end="")
            log(f"  [-] email: {email.id} ", use_log, log_file)

            for logx in logs:
                log(f"      -> {logx}", use_log, log_file)
        
            if not result:
                not_pass.append(email)
            progress.update(1)

    log(f"\n\n[{'-' if final_result else '!'}] FINAL RESULT: {'PASS' if final_result else 'NOT PASS'}", use_log, log_file)
    if not final_result:
        log(f"[!] List of not passed emails")
        for email in not_pass:
            log(f"  -> {email.id}")
    
    







    
    
    
        
    



   
    


        


    


# def get_cli(start_date:datetime, end_date:datetime, save_path:Path, keywords:bool):

#     while True:
#         email = typer.prompt("> insert email")

#         if tools.is_valid_email(email):
#             break

#         log("[!] Email not valid")
    
#     password = typer.prompt("> insert password", hide_input=True)
#     log("[-] Searching for configuration")
#     (config, error) = mail.get_automatic_imap_config(email)
#     if error!= None:
#         log("[!] Configuration not found")
#         log(f"[-] Asking manual configuration")
#         config = mail.get_manual_imap_config()
#     else:
#         log(f"[-] Configuration found: {config}")
    
#     log("[-] Login attempt")
#     user, err = mail.login(email=email, password=password,imapConfig=config)
#     if err!=None:
#         log(f"[!] Login failed: {err}")
#         return
    
#     log("[-] Login successfull")

#     if keywords:
#         log("[-] Asking keywords")
#         keywords=typer.prompt(">insert keywords divided by space (ex: home people printer)").split(" ")
#     else:
#         keywords=None
        

#     log("[-] Searching emails")
#     (mails, err) = mail.search_emails(user, start_date,end_date,keywords)
#     if err!=None:
#         log(f"[!] Search failed: {err}")
#         return
#     log(f"[-] {len(mails)} emails found")

#     log(f"[-] Saving emails")
#     extraction_name= mail.save_emails(path=save_path, emails=mails)
#     log(f"[-] Emails saved")
#     log(f"[-] Generating report")
#     mail.generate_report(extraction_name=extraction_name, email=email, start_date=start_date, end_date=end_date, keywords=keywords,forensic_emails=mails, save_path=save_path )
#     log(f"[-] Report saved")



  




    