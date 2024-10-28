
from datetime import date, datetime
from email import policy
from email.parser import BytesParser
from io import TextIOWrapper
import json
import os
import re
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


def log(message:str, use_log:bool=False, log_file:IO[Any]=None):
    typer.echo(message=message)
    if use_log and log_file is not None:
        typer.echo(message=message, file=log_file)

def initiate_log_file(path:Path, command:str,  params:List[Tuple[str, str]])->IO[Any]:
    log_path=path/f"{command}_log_{datetime.utcnow()}.txt"
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


def get_cli(save_path:Path, config_path:Path, q:bool, use_log:bool):
    try:
        log_file=None
        if use_log:
            log_file = initiate_log_file(save_path, "get", [
                ("save_path", save_path), 
                ("config_path", config_path), 
                ("q", q)
                ])
        domains= mail.load_supported_domains(config_path=config_path)

        log("Currently supported domains:")
        for x in domains:
            log(f"  {x}")
        
        log("\n")

        while True:
            domain = typer.prompt("> insert a domain for login")

            if domain in domains:
                break

            log("[!] domain not supported")
        
        log("[-] Searching OAuth internal config", use_log, log_file)
        (oauth, err)=mail.getOAuth_from_domain(domain=domain, config_path=config_path)
        if err!=None:
            log(f"[!] Some error occurred: {err}", use_log, log_file)
            return
    except Exception as e:
        log("[!!!] Something went wrong. Configuration file not found or bad formatting.", use_log, log_file)
        log(f"More info: {e}", use_log, log_file)
        return

    try:
        log("[-] Starting login phase", use_log, log_file)
        oauth.login()
        log("[-] Login successfull", use_log, log_file)
    except Exception as e:
        log(f"[!] Login Failed:{e}", use_log, log_file)
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
        return

    try:
        emails = oauth.search_emails(query=query)
        log(f"  -> downloaded {len(emails)} emails", use_log, log_file)
    except Exception as e:
        log("[!] search email failed", use_log, log_file)
        log(f"more info: {e}",use_log, log_file)
        return

    log(f"[-] Saving emails on device", use_log, log_file)
    extraction_name = mail.save_emails(path=save_path, emails=emails)
    
    log(f"[-] Generating report", use_log, log_file)
    mail.generate_report(
        extraction_name=extraction_name, 
        user_email=email,
        query=query, 
        save_path= save_path, 
        forensic_emails=emails
        )
    
    log("\n[!!!] REMEMBER TO MANUALLY SIGN YOUR REPORT", use_log, log_file)
    log("  -> you can sign the report using 'pyfet sign' ", use_log, log_file)
    

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

    if "emails" not in report:
        log("[!] Report not well formatted: emails missing", use_log, log_file)
        return
    
    emails = report["emails"]
    count_emails = tools.count_eml_files_in_directory(path)
    if len(emails)!= count_emails:
        log(f"  -> WARNING: number of emails missmatch (report {len(emails)}/{count_emails} folder)", use_log, log_file)
    
    missing_emails=[]
    email_tampered=[]
    email_notwell_formatted=[]
    email_ok=[]

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

            email_path = path / f"{filename}.eml"

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
            log(f"     {x['id']}  {x['error']}")
        
        eml_files=[]
        for file in path.glob('*.eml'):
            if file.is_file():
                eml_files.append(file.stem)
        
        set_ok=set(email_ok)
        set_tampered =set([entry["id"] for entry in email_tampered])
        set_eml_files= set(eml_files)

        missmatch = set_eml_files - set_ok.union(set_tampered)
        missmatch = list(missmatch)
        log(f"  -> email in folder but not in the report: {len(missmatch)}", use_log, log_file)
        for x in missmatch:
            log(f"     {x}", use_log, log_file)

        
        if len(missmatch)+len(missing_emails)+len(email_tampered)+len(email_notwell_formatted)==0:
            log("\n\n[-] RESULT: Verification successful", use_log, log_file)
        else:
            log("\n\n[!] RESULT: Verification failed", use_log, log_file)


def sign_cli(file:Path,pkey:Path, cert:Path, use_log:bool ):
    
    try:
        log_file = None
        if use_log:
            log_file= initiate_log_file(path=file.parent, command="sign", params=[
                ("file", file), l
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
        log_file=initiate_log_file(path=path, command="scan", params=[
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

    log("\n[-] SPF Check", use_log, log_file)
    final_result = True
    not_pass=0
    with typer.progressbar(length=len(emails), label="  -> scanning") as progress:
        for email in emails:
            result, logs = email.check_spf()
            final_result = final_result and result
            if not result:
                not_pass+=1
                print(f"\r", end="")
                log(f"  -> WARNING id: {email.id}", use_log, log_file)

                for logx in logs:
                    log(f"    -> {logx}", use_log, log_file)
        
            progress.update(1)

    log(f"[{'-' if final_result else '!'}] SPF RESULT: {'PASS' if final_result else 'NOT PASS'}", use_log, log_file)
    if not_pass>0:
        log(f"  -> spf-failed: {not_pass} / {len(emails)}", use_log, log_file)
    
    







    
    
    
        
    



   
    


        


    


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



  




    