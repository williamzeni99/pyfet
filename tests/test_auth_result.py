from pathlib import Path
from typing import List

import typer
from pyfet.scanner.scanner import FET

def test():

    path= Path("/home/williamzeni/Documents/pyfet/export-20241029163340")

    emails:List[FET]=[]

    if path.is_file():
        print("[-] Loading eml file")
        with path.open("rb") as f:
                eml = f.read()
                emails.append(FET(raw=eml, mail_id= path.name))
    else:
        print("[-] Loading eml files" )
        eml_files = list(path.glob("*.eml"))
        print(f"  -> found {len(eml_files)} emails")
        if len(eml_files)==0:
            print("[!] No emails found: scan aborted")
            return
        
        with typer.progressbar(length=len(eml_files), label="  -> loading") as progress:
            for eml_file in eml_files:
                with eml_file.open("rb") as f:
                    eml = f.read()
                    emails.append(FET(raw=eml, mail_id=eml_file.name))
                progress.update(1)
    
    path= Path("/home/williamzeni/Documents/pyfet/export-20241029162646")


    if path.is_file():
        print("[-] Loading eml file")
        with path.open("rb") as f:
                eml = f.read()
                emails.append(FET(raw=eml, mail_id= path.name))
    else:
        print("[-] Loading eml files" )
        eml_files = list(path.glob("*.eml"))
        print(f"  -> found {len(eml_files)} emails")
        if len(eml_files)==0:
            print("[!] No emails found: scan aborted")
            return
        
        with typer.progressbar(length=len(eml_files), label="  -> loading") as progress:
            for eml_file in eml_files:
                with eml_file.open("rb") as f:
                    eml = f.read()
                    emails.append(FET(raw=eml, mail_id=eml_file.name))
                progress.update(1)

    path= Path("/home/williamzeni/Documents/pyfet/export-20241028160329")


    if path.is_file():
        print("[-] Loading eml file")
        with path.open("rb") as f:
                eml = f.read()
                emails.append(FET(raw=eml, mail_id= path.name))
    else:
        print("[-] Loading eml files" )
        eml_files = list(path.glob("*.eml"))
        print(f"  -> found {len(eml_files)} emails")
        if len(eml_files)==0:
            print("[!] No emails found: scan aborted")
            return
        
        with typer.progressbar(length=len(eml_files), label="  -> loading") as progress:
            for eml_file in eml_files:
                with eml_file.open("rb") as f:
                    eml = f.read()
                    emails.append(FET(raw=eml, mail_id=eml_file.name))
                progress.update(1)

    total= len(emails)
    found = 0

    with typer.progressbar(length=len(emails), label="  -> scanning") as progress:
        for email in emails:
            
            receives = email.parsed.get_all("Authentication-Results") or []
            found+=len(receives)
            
            progress.update(1)

    typer.echo(f"not pass: {found}/{total}")


test()