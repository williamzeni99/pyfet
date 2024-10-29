from pathlib import Path
from typing import List

import typer

from pyfet.headerparser import parser
from pyfet.scanner.scanner import FET


def test():

    path= Path("/home/williamzeni/Documents/pyfet/export-20241028160329")

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

    total=0
    not_pass=0

    file = open("/home/williamzeni/Documents/pyfet/test.txt", "w")
    with typer.progressbar(length=len(emails), label="  -> scanning") as progress:
        for email in emails:
            
            receives = email.parsed.get_all("Received")
            total+=len(receives)
            for received in receives:
                if not parser.validate_received_header_RFC5322(received):
                    not_pass+=1
                    typer.echo(message=received, file=file)
                    typer.echo(message="####################", file=file)

            progress.update(1)

    typer.echo(f"not pass: {not_pass}/{total}", file=file)
    typer.echo(f"not pass: {not_pass}/{total}")


def test2():

    path= Path("/home/williamzeni/Documents/pyfet/export-20241028155746")

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

    total=0
    not_pass=0

    file = open("/home/williamzeni/Documents/pyfet/test2.txt", "w")
    with typer.progressbar(length=len(emails), label="  -> scanning") as progress:
        for email in emails:
            
            receives = email.parsed.get_all("Return-Path") or []
            total+=len(receives)
            for received in receives:
                if not parser.validate_return_path_header_RFC5321(received):
                    not_pass+=1
                    typer.echo(message=received, file=file)
                    typer.echo(message="####################", file=file)

            progress.update(1)

    typer.echo(f"not pass: {not_pass}/{total}", file=file)
    typer.echo(f"not pass: {not_pass}/{total}")
         

test2()