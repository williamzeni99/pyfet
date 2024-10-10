import imaplib
import typer
import pyfet.utils.mail as mail
from datetime import datetime
from pathlib import Path
import pyfet.utils.generics as tools


def get_cli(start_date:datetime, end_date:datetime, save_path:Path, keywords:bool):

    while True:
        email = typer.prompt("> insert email")

        if tools.is_valid_email(email):
            break

        typer.echo("[!] Email not valid")
    
    password = typer.prompt("> insert password", hide_input=True)
    typer.echo("[-] Searching for configuration")
    (config, error) = mail.get_automatic_imap_config(email)
    if error!= None:
        typer.echo("[!] Configuration not found")
        typer.echo(f"[-] Asking manual configuration")
        config = mail.get_manual_imap_config()
    else:
        typer.echo(f"[-] Configuration found: {config}")
    
    typer.echo("[-] Login attempt")
    user, err = mail.login(email=email, password=password,imapConfig=config)
    if err!=None:
        typer.echo(f"[!] Login failed: {err}")
        return
    
    typer.echo("[-] Login successfull")

    if keywords:
        typer.echo("[-] Asking keywords")
        keywords=typer.prompt(">insert keywords divided by space (ex: home people printer)").split(" ")
    else:
        keywords=None
        

    typer.echo("[-] Searching emails")
    (mails, err) = mail.search_emails(user, start_date,end_date,keywords)
    if err!=None:
        typer.echo(f"[!] Search failed: {err}")
        return
    typer.echo(f"[-] {len(mails)} emails found")

    typer.echo(f"[-] Saving emails")
    extraction_name= mail.save_emails(path=save_path, emails=mails)
    typer.echo(f"[-] Emails saved")
    typer.echo(f"[-] Generating report")
    mail.generate_report(extraction_name=extraction_name, email=email, start_date=start_date, end_date=end_date, keywords=keywords,forensic_emails=mails, save_path=save_path )
    typer.echo(f"[-] Report saved")



  




    