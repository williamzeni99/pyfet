
import typer
import pyfet.utils.mail as mail
from pathlib import Path



def get_cli(save_path:Path, config_path:Path, q:bool):
    try:
        domains= mail.load_supported_domains(config_path=config_path)

        typer.echo("Currently supported domains:")
        for x in domains:
            typer.echo(f"  {x}")
        
        typer.echo("\n")

        while True:
            domain = typer.prompt("> insert a domain for login")

            if domain in domains:
                break

            typer.echo("[!] domain not supported")
        
        typer.echo("[-] Searching OAuth internal config")
        (oauth, err)=mail.getOAuth_from_domain(domain=domain, config_path=config_path)
        if err!=None:
            typer.echo(f"[!] Some error occurred: {err}")
            return
    except Exception as e:
        typer.echo("[!!!] Something went wrong. Configuration file not found or bad formatting.")
        typer.echo(f"More info: {e}")
        return

    try:
        typer.echo("[-] Starting login phase")
        oauth.login()
        typer.echo("[-] Login successfull")
    except Exception as e:
        typer.echo(f"[!] Login Failed:{e}")
        return
    
    typer.echo("[-] Searching for emails")
    query=""
    if q:
        query=typer.prompt("> insert search query")

    try:
        email=oauth.getMe()
    except Exception as e:
        typer.echo("[!!!] something strage happend: impossible to read basic data")
        typer.echo(f"More info: {e}")
        return

    emails = oauth.search_emails(query=query)
    typer.echo(f"[-] {len(emails)} emails found")
    typer.echo(f"[-] downloading emails")
    extraction_name = mail.save_emails(path=save_path, emails=emails)
    typer.echo(f"[-] emails downloaded")
    typer.echo(f"[-] generating report")
    mail.generate_report(
        extraction_name=extraction_name, 
        user_email=email,
        query=query, 
        save_path= save_path, 
        forensic_emails=emails
        )
    typer.echo(f"[-] report generated")
    typer.echo("\nREMEMBER TO MANUALLY SIGN YOUR REPORT")
    


   
    


        


    


# def get_cli(start_date:datetime, end_date:datetime, save_path:Path, keywords:bool):

#     while True:
#         email = typer.prompt("> insert email")

#         if tools.is_valid_email(email):
#             break

#         typer.echo("[!] Email not valid")
    
#     password = typer.prompt("> insert password", hide_input=True)
#     typer.echo("[-] Searching for configuration")
#     (config, error) = mail.get_automatic_imap_config(email)
#     if error!= None:
#         typer.echo("[!] Configuration not found")
#         typer.echo(f"[-] Asking manual configuration")
#         config = mail.get_manual_imap_config()
#     else:
#         typer.echo(f"[-] Configuration found: {config}")
    
#     typer.echo("[-] Login attempt")
#     user, err = mail.login(email=email, password=password,imapConfig=config)
#     if err!=None:
#         typer.echo(f"[!] Login failed: {err}")
#         return
    
#     typer.echo("[-] Login successfull")

#     if keywords:
#         typer.echo("[-] Asking keywords")
#         keywords=typer.prompt(">insert keywords divided by space (ex: home people printer)").split(" ")
#     else:
#         keywords=None
        

#     typer.echo("[-] Searching emails")
#     (mails, err) = mail.search_emails(user, start_date,end_date,keywords)
#     if err!=None:
#         typer.echo(f"[!] Search failed: {err}")
#         return
#     typer.echo(f"[-] {len(mails)} emails found")

#     typer.echo(f"[-] Saving emails")
#     extraction_name= mail.save_emails(path=save_path, emails=mails)
#     typer.echo(f"[-] Emails saved")
#     typer.echo(f"[-] Generating report")
#     mail.generate_report(extraction_name=extraction_name, email=email, start_date=start_date, end_date=end_date, keywords=keywords,forensic_emails=mails, save_path=save_path )
#     typer.echo(f"[-] Report saved")



  




    