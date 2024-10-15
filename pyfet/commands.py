
import json
import typer
from pyfet.oauth.login_interface import ForensicEmail
import pyfet.utils.mail as mail
from pathlib import Path
import pyfet.utils.generics as tools


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
    
    query=""
    if q:
        query=typer.prompt("> insert search query")

    typer.echo("[-] Searching for emails")

    try:
        email=oauth.getMe()
    except Exception as e:
        typer.echo("[!!!] something strage happend: impossible to read basic data")
        typer.echo(f"more info: {e}")
        return

    emails = oauth.search_emails(query=query)

    typer.echo(f"[-] Saving emails on device")
    extraction_name = mail.save_emails(path=save_path, emails=emails)
    
    typer.echo(f"[-] Generating report")
    mail.generate_report(
        extraction_name=extraction_name, 
        user_email=email,
        query=query, 
        save_path= save_path, 
        forensic_emails=emails
        )
    
    typer.echo("\nREMEMBER TO MANUALLY SIGN YOUR REPORT")
    

def verify_cli(path:Path):

    report_path = path.joinpath(path.name+"_report.json")

    typer.echo("[-] Searching for report")

    try:
        with open(report_path) as report_file:
            report = json.load(report_file)
    except FileNotFoundError:
        typer.echo(f"  -> file {report_path} not found")
        typer.echo(f"  -> searching a json in the folder")

        jsonfile= tools.find_json_file(path)
        if jsonfile==None:
            typer.echo("[!] No report found, verify aborted")
            return
        typer.echo(f"  -> found {jsonfile.name}")

        try:
            with open(jsonfile) as x:
                report= json.load(x)
        except Exception as e:
            typer.echo(f"[!!] Something strange happend: {e}")
            return

    except Exception as e:
        typer.echo(f"[!!] Something strange happend: {e}")
        return

    typer.echo("[-] Loading data from report")

    if "emails" not in report:
        typer.echo("[!] Report not well formatted: emails missing")
        return
    
    emails = report["emails"]
    count_emails = tools.count_eml_files_in_directory(path)
    if len(emails)!= count_emails:
        typer.echo(f"  -> WARNING: number of emails missmatch (report {len(emails)}/{count_emails} folder)")
    
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
                id= email["id"]
                sha256 = email["sha256"]
                sha1 = email["sha1"]
                md5 = email["md5"]
            except Exception as e:
                email_notwell_formatted.append(email)
                continue

            email_path = path / f"{id}.eml"

            if not email_path.is_file():
                missing_emails.append(id)
                continue

            with open(email_path, 'rb') as y:
                x=y.read()
                if(ForensicEmail.calculate_sha256(x)!=sha256):
                    email_tampered.append({
                        "id":id, 
                        "error": "sha256 missmatch"
                        })
                    continue

                if(ForensicEmail.calculate_sha1(x)!=sha1):
                    email_tampered.append({
                        "id":id, 
                        "error": "sha1 missmatch"
                        })
                    continue

                if(ForensicEmail.calculate_md5(x)!=md5):
                    email_tampered.append({
                        "id":id, 
                        "error": "md5 missmatch"
                        })
                    continue

            email_ok.append(id)
        
        
        typer.echo("\n\n[-] RECAP")
        typer.echo(f"  -> email missing: {len(missing_emails)}")
        for x in missing_emails:
            typer.echo(f"     {x}")

        typer.echo(f"  -> email not well formatted in report (positional referiment): {len(email_notwell_formatted)}")
        for x in email_notwell_formatted:
            pretty = json.dumps(x, indent=4)
            indented_json = "\n".join("    " + line for line in pretty.splitlines())
            typer.echo(f"{indented_json}")
        
        typer.echo(f"  -> email tampered: {len(email_tampered)}")
        for x in email_tampered:
            typer.echo(f"     {x['id']}  {x['error']}")
        
        eml_files=[]
        for file in path.glob('*.eml'):
            if file.is_file():
                eml_files.append(file.stem)
        
        set_ok=set(email_ok)
        set_tampered =set([entry["id"] for entry in email_tampered])
        set_eml_files= set(eml_files)

        missmatch = set_eml_files - set_ok.union(set_tampered)
        missmatch = list(missmatch)
        typer.echo(f"  -> email in folder but not in the report: {len(missmatch)}")
        for x in missmatch:
            typer.echo(f"     {x}")

        
        if len(missmatch)+len(missing_emails)+len(email_tampered)+len(email_notwell_formatted)==0:
            typer.echo("\n\n[-] RESULT: Verification successful")
        else:
            typer.echo("\n\n[!] RESULT: Verification failed")

        






    
    
    
        
    



   
    


        


    


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



  




    