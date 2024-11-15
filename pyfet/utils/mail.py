from datetime import datetime, timezone
from email.policy import default
import imaplib
import json
from pathlib import Path
import socket
from typing import List, Tuple
import requests
import typer
import xmltodict
from pyfet.oauth.IMAP_auth import IMAPAuth

from pyfet.oauth.google_oauth import GoogleOAuth
from pyfet.oauth.login_interface import ForensicEmail, Auth
from pyfet.oauth.microsoft_oauth import MicrosoftOAuth
from pyfet.sniffer.utils import ForensicSniffer

class IMAPConfig:
    def __init__(self, host: str, port: int = 993, ssl: bool = True):
        self.host = host
        self.port = port
        self.ssl = ssl

    def __str__(self):
        ssl_status = "Enabled" if self.ssl else "Disabled"
        return f"[ host='{self.host}', port={self.port}, ssl={ssl_status} ]"

def get_manual_imap_config() -> IMAPConfig:
    """
    Prompts the user for manual IMAP configuration settings.

    Args:
        email (str): The user's email address (currently unused, but could be used to suggest defaults).

    Returns:
        IMAPConfig: An object containing the manually entered IMAP configuration.
    """
    host = typer.prompt("> insert host (ex: imap.gmail.com)")
    
    # Prompt for the port and validate input
    while True:
        try:
            port = typer.prompt("> insert port (default: 993)", default=993)
            port = int(port)  # Attempt to convert to integer
            break  # If successful, exit the loop
        except ValueError:
            typer.echo("[!] Invalid input. Please enter a valid number for the port.")

    # Ask for SSL as a boolean input
    ssl = typer.confirm("> Use SSL?", default=True)

    # Return the configured IMAPConfig object
    return IMAPConfig(host=host, port=port, ssl=ssl)

def get_automatic_imap_config(email: str):
    # Split the email to get the domain
    parts = email.split("@")
    domain = parts[1]
    url = f"https://autoconfig.thunderbird.net/v1.1/{domain}"
    
    # Make an HTTP GET request
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an error for bad responses
    except requests.RequestException as e:
        return None, e
    
    data = xmltodict.parse(response.content)
    
    incoming_servers = data['clientConfig']['emailProvider']['incomingServer']
    
    # Se incomingServer è una lista, cerca il primo con tipo "imap"
    if isinstance(incoming_servers, list):
        for server in incoming_servers:
            if server['@type'] == 'imap':
                return IMAPConfig(
                    host=server['hostname'],
                    port=int(server['port']),
                    ssl= server['socketType']=="SSL"
                ), None
            
    elif incoming_servers['@type'] == 'imap':  # Gestisci il caso in cui ci sia solo un server
         return IMAPConfig(
                    host=server['hostname'],
                    port=int(server['port']),
                    ssl= server['socketType']=="SSL"
                ), None
   
    return None, ValueError(f"Config not found: {domain}")  # Handle case with no configuration

def loginIMAP(email:str, password:str, imapConfig):

    """
    Logs into an IMAP server with the provided credentials.

    Args:
        email (str): The user's email address.
        password (str): The user's password.
        imapConfig (IMAPConfig): Configuration object containing IMAP server details.

    Returns:
        imaplib.IMAP4_SSL: An authenticated mail object if login is successful.
    
    Raises:
        imaplib.IMAP4.error: If the login fails due to incorrect credentials or other issues.
    """
    
    if imapConfig.ssl:
        mail = imaplib.IMAP4_SSL(imapConfig.host, imapConfig.port)
    else:
        mail = imaplib.IMAP4(imapConfig.host, imapConfig.port)

    # Attempt to login
    try:
        mail.login(email, password)
        return mail, None
    except imaplib.IMAP4.error as e:
        return  None,f"{e.args[0].decode('utf-8')}"
    except (socket.timeout, TimeoutError) as e:
        return None, "connection timed out. Please check your network and server settings."


def save_emails(path: Path, emails: List[ForensicEmail])->str:
    """
    Save the raw emails in EML format to a new directory named export-(date) under the specified path.

    :param path: The base directory where the EML files will be saved.
    :param emails: List of ForensicEmail objects to save.

    :return: export directory name
    """
    # Get the current UTC datetime and format it
    current_utc_time = datetime.now(timezone.utc)
    formatted_date = current_utc_time.strftime("%Y%m%d%H%M%S")
    
    # Create the new directory name
    export_dir_name = f"export-{formatted_date}"
    export_path = path / export_dir_name
    email_path = export_path / "emails"

    # Ensure the export path exists
    export_path.mkdir(parents=True, exist_ok=True)
    email_path.mkdir(parents=True, exist_ok=True)

    with typer.progressbar(length=len(emails), label="  -> saving") as progress:
        for email in emails:
            # Construct the filename using the email ID
            file_path = email_path / email.filename
            
            # Save the raw email content to the file
            with open(file_path, 'wb') as f:
                f.write(email.raw)
                email.set_save_timestamp()

            progress.update(1)
    
    return export_dir_name

def generate_report(
    extraction_name: str,
    user_email: str,
    query:str,
    forensic_emails: List[ForensicEmail], 
    save_path: Path,
    sniffer: ForensicSniffer|None
):
    """
    Generate a JSON report of the email extraction results.

    :param extraction_name: Name of the extraction.
    :param email: Email address associated with the extraction.
    :param start_date: Start date of the research.
    :param end_date: End date of the research.
    :param keywords: List of keywords used in the search.
    :param forensic_emails: List of ForensicEmail objects obtained from the extraction.
    :param save_path: original path requested from the user
    :return: JSON report as a string.
    """
    report = {
        "name": extraction_name,
        "email": user_email,
        "search_query":query
    }

    if sniffer is not None:
        report["recorded_pcap"]={}
        report["recorded_pcap"]["filename"] = str(sniffer.save_file.filename)
        report["recorded_pcap"]["sha256"] = sniffer.save_file.sha256
        report["recorded_pcap"]["sha1"] = sniffer.save_file.sha1
        report["recorded_pcap"]["md5"] = sniffer.save_file.md5
        report["session_keys"]={}
        report["session_keys"]["filename"] = str(sniffer.session_keys_file.filename)
        report["session_keys"]["sha256"] = sniffer.session_keys_file.sha256
        report["session_keys"]["sha1"] = sniffer.session_keys_file.sha1
        report["session_keys"]["md5"] = sniffer.session_keys_file.md5
    
    report["emails"]=[]


    # Create a progress bar for processing forensic emails
    with typer.progressbar(length=len(forensic_emails), label="  -> writing") as progress:
        for email in forensic_emails:
            report["emails"].append({
                "request_timestamp": email.request_timestamp.isoformat(),
                "save_timestamp": email.save_timestamp.isoformat(),
                "filename": email.filename,
                "id": email.id,
                "sha256": email.sha256,
                "sha1": email.sha1,
                "md5": email.md5,
            })
            # Update the progress bar
            progress.update(1)

    # Convert report to JSON
    report_json = json.dumps(report, indent=4)

    # Save the report to a file
    report_filename = f"{extraction_name}_report.json"
    export_path = save_path/extraction_name/report_filename 
    with open(export_path, 'w', encoding='utf-8') as f:
        f.write(report_json)
    return report_json


def getAuth_from_domain(domain:str, config_path)-> Tuple[Auth, str]:

    with open(config_path, 'r') as file:
        config = json.load(file)


    if domain=="google":
        google = config["google"]
        client_id=google["client_id"]
        client_secret=google["client_secret"]
        port=google["server_port"]

        if client_id=="":
            return None, "you forget to configure client_id in the configuration file"
        if client_secret=="":
            return None, "you forget to configure client_secret in the configuration file"
        if port=="":
            return None, "you forget to configure port in the configuration file"

        return GoogleOAuth(client_id=client_id, client_secret=client_secret, port=port), None
    
    #todo implementa microsoft

    if domain=="microsoft":
        microsoft=config["microsoft"]
        client_id=microsoft["client_id"]
        
        if client_id=="":
            return None, "you forget to configure client_id in the configuration file"
       
        return MicrosoftOAuth(client_id=client_id), None

    if domain=="IMAP":
        return IMAPAuth(), None
    
    return None, "domain not implemented yet"

def load_supported_domain(config_path)-> List[str]:

    with open(config_path, 'r') as file:
        config = json.load(file) 
    
    return list(config.keys())
        

    
