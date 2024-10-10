from datetime import datetime
from email.message import Message
from email.policy import default
import hashlib
import imaplib
import json
from pathlib import Path
import socket
from typing import List, Optional, Tuple
import requests
from lxml import etree
import typer
import xmltodict
import email

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


def login(email:str, password:str, imapConfig):

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



class ForensicEmail:
    def __init__(self, date: datetime, email_id: str, raw: str):
        self.date = date
        self.id = email_id
        self.raw = raw
        self.sha256 = self.calculate_sha256(raw)
        self.sha1 = self.calculate_sha1(raw)
        self.md5 = self.calculate_md5(raw)
        self.parsed= self.parse(raw)
    
    def __str__(self) -> str:
        return (f"ForensicEmail[ id='{self.id}', "
                f"date='{self.date.strftime('%Y-%m-%d %H:%M:%S')}', "
                f"sha256='{self.sha256}', "
                f"sha1='{self.sha1}', "
                f"md5='{self.md5}']")
    
    @staticmethod
    def parse(raw:str):
        """
        Parse the raw email and return an EmailMessage object.

        :return: Parsed email as an EmailMessage object.
        """
        return email.message_from_string(raw, policy=default)

    @staticmethod
    def calculate_sha256(data: str) -> str:
        return hashlib.sha256(data.encode('utf-8')).hexdigest()

    @staticmethod
    def calculate_sha1(data: str) -> str:
        return hashlib.sha1(data.encode('utf-8')).hexdigest()

    @staticmethod
    def calculate_md5(data: str) -> str:
        return hashlib.md5(data.encode('utf-8')).hexdigest()

    def get_basics(self)-> dict:
        parsed_email = self.parsed
        sender = parsed_email["From"]
        subject = parsed_email["Subject"]
        body = ""
        if parsed_email.is_multipart():
            # If the email is multipart, get the payload
            for part in parsed_email.iter_parts():
                if part.get_content_type() == 'text/plain':
                    body = part.get_payload(decode=True).decode(part.get_content_charset())
                    break
        else:
            # If it's not multipart, get the payload directly
            body = parsed_email.get_payload(decode=True).decode(parsed_email.get_content_charset())
        
        return {
            'Sender': sender,
            'Subject': subject,
            'Body': body[:50]+"..."
        }



def search_emails(imap_client: imaplib.IMAP4_SSL | imaplib.IMAP4, start_date: datetime, end_date: datetime, keywords: List[str] = None) -> Tuple[List[ForensicEmail], str|None]:
    """
    Search for emails within a date range with specific keywords and return them in raw format.

    :param imap_client: The authenticated and connected IMAP client.
    :param start_date: Start date for the search (datetime object).
    :param end_date: End date for the search (datetime object).
    :param keywords: Optional list of keywords to search for in the subject or body of the emails.
    :return: List of emails in raw format.
    """

    # Convert the datetime objects to the required IMAP format (DD-Month-YYYY)
    def format_date(date_obj: datetime) -> str:
        return date_obj.strftime("%d-%b-%Y")

    start_date_imap = format_date(start_date) if start_date else None
    end_date_imap = format_date(end_date) if end_date else None

    # Select the inbox
    imap_client.select("INBOX")

    # Build the search query
    search_criteria = []
    if start_date_imap:
        search_criteria.append(f'SINCE "{start_date_imap}"')
    if end_date_imap:
        search_criteria.append(f'BEFORE "{end_date_imap}"')

    if keywords:
        keyword_query = ' '.join([f'TEXT "{keyword}"' for keyword in keywords])
        search_criteria.append(keyword_query)

    search_criteria_str = ' '.join(search_criteria)

    # Execute the search
    result, data = imap_client.search(None, search_criteria_str)

    if result != 'OK':
        return [],"Error occurred while searching for emails."

    email_ids = data[0].split()

    forensic_emails = []

    # Fetch emails in raw format
    for email_id in email_ids:
        result, email_data = imap_client.fetch(email_id, '(RFC822)')
        
        if result == 'OK':
            raw_email = email_data[0][1].decode('utf-8')
            email_date = datetime.now()  # Or retrieve from the email header if needed
            forensic_email = ForensicEmail(
                date=email_date,
                email_id=email_id.decode('utf-8'),
                raw=raw_email
            )
            forensic_emails.append(forensic_email)
        else:
            return [],f"Error retrieving email with ID {email_id}."
        
    if len(forensic_emails)==0:
        return [],f"no email found"

    return forensic_emails, None


def save_emails(path: Path, emails: List[ForensicEmail])->str:
    """
    Save the raw emails in EML format to a new directory named export-(date) under the specified path.

    :param path: The base directory where the EML files will be saved.
    :param emails: List of ForensicEmail objects to save.
    """
    # Get the current UTC datetime and format it
    current_utc_time = datetime.utcnow()
    formatted_date = current_utc_time.strftime("%Y%m%d%H%M%S")
    
    # Create the new directory name
    export_dir_name = f"export-{formatted_date}"
    export_path = path / export_dir_name

    # Ensure the export path exists
    export_path.mkdir(parents=True, exist_ok=True)

    with typer.progressbar(length=len(emails), label="[\] Saving emails") as progress:
        for email in emails:
            # Construct the filename using the email ID
            filename = f"{email.id}.eml"
            file_path = export_path / filename
            
            # Save the raw email content to the file
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(email.raw)

            progress.update(1)
    
    return export_dir_name


def generate_report(
    extraction_name: str,
    email: str,
    start_date: datetime,
    end_date: datetime,
    keywords: List[str],
    forensic_emails: List[ForensicEmail], 
    save_path: Path
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
        "email": email,
        "research criteria": {
            "start-date": start_date.isoformat(),
            "end-date": end_date.isoformat(),
            "keywords": keywords
        },
        "emails": []
    }

    # Create a progress bar for processing forensic emails
    with typer.progressbar(length=len(forensic_emails), label="[\] Generating report") as progress:
        for email in forensic_emails:
            report["emails"].append({
                "download_date": email.date.isoformat(),
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

    

    