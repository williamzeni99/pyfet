from typing import List
from pyfet.oauth.login_interface import Auth, ForensicEmail
import typer
import pyfet.utils.mail as mail

class IMAPAuth(Auth):

    def __init__(self) -> None:
        pass

    def login(self):
        self.email=typer.prompt("> insert email")
        password= typer.prompt("> insert password", hide_input=True)

        
        imap_config = mail.get_manual_imap_config()

        self.mailbox, message = mail.loginIMAP(email=self.email, password=password, imapConfig=imap_config)
        if self.mailbox is None:
            raise Exception(message)
        

    def getMe(self) -> str:
        return self.email
    
    def search_emails(self, query:str) -> List[ForensicEmail]:
        forensic_emails=[]

        self.mailbox.select("INBOX")
        if query=="":
            query = "ALL"

        result, data = self.mailbox.search(None, query)
        if result!="OK":
            raise Exception(f"No messages found. Status: {result}")
        
        email_ids = data[0].split()

        forensic_emails = []

        with typer.progressbar(length=len(email_ids), label="  -> downloading") as progress:
            # Fetch emails in raw format
            for email_id in email_ids:
                result, email_data = self.mailbox.fetch(email_id, '(RFC822)')
                
                if result == 'OK':
                    raw_email = email_data[0][1]
                    forensic_email = ForensicEmail(
                        email_id=email_id.decode('utf-8'),
                        raw=raw_email
                    )
                    forensic_emails.append(forensic_email)
                    progress.update(1)
                
            
        if len(forensic_emails)==0:
            raise Exception(f"No messages found.")

        return forensic_emails