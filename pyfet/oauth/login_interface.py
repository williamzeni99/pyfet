from abc import ABC, abstractmethod
from datetime import datetime, timezone
import email
from email.policy import default
import hashlib
from typing import List

class ForensicEmail:
    def __init__(self, email_id: str, raw: bytes):
        self.request_timestamp = datetime.now(timezone.utc)
        self.id = email_id #message id of the email
        self.raw = raw #raw email file
        self.sha256 = self.calculate_sha256(raw)
        self.sha1 = self.calculate_sha1(raw)
        self.md5 = self.calculate_md5(raw)
        self.filename = f"{self.calculate_sha256(email_id.encode())}.eml"
    
    def __str__(self) -> str:
        return (f"ForensicEmail[ id='{self.id}', "
                f"saved_at='{self.save_timestamp.strftime('%Y-%m-%d %H:%M:%S')}', "
                f"sha256='{self.sha256}', "
                f"sha1='{self.sha1}', "
                f"md5='{self.md5}']")
    
    def set_save_timestamp(self):
        self.save_timestamp=datetime.now(timezone.utc)


    @staticmethod
    def calculate_sha256(data:bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def calculate_sha1(data:bytes) -> str:
        return hashlib.sha1(data).hexdigest()

    @staticmethod
    def calculate_md5(data:bytes) -> str:
        return hashlib.md5(data).hexdigest()

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

class OAuth(ABC):
    @abstractmethod
    def login(self):
        """Get access token or authentication in general"""
        pass

    @abstractmethod
    def getMe(self)->str:
        """Get my email and info"""
        pass
    
    @abstractmethod
    def search_emails(self, query)-> List[ForensicEmail]:
        """
        Use the user or token granted from login to get a List of Forensic Emails
        :param query: custom research query from given api
        :return List of ForensicEmail objects.
        """
        pass



