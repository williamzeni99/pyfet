from datetime import datetime, timedelta
import os
import hashlib
import base64
from typing import List
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
import requests
from urllib.parse import urlencode, urlparse, parse_qs
from http.server import BaseHTTPRequestHandler, HTTPServer

from pyfet.oauth.login_interface import ForensicEmail, OAuth
import webbrowser



class GoogleOAuth(OAuth):
    def __init__(self, client_id:str, client_secret:str, port:int):
        self.client_id = client_id
        self.client_secret= client_secret
        self.port=port
    
    def login(self):
       # build the codes for PKCE auth
        code_verifier = generate_code_verifier()
        code_challenge = generate_code_challenge(code_verifier)

        #build the auth url
        authorization_url = (
            f"{AUTHORIZATION_ENDPOINT}?"
            + urlencode({
                "response_type": "code",
                "client_id": self.client_id,
                "redirect_uri": f"{REDIRECT_URI}:{self.port}",
                "scope": SCOPE,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
                "prompt": "consent"
            })
        )

        #open auth web page
        webbrowser.open(authorization_url, new=2)
        # waiting server for answer
        auth_code = start_http_server(self.port)


        # Richiedi il token di accesso
        token_data = {
            "code": auth_code,
            "client_id": self.client_id,
            "redirect_uri": f"{REDIRECT_URI}:{self.port}",
            "grant_type": "authorization_code",
            "code_verifier": code_verifier, 
            "client_secret":self.client_secret
        }

        response = requests.post(TOKEN_ENDPOINT, data=token_data)
        tokens = response.json()
        if "error" in tokens:
            raise ValueError(f"{tokens['error']}:{tokens['error_description']}")
        
        self.credentials= Credentials(
            token=tokens['access_token'], 
            refresh_token=tokens["refresh_token"], 
            scopes=tokens["scope"], 
            expiry=datetime.utcnow() + timedelta(seconds=tokens["expires_in"])
            )
    
    def getMe(self)->str:
        service = build('gmail', 'v1', credentials=self.credentials)
        profile = service.users().getProfile(userId='me').execute()
        return profile['emailAddress']

    def search_emails(self, query)-> List[ForensicEmail]:
        """
        Search Gmail for emails within a date range containing specified keywords.
        :param query: custom research query from given api
        :return: List of ForensicEmail objects.
        """
        service = build('gmail', 'v1', credentials=self.credentials)

        # List of ForensicEmail objects
        forensic_emails = []

        # Perform the search
        results = service.users().messages().list(userId='me', q=query).execute()
        messages = results.get('messages', [])
        if len(messages)==0:
            raise Exception("no message found")
        
        for msg in messages:
            # Get the email message by ID
            msg_id = msg['id']
            msg_data = service.users().messages().get(userId='me', id=msg_id, format='raw').execute()

            # Decode the raw email
            raw_email = base64.urlsafe_b64decode(msg_data['raw'])

            # Create a ForensicEmail object
            forensic_email = ForensicEmail(date=datetime.now(), email_id=msg_id, raw=raw_email)
            forensic_emails.append(forensic_email)
        
        return forensic_emails
        
        

REDIRECT_URI = "http://127.0.0.1"
AUTHORIZATION_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
SCOPE = "https://www.googleapis.com/auth/gmail.readonly"


def generate_code_verifier():
    return base64.urlsafe_b64encode(os.urandom(32)).rstrip(b'=').decode('utf-8')

def generate_code_challenge(verifier):
    code_challenge = hashlib.sha256(verifier.encode('utf-8')).digest()
    return base64.urlsafe_b64encode(code_challenge).rstrip(b'=').decode('utf-8')

class OAuthCallbackHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        query_components = parse_qs(urlparse(self.path).query)
        self.server.auth_code = query_components.get("code", [None])[0]

        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(b"Authentication complete. Close this window.")

def start_http_server(port):
    server_address = ('', port)
    httpd = HTTPServer(server_address, OAuthCallbackHandler)
    httpd.handle_request()
    return httpd.auth_code

