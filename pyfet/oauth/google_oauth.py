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

import typer
from pyfet.oauth.login_interface import ForensicEmail, OAuth
import webbrowser

class GoogleOAuth(OAuth):
    def __init__(self, client_id:str, client_secret:str, port:int):
        self.client_id = client_id
        self.client_secret= client_secret
        self.port=port
        self.credentials = None
    
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
    
    def getMe(self)-> str :
        if self.credentials is None:
            raise Exception("credentials not found: use login() first")
        service = build('gmail', 'v1', credentials=self.credentials)
        profile = service.users().getProfile(userId='me').execute()
        if profile['emailAddress']:
            return profile['emailAddress']
        else:
            raise Exception("something went wrong")  

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
        next_page_token = results.get('nextPageToken')

        print(f"\r  -> found {len(messages)} emails", end="")
        page=0
        # Continue fetching emails if there are more pages
        while next_page_token:
            page+=1
            print(f"\r  -> found {len(messages)} emails... in {page} page ", end="")
            results = service.users().messages().list(userId='me', q=query, pageToken=next_page_token).execute()
            messages.extend(results.get('messages', []))
            next_page_token = results.get('nextPageToken')
        
        if len(messages)==0:
            raise Exception("no message found")
        
        print(f"\r  -> found {len(messages)} emails")

        with typer.progressbar(length=len(messages), label="  -> downloading") as progress:
            for msg in messages:
                # Get the email message by ID
                msg_id = msg['id']
                msg_data = service.users().messages().get(userId='me', id=msg_id, format='raw').execute()

                # Decode the raw email
                raw_email = base64.urlsafe_b64decode(msg_data['raw'])

                # Create a ForensicEmail object
                forensic_email = ForensicEmail(email_id=msg_id, raw=raw_email)
                forensic_emails.append(forensic_email)
                progress.update(1)
        
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
    
    def log_message(self, format, *args):
        # Non fa nulla, quindi non stampa i log
        pass

    def log_error(self, format, *args):
        pass

    def log_date_time_string(self):
        pass

    def log_request(self, code='-', size='-'):
        pass

    

def start_http_server(port):
    server_address = ('', port)
    httpd = HTTPServer(server_address, OAuthCallbackHandler)
    httpd.handle_request()
    return httpd.auth_code

# def start_http_server(port):
#     server_address = ('', port)
#     httpd = HTTPServer(server_address, OAuthCallbackHandler)
    
#     # Utilizza serve_forever per gestire le richieste continuamente
#     httpd.timeout = 1  # Imposta un timeout per non bloccare indefinitamente
#     while not hasattr(httpd, 'auth_code'):  # Continua finché non si riceve il codice
#         httpd.handle_request()
    
#     return httpd.auth_code