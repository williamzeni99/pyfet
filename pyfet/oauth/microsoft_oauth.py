from typing import List

import requests
import typer
from pyfet.oauth.login_interface import ForensicEmail, OAuth
from msal import PublicClientApplication

class MicrosoftOAuth(OAuth):

    def __init__(self, client_id:str):
        self.app = PublicClientApplication(
            client_id=client_id,
            authority=f"https://login.microsoftonline.com/common"
            )
        self.access_token=None
    
    def login(self):
        # initialize result variable to hole the token response
        result = None 

        result = self.app.acquire_token_interactive(scopes=["Mail.Read", "User.Read"])
        if "access_token" in result:
            self.access_token = result["access_token"]
        else:
            raise Exception("login failed")
                    

    
    def getMe(self)->str:
        """
        Retrieve the personal email information of the user from Microsoft Graph.

        Args:
            access_token (str): The access token obtained from MSAL authentication.

        Returns:
            dict: User profile information if successful, otherwise an error message.
        """
        # Microsoft Graph API endpoint for the authenticated user's profile
        endpoint = "https://graph.microsoft.com/v1.0/me"

        if self.access_token is None:
            raise Exception("No access token found: use login() first")

        # Set the authorization header with the access token
        headers = {
            "Authorization": f"Bearer {self.access_token}"
        }

        # Make the request to the Graph API
        response = requests.get(endpoint, headers=headers)

        # Check if the request was successful
        if response.status_code == 200:
            user_info = response.json()
            return user_info.get('userPrincipalName')
        else:
            raise Exception(f"getMe failed: {response.status_code} - {response.json()}")
            
    
    
    def search_emails(self, query)-> List[ForensicEmail]:
        """
        Use the user or token granted from login to get a List of Forensic Emails
        :param query: custom research query from given api
        :return List of ForensicEmail objects.
        """
        # Microsoft Graph API endpoint for retrieving messages
        endpoint = "https://graph.microsoft.com/v1.0/me/messages"

        # Set the authorization header with the access token
        headers = {
            "Authorization": f"Bearer {self.access_token}"
        }

        # Set the query parameters, including the filter
        params = {
            "$top": 100  # Number of messages to retrieve per request (adjust as needed)
        }
        
        if query is not None:
            params["$filter"]=query

        all_emails = []
        next_link = endpoint
        print(f"\r  -> found {len(all_emails)} emails", end="")
        page =0 
        while next_link:
            # Make the request to the Graph API
            response = requests.get(next_link, headers=headers, params=params if next_link == endpoint else None)

            # Check if the request was successful
            if response.status_code == 200:
                # Add the current batch of messages to the list
                page+=1
                emails = response.json().get('value', [])
                print(f"\r  -> found {len(all_emails)} emails... in {page} page ", end="")
                all_emails.extend(emails)

                # Check for the next page link
                next_link = response.json().get('@odata.nextLink')
            else:
                # Return an error message if the request failed
                raise Exception(f"search email failed with status code {response.status_code}: {response.json()}")

        print(f"\r  -> found {len(all_emails)} emails")
        forensic_emails=[]
        with typer.progressbar(length=len(all_emails), label="  -> downloading") as progress:
            for email in all_emails:
                email_id = email['id']
                raw_email = get_raw_email_data(access_token=self.access_token, message_id=email_id)
                forensic_emails.append(ForensicEmail(email_id=email_id, raw=raw_email))
                progress.update(1)
                
        return forensic_emails

def get_raw_email_data(access_token, message_id):
    endpoint = f"https://graph.microsoft.com/v1.0/me/messages/{message_id}/$value"

    # Set the authorization header with the access token
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/octet-stream"  # Request the raw MIME format
    }

    # Make the request to the Graph API
    response = requests.get(endpoint, headers=headers)

    # Check if the request was successful
    if response.status_code == 200:
        return response.content
    else:
        raise Exception(f"unable to download email {message_id}")
