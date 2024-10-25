from typing import List
from pyfet.oauth.login_interface import ForensicEmail, OAuth
from msal import PublicClientApplication

class MicrosoftOAuth(OAuth):

    def __init__(self, client_id:str, client_secret:str, tenant_id:str, secret_id:str,  port:int):
        self.client_id = client_id
        self.client_secret= client_secret
        self.port=port
        self.tenant_id=tenant_id
        self.secret_id=secret_id
        self.app = PublicClientApplication(
            client_id=client_id,
            authority=f"https://login.microsoftonline.com/{tenant_id}"
            )
    
    def login(self):
        # initialize result variable to hole the token response
        result = None 

        result = self.app.acquire_token_interactive(scopes=["Mail.Read", "User.Read", "Mail.Read.Shared"])
        if "access_token" in result:
            print(result["access_token"])  
        else:
            print(result.get("error"))
            print(result.get("error_description"))
            print(result.get("correlation_id"))  
                    

    
    def getMe(self)->str:
        """Get my email and info"""
        pass
    
    
    def search_emails(self, query)-> List[ForensicEmail]:
        """
        Use the user or token granted from login to get a List of Forensic Emails
        :param query: custom research query from given api
        :return List of ForensicEmail objects.
        """
        pass

