import json
from pathlib import Path
from typing import IO

import typer

def find_provider_by_domain(domain, json_data):
    for provider, details in json_data.items():
        if domain in details.get("domains", []):
            return provider
    return None

# # Esempio di utilizzo
# json_data = {
#     "google": {
#         "domains": [
#             "gmail.com"
#         ],
#         "client_id": "MYCLIENT",
#         "client_secret": "MYSECRET",
#         "server_port": 8000
#     },
#     "microsoft": {
#         "domains": [
#             "outlook.com",
#             "hotmail.com"
#         ],
#         "tenat_id": "MYTENANT",
#         "client_secret": "MYSECRET"
#     }
# }

# domain = "gmail.com"
# provider = find_provider_by_domain(domain, json_data)

# if provider:
#     print(f"L'oggetto che contiene il dominio '{domain}' è: {provider}")
# else:
#     print(f"Nessun oggetto trovato per il dominio '{domain}'")


def cli_print():
    save_path = Path().resolve()/"miao.txt"

    with open(save_path, "w") as file:
        x = file.read()
        typer.echo(message="MIAO", file=file)



cli_print()