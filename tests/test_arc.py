

from pathlib import Path
from typing import List
import dkim as dikimpy

import typer

from pyfet.scanner.scanner import FET


emails:List[FET]=[]

email_path= Path("/home/williamzeni/Documents/pyfet/export-20241114130940/emails")
eml_files = list(email_path.glob("*.eml"))


with typer.progressbar(length=len(eml_files), label="  -> loading") as progress:
    for eml_file in eml_files:
        with eml_file.open("rb") as f:
            eml = f.read()
            emails.append(FET(raw=eml, mail_id=eml_file.name))
        progress.update(1)


for email in emails:
    result,_,reason= dikimpy.arc_verify(email.raw)
    print(result, reason)