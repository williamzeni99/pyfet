import typer
from typing import Optional
from pyfiglet import Figlet
import pyfet.commands as commands
from pathlib import Path

app = typer.Typer()

if __name__ == "__main__":
    app()

@app.callback()
def main() -> None:
    """Pyfet: A Python Forensics Email Tool."""
    pass  # The main function is just a placeholder for the callback

def print_graphic():
    f = Figlet(font='slant')
    typer.echo(f.renderText('pyfet'))

@app.command("get")
def get(
    save_path: Optional[Path] = typer.Option(default="./", exists=True, file_okay=False, dir_okay=True,writable=True, help="Path to save the results"),
    config_path: Optional[Path] = typer.Option(default="./config.json", exists=True, file_okay=True, dir_okay=False,writable=True, help="Path of the configuration file (rename it as config.json)"),
    q: Optional[bool] = typer.Option(False, help="The tool will ask for a search query" ),
):  
    """
    It acquires the emails and creates a report with the file hashes 
    """
    print_graphic()
    typer.echo(f"Fetching emails with the following parameters:")
    if save_path:
        typer.echo(f"  Save path: {save_path}")
    if config_path:
        typer.echo(f"  Config path: {config_path}")
    if q:
        typer.echo(f"  Search query: {q}")
    

    typer.echo("\n")
    commands.get_cli(save_path=save_path, config_path=config_path, q=q)

@app.command("check")
def checktamper(
    folder: Optional[Path] = typer.Argument(default=Path().resolve(),exists=True, file_okay=False, dir_okay=True, writable=True, help="Folder with the emails and the report")
):
    """
    It checks the hashes from the report and looks if some email is missing. 
    NOTE: this method doesn't assure the folder has not been tampered, it just checks
    the integrity of the content.   
    """
    print_graphic()
    typer.echo(f"It checks the integrity of the folder")
    typer.echo(f"  folder path: {folder}\n")
    commands.check_cli(path=folder)

@app.command("sign")
def sign(
    file: Path = typer.Argument(exists=True, file_okay=True, dir_okay=False, writable=True, help="File to sign"),
    pkey: Path = typer.Argument(exists=True, file_okay=True, dir_okay=False, writable=True, help="private_key.pem"),
    cert: Path = typer.Argument(exists=True, file_okay=True, dir_okay=False, writable=True, help="certificate.pem"),
):
    """
    This method signs the file with the p7m standard.
    It deletes the old file. 
    """
    print_graphic()
    typer.echo(f"Signing {file}")
    typer.echo(f"  -> private key: {pkey}")
    typer.echo(f"  -> certificate: {cert}")

    typer.echo("\n")
    commands.sign_cli(file=file, pkey=pkey, cert=cert)


@app.command("verify")
def verify(
    file: Path = typer.Argument(exists=True, file_okay=True, dir_okay=False, writable=True, help="Signed p7m file to verify"),
    cert: Path = typer.Argument(exists=True, file_okay=True, dir_okay=False, writable=True, help="certificate.pem"),
):
    """
    This method verify the signed p7m document.
    """
    print_graphic()
    typer.echo(f"Verifying {file}")
    typer.echo(f"  -> certificate: {cert}")

    typer.echo("\n")
    commands.verify_cli(signed_file=file, cert=cert)