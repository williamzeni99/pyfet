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
        typer.echo(f"  Save path: {config_path}")
    if q:
        typer.echo(f"  Search query: {q}")
    

    typer.echo("\n")
    commands.get_cli(save_path=save_path, config_path=config_path, q=q)

@app.command("verify")
def checktamper(
    folder: Optional[Path] = typer.Argument(default="./",exists=True, file_okay=False, dir_okay=True, writable=True, help="Folder with the emails and the report")
):
    """
    It checks the hashes from the report and looks if some email is missing. 
    NOTE: this method doesn't assure the folder has not been tampered 
    (no sign verification applied) 
    """
    print_graphic()
    typer.echo(f"Verify integrity of the files")
    typer.echo(f"  folder path: {folder}\n")
    commands.verify_cli(path=folder)