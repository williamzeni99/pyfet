import typer
from typing import Optional, List
from datetime import datetime
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

@app.command()
def get(
    start_date: Optional[datetime] = typer.Option(default=datetime(1900, 1, 1), help="Start date in YYYY-MM-DD format"),
    end_date: Optional[datetime] = typer.Option(default=datetime.now(), help="End date in YYYY-MM-DD format"),
    save_path: Optional[Path] = typer.Option(default="./", exists=True, file_okay=False, dir_okay=True,writable=True, help="Path to save the results"),
    keywords: Optional[bool] = typer.Option(False, help="The tool will ask for search keywords" ),
):  
    print_graphic()
    typer.echo(f"Fetching emails with the following parameters:")
    if start_date:
        formatted = start_date.strftime("%d/%m/%Y")
        typer.echo(f"  Start date: {formatted}")
    if end_date:
        formatted = end_date.strftime("%d/%m/%Y")
        typer.echo(f"  End date: {formatted}")
    if save_path:
        typer.echo(f"  Save path: {save_path}")
    if keywords:
        typer.echo(f"  Search keywords: {keywords}")
    

    typer.echo("\n")
    commands.get_cli(start_date, end_date, save_path, keywords)