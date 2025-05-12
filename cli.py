import typer
from pathlib import Path
from typing_extensions import Annotated

from crypt import encrypt, decrypt
from archive import archive_folder, extract_archive

app = typer.Typer()


@app.command()
def obscure(
    path: Annotated[
        Path,
        typer.Argument(
            help="Path to the file or directory that must be encrypted.",
            metavar="PATH",
        ),
    ],
    password: Annotated[
        str,
        typer.Option(
            help="Password for encrypting the file or directory.",
            prompt=True,
            confirmation_prompt=True,
            hide_input=True,
        ),
    ],
) -> None:
    """
    Encrypts a file or directory at the specified path using a password.

    This command reads the content of the specified file or directory and encrypts it using
    the provided password. If the path is a directory, it will first be archived before
    encryption. The encrypted data is saved with a `.obscured` extension, and if a file with
    that name already exists, the user will be prompted for confirmation to overwrite it.

    Arguments:
    - path: The path to the file or directory that needs to be encrypted.
    - password: The password used for encryption. The user will be prompted for this input
    and asked for confirmation, with input hidden.

    If the specified path does not exist or is not a valid file or directory, the operation
    will be aborted with an error message.

    The command will also handle overwriting existing encrypted files by asking for
    confirmation before proceeding.
    """

    path = Path(path)

    if not path.exists():
        typer.echo(f"{path} is not a valid file or directory.")
        raise typer.Exit(code=1)

    if path.is_dir():
        path = archive_folder(path)

    with open(path, "rb") as file:
        data = file.read()

    original_extension = path.suffix
    encrypted_data = encrypt(data, password, original_extension)

    output_path = path.with_suffix(".obscured")

    if output_path.exists():
        should_overwrite = typer.confirm(
            f"{output_path} already exists. Do you want to overwrite it?"
        )
        if not should_overwrite:
            typer.echo("Exiting...")
            raise typer.Exit(code=1)

    with open(output_path, "wb") as file:
        file.write(encrypted_data)

    typer.echo("File encrypted.")


@app.command()
def reveal(
    path: Annotated[
        Path, typer.Argument(help="Path to encrypted file.", metavar="PATH")
    ],
    password: Annotated[
        str,
        typer.Option(
            help="Password for decrypting the file.", prompt=True, hide_input=True
        ),
    ],
) -> None:
    """
    Decrypts an encrypted file and restores it to its original format.

    This command takes an encrypted file and a password, decrypts the content, and saves
    the result with the original file extension. If the file is a zip archive, it will be
    extracted to the same location, and the encrypted zip file will be deleted after extraction.

    Arguments:
    - path: The path to the encrypted file that needs to be decrypted.
    - password: The password used for decryption. The user will be prompted for this input
    with the input hidden.

    If the specified path does not exist or is not a valid file, the operation will be aborted
    with an error message. In case of decryption failure, an error message is displayed, and the
    operation is aborted.

    If the decrypted file already exists, the user will be asked whether to overwrite it.

    If the decrypted file is a zip archive, the contents will be extracted, and the zip file
    will be removed after extraction.
    """

    path = Path(path)

    if not path.exists():
        typer.echo(f"{path} is not a valid file or directory.")
        raise typer.Exit(code=1)

    with open(path, "rb") as file:
        encrypted_data = file.read()

    try:
        decrypted_data, original_extension = decrypt(encrypted_data, password)
    except Exception as e:
        typer.echo(f"Decryption failed: {e}")
        raise typer.Exit(code=1)

    output_path = path.with_suffix("")
    output_path = output_path.with_suffix(original_extension)

    if output_path.is_dir():
        typer.echo(f"{output_path} is a directory, cannot write to it.")
        raise typer.Exit(code=1)

    if output_path.exists():
        should_overwrite = typer.confirm(
            f"{output_path} already exists. Do you want to overwrite it?"
        )
        if not should_overwrite:
            typer.echo("Exiting...")
            raise typer.Exit(code=1)

    with open(output_path, "wb") as f:
        f.write(decrypted_data)

    if output_path.suffix == ".zip":
        extract_to = output_path.with_suffix("")
        if extract_to.exists():
            should_overwrite = typer.confirm(
                f"{extract_to} already exists. Do you want to overwrite it?"
            )
            if not should_overwrite:
                typer.echo("Exiting...")
                raise typer.Exit(code=1)
        extract_archive(output_path, extract_to)
        output_path.unlink()
        typer.echo(f"Extracted to: {extract_to}")
    else:
        typer.echo("File decrypted.")


if __name__ == "__main__":
    app()
