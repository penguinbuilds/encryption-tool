import shutil
from pathlib import Path


def archive_folder(folder_path: Path) -> Path:
    archive_path = shutil.make_archive(folder_path, "zip", folder_path)
    return Path(archive_path)


def extract_archive(zip_path: Path, extract_to: Path) -> None:
    shutil.unpack_archive(zip_path, extract_to)
