import argparse
import logging
import os
import pathlib
import stat
import time
import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Creates a timeline of file modifications, access times, and metadata changes for forensic investigations.")
    parser.add_argument("path", help="The path to the file or directory to analyze.")
    parser.add_argument("-r", "--recursive", action="store_true", help="Recursively process all files in the directory.")
    parser.add_argument("-o", "--output", help="The output file to write the timeline to. Defaults to stdout.", default=None)
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging.")
    return parser.parse_args()

def get_file_metadata(file_path):
    """
    Retrieves metadata for a given file path.

    Args:
        file_path (pathlib.Path): The path to the file.

    Returns:
        dict: A dictionary containing file metadata.
    """
    try:
        stat_info = file_path.stat()

        metadata = {
            "file_path": str(file_path),
            "file_name": file_path.name,
            "file_size": stat_info.st_size,
            "modified_time": datetime.datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
            "accessed_time": datetime.datetime.fromtimestamp(stat_info.st_atime).isoformat(),
            "created_time": datetime.datetime.fromtimestamp(stat_info.st_ctime).isoformat(),
            "permissions": stat.filemode(stat_info.st_mode),
            "owner_uid": stat_info.st_uid,
            "owner_gid": stat_info.st_gid,
        }
        return metadata
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
        return None
    except OSError as e:
        logging.error(f"Error accessing file {file_path}: {e}")
        return None

def process_file(file_path, output_file=None):
    """
    Processes a single file and writes its metadata to the output.

    Args:
        file_path (pathlib.Path): The path to the file.
        output_file (io.TextIOWrapper, optional): The output file to write to. Defaults to None (stdout).
    """
    metadata = get_file_metadata(file_path)
    if metadata:
        output_string = f"{metadata['modified_time']},{metadata['accessed_time']},{metadata['created_time']},{metadata['file_path']},{metadata['file_name']},{metadata['file_size']},{metadata['permissions']},{metadata['owner_uid']},{metadata['owner_gid']}\n"

        if output_file:
            try:
                output_file.write(output_string)
            except Exception as e:
                logging.error(f"Error writing to output file: {e}")
        else:
            print(output_string, end="")  # Write to stdout
    else:
        logging.warning(f"Could not process file: {file_path}")

def process_directory(dir_path, recursive=False, output_file=None):
    """
    Processes a directory, either recursively or non-recursively.

    Args:
        dir_path (pathlib.Path): The path to the directory.
        recursive (bool, optional): Whether to process the directory recursively. Defaults to False.
        output_file (io.TextIOWrapper, optional): The output file to write to. Defaults to None (stdout).
    """
    try:
        if recursive:
            for file_path in dir_path.rglob("*"):
                if file_path.is_file():
                    process_file(file_path, output_file)
        else:
            for file_path in dir_path.iterdir():
                if file_path.is_file():
                    process_file(file_path, output_file)
    except OSError as e:
        logging.error(f"Error accessing directory {dir_path}: {e}")


def main():
    """
    Main function to drive the file forensic timeline tool.
    """
    args = setup_argparse()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    path = pathlib.Path(args.path)

    # Input validation
    if not path.exists():
        logging.error(f"Path does not exist: {args.path}")
        return

    output_file_object = None
    if args.output:
        try:
            output_file_object = open(args.output, "w", encoding="utf-8")
        except Exception as e:
            logging.error(f"Error opening output file: {e}")
            return

    try:
        if path.is_file():
            process_file(path, output_file_object)
        elif path.is_dir():
            process_directory(path, args.recursive, output_file_object)
        else:
            logging.error("Invalid path type.  Must be a file or directory.")
    finally:
        if output_file_object:
            output_file_object.close() # Ensure the file is closed.

if __name__ == "__main__":
    main()

# Usage Examples:
# 1. Analyze a single file and print to stdout:
#    python file_forensic_timeline.py /path/to/file.txt

# 2. Analyze a directory recursively and print to stdout:
#    python file_forensic_timeline.py /path/to/directory -r

# 3. Analyze a single file and write to a file:
#    python file_forensic_timeline.py /path/to/file.txt -o output.csv

# 4. Analyze a directory recursively and write to a file:
#    python file_forensic_timeline.py /path/to/directory -r -o output.csv

# 5. Enable verbose logging:
#    python file_forensic_timeline.py /path/to/file.txt -v