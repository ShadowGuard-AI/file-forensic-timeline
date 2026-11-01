import argparse
import csv
import logging
import os
import pathlib
import stat
import sys
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
        dict: A dictionary containing file metadata, or None on error.
        The third time value is a real creation time (st_birthtime)
        where the platform provides one, labelled created_time.
        Where only st_ctime exists (Linux), it is the inode change
        time and is labelled changed_time.
    """
    try:
        stat_info = file_path.stat()

        if hasattr(stat_info, "st_birthtime"):
            third_label = "created_time"
            third_value = datetime.datetime.fromtimestamp(stat_info.st_birthtime).isoformat()
        else:
            third_label = "changed_time"
            # Every timestamp here is converted with fromtimestamp, which uses the
            # local timezone of the machine running the scan and produces a naive
            # value with no offset recorded. Two timelines built on machines in
            # different timezones cannot be merged by comparing their strings.
            third_value = datetime.datetime.fromtimestamp(stat_info.st_ctime).isoformat()

        metadata = {
            "modified_time": datetime.datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
            "accessed_time": datetime.datetime.fromtimestamp(stat_info.st_atime).isoformat(),
            "third_time_label": third_label,
            "third_time": third_value,
            "file_path": str(file_path),
            "file_name": file_path.name,
            "file_size": stat_info.st_size,
            "permissions": stat.filemode(stat_info.st_mode),
            "owner_uid": stat_info.st_uid,
            "owner_gid": stat_info.st_gid,
            "_mtime": stat_info.st_mtime,
        }
        return metadata
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
        return None
    except OSError as e:
        logging.error(f"Error accessing file {file_path}: {e}")
        return None

def collect_files(path, recursive=False, output_resolved=None):
    """
    Collects the list of files to scan before any output is opened.

    The resolved output path is excluded, so a recursive scan never
    includes its own output file.
    """
    files = []
    if path.is_file():
        candidates = [path]
    elif path.is_dir():
        if recursive:
            candidates = [p for p in path.rglob("*") if p.is_file()]
        else:
            candidates = [p for p in path.iterdir() if p.is_file()]
    else:
        return files
    for candidate in candidates:
        if output_resolved is not None and candidate.resolve() == output_resolved:
            continue
        files.append(candidate)
    return files

def collect_rows(files):
    """Collects metadata rows and sorts them by modification time ascending."""
    rows = []
    for file_path in files:
        metadata = get_file_metadata(file_path)
        if metadata:
            rows.append(metadata)
        else:
            logging.warning(f"Could not process file: {file_path}")
    # Sorting uses the raw epoch value in the underscored key, not the ISO
    # string in the visible column. The string would sort the same way on
    # one machine, but the epoch is the honest key, and the underscore key
    # is left out of the CSV field list in write_rows.
    rows.sort(key=lambda row: row["_mtime"])
    return rows

def write_rows(rows, out):
    """Writes rows as CSV with a header row, using the csv module quoting."""
    if not rows:
        return
    # The header takes its third column name from the first row. Every row
    # in a run shares the label, because the label depends on the platform
    # the scan runs on, not on the file, so borrowing it from row one is
    # safe here.
    third_label = rows[0]["third_time_label"]
    fieldnames = ["modified_time", "accessed_time", third_label, "file_path", "file_name", "file_size", "permissions", "owner_uid", "owner_gid"]
    writer = csv.writer(out)
    writer.writerow(fieldnames)
    for row in rows:
        writer.writerow([
            row["modified_time"],
            row["accessed_time"],
            row["third_time"],
            row["file_path"],
            row["file_name"],
            row["file_size"],
            row["permissions"],
            row["owner_uid"],
            row["owner_gid"],
        ])

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
        sys.exit(1)

    output_resolved = pathlib.Path(args.output).resolve() if args.output else None

    # Settled ruling: refuse when the output would overwrite a scanned file.
    if output_resolved is not None and path.is_file() and output_resolved == path.resolve():
        logging.error(f"Output path is the file being analyzed, refusing: {args.output}")
        sys.exit(1)

    # Collect the file list before opening the output, so the output
    # file is never part of its own scan.
    try:
        # Collection finishes before the output file is opened, and the
        # resolved output path is excluded from the candidates. Without both
        # halves of that, a recursive scan writing into the scanned directory
        # would list its own half written output as evidence.
        files = collect_files(path, args.recursive, output_resolved)
    except OSError as e:
        logging.error(f"Error accessing path {path}: {e}")
        sys.exit(1)

    if not path.is_file() and not path.is_dir():
        logging.error("Invalid path type.  Must be a file or directory.")
        sys.exit(1)

    if not files:
        logging.info("No files found.")
        print("No files found.")
        sys.exit(1)

    rows = collect_rows(files)

    if not rows:
        logging.info("No files found.")
        print("No files found.")
        sys.exit(1)

    if args.output:
        try:
            output_file_object = open(args.output, "w", encoding="utf-8", newline="")
        except Exception as e:
            logging.error(f"Error opening output file: {e}")
            sys.exit(1)
        try:
            write_rows(rows, output_file_object)
        finally:
            output_file_object.close()
    else:
        write_rows(rows, sys.stdout)

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
