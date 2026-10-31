![Banner](banner.png)

# file-forensic-timeline
Creates a timeline of file modifications, access times, and metadata changes to aid in forensic investigations, leveraging stat and metadata libraries. - Focused on File operations and analysis

## Install
`git clone https://github.com/ShadowStrikeHQ/file-forensic-timeline`

## Usage
`python3 main.py <path> [-r] [-o output.csv] [-v]`

Rows are written as CSV with a header row, using standard CSV quoting, so a comma or newline in a filename does not shift columns. Rows are sorted by modification time, oldest first.

The third time column is labelled truthfully for the platform: `created_time` where the platform provides a real birth time (st_birthtime), and `changed_time` where only the inode change time (st_ctime) exists, as on Linux. The changed time is not a creation time.

Naming the analyzed file as its own `-o` output is refused at exit 1 before anything is opened, and the input is left unchanged. An `-o` file inside a recursively scanned tree is excluded from that scan. A missing path and an output file that cannot be opened exit 1. An empty directory, or a scan that finds no files, prints "No files found." and exits 1.

## Parameters
- `path`: The path to the file or directory to analyze (required, positional)
- `-h`: Show help message and exit
- `-r`: Recursively process all files in the directory.
- `-o`: The output file to write the timeline to. Defaults to stdout.
- `-v`: Enable verbose logging.

## License
Copyright (c) ShadowStrikeHQ
