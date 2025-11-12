# tarlite

tarlite is a lightweight tar extractor written in C, designed to handle USTAR format tar archives. It provides essential functionality for extracting tar files to a specified destination directory.

## Features

- **USTAR Header Parsing**: Reads and validates USTAR tar headers, including checksum verification.
- **File Type Support**: Extracts regular files, directories, symbolic links, and hard links from tar archives.
- **Directory Creation**: Automatically creates necessary parent directories during extraction.
- **File Permissions**: Sets appropriate file modes and permissions as specified in the tar headers.
- **Index Reporting**: Generates a detailed report of all extracted files, including paths, sizes, modes, and types.
- **Self-Test Mode**: Includes a built-in self-test feature to verify functionality with a sample tar archive.
- **Cross-Platform Compatibility**: Works on systems supporting POSIX file operations.

## Usage

### Basic Extraction
To extract a tar archive to a directory:
```
./tarlite <tar-file> <dest-dir>
```

- `<tar-file>`: Path to the tar archive file to extract.
- `<dest-dir>`: Destination directory where files will be extracted.

### Self-Test
To run the built-in self-test:
```
./tarlite --selftest
```

This creates a sample tar file, extracts it, and prints a report.

## Build Instructions

Compile the program using a C compiler:

### Standard Build
```
cc -O0 -g -Wall -Wextra -o tarlite tarlite.c
```

### With Sanitizers (for debugging)
```
clang -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -o tarlite_asan tarlite.c
```

## Example

Extracting a tar archive named `archive.tar` to a directory `extracted/`:
```
./tarlite archive.tar extracted/
```

After extraction, a report will be printed showing details of all extracted files.