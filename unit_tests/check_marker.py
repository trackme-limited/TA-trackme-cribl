import re
from pathlib import Path


def check_for_marker(py_file):
    """
    Check if the file contains any logging statement with "MARKER" in it.
    """
    with open(py_file, "r") as file:
        lines = file.readlines()
        for line_no, line in enumerate(lines, start=1):
            # Check if line is not commented and contains 'logging' and 'MARKER'
            if (
                not line.strip().startswith("#")
                and "logging" in line
                and re.search(r"logging\..*\bMARKER\b", line)
            ):
                raise AssertionError(
                    f"MARKER found in {py_file} at line {line_no}: {line.strip()}"
                )


def main():
    lib_files = list(Path("../package/lib").rglob("*.py"))
    bin_files = list(Path("../package/bin").rglob("*.py"))

    for file in lib_files + bin_files:
        check_for_marker(file)

    print("No 'MARKER' found in logging statements!")


if __name__ == "__main__":
    main()
