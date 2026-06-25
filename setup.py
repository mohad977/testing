"""
Build command (run on Windows):
    python setup.py bdist_msi
Output: dist/NetScanner-1.0-*.msi
"""
import sys
from cx_Freeze import setup, Executable

build_options = {
    "packages": ["socket", "argparse", "concurrent.futures", "ipaddress"],
    "excludes": ["tkinter", "unittest", "email", "http", "urllib", "xml"],
}

# Windows MSI options
msi_options = {
    "upgrade_code": "{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}",
    "add_to_path": True,
    "initial_target_dir": r"[ProgramFilesFolder]\NetScanner",
    "summary_data": {
        "author": "NetScanner",
        "comments": "Network Scanner — host discovery and port scanning tool",
    },
}

executable = Executable(
    script="netscanner.py",
    base=None,                    # Console app (no GUI base)
    target_name="netscanner.exe",
    icon=None,
)

setup(
    name="NetScanner",
    version="1.0",
    description="Network Scanner — host discovery and port scanning",
    author="NetScanner",
    options={
        "build_exe": build_options,
        "bdist_msi": msi_options,
    },
    executables=[executable],
)
