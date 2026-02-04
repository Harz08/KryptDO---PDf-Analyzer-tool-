"""
Build Script for PDF Malware Analyzer
Creates a standalone .exe file for Windows users

HOW TO USE:
    1. Install PyInstaller:  pip install pyinstaller
    2. Run this script:      python build.py
    3. Find your .exe in:    dist/ folder
"""

import subprocess
import sys
import os
import shutil


def build_exe():
    """Build the EXE using PyInstaller"""

    print("=" * 60)
    print("  PDF Malware Analyzer - Build Script")
    print("=" * 60)

    # Step 1: Check PyInstaller
    print("\n[1/5] Checking PyInstaller...")
    try:
        import PyInstaller
        print("    [✓] PyInstaller is installed")
    except ImportError:
        print("    [!] PyInstaller not found. Installing...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])
        print("    [✓] PyInstaller installed")

    # Step 2: Check dependencies
    print("\n[2/5] Installing dependencies...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
    print("    [✓] All dependencies installed")

    # Step 3: Clean old builds
    print("\n[3/5] Cleaning old builds...")
    for folder in ["build", "dist"]:
        if os.path.exists(folder):
            shutil.rmtree(folder)
            print(f"    [✓] Removed old {folder}/ folder")

    # Step 4: Build EXE
    print("\n[4/5] Building EXE (this may take a minute)...")
    build_command = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",                          # Single EXE file
        "--name", "PDF_Malware_Analyzer",     # Output EXE name
        "--icon", "icon.ico",                 # Icon (optional, ignore error if missing)
        "--add-data", "config;config",        # Include config folder
        "--hidden-import", "colorama",
        "--hidden-import", "PyPDF2",
        "--hidden-import", "validators",
        "--hidden-import", "pdfminer",
        "main.py"                             # Entry point
    ]

    try:
        subprocess.check_call(build_command)
    except subprocess.CalledProcessError:
        # Retry without icon if it fails
        print("    [!] Retrying without icon...")
        build_command.remove("--icon")
        build_command.remove("icon.ico")
        subprocess.check_call(build_command)

    # Step 5: Verify build
    print("\n[5/5] Verifying build...")
    exe_path = os.path.join("dist", "PDF_Malware_Analyzer.exe")

    if os.path.exists(exe_path):
        size_mb = os.path.getsize(exe_path) / (1024 * 1024)
        print(f"    [✓] EXE created successfully!")
        print(f"    [✓] Location: {exe_path}")
        print(f"    [✓] Size: {size_mb:.2f} MB")
    else:
        print("    [!] EXE not found. Check build logs above.")
        return

    # Done
    print("\n" + "=" * 60)
    print("  BUILD COMPLETE!")
    print("=" * 60)
    print(f"\n  📦 Your EXE is ready at: dist/PDF_Malware_Analyzer.exe")
    print(f"  📌 Users can double-click it — no Python needed!\n")
    print("  HOW TO USE THE EXE:")
    print("  1. Copy PDF_Malware_Analyzer.exe anywhere")
    print("  2. Open CMD in that folder")
    print("  3. Run: PDF_Malware_Analyzer.exe <your-file.pdf>")
    print("=" * 60)


if __name__ == "__main__":
    build_exe()
