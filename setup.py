"""
Setup Script for PDF Malware Analyzer
Run: pip install -e .
After install, use command: pdf-analyzer <file.pdf>
"""

from setuptools import setup, find_packages

setup(
    name="pdf-malware-analyzer",
    version="1.0.0",
    author="Your Name",
    author_email="your-email@gmail.com",
    description="A PDF Malware Analysis Toolkit for detecting malicious content in PDF files",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/YOUR-GITHUB-USERNAME/PDF-Malware-Analyzer",
    packages=find_packages(),
    python_requires=">=3.7",
    install_requires=[
        "PyPDF2==3.0.1",
        "pdfminer.six==20221105",
        "python-magic-bin==0.4.14",
        "validators==0.22.0",
        "colorama==0.4.6",
    ],
    entry_points={
        "console_scripts": [
            "pdf-analyzer=main:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries",
    ],
)
