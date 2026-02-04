"""
PDF Parser Utilities
Helper functions for PDF parsing and content extraction
"""

import re
from PyPDF2 import PdfReader


class PDFParser:
    """Utility class for PDF parsing operations"""

    def __init__(self, pdf_path):
        self.pdf_path = pdf_path
        self.reader = None

    def load_pdf(self):
        """Load PDF file and return reader object"""
        try:
            self.reader = PdfReader(self.pdf_path)
            return self.reader
        except Exception as e:
            raise Exception(f"Failed to load PDF: {str(e)}")

    def get_raw_content(self):
        """Read raw PDF content as bytes"""
        try:
            with open(self.pdf_path, 'rb') as f:
                return f.read()
        except Exception as e:
            raise Exception(f"Failed to read PDF content: {str(e)}")

    def get_text_content(self):
        """Get PDF content as text string"""
        try:
            content = self.get_raw_content()
            return content.decode('utf-8', errors='ignore')
        except Exception as e:
            raise Exception(f"Failed to decode PDF content: {str(e)}")

    def extract_text_from_pages(self):
        """Extract text from all PDF pages"""
        try:
            if not self.reader:
                self.load_pdf()

            text_content = []
            for page_num, page in enumerate(self.reader.pages):
                try:
                    text = page.extract_text()
                    if text:
                        text_content.append({
                            'page': page_num + 1,
                            'text': text
                        })
                except:
                    continue

            return text_content
        except Exception as e:
            raise Exception(f"Failed to extract text: {str(e)}")

    def get_page_count(self):
        """Get total number of pages"""
        try:
            if not self.reader:
                self.load_pdf()
            return len(self.reader.pages)
        except Exception as e:
            return 0

    def is_encrypted(self):
        """Check if PDF is encrypted"""
        try:
            if not self.reader:
                self.load_pdf()
            return self.reader.is_encrypted
        except Exception as e:
            return False

    def get_metadata(self):
        """Extract PDF metadata"""
        try:
            if not self.reader:
                self.load_pdf()

            if self.reader.metadata:
                return {
                    'title': self.reader.metadata.get('/Title', 'N/A'),
                    'author': self.reader.metadata.get('/Author', 'N/A'),
                    'subject': self.reader.metadata.get('/Subject', 'N/A'),
                    'creator': self.reader.metadata.get('/Creator', 'N/A'),
                    'producer': self.reader.metadata.get('/Producer', 'N/A'),
                    'creation_date': self.reader.metadata.get('/CreationDate', 'N/A'),
                    'mod_date': self.reader.metadata.get('/ModDate', 'N/A'),
                }
            return {}
        except Exception as e:
            return {}

    def search_keyword(self, keyword):
        """Search for a keyword in PDF content"""
        try:
            content = self.get_text_content()
            return keyword in content
        except Exception as e:
            return False

    def search_keywords(self, keywords):
        """Search for multiple keywords and return matches"""
        try:
            content = self.get_text_content()
            matches = {}

            for keyword in keywords:
                if keyword in content:
                    count = content.count(keyword)
                    matches[keyword] = count

            return matches
        except Exception as e:
            return {}

    def extract_urls(self, content=None):
        """Extract URLs from PDF content"""
        try:
            if content is None:
                content = self.get_text_content()

            url_pattern = re.compile(
                r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
                re.IGNORECASE
            )

            urls = url_pattern.findall(content)
            return list(set(urls))  # Remove duplicates
        except Exception as e:
            return []

    def extract_ips(self, content=None):
        """Extract IP addresses from PDF content"""
        try:
            if content is None:
                content = self.get_text_content()

            ip_pattern = re.compile(
                r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
            )

            ips = ip_pattern.findall(content)
            return list(set(ips))  # Remove duplicates
        except Exception as e:
            return []

    def get_file_size(self):
        """Get PDF file size in bytes"""
        try:
            import os
            return os.path.getsize(self.pdf_path)
        except Exception as e:
            return 0

    def get_objects_count(self):
        """Get total number of PDF objects"""
        try:
            if not self.reader:
                self.load_pdf()

            if hasattr(self.reader, 'trailer') and '/Size' in self.reader.trailer:
                return self.reader.trailer['/Size']
            return 0
        except Exception as e:
            return 0


def quick_scan(pdf_path, keywords):
    """
    Quick scan helper function
    Scans PDF for keywords and returns matches
    """
    try:
        parser = PDFParser(pdf_path)
        return parser.search_keywords(keywords)
    except Exception as e:
        return {}


def extract_basic_info(pdf_path):
    """
    Extract basic PDF information
    Returns: dict with basic PDF info
    """
    try:
        parser = PDFParser(pdf_path)
        parser.load_pdf()

        return {
            'page_count': parser.get_page_count(),
            'file_size': parser.get_file_size(),
            'is_encrypted': parser.is_encrypted(),
            'metadata': parser.get_metadata(),
            'objects_count': parser.get_objects_count()
        }
    except Exception as e:
        return {
            'error': str(e)
        }