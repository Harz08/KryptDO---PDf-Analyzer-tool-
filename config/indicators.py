"""
Configuration file containing suspicious keywords, patterns, and indicators
used for PDF malware detection
"""

# Suspicious PDF Keywords (used by attackers)
SUSPICIOUS_KEYWORDS = [
    '/JavaScript',
    '/JS',
    '/OpenAction',
    '/AA',  # Additional Actions
    '/AcroForm',
    '/Launch',
    '/EmbeddedFile',
    '/RichMedia',
    '/XFA',  # XML Forms Architecture
    '/URI',
    '/SubmitForm',
    '/GoToR',  # Go To Remote
    '/Sound',
    '/Movie',
    '/ImportData',
    '/GoToE',  # Go To Embedded
]

# High-risk actions (automatically executed)
HIGH_RISK_ACTIONS = [
    '/OpenAction',
    '/AA',
    '/Launch'
]

# JavaScript obfuscation patterns
OBFUSCATION_PATTERNS = [
    'eval(',
    'unescape(',
    'String.fromCharCode(',
    'atob(',  # Base64 decode
    'btoa(',  # Base64 encode
    'document.write(',
    'this.exportDataObject',
    'util.printf',
    'getAnnots',
    'spell.customDictionaryOpen'
]

# Known CVE exploit patterns
EXPLOIT_PATTERNS = {
    'CVE-2010-0188': ['JBIG2Decode'],
    'CVE-2013-2729': ['cooltype.dll'],
    'CVE-2009-0927': ['getIcon'],
    'CVE-2008-2992': ['util.printf'],
    'CVE-2007-5659': ['Collab.collectEmailInfo']
}

# File extensions for embedded executables
DANGEROUS_EXTENSIONS = [
    '.exe',
    '.dll',
    '.bat',
    '.cmd',
    '.vbs',
    '.ps1',
    '.jar',
    '.scr',
    '.com'
]

# Risk scoring weights
RISK_WEIGHTS = {
    'javascript_found': 20,
    'auto_action': 25,
    'embedded_file': 15,
    'obfuscation': 20,
    'url_found': 10,
    'exploit_pattern': 30,
    'suspicious_metadata': 5,
    'encoded_stream': 10
}

# Severity thresholds
SEVERITY_THRESHOLDS = {
    'LOW': (0, 30),
    'MEDIUM': (31, 50),
    'HIGH': (51, 75),
    'CRITICAL': (76, 100)
}