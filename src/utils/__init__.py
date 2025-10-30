"""
Pacote de utilitários para o Web Security Scanner - Conceito B
"""
from .helpers import Logger, normalize_url, extract_forms, extract_links, extract_parameters
from .helpers import (
    XSS_PAYLOADS, SQL_PAYLOADS, DIRECTORY_TRAVERSAL_PAYLOADS, 
    COMMAND_INJECTION_PAYLOADS, INFORMATION_DISCLOSURE_PATHS,
    AUTHENTICATION_BYPASS_PAYLOADS, check_error_patterns
)

__all__ = [
    'Logger',
    'normalize_url', 
    'extract_forms',
    'extract_links',
    'extract_parameters',
    'XSS_PAYLOADS',
    'SQL_PAYLOADS',
    'DIRECTORY_TRAVERSAL_PAYLOADS',
    'COMMAND_INJECTION_PAYLOADS', 
    'INFORMATION_DISCLOSURE_PATHS',
    'AUTHENTICATION_BYPASS_PAYLOADS',
    'check_error_patterns'
]
