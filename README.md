# Web Security Scanner - OWASP Top 10 Analyzer

**Disciplina:** Tecnologias Hackers  
**Aluno:** Daniel Marco  
**Instituição:** Insper  
**Repositório:** https://github.com/DanielMarcoD/Avaliacao-Final-TH-Daniel  
**Vídeo demonstrativo:** [Adicione o link após gravação - até 7 minutos]

---

## Índice

1. [Visão Geral](#1-visão-geral)
2. [Arquitetura do Sistema](#2-arquitetura-do-sistema)
3. [Metodologia de Testes](#3-metodologia-de-testes)
4. [Instalação e Execução](#4-instalação-e-execução)
5. [Estrutura do Projeto](#5-estrutura-do-projeto)
6. [Cobertura OWASP Top 10](#6-cobertura-owasp-top-10)
7. [Resultados e Exemplos](#7-resultados-e-exemplos)
8. [Recomendações de Mitigação](#8-recomendações-de-mitigação)
9. [Tecnologias Utilizadas](#9-tecnologias-utilizadas)
10. [Aviso Legal e Ética](#10-aviso-legal-e-ética)
11. [Documentação Adicional](#11-documentação-adicional)

---

## 1. Visão Geral

Este projeto implementa uma **ferramenta completa de avaliação automatizada de segurança em aplicações web**, com foco nas vulnerabilidades do **OWASP Top 10**. A solução atende aos requisitos do **Conceito A**, incluindo:

- **Análise heurística** com priorização de vulnerabilidades por severidade
- **Dashboard web interativo** com gráficos, filtros e monitoramento em tempo real
- **Sistema de autenticação multi-usuário** com controle de acesso
- **Relatórios detalhados** em múltiplos formatos (JSON, CSV, Markdown)
- **Integração com ferramentas profissionais** (OWASP ZAP, Nikto, Nmap)
- **Containerização completa** com Docker e docker-compose
- **CI/CD** implementado com GitHub Actions

### Vulnerabilidades Detectadas

A ferramenta identifica e analisa as seguintes vulnerabilidades:

- Cross-Site Scripting (XSS) - Reflected, Stored e DOM-based
- SQL Injection (SQLi) - Error-based, Boolean-based, Time-based
- Cross-Site Request Forgery (CSRF)
- Command Injection
- Directory/Path Traversal
- Security Misconfiguration (Headers HTTP, TLS/SSL)
- Information Disclosure
- Broken Authentication
- Open Redirect
- Insecure Direct Object Reference (IDOR)

---

## 2. Arquitetura do Sistema

A arquitetura segue o padrão MVC (Model-View-Controller) com componentes especializados:

### Componentes Principais

**Frontend (View)**
- Templates HTML com Jinja2
- Interface responsiva com Bootstrap 5
- Gráficos interativos com Chart.js
- JavaScript para requisições assíncronas e atualização em tempo real

**Backend (Controller)**
- Framework Flask 3.0 para API REST
- Sistema de autenticação com sessões seguras
- Gerenciamento de threads para scans paralelos
- APIs para progresso, estatísticas e download de relatórios

**Mecanismo de Scanner (Model)**
- `scanner.py` - Scanner principal com todas as funcionalidades
- Detecção baseada em payloads e análise de respostas
- Sistema de scoring CVSS-like (0-10)
- Timeout configurável e controle de taxa de requisições

**Banco de Dados**
- SQLite para persistência
- Tabelas: users, companies, scans, vulnerabilities, sessions
- Seed inicial com usuário admin/admin123

**Geração de Relatórios**
- `report_generator.py` - Geração de relatórios em múltiplos formatos
- Markdown com recomendações de mitigação detalhadas
- CSV para análise em planilhas
- JSON para integração com outras ferramentas

**Integrações Externas**
- OWASP ZAP 2.15.0 - Spider e Active Scan
- Nikto 2.5.0 - Detecção de misconfigurations
- Nmap 7.95 - Port scanning e service detection

**Infraestrutura**
- Dockerfile multi-stage para otimização
- docker-compose para orquestração
- GitHub Actions para CI/CD (linting, testes, segurança)
- Healthcheck e auto-restart configurados

### Diagrama de Arquitetura

Consulte `docs/architecture_diagram.png` para visualização completa da arquitetura.

### Fluxograma de Funcionamento

Consulte `docs/flowchart.pdf` para o fluxo detalhado de execução dos scans.

---

## 3. Metodologia de Testes

A ferramenta implementa uma abordagem híbrida de testes de segurança:

### 3.1 Fase de Reconhecimento

**Coleta Passiva:**
- Análise de headers HTTP (CSP, HSTS, X-Frame-Options, etc)
- Verificação de certificados SSL/TLS
- Extração de cookies e análise de flags de segurança
- Captura de banners e versões de servidores
- Detecção de mensagens de erro verbosas

**Descoberta de Superfície de Ataque:**
- Spider automático para descoberta de URLs
- Extração de formulários HTML
- Identificação de parâmetros GET/POST
- Mapeamento de endpoints da API

### 3.2 Fase de Testes Ativos

**XSS (Cross-Site Scripting):**
- 30+ payloads especializados
- Testes em parâmetros GET
- Testes em formulários POST
- Detecção de reflexão de entrada
- Análise de contexto de injeção

**SQL Injection:**
- 40+ payloads avançados
- Error-based detection
- Boolean-based blind SQLi
- Time-based blind SQLi
- Testes em múltiplos DBMSs (MySQL, PostgreSQL, MSSQL)

**CSRF:**
- Verificação de tokens anti-CSRF
- Análise de cabeçalhos de origem
- Testes de validação de referer
- Verificação de cookies SameSite

**Command Injection:**
- Payloads para Linux/Unix
- Payloads para Windows
- Detecção de execução remota de código
- Análise de resposta temporal

**Directory Traversal:**
- Padrões de path traversal (../, ..\)
- Encoding variations (URL, Unicode)
- Testes em parâmetros de arquivo
- Detecção de leitura de arquivos sensíveis

### 3.3 Integração com Ferramentas Profissionais

**OWASP ZAP:**
- Spider completo do site
- Active Scan com todas as regras
- Detecção de vulnerabilidades adicionais
- Análise de JavaScript

**Nikto:**
- Scan de servidor web
- Detecção de arquivos perigosos
- Verificação de configurações inseguras
- Identificação de vulnerabilidades conhecidas

**Nmap:**
- Port scanning (65535 portas)
- Service detection
- Version detection
- Análise de serviços expostos

### 3.4 Sistema de Scoring e Priorização

**Algoritmo CVSS-like:**

Cada vulnerabilidade recebe um score de 0 a 10 baseado em:

- **Impacto** (0-4 pontos): Gravidade do comprometimento
- **Explorabilidade** (0-3 pontos): Facilidade de exploração
- **Confiabilidade** (0-2 pontos): Certeza da detecção
- **Contexto** (0-1 ponto): Ambiente e exposição

**Classificação de Severidade:**

- **CRITICAL** (9.0-10.0): Vulnerabilidades críticas com exploração trivial
- **HIGH** (7.0-8.9): Vulnerabilidades graves que requerem ação imediata
- **MEDIUM** (4.0-6.9): Vulnerabilidades moderadas que devem ser corrigidas
- **LOW** (1.0-3.9): Vulnerabilidades menores ou de baixo risco
- **INFO** (0.0-0.9): Informações e recomendações gerais

### 3.5 Controles de Qualidade

- Rate limiting para evitar sobrecarga do servidor
- Timeout configurável por requisição
- Timeout global para o scan completo
- Validação de respostas HTTP
- Logging detalhado de todas as operações
- Tratamento robusto de erros

---

## 4. Instalação e Execução

### 4.1 Pré-requisitos

- Python 3.12+ (ou 3.10+)
- Docker e docker-compose (opcional, mas recomendado)
- Git

### 4.2 Instalação via Docker (Recomendado)

```bash
# 1. Clone o repositório
git clone https://github.com/DanielMarcoD/Avaliacao-Final-TH-Daniel.git
cd Avaliacao-Final-TH-Daniel

# 2. Construir e iniciar os containers
docker compose up -d

# 3. Acessar o dashboard
# URL: http://localhost:5000
# Credenciais padrão: admin / admin123

# 4. Visualizar logs (opcional)
docker logs -f enhanced-web-scanner

# 5. Parar os containers
docker compose down
```

### 4.3 Instalação Local

```bash
# 1. Clone o repositório
git clone https://github.com/DanielMarcoD/Avaliacao-Final-TH-Daniel.git
cd Avaliacao-Final-TH-Daniel

# 2. Criar ambiente virtual
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# ou
venv\Scripts\activate     # Windows

# 3. Instalar dependências
pip install -r src/requirements.txt

# 4. Executar a aplicação web
python src/web_interface.py

# 5. Acessar o dashboard
# URL: http://localhost:5000
# Credenciais padrão: admin / admin123
```

### 4.4 Uso via Linha de Comando

```bash
# Ativar ambiente virtual
source venv/bin/activate

# Executar scan via CLI
python src/scanner.py \
    --url http://testphp.vulnweb.com \
    --timeout 30 \
    --max-paths 50 \
    --output reports/

# Ver todas as opções disponíveis
python src/scanner.py --help
```

### 4.5 Configuração das Ferramentas Auxiliares

**OWASP ZAP (Opcional - já incluído no Docker):**

```bash
# Download e instalação (Linux)
wget https://github.com/zaproxy/zaproxy/releases/download/v2.15.0/ZAP_2_15_0_unix.sh
chmod +x ZAP_2_15_0_unix.sh
./ZAP_2_15_0_unix.sh

# Iniciar em modo daemon
zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true
```

**Nikto (Opcional - já incluído no Docker):**

```bash
# Instalação
git clone https://github.com/sullo/nikto
cd nikto/program

# Uso
./nikto.pl -h testphp.vulnweb.com
```

**Nmap (Opcional - já incluído no Docker):**

```bash
# Instalação Ubuntu/Debian
sudo apt-get install nmap

# Instalação Mac
brew install nmap
```

### 4.6 Variáveis de Ambiente

Copie `.env.example` para `.env` e ajuste conforme necessário:

```bash
# Configurações do Flask
FLASK_ENV=production
FLASK_DEBUG=0
SECRET_KEY=sua-chave-secreta-aqui

# Configurações do Banco
DATABASE_URL=sqlite:///scanner_db.sqlite

# Configurações das Ferramentas
ZAP_HOST=localhost
ZAP_PORT=8080
NIKTO_PATH=/usr/local/bin/nikto.pl
NMAP_PATH=/usr/bin/nmap
```

---

## 5. Estrutura do Projeto

```
Avaliacao-Final-TH-Daniel/
├── src/
│   ├── scanner.py              # Scanner principal (Conceito A)
│   ├── report_generator.py     # Gerador de relatórios
│   ├── web_interface.py        # Dashboard web interativo
│   ├── start_zap.sh            # Script de inicialização do OWASP ZAP
│   ├── requirements.txt        # Dependências Python
│   ├── utils/
│   │   ├── __init__.py
│   │   └── helpers.py          # Funções auxiliares
│   ├── tests/
│   │   └── test_scanner.py     # Testes unitários
│   └── templates/
│       ├── login.html          # Página de login
│       ├── enhanced_dashboard.html  # Dashboard principal
│       └── admin_dashboard.html     # Painel administrativo
│
├── docs/
│   ├── RELATORIO_TECNICO.md    # Documentação técnica detalhada
│   ├── architecture_diagram.png     # Diagrama de arquitetura
│   └── flowchart.pdf           # Fluxograma de funcionamento
│
├── .github/
│   └── workflows/
│       └── security_scan.yml   # CI/CD pipeline
│
├── reports/                     # Relatórios gerados (criado automaticamente)
│   └── README.md               # Documentação do diretório
│
├── Dockerfile                   # Imagem Docker
├── docker-compose.yml          # Orquestração de containers
├── entrypoint.sh               # Script de inicialização
├── .env.example                # Exemplo de variáveis de ambiente
├── .gitignore                  # Arquivos ignorados pelo Git
└── README.md                   # Este arquivo
```

---

## 6. Cobertura OWASP Top 10

| # | Categoria OWASP | Status | Técnicas Implementadas |
|---|-----------------|:------:|------------------------|
| 1 | Broken Access Control | Implementado | IDOR detection, Path traversal, Directory listing |
| 2 | Cryptographic Failures | Implementado | SSL/TLS analysis, Weak ciphers, Certificate validation |
| 3 | Injection (SQL, Command) | Implementado | 40+ SQLi payloads, Command injection, LDAP injection |
| 4 | Insecure Design | Parcial | Heuristic analysis, Pattern detection |
| 5 | Security Misconfiguration | Implementado | Header analysis, Banner grabbing, Default credentials |
| 6 | Vulnerable Components | Parcial | Version detection via banners |
| 7 | Authentication Failures | Implementado | Auth bypass, Weak credentials, Session management |
| 8 | Data Integrity Failures | Implementado | CSRF token detection, Input validation |
| 9 | Logging Failures | N/A | Não aplicável para scanner externo |
| 10 | SSRF | Parcial | Open redirect detection, URL manipulation |
| - | XSS (Cross-Site Scripting) | Implementado | 30+ payloads (Reflected, Stored, DOM-based) |
| - | Directory Traversal | Implementado | Path traversal patterns, File inclusion |

**Legenda:**
- Implementado = Detecção completa com múltiplas técnicas
- Parcial = Detecção básica ou limitada
- N/A = Não aplicável ao escopo

---

## 7. Resultados e Exemplos

### 7.1 Exemplo de Scan Completo

**Target:** http://testphp.vulnweb.com

**Estatísticas:**
- Duração: 127 segundos
- URLs testadas: 15
- Formulários testados: 8
- Parâmetros testados: 23
- Vulnerabilidades encontradas: 47

**Distribuição por Severidade:**
- CRITICAL: 3 vulnerabilidades
- HIGH: 8 vulnerabilidades
- MEDIUM: 15 vulnerabilidades
- LOW: 18 vulnerabilidades
- INFO: 3 ocorrências

### 7.2 Exemplos de Vulnerabilidades Detectadas

**CRITICAL - SQL Injection (Error-based):**
```
URL: http://testphp.vulnweb.com/artists.php?artist=1'
Parâmetro: artist
Payload: 1' OR '1'='1
Evidência: "You have an error in your SQL syntax"
Score: 9.5/10
Impacto: Acesso não autorizado ao banco de dados
```

**HIGH - Cross-Site Scripting (Reflected):**
```
URL: http://testphp.vulnweb.com/search.php?query=test
Parâmetro: query
Payload: <script>alert(1)</script>
Evidência: Reflexão completa sem sanitização
Score: 8.2/10
Impacto: Roubo de sessão, phishing
```

**MEDIUM - CSRF sem Token:**
```
URL: http://testphp.vulnweb.com/userinfo.php
Formulário: updateProfile
Evidência: Nenhum token anti-CSRF encontrado
Score: 6.5/10
Impacto: Ações não autorizadas em nome do usuário
```

**LOW - Information Disclosure:**
```
Server: Apache/2.4.41 (Ubuntu)
X-Powered-By: PHP/7.4.3
Evidência: Versões de software expostas
Score: 3.0/10
Impacto: Facilita reconnaissance para ataques
```

### 7.3 Formato dos Relatórios

**Markdown (security_report_[scan_id]_[timestamp].md):**
- Sumário executivo
- Estatísticas do scan
- Vulnerabilidades por severidade
- Detalhamento técnico de cada vulnerabilidade
- Recomendações específicas de mitigação
- Referências OWASP

**CSV (vulnerabilities_[scan_id]_[timestamp].csv):**
```csv
URL,Type,Severity,Score,Parameter,Payload,Evidence,Recommendation
http://testphp.vulnweb.com/artists.php,SQL Injection,CRITICAL,9.5,artist,"1' OR '1'='1","SQL syntax error","Use prepared statements"
```

**JSON (scan_report_[scan_id]_[timestamp].json):**
```json
{
  "scan_id": "abc123",
  "target": "http://testphp.vulnweb.com",
  "start_time": "2025-11-04T19:00:00",
  "duration": 127,
  "vulnerabilities": [
    {
      "type": "SQL Injection",
      "severity": "CRITICAL",
      "score": 9.5,
      "url": "http://testphp.vulnweb.com/artists.php",
      "parameter": "artist",
      "payload": "1' OR '1'='1",
      "evidence": "SQL syntax error",
      "recommendation": "Use prepared statements"
    }
  ]
}
```

---

## 8. Recomendações de Mitigação

### 8.1 Cross-Site Scripting (XSS)

**Práticas Recomendadas:**
- Sanitizar todas as entradas do usuário
- Implementar encoding apropriado para o contexto (HTML, JavaScript, URL)
- Utilizar Content Security Policy (CSP) restritiva
- Validar entrada no servidor (não apenas no cliente)
- Usar bibliotecas de sanitização confiáveis (DOMPurify, OWASP Java Encoder)

**Exemplo CSP:**
```
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:
```

### 8.2 SQL Injection

**Práticas Recomendadas:**
- Usar prepared statements ou consultas parametrizadas
- Utilizar ORM (Sequelize, SQLAlchemy, Hibernate)
- Implementar validação de entrada rigorosa
- Aplicar princípio do menor privilégio no banco
- Escapar caracteres especiais quando necessário
- Desabilitar mensagens de erro detalhadas em produção

**Exemplo Python (SQLAlchemy):**
```python
# INSEGURO
query = f"SELECT * FROM users WHERE id = {user_id}"

# SEGURO
query = "SELECT * FROM users WHERE id = ?"
cursor.execute(query, (user_id,))
```

### 8.3 Cross-Site Request Forgery (CSRF)

**Práticas Recomendadas:**
- Implementar tokens anti-CSRF únicos por sessão
- Validar cabeçalho Origin/Referer
- Utilizar cookies com flag SameSite=Strict ou Lax
- Requerer re-autenticação para ações sensíveis
- Implementar CAPTCHA para operações críticas

**Exemplo Flask:**
```python
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
csrf = CSRFProtect(app)
```

### 8.4 Command Injection

**Práticas Recomendadas:**
- Evitar execução de comandos do sistema quando possível
- Usar APIs nativas em vez de shell commands
- Implementar whitelist rigorosa de comandos permitidos
- Validar e sanitizar todos os parâmetros
- Usar subprocess sem shell=True (Python)
- Aplicar princípio do menor privilégio

**Exemplo Python:**
```python
# INSEGURO
os.system(f"ping {user_input}")

# SEGURO
import subprocess
subprocess.run(['ping', '-c', '4', validated_host], check=True)
```

### 8.5 Directory Traversal

**Práticas Recomendadas:**
- Normalizar e validar todos os caminhos de arquivo
- Implementar whitelist de diretórios acessíveis
- Bloquear padrões perigosos (../, ..\)
- Usar funções de manipulação de caminho seguras
- Executar aplicação em ambiente chroot quando possível
- Validar extensões de arquivo

**Exemplo Python:**
```python
import os
from pathlib import Path

def safe_path(base_dir, user_path):
    base = Path(base_dir).resolve()
    requested = (base / user_path).resolve()
    return requested.is_relative_to(base)
```

### 8.6 Security Misconfiguration

**Headers de Segurança Recomendados:**

```http
# Prevenir clickjacking
X-Frame-Options: DENY

# Prevenir MIME sniffing
X-Content-Type-Options: nosniff

# Forçar HTTPS
Strict-Transport-Security: max-age=31536000; includeSubDomains

# Content Security Policy
Content-Security-Policy: default-src 'self'

# Referrer Policy
Referrer-Policy: strict-origin-when-cross-origin

# Permissions Policy
Permissions-Policy: geolocation=(), microphone=()
```

**Configurações Adicionais:**
- Desabilitar listagem de diretórios
- Remover/ocultar banners de versão
- Implementar rate limiting
- Configurar timeouts apropriados
- Manter frameworks e dependências atualizados
- Usar secrets manager para credenciais

### 8.7 Information Disclosure

**Práticas Recomendadas:**
- Desabilitar páginas de erro detalhadas em produção
- Remover comentários do código em produção
- Ocultar versões de software nos headers
- Implementar logging sem expor dados sensíveis
- Sanitizar stack traces antes de mostrar ao usuário
- Usar mensagens de erro genéricas

---

## 9. Tecnologias Utilizadas

### 9.1 Backend

**Python 3.12**
- Linguagem principal do projeto
- Suporte a type hints e async/await
- Performance otimizada

**Flask 3.0**
- Framework web minimalista
- Routing e templates Jinja2
- Extensões para autenticação e sessões

**BeautifulSoup4 4.12**
- Parsing de HTML/XML
- Extração de formulários e links
- Análise de estrutura DOM

**Requests 2.31**
- HTTP client robusto
- Suporte a sessões
- Tratamento de SSL/TLS

**SQLite 3**
- Banco de dados embutido
- Zero configuração
- Adequado para aplicação acadêmica

### 9.2 Frontend

**Bootstrap 5.3**
- Framework CSS responsivo
- Componentes prontos
- Grid system flexível

**Chart.js 4.4**
- Biblioteca de gráficos JavaScript
- Gráficos de pizza, linha e barra
- Interatividade e animações

**Font Awesome 6.5**
- Biblioteca de ícones
- Ícones vetoriais escaláveis
- Ampla variedade de símbolos

**JavaScript ES6+**
- Fetch API para requisições assíncronas
- Promises e async/await
- Event listeners e DOM manipulation

### 9.3 Ferramentas de Segurança

**OWASP ZAP 2.15.0**
- Proxy de interceptação
- Spider automático
- Active Scanner com múltiplas regras
- API REST para integração

**Nikto 2.5.0**
- Scanner de servidor web
- Banco de dados de 6700+ vulnerabilidades
- Detecção de configurações inseguras
- Identificação de arquivos perigosos

**Nmap 7.95**
- Network mapper
- Port scanning completo
- Service e version detection
- OS fingerprinting

### 9.4 DevOps e Infraestrutura

**Docker 24.0+**
- Containerização da aplicação
- Isolamento de dependências
- Portabilidade entre ambientes

**docker-compose 2.0+**
- Orquestração de containers
- Configuração declarativa
- Gerenciamento de volumes e networks

**GitHub Actions**
- CI/CD pipeline automatizado
- Testes em múltiplas versões Python
- Linting e análise de código
- Security scanning

### 9.5 Bibliotecas Auxiliares

```
Flask==3.0.0
Flask-Session==0.5.0
requests==2.31.0
beautifulsoup4==4.12.2
lxml==4.9.3
pandas==2.1.1
matplotlib==3.8.0
python-dotenv==1.0.0
werkzeug==3.0.0
```

---

## 10. Aviso Legal e Ética

### 10.1 Uso Autorizado

Esta ferramenta foi desenvolvida **exclusivamente para fins educacionais** e deve ser utilizada APENAS em:

- Ambientes de teste autorizados
- Aplicações próprias ou com permissão explícita do proprietário
- Laboratórios controlados de segurança
- Plataformas de treinamento (DVWA, OWASP Juice Shop, etc)

### 10.2 Proibições

**NÃO utilize esta ferramenta para:**

- Atacar sistemas sem autorização prévia e por escrito
- Realizar testes em ambientes de produção de terceiros
- Violar leis de segurança cibernética locais ou internacionais
- Causar danos ou interrupção de serviços
- Acessar, modificar ou destruir dados não autorizados

### 10.3 Responsabilidades

**O autor deste projeto:**
- Não se responsabiliza por uso indevido da ferramenta
- Não autoriza atividades ilegais ou não éticas
- Recomenda fortemente o cumprimento de todas as leis aplicáveis
- Incentiva o uso responsável para melhoria da segurança

**O usuário desta ferramenta:**
- É totalmente responsável por suas ações
- Deve obter autorização prévia para qualquer teste
- Deve respeitar todas as leis e regulamentações
- Deve configurar rate limiting e timeouts apropriados

### 10.4 Legislação Aplicável

No Brasil, o uso não autorizado de ferramentas de segurança pode configurar crimes previstos em:

- Lei Carolina Dieckmann (Lei 12.737/2012) - Invasão de dispositivo informático
- Marco Civil da Internet (Lei 12.965/2014)
- Lei Geral de Proteção de Dados - LGPD (Lei 13.709/2018)

**Penalidades podem incluir:**
- Detenção de 3 meses a 1 ano
- Multa
- Agravantes em caso de danos ou obtenção de vantagem ilícita

### 10.5 Boas Práticas

**Ao realizar testes de segurança:**

1. Obtenha autorização por escrito do proprietário do sistema
2. Defina escopo claro e limitado dos testes
3. Configure rate limiting para evitar DoS acidental
4. Utilize timeouts apropriados
5. Documente todas as atividades realizadas
6. Reporte vulnerabilidades de forma responsável
7. Não divulgue vulnerabilidades publicamente antes de correção
8. Mantenha confidencialidade dos dados encontrados

### 10.6 Segurança da Ferramenta

**Credenciais padrão:**

As credenciais padrão (admin/admin123) são para fins de demonstração acadêmica. Em ambiente real:

- Altere imediatamente após instalação
- Use senhas fortes e únicas
- Implemente autenticação de dois fatores
- Rotacione credenciais periodicamente

**Armazenamento de dados:**

- Nunca comite credenciais reais no repositório
- Use .env para variáveis sensíveis
- Implemente criptografia para dados em repouso
- Limpe logs com informações sensíveis

---

## 11. Documentação Adicional

### 11.1 Diagramas

**Arquitetura do Sistema:**
- Localização: `docs/architecture_diagram.png`
- Conteúdo: Diagrama completo dos componentes, fluxo de dados e integrações

**Fluxograma de Funcionamento:**
- Localização: `docs/flowchart.pdf`
- Conteúdo: Fluxo detalhado de execução dos scans, desde a configuração até geração de relatórios

### 11.2 Relatório Técnico Detalhado

Para informações técnicas mais aprofundadas, consulte:
- `docs/RELATORIO_TECNICO.md`

Contém:
- Especificações técnicas detalhadas
- Algoritmos de detecção
- Exemplos de payloads
- Casos de teste
- Análise comparativa com ferramentas comerciais

### 11.3 Testes

**Executar testes unitários:**

```bash
# Ativar ambiente virtual
source venv/bin/activate

# Executar todos os testes
python -m pytest src/tests/ -v

# Executar teste específico
python -m pytest src/tests/test_scanner.py -v

# Gerar relatório de cobertura
python -m pytest src/tests/ --cov=src --cov-report=html
```

### 11.4 CI/CD

O projeto inclui pipeline GitHub Actions (`.github/workflows/security_scan.yml`) que:

- Executa testes automaticamente em cada push
- Valida código com flake8 (PEP 8)
- Analisa segurança com bandit
- Verifica dependências com safety
- Constrói imagem Docker
- Executa scan de segurança da imagem

### 11.5 Contribuindo

Este é um projeto acadêmico, mas sugestões de melhoria são bem-vindas:

1. Fork o repositório
2. Crie uma branch para sua feature
3. Implemente as mudanças
4. Adicione testes se aplicável
5. Commit com mensagens descritivas
6. Push para sua branch
7. Abra um Pull Request

### 11.6 Suporte

**Para dúvidas ou problemas:**

- Email: danielmd@al.insper.edu.br
- GitHub Issues: https://github.com/DanielMarcoD/Avaliacao-Final-TH-Daniel/issues
- GitHub: @DanielMarcoD

### 11.7 Licença

Este projeto está sob a licença MIT. Veja o arquivo LICENSE para mais detalhes.

---

## Conclusão

Este projeto implementa uma solução completa de avaliação de segurança web que atende e supera os requisitos do **Conceito A**:

**Conceito C - Base:**
- Varredura básica implementada
- XSS e SQLi funcionais
- CLI operacional
- Relatórios básicos gerados

**Conceito B - Intermediário:**
- Múltiplas vulnerabilidades (6+ do OWASP Top 10)
- Relatórios em JSON, CSV e Markdown
- Integrações com ZAP, Nikto e Nmap
- Automação completa via CLI e web

**Conceito A - Avançado:**
- Análise heurística com scoring CVSS-like
- Dashboard interativo com gráficos e filtros
- Sistema de autenticação multi-usuário
- Relatórios detalhados com recomendações
- Docker e docker-compose funcionais
- CI/CD implementado com GitHub Actions
- Documentação técnica completa

**Próximos passos:**
- Gravar vídeo demonstrativo (até 7 minutos)
- Adicionar link do vídeo neste README

---

**Desenvolvido por Daniel Marco para a disciplina Tecnologias Hackers - Insper - 2025**
