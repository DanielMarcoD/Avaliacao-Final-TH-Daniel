# Web Security Scanner — Entrega Final (Conceito A)

[![Security Scan](https://github.com/<user>/<repo>/actions/workflows/security_scan.yml/badge.svg)](https://github.com/<user>/<repo>/actions/workflows/security_scan.yml)

Ferramenta de **avaliação automatizada de segurança web** com foco em OWASP Top 10. Inclui **scanner** (C/B/A), **heurística de severidade**, **dashboard web**, **relatórios MD/CSV/JSON**, **autenticação** (SQLite), **Docker** e **CI**.

## Links Importantes
- **Vídeo demonstrativo (≤ 7 min):** _cole o link aqui_
- **Relatório Técnico:** `docs/RELATORIO_TECNICO.md`
- **Diagrama de Arquitetura (PNG):** `docs/architecture_diagram.png`
- **Fluxograma (PDF):** `docs/flowchart.pdf`

---

## Como Executar

### Requisitos
- Python 3.12+
- Docker (opcional) e docker-compose (opcional)

### Ambiente local
``` bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r src/requirements.txt

# Executar o dashboard
export FLASK_APP=src/web_interface_a.py
python src/web_interface_a.py  # abre em http://localhost:5000

# Credenciais de demonstração
# usuário: admin
# senha:   admin123
```

### Docker
``` bash
docker compose build
docker compose up -d
# Acesse http://localhost:5000 (login: admin / admin123)
#Depois que acabar de usar 
docker compose down
```

### Variáveis de ambiente
1. Copie `.env.example` para `.env` e ajuste valores (chave do Flask, integrações, etc.).  
2. O banco SQLite padrão é `scanner_db.sqlite` na raiz (mapeado no compose).

---

## Uso via CLI (além do dashboard)
``` bash
# Ambiente (opcional)
python3 -m venv .venv && source .venv/bin/activate
pip install -r src/requirements.txt

# Exemplo de execução
python src/scanner.py --url http://localhost:3000       --out-md reports/security_report_demo.md       --out-csv reports/vulnerabilities_demo.csv       --out-json reports/advanced_scan_demo.json       --max-time 120

# Ajuda
python src/scanner.py --help
```

---

## O que foi implementado (C → B → A)

**Conceito C**
- Varredura básica (ex.: XSS/SQLi)  
- Interface por linha de comando (CLI)  
- Relatório básico

**Conceito B (C +)**  
- ≥ 4 vulnerabilidades do OWASP Top 10  
- Relatórios **MD/CSV/JSON**  
- Integrações (opcionais): **OWASP ZAP**, **Nikto**, **Nmap**  
- Automação de execução

**Conceito A (B +)**  
- **Heurística de risco** (score CVSS-like) e **priorização por severidade**  
- **Dashboard web interativo** (gráficos, filtros, ranking)  
- **Autenticação** (multi-tenant/SQLite)  
- **Containerização (Docker)** e **CI com badge**  
- **Documentação e diagramas exportados** (PNG/PDF)

---

## Exemplos de Relatórios
- **Markdown:** `reports/security_report_demo.md`  
- **CSV:** `reports/vulnerabilities_demo.csv`  
- **JSON:** `reports/advanced_scan_demo.json`  

> Gere um scan no seu alvo de laboratório e salve as saídas com esses nomes para facilitar a correção.

---

## Cobertura OWASP (amostras)
| Categoria | Onde é detectado | Evidência/Relatório |
|---|---|---|
| **XSS** | `src/scanner.py`, `src/scanner_a.py` | `reports/*.md`, `reports/*.json` |
| **SQL Injection** | `src/scanner.py`, `src/scanner_a.py` | `reports/*.json`, `reports/*.csv` |
| **Command Injection** | `src/scanner_b.py` | `reports/*.md` |
| **Path Traversal** | `src/scanner.py` | `reports/*.csv` |
| **CSRF** | Heurísticas em `src/scanner_a.py` | `reports/*.md` |
| **Security Misconfiguration** | Checagens passivas (headers/TLS) | `reports/*.md` |

> Ajuste a tabela à nomenclatura da versão do OWASP Top 10 usada pelo professor.

---

## Integrações (opcionais)
- **ZAP**: iniciar daemon e configurar host/porta nas envs.  
  ---bash
  zap.sh -daemon -port 8090
  ---
- **Nikto/Nmap**: instalar no host/container e habilitar no `scanner_b.py`.

---

## Estrutura do Projeto (resumo)
    /src
      scanner.py
      scanner_b.py
      scanner_a.py
      report_generator*.py
      templates/...
      requirements.txt
    /docs
      RELATORIO_TECNICO.md
      architecture_diagram.png
      flowchart.pdf
    /reports
      security_report_demo.md
      vulnerabilities_demo.csv
      advanced_scan_demo.json
    .github/workflows/security_scan.yml
    Dockerfile
    docker-compose.yml
    .env.example
    README.md

---

## Aviso Legal e Ética
Ferramenta destinada a **ambientes autorizados** para fins acadêmicos. Não execute scans em sistemas de terceiros sem permissão. Use rate-limit/timeout para evitar DoS acidental e **rotacione credenciais** de demonstração após a avaliação.

---

## Créditos
Desenvolvido por **Daniel Marco** na disciplina **Tecnologias Hackers**.