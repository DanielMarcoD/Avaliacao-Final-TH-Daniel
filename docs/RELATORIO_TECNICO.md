# RELATÓRIO TÉCNICO — Ferramenta de Avaliação de Segurança Web (Opção 1)

**Disciplina:** Tecnologias Hackers  
**Aluno:** Daniel Marco  
**Projeto:** Web Security Scanner (Conceito A)  
**Repositório:** (adicione o link do seu GitHub)  
**Vídeo demonstrativo:** (substitua pelo link do vídeo — até 7 minutos)

---

## 1. Visão Geral
A ferramenta realiza **avaliação automatizada de segurança em aplicações web**, com foco nas vulnerabilidades do **OWASP Top 10**, integrando **heurística de priorização por severidade**, **dashboard web interativo**, **relatórios detalhados** (MD/CSV/JSON), **autenticação multi-tenant** (SQLite) e **containerização (Docker)**.

**Principais vulnerabilidades cobertas:**
- XSS (Cross-Site Scripting)  
- SQL Injection (SQLi)  
- CSRF (Cross-Site Request Forgery)  
- Command Injection  
- Directory/Path Traversal  
- Security Misconfiguration (headers/TLS)  
- Information Disclosure  
- (Opcional/Experimental) Broken Authentication / Open Redirect

---

## 2. Arquitetura do Sistema
- **Frontend (HTML/JS)** — templates Jinja2 com dashboard, gráficos e filtros.  
- **Backend (Flask)** — autenticação, criação/execução de scans (thread), APIs de progresso/estatísticas e download de relatórios.  
- **Mecanismo de Scanner** — `scanner.py` (básico/C), `scanner_b.py` (integrações/B), `scanner_a.py` (heurística/A).  
- **Banco (SQLite)** — usuários/empresas/sessões/histórico (seed `admin`).  
- **Relatórios** — `report_generator*.py` gerando **MD/CSV/JSON** com severidade e recomendações.  
- **Integrações (B)** — ZAP/Nikto/Nmap quando instalados.  
- **Infra** — Dockerfile + docker-compose, CI com flake8/bandit/safety.

---

## 3. Metodologia de Testes
1. **Alvo:** URL informada no dashboard/CLI.  
2. **Coleta & Varredura:**  
   - **Passivo:** headers, SSL/TLS, cookies, erros e banners.  
   - **Ativo:** payloads para **XSS/SQLi/Command Injection/Traversal/CSRF** com limites.  
   - **Auxiliares (B):** ZAP/Nikto/Nmap quando disponíveis.  
3. **Heurística (A):** score **CVSS-like (0–10)** → **Critical/High/Medium/Low**; fatores: impacto, explorabilidade, confiabilidade, contexto.  
4. **Persistência:** resultados e score por scan, agregados por usuário/empresa.  
5. **Relatórios:** **JSON/CSV/MD** com **mitigações**.  
6. **Dashboard (A):** métricas, gráficos, ranking por endpoint/IP, filtros por data/risco; **progresso via polling**.

**Stack:** Python 3.12+, Flask, SQLite, Jinja2, Pandas/Matplotlib; integrações ZAP/Nikto/Nmap (opcional).

---

## 4. Resultados (exemplo)
- `Critical`: XSS refletido confiável; SQLi com erro de banco exposto.  
- `High`: Directory Traversal com leitura de arquivo sensível; possível Command Injection.  
- `Medium`: CSRF sem token; headers ausentes (`X-Frame-Options`, `CSP`).  
- `Low`: banners de versão, listagem de diretório.

Relatórios versionados (MD/CSV/JSON) com timestamp e hash da execução.

---

## 5. Recomendações de Mitigação
- **XSS:** sanitização/escape; **CSP** restritiva; encoding seguro.  
- **SQLi:** prepared statements/ORM; validação; least privilege.  
- **CSRF:** tokens anti-CSRF; validação de origem; cookies **SameSite**.  
- **Command Injection:** whitelists; validação forte; `subprocess` sem `shell=True`.  
- **Directory Traversal:** normalização de caminho; bloqueio `../`; jail/chroot quando possível.  
- **Misconfiguration:** headers (HSTS, XFO, X-CTO); atualizar dependências; segredos fora do repo.  
- **Disclosure:** mensagens de erro sucintas; reduzir banners; segmentar/limpar logs.

---

## 6. Execução
### 6.1 Local
--- bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r src/requirements.txt
export FLASK_APP=src/web_interface_a.py
python src/web_interface_a.py  # http://localhost:5000
# login: admin / admin123
---

### 6.2 Docker
--- bash
docker build -t websec-scanner:latest .
docker compose up -d
# http://localhost:5000  (login: admin / admin123)
---

### 6.3 Integrações (opcional)
- **ZAP**: `zap.sh -daemon -port 8090` e configurar host/porta nas envs.  
- **Nikto/Nmap**: instalar e habilitar no `scanner_b.py` quando necessário.

---

## 7. Estrutura Esperada
    /src
      ├── scanner.py
      ├── scanner_b.py
      ├── scanner_a.py
      ├── report_generator*.py
      └── requirements.txt
    /docs
      ├── architecture_diagram.png   (exportado do .drawio)
      ├── flowchart.pdf              (exportado do .drawio)
    .github/workflows
      └── security_scan.yml
    Dockerfile
    docker-compose.yml
    README.md

---

## 8. Segurança e Ética
- Executar **apenas** em ambientes autorizados. Configurar rate-limit e timeouts para evitar DoS acidental.  
- Não publicar credenciais reais; rotacionar segredos; alterar `admin/admin123` após a avaliação.

---

## 9. Conclusão
Implementados **C + B + A**: detecção multi-vulnerabilidade, integrações, heurística/score, dashboard com filtros, autenticação, Docker e documentação.  
Falta somente **gravar o vídeo** e inserir o link no README.