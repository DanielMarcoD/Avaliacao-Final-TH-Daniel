#!/usr/bin/env python3
"""
Interface Web para o Web Security Scanner - Conceito B
Flask web interface para escaneamento de segurança
"""
import os
import sys
import json
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, flash
import threading
import time

# Adicionar o diretório src ao path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner_b import AdvancedWebSecurityScanner
from report_generator_b import generate_advanced_reports

app = Flask(__name__)
app.secret_key = 'websecurity_scanner_conceito_b_2025'

# Armazenar resultados de scans em memória (em produção usar banco de dados)
scan_results = {}
scan_status = {}

class ScanThread(threading.Thread):
    """Thread para executar scan em background"""
    
    def __init__(self, scan_id, target_url, timeout, use_nmap):
        super().__init__()
        self.scan_id = scan_id
        self.target_url = target_url
        self.timeout = timeout
        self.use_nmap = use_nmap
    
    def run(self):
        """Executa o scan"""
        try:
            scan_status[self.scan_id] = {'status': 'running', 'progress': 0}
            
            # Criar scanner
            scanner = AdvancedWebSecurityScanner(
                self.target_url, 
                self.timeout, 
                self.use_nmap
            )
            
            # Atualizar progresso
            scan_status[self.scan_id]['progress'] = 25
            
            # Executar scan
            results = scanner.scan()
            
            # Finalizar
            scan_status[self.scan_id] = {'status': 'completed', 'progress': 100}
            scan_results[self.scan_id] = results
            
            # Gerar relatórios
            generate_advanced_reports(results, ['json', 'markdown'])
            
        except Exception as e:
            scan_status[self.scan_id] = {
                'status': 'error', 
                'progress': 0,
                'error': str(e)
            }

@app.route('/')
def index():
    """Página inicial"""
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def start_scan():
    """Iniciar novo scan"""
    target_url = request.form.get('target_url')
    timeout = int(request.form.get('timeout', 15))
    use_nmap = 'use_nmap' in request.form
    
    if not target_url:
        flash('URL é obrigatória!', 'error')
        return redirect(url_for('index'))
    
    # Gerar ID único para o scan
    scan_id = f"scan_{int(time.time())}"
    
    # Iniciar scan em background
    scan_thread = ScanThread(scan_id, target_url, timeout, use_nmap)
    scan_thread.start()
    
    flash(f'Scan iniciado! ID: {scan_id}', 'success')
    return redirect(url_for('scan_progress', scan_id=scan_id))

@app.route('/scan/<scan_id>')
def scan_progress(scan_id):
    """Página de progresso do scan"""
    if scan_id not in scan_status:
        flash('Scan não encontrado!', 'error')
        return redirect(url_for('index'))
    
    return render_template('scan_progress.html', scan_id=scan_id)

@app.route('/api/scan/<scan_id>/status')
def scan_status_api(scan_id):
    """API para verificar status do scan"""
    if scan_id not in scan_status:
        return jsonify({'error': 'Scan não encontrado'}), 404
    
    return jsonify(scan_status[scan_id])

@app.route('/api/scan/<scan_id>/results')
def scan_results_api(scan_id):
    """API para obter resultados do scan"""
    if scan_id not in scan_results:
        return jsonify({'error': 'Resultados não encontrados'}), 404
    
    return jsonify(scan_results[scan_id])

@app.route('/scan/<scan_id>/report')
def scan_report(scan_id):
    """Página de relatório do scan"""
    if scan_id not in scan_results:
        flash('Resultados não encontrados!', 'error')
        return redirect(url_for('index'))
    
    results = scan_results[scan_id]
    return render_template('scan_report.html', results=results, scan_id=scan_id)

@app.route('/scan/<scan_id>/download/<format>')
def download_report(scan_id, format):
    """Download do relatório em formato específico"""
    if scan_id not in scan_results:
        return jsonify({'error': 'Resultados não encontrados'}), 404
    
    results = scan_results[scan_id]
    
    # Gerar arquivo temporário
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    if format == 'json':
        filename = f"scan_report_{timestamp}.json"
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        return send_file(filename, as_attachment=True, download_name=filename)
    
    elif format == 'csv':
        from report_generator_b import AdvancedReportGenerator
        generator = AdvancedReportGenerator()
        filename = f"vulnerabilities_{timestamp}.csv"
        generator.generate_csv_report(results, filename)
        return send_file(filename, as_attachment=True, download_name=filename)
    
    elif format == 'markdown':
        from report_generator_b import AdvancedReportGenerator
        generator = AdvancedReportGenerator()
        filename = f"security_report_{timestamp}.md"
        generator.generate_markdown_report(results, filename)
        return send_file(filename, as_attachment=True, download_name=filename)
    
    else:
        return jsonify({'error': 'Formato não suportado'}), 400

@app.route('/scans')
def list_scans():
    """Listar todos os scans"""
    return render_template('scan_list.html', 
                         scan_results=scan_results, 
                         scan_status=scan_status)

# Criar templates se não existirem
def create_templates():
    """Criar templates HTML básicos"""
    templates_dir = os.path.join(os.path.dirname(__file__), 'templates')
    if not os.path.exists(templates_dir):
        os.makedirs(templates_dir)
    
    # Template base
    base_template = '''<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}Web Security Scanner - Conceito B{% endblock %}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        .vulnerability-high { border-left: 4px solid #dc3545; }
        .vulnerability-medium { border-left: 4px solid #ffc107; }
        .vulnerability-low { border-left: 4px solid #28a745; }
        .vulnerability-critical { border-left: 4px solid #6f42c1; }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="{{ url_for('index') }}">
                <i class="fas fa-shield-alt"></i> Web Security Scanner B
            </a>
            <div class="navbar-nav">
                <a class="nav-link" href="{{ url_for('index') }}">Novo Scan</a>
                <a class="nav-link" href="{{ url_for('list_scans') }}">Histórico</a>
            </div>
        </div>
    </nav>

    <div class="container mt-4">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ 'danger' if category == 'error' else 'success' }} alert-dismissible fade show">
                        {{ message }}
                        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                    </div>
                {% endfor %}
            {% endif %}
        {% endwith %}

        {% block content %}{% endblock %}
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    {% block scripts %}{% endblock %}
</body>
</html>'''
    
    with open(os.path.join(templates_dir, 'base.html'), 'w', encoding='utf-8') as f:
        f.write(base_template)
    
    # Template inicial
    index_template = '''{% extends "base.html" %}

{% block content %}
<div class="row">
    <div class="col-md-8 mx-auto">
        <div class="card">
            <div class="card-header">
                <h3><i class="fas fa-scan"></i> Novo Scan de Segurança</h3>
            </div>
            <div class="card-body">
                <form method="POST" action="{{ url_for('start_scan') }}">
                    <div class="mb-3">
                        <label for="target_url" class="form-label">URL Alvo</label>
                        <input type="url" class="form-control" id="target_url" name="target_url" 
                               placeholder="https://exemplo.com" required>
                        <div class="form-text">Digite a URL completa do site a ser escaneado</div>
                    </div>
                    
                    <div class="mb-3">
                        <label for="timeout" class="form-label">Timeout (segundos)</label>
                        <input type="number" class="form-control" id="timeout" name="timeout" 
                               value="15" min="5" max="60">
                    </div>
                    
                    <div class="mb-3 form-check">
                        <input type="checkbox" class="form-check-input" id="use_nmap" name="use_nmap" checked>
                        <label class="form-check-label" for="use_nmap">
                            Incluir scan de portas (Nmap)
                        </label>
                    </div>
                    
                    <button type="submit" class="btn btn-primary btn-lg">
                        <i class="fas fa-play"></i> Iniciar Scan
                    </button>
                </form>
            </div>
        </div>
        
        <div class="card mt-4">
            <div class="card-header">
                <h5>Vulnerabilidades Detectadas</h5>
            </div>
            <div class="card-body">
                <ul class="list-unstyled">
                    <li><i class="fas fa-bug text-danger"></i> XSS (Cross-Site Scripting)</li>
                    <li><i class="fas fa-database text-danger"></i> SQL Injection</li>
                    <li><i class="fas fa-folder-open text-warning"></i> Directory Traversal</li>
                    <li><i class="fas fa-terminal text-warning"></i> Command Injection</li>
                    <li><i class="fas fa-eye text-info"></i> Information Disclosure</li>
                    <li><i class="fas fa-key text-danger"></i> Broken Authentication</li>
                </ul>
            </div>
        </div>
    </div>
</div>
{% endblock %}'''
    
    with open(os.path.join(templates_dir, 'index.html'), 'w', encoding='utf-8') as f:
        f.write(index_template)
    
    # Template de progresso
    progress_template = '''{% extends "base.html" %}

{% block content %}
<div class="row">
    <div class="col-md-8 mx-auto">
        <div class="card">
            <div class="card-header">
                <h3><i class="fas fa-spinner fa-spin"></i> Scan em Progresso</h3>
            </div>
            <div class="card-body text-center">
                <div class="progress mb-3" style="height: 30px;">
                    <div id="progress-bar" class="progress-bar progress-bar-striped progress-bar-animated" 
                         style="width: 0%"></div>
                </div>
                <p id="status-text">Inicializando scan...</p>
                <div id="result-section" style="display: none;">
                    <a href="{{ url_for('scan_report', scan_id=scan_id) }}" class="btn btn-success">
                        <i class="fas fa-chart-line"></i> Ver Relatório
                    </a>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}

{% block scripts %}
<script>
function checkStatus() {
    fetch('/api/scan/{{ scan_id }}/status')
        .then(response => response.json())
        .then(data => {
            const progressBar = document.getElementById('progress-bar');
            const statusText = document.getElementById('status-text');
            const resultSection = document.getElementById('result-section');
            
            if (data.status === 'running') {
                progressBar.style.width = data.progress + '%';
                statusText.textContent = 'Executando scan... ' + data.progress + '%';
                setTimeout(checkStatus, 2000);
            } else if (data.status === 'completed') {
                progressBar.style.width = '100%';
                progressBar.classList.remove('progress-bar-animated');
                progressBar.classList.add('bg-success');
                statusText.textContent = 'Scan concluído com sucesso!';
                resultSection.style.display = 'block';
            } else if (data.status === 'error') {
                progressBar.classList.add('bg-danger');
                statusText.textContent = 'Erro: ' + (data.error || 'Erro desconhecido');
            }
        })
        .catch(error => {
            console.error('Erro ao verificar status:', error);
            setTimeout(checkStatus, 5000);
        });
}

// Iniciar verificação
checkStatus();
</script>
{% endblock %}'''
    
    with open(os.path.join(templates_dir, 'scan_progress.html'), 'w', encoding='utf-8') as f:
        f.write(progress_template)

def main():
    """Função principal para executar a aplicação Flask"""
    # Criar templates
    create_templates()
    
    print("🌐 Iniciando interface web do Scanner - Conceito B")
    print("📡 Acesse: http://localhost:5000")
    
    # Executar aplicação
    app.run(debug=True, host='0.0.0.0', port=5000)

if __name__ == "__main__":
    main()
