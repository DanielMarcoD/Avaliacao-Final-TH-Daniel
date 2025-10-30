#!/usr/bin/env python3
"""
Advanced Web Interface for Web Security Scanner - Conceito A
Enhanced dashboard with authentication, real-time analytics, and interactive features
"""

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_file
from werkzeug.security import generate_password_hash, check_password_hash
import threading
import time
import uuid
import json
import os
import sqlite3
from datetime import datetime, timedelta
from scanner_a import EnhancedWebSecurityScanner
from report_generator_a import AdvancedReportGeneratorA
from report_generator_a import AdvancedReportGeneratorA
import sqlite3
from functools import wraps

app = Flask(__name__, template_folder='templates')
app.secret_key = 'enhanced_security_scanner_secret_key_2024'

# Global variables for scan management
active_scans = {}
scan_results = {}

# Initialize report generator
report_generator = AdvancedReportGeneratorA()

# Database setup

# Initialize database
def init_db():
    """Initialize SQLite database for user management and scan history"""
    conn = sqlite3.connect('scanner_db.sqlite')
    cursor = conn.cursor()
    
    # Companies table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS companies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            domain TEXT,
            industry TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            subscription_plan TEXT DEFAULT 'basic',
            max_scans_per_month INTEGER DEFAULT 100
        )
    ''')
    
    # Users table with company association
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            is_admin BOOLEAN DEFAULT 0,
            company_id INTEGER,
            last_login TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Try to add company_id column if it doesn't exist (backwards-compat)
    try:
        cursor.execute('ALTER TABLE users ADD COLUMN company_id INTEGER')
    except sqlite3.OperationalError:
        pass  # Column already exists
    
    # Try to add is_admin column if it doesn't exist (backwards-compat)
    try:
        cursor.execute('ALTER TABLE users ADD COLUMN is_admin BOOLEAN DEFAULT 0')
    except sqlite3.OperationalError:
        pass  # Column already exists
    
    # Scans table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT UNIQUE NOT NULL,
            user_id INTEGER,
            target_url TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            start_time TIMESTAMP,
            end_time TIMESTAMP,
            vulnerabilities_count INTEGER DEFAULT 0,
            risk_score REAL DEFAULT 0.0,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Create default company and admin user
    cursor.execute('''
        INSERT OR IGNORE INTO companies (name, domain, industry, subscription_plan) 
        VALUES (?, ?, ?, ?)
    ''', ('TechAcker Demo Corp', 'techacker.com', 'Technology', 'enterprise'))
    
    admin_hash = generate_password_hash('admin123')
    cursor.execute('''
        INSERT OR IGNORE INTO users (username, password_hash, company_id, is_admin) 
        VALUES (?, ?, ?, ?)
    ''', ('admin', admin_hash, 1, 1))
    
    # Update admin user to have is_admin=1 if it exists but is_admin is not set
    cursor.execute('''
        UPDATE users SET is_admin = 1 WHERE username = 'admin' AND (is_admin IS NULL OR is_admin = 0)
    ''')
    
    conn.commit()
    conn.close()

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        
        conn = sqlite3.connect('scanner_db.sqlite')
        cursor = conn.cursor()
        cursor.execute('SELECT role FROM users WHERE id = ?', (session['user_id'],))
        user = cursor.fetchone()
        conn.close()
        
        if not user or user[0] != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated_function

class EnhancedScanThread(threading.Thread):
    """Enhanced scan thread with database logging and detailed progress tracking"""
    
    def __init__(self, scan_id: str, url: str, timeout: int = 20, user_id: int = None):
        super().__init__()
        self.scan_id = scan_id
        self.url = url
        self.timeout = timeout
        self.user_id = user_id
        self.daemon = True
        
    def run(self):
        """Execute the enhanced security scan"""
        try:
            # Update scan status in database
            self._update_scan_status('running')
            
            # Initialize scanner
            scanner = EnhancedWebSecurityScanner(self.url, self.timeout)
            
            # Update progress
            active_scans[self.scan_id] = {
                'status': 'running',
                'progress': 10,
                'stage': 'Initializing scanner...',
                'start_time': datetime.now()
            }
            
            # Perform comprehensive scan
            vulnerabilities, metadata = scanner.perform_comprehensive_scan()
            
            # Calculate risk metrics
            total_risk = sum(v['risk_score'] for v in vulnerabilities) if vulnerabilities else 0
            avg_risk = total_risk / len(vulnerabilities) if vulnerabilities else 0
            
            # Store results
            scan_results[self.scan_id] = {
                'vulnerabilities': vulnerabilities,
                'metadata': metadata,
                'status': 'completed',
                'total_vulnerabilities': len(vulnerabilities),
                'average_risk_score': avg_risk,
                'completion_time': datetime.now()
            }
            
            # Update progress
            active_scans[self.scan_id] = {
                'status': 'completed',
                'progress': 100,
                'stage': 'Scan completed',
                'start_time': active_scans[self.scan_id]['start_time'],
                'end_time': datetime.now(),
                'vulnerabilities_found': len(vulnerabilities),
                'risk_score': avg_risk
            }
            
            # Update database
            self._update_scan_status('completed', len(vulnerabilities), avg_risk)
            
        except Exception as e:
            # Handle scan failure
            scan_results[self.scan_id] = {
                'error': str(e),
                'status': 'failed'
            }
            
            active_scans[self.scan_id] = {
                'status': 'failed',
                'error': str(e),
                'progress': 0
            }
            
            self._update_scan_status('failed')
            
    def _update_scan_status(self, status: str, vuln_count: int = 0, risk_score: float = 0.0):
        """Update scan status in database"""
        conn = sqlite3.connect('scanner_db.sqlite')
        cursor = conn.cursor()
        
        if status == 'running':
            cursor.execute('''
                UPDATE scans SET status = ?, start_time = CURRENT_TIMESTAMP 
                WHERE scan_id = ?
            ''', (status, self.scan_id))
        elif status in ['completed', 'failed']:
            cursor.execute('''
                UPDATE scans SET status = ?, end_time = CURRENT_TIMESTAMP,
                vulnerabilities_count = ?, risk_score = ?
                WHERE scan_id = ?
            ''', (status, vuln_count, risk_score, self.scan_id))
        
        conn.commit()
        conn.close()

# Routes
@app.route('/')
def index():
    """Enhanced dashboard with analytics"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Get user scan statistics
    conn = sqlite3.connect('scanner_db.sqlite')
    cursor = conn.cursor()
    
    # Recent scans
    cursor.execute('''
        SELECT scan_id, target_url, status, start_time, vulnerabilities_count, risk_score
        FROM scans WHERE user_id = ? 
        ORDER BY start_time DESC LIMIT 10
    ''', (session['user_id'],))
    recent_scans = cursor.fetchall()
    
    # Statistics
    cursor.execute('''
        SELECT 
            COUNT(*) as total_scans,
            SUM(vulnerabilities_count) as total_vulns,
            AVG(risk_score) as avg_risk
        FROM scans WHERE user_id = ? AND status = 'completed'
    ''', (session['user_id'],))
    stats = cursor.fetchone()
    
    conn.close()
    
    
    # Debug template variables
    print(f"DEBUG: Template vars - username: {session.get('username')}, is_admin: {session.get('is_admin', False)}")
    
    return render_template('enhanced_dashboard.html', 
                         recent_scans=recent_scans, 
                         stats=stats,
                         username=session.get('username'),
                         is_admin=session.get('is_admin', False))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Enhanced login with session management"""
    if request.method == 'POST':
        username = request.json.get('username')
        password = request.json.get('password')
        
        conn = sqlite3.connect('scanner_db.sqlite')
        cursor = conn.cursor()
        cursor.execute('SELECT id, password_hash, role, is_admin FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        
        if user and check_password_hash(user[1], password):
            session['user_id'] = user[0]
            session['username'] = username
            session['role'] = user[2]
            session['is_admin'] = bool(user[3])
            

            
            # Update last login
            cursor.execute('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', (user[0],))
            conn.commit()
            conn.close()
            
            return jsonify({'success': True, 'redirect': url_for('index')})
        
        conn.close()
        return jsonify({'success': False, 'message': 'Invalid credentials'})
    
    return render_template('login.html')

@app.route('/register', methods=['POST'])
def register():
    """User registration"""
    username = request.json.get('username')
    password = request.json.get('password')
    
    if not username or not password:
        return jsonify({'success': False, 'message': 'Username and password required'})
    
    password_hash = generate_password_hash(password)
    
    try:
        conn = sqlite3.connect('scanner_db.sqlite')
        cursor = conn.cursor()
        cursor.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', 
                      (username, password_hash))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Registration successful'})
    except sqlite3.IntegrityError:
        return jsonify({'success': False, 'message': 'Username already exists'})

@app.route('/logout')
def logout():
    """User logout"""
    session.clear()
    return redirect(url_for('login'))

@app.route('/scan', methods=['POST'])
@login_required
def start_scan():
    """Start enhanced security scan"""
    data = request.get_json()
    url = data.get('url', '').strip()
    timeout = int(data.get('timeout', 20))
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    # Generate unique scan ID
    scan_id = str(uuid.uuid4())[:8]
    
    # Save scan to database
    conn = sqlite3.connect('scanner_db.sqlite')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO scans (scan_id, user_id, target_url, status) 
        VALUES (?, ?, ?, ?)
    ''', (scan_id, session['user_id'], url, 'pending'))
    conn.commit()
    conn.close()
    
    # Initialize scan progress
    active_scans[scan_id] = {
        'status': 'pending',
        'progress': 0,
        'stage': 'Preparing scan...'
    }
    
    # Start scan thread
    scan_thread = EnhancedScanThread(scan_id, url, timeout, session['user_id'])
    scan_thread.start()
    
    return jsonify({'scan_id': scan_id})

@app.route('/api/scan/<scan_id>/status')
@login_required
def get_scan_status(scan_id):
    """Get enhanced scan status with detailed progress"""
    if scan_id in active_scans:
        status = active_scans[scan_id].copy()
        
        # Add time information
        if 'start_time' in status:
            elapsed = (datetime.now() - status['start_time']).total_seconds()
            status['elapsed_time'] = f"{elapsed:.1f}s"
            
        return jsonify(status)
    
    return jsonify({'status': 'not_found'}), 404

@app.route('/api/scan/<scan_id>/results')
@login_required
def get_scan_results(scan_id):
    """Get detailed scan results with enhanced formatting"""
    if scan_id in scan_results:
        results = scan_results[scan_id].copy()
        
        # Add vulnerability summary
        if 'vulnerabilities' in results:
            vulns = results['vulnerabilities']
            results['summary'] = {
                'total': len(vulns),
                'by_severity': {},
                'by_type': {},
                'top_risks': sorted(vulns, key=lambda x: x['risk_score'], reverse=True)[:5]
            }
            
            # Calculate distributions
            for vuln in vulns:
                severity = vuln['severity']
                vuln_type = vuln['type']
                
                results['summary']['by_severity'][severity] = results['summary']['by_severity'].get(severity, 0) + 1
                results['summary']['by_type'][vuln_type] = results['summary']['by_type'].get(vuln_type, 0) + 1
        
        return jsonify(results)
    
    return jsonify({'error': 'Results not found'}), 404

@app.route('/api/dashboard/stats')
@login_required
def dashboard_stats():
    """Get dashboard statistics for charts"""
    conn = sqlite3.connect('scanner_db.sqlite')
    cursor = conn.cursor()
    
    try:
        # Get vulnerability distribution (simulated based on scan counts)
        cursor.execute('''
            SELECT 
                COUNT(CASE WHEN vulnerabilities_count > 20 THEN 1 END) as high_risk,
                COUNT(CASE WHEN vulnerabilities_count BETWEEN 10 AND 20 THEN 1 END) as medium_risk,
                COUNT(CASE WHEN vulnerabilities_count BETWEEN 1 AND 9 THEN 1 END) as low_risk,
                COUNT(CASE WHEN vulnerabilities_count = 0 THEN 1 END) as info
            FROM scans 
            WHERE user_id = ? AND status = "completed"
        ''', (session['user_id'],))
        
        distribution = cursor.fetchone()
        
        # Get trend data (last 10 scans)
        cursor.execute('''
            SELECT vulnerabilities_count, start_time 
            FROM scans 
            WHERE user_id = ? AND status = "completed"
            ORDER BY start_time DESC LIMIT 10
        ''', (session['user_id'],))
        
        trend_data = cursor.fetchall()
        
        # Format trend data
        trend_labels = [f"Scan {i+1}" for i in range(len(trend_data))][::-1]
        trend_values = [row[0] or 0 for row in trend_data][::-1]
        
        stats = {
            'high_risk': distribution[0] or 0,
            'medium_risk': distribution[1] or 0,
            'low_risk': distribution[2] or 0,
            'info': distribution[3] or 0,
            'trend_labels': trend_labels,
            'trend_data': trend_values
        }
        
        conn.close()
        return jsonify(stats)
        
    except Exception as e:
        conn.close()
        # Return demo data if no scans available
        return jsonify({
            'high_risk': 15,
            'medium_risk': 28,
            'low_risk': 42,
            'info': 8,
            'trend_labels': ['Scan 1', 'Scan 2', 'Scan 3', 'Scan 4', 'Scan 5'],
            'trend_data': [12, 19, 8, 25, 15]
        })

@app.route('/api/scan/<scan_id>/report/<format>')
@login_required
def download_report(scan_id, format):
    """Download scan report in specified format"""
    # Check if scan results exist in memory first
    if scan_id in scan_results:
        results = scan_results[scan_id]
        
        if 'vulnerabilities' in results:
            try:
                if format == 'json':
                    filepath = report_generator.generate_json_report(results['vulnerabilities'], results.get('metadata', {}))
                elif format == 'csv':
                    filepath = report_generator.generate_csv_report(results['vulnerabilities'], results.get('metadata', {}))
                elif format == 'markdown':
                    filepath = report_generator.generate_markdown_report(results['vulnerabilities'], results.get('metadata', {}))
                else:
                    return jsonify({'error': 'Unsupported format'}), 400
                    
                return send_file(filepath, as_attachment=True)
                
            except Exception as e:
                return jsonify({'error': f'Report generation failed: {str(e)}'}), 500
    
    # Fallback to database lookup
    conn = sqlite3.connect('scanner_db.sqlite')
    cursor = conn.cursor()
    
    # Get scan results using scan_id string
    cursor.execute('SELECT results FROM scans WHERE scan_id = ? AND user_id = ?', 
                   (scan_id, session['user_id']))
    result = cursor.fetchone()
    conn.close()
    
    if not result:
        return jsonify({'error': 'Scan not found'}), 404
    
    try:
        results = json.loads(result[0])
    except:
        return jsonify({'error': 'Invalid scan results'}), 400
    
    try:
        if format == 'json':
            filepath = report_generator.generate_json_report(results['vulnerabilities'], results['metadata'])
        elif format == 'csv':
            filepath = report_generator.generate_csv_report(results['vulnerabilities'], results['metadata'])
        elif format == 'markdown':
            filepath = report_generator.generate_markdown_report(results['vulnerabilities'], results['metadata'])
        else:
            return jsonify({'error': 'Unsupported format'}), 400
            
        return send_file(filepath, as_attachment=True)
        
    except Exception as e:
        return jsonify({'error': f'Report generation failed: {str(e)}'}), 500

@app.route('/admin')
@admin_required
def admin_dashboard():
    """Admin dashboard with system statistics"""
    conn = sqlite3.connect('scanner_db.sqlite')
    cursor = conn.cursor()
    
    # Get system statistics
    cursor.execute('SELECT COUNT(*) FROM users')
    total_users = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM scans')
    total_scans = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM scans WHERE status = "completed"')
    completed_scans = cursor.fetchone()[0]
    
    cursor.execute('SELECT SUM(vulnerabilities_count) FROM scans WHERE status = "completed"')
    total_vulns = cursor.fetchone()[0] or 0
    
    # Recent activity
    cursor.execute('''
        SELECT u.username, s.target_url, s.status, s.start_time, s.vulnerabilities_count
        FROM scans s
        JOIN users u ON s.user_id = u.id
        ORDER BY s.start_time DESC LIMIT 20
    ''')
    recent_activity = cursor.fetchall()
    
    conn.close()
    
    return render_template('admin_dashboard.html',
                         total_users=total_users,
                         total_scans=total_scans,
                         completed_scans=completed_scans,
                         total_vulns=total_vulns,
                         recent_activity=recent_activity)

@app.route('/api/admin/stats')
@admin_required
def admin_stats():
    """API endpoint for admin statistics"""
    conn = sqlite3.connect('scanner_db.sqlite')
    cursor = conn.cursor()
    
    # Daily scan counts for the last 30 days
    cursor.execute('''
        SELECT DATE(start_time) as scan_date, COUNT(*) as count
        FROM scans 
        WHERE start_time >= DATE('now', '-30 days')
        GROUP BY DATE(start_time)
        ORDER BY scan_date
    ''')
    daily_scans = cursor.fetchall()
    
    # Vulnerability distribution
    cursor.execute('''
        SELECT 
            CASE 
                WHEN risk_score >= 9 THEN 'Critical'
                WHEN risk_score >= 7 THEN 'High' 
                WHEN risk_score >= 4 THEN 'Medium'
                ELSE 'Low'
            END as severity,
            COUNT(*) as count
        FROM scans 
        WHERE status = 'completed' AND vulnerabilities_count > 0
        GROUP BY severity
    ''')
    severity_dist = cursor.fetchall()
    
    conn.close()
    
    return jsonify({
        'daily_scans': daily_scans,
        'severity_distribution': severity_dist
    })

# Template creation for enhanced dashboard
def create_templates():
    """Create template files if they don't exist"""
    os.makedirs('templates', exist_ok=True)
    os.makedirs('reports', exist_ok=True)
    
    # Enhanced dashboard template
    dashboard_html = '''<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enhanced Security Scanner - Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        .dashboard-header { background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%); color: white; }
        .stat-card { border-left: 4px solid #007bff; }
        .vulnerability-badge { font-size: 0.8em; }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark dashboard-header">
        <div class="container">
            <a class="navbar-brand" href="#"><i class="fas fa-shield-alt"></i> Enhanced Security Scanner</a>
            <div class="navbar-nav ms-auto">
                <span class="navbar-text me-3">Welcome, {{ username }}</span>
                <a class="btn btn-outline-light btn-sm" href="/logout">Logout</a>
            </div>
        </div>
    </nav>

    <div class="container mt-4">
        <!-- Statistics Cards -->
        <div class="row mb-4">
            <div class="col-md-4">
                <div class="card stat-card">
                    <div class="card-body">
                        <h5 class="card-title"><i class="fas fa-search text-primary"></i> Total Scans</h5>
                        <h2 class="text-primary">{{ stats[0] or 0 }}</h2>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card stat-card">
                    <div class="card-body">
                        <h5 class="card-title"><i class="fas fa-bug text-danger"></i> Vulnerabilities Found</h5>
                        <h2 class="text-danger">{{ stats[1] or 0 }}</h2>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card stat-card">
                    <div class="card-body">
                        <h5 class="card-title"><i class="fas fa-chart-line text-warning"></i> Avg Risk Score</h5>
                        <h2 class="text-warning">{{ "%.1f"|format(stats[2] or 0) }}/10</h2>
                    </div>
                </div>
            </div>
        </div>

        <!-- New Scan Form -->
        <div class="card mb-4">
            <div class="card-header">
                <h5><i class="fas fa-plus"></i> Start New Enhanced Scan</h5>
            </div>
            <div class="card-body">
                <form id="scanForm">
                    <div class="row">
                        <div class="col-md-8">
                            <input type="url" class="form-control" id="targetUrl" placeholder="https://example.com" required>
                        </div>
                        <div class="col-md-2">
                            <input type="number" class="form-control" id="timeout" placeholder="20" value="20" min="5" max="60">
                        </div>
                        <div class="col-md-2">
                            <button type="submit" class="btn btn-primary w-100">
                                <i class="fas fa-play"></i> Start Scan
                            </button>
                        </div>
                    </div>
                </form>
            </div>
        </div>

        <!-- Charts and Analytics -->
        <div class="row mb-4">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h6><i class="fas fa-chart-pie"></i> Vulnerability Distribution</h6>
                    </div>
                    <div class="card-body">
                        <canvas id="vulnerabilityChart" width="400" height="200"></canvas>
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h6><i class="fas fa-chart-line"></i> Risk Trend</h6>
                    </div>
                    <div class="card-body">
                        <canvas id="riskChart" width="400" height="200"></canvas>
                    </div>
                </div>
            </div>
        </div>

        <!-- Active Scans -->
        <div id="activeScans"></div>

        <!-- Recent Scans with Filters -->
        <div class="card">
            <div class="card-header d-flex justify-content-between align-items-center">
                <h5><i class="fas fa-history"></i> Recent Scans</h5>
                <div class="btn-group" role="group">
                    <button type="button" class="btn btn-outline-primary btn-sm" onclick="filterScans('all')">All</button>
                    <button type="button" class="btn btn-outline-success btn-sm" onclick="filterScans('completed')">Completed</button>
                    <button type="button" class="btn btn-outline-warning btn-sm" onclick="filterScans('running')">Running</button>
                    <button type="button" class="btn btn-outline-danger btn-sm" onclick="filterScans('failed')">Failed</button>
                </div>
            </div>
            <div class="card-body">
                <div class="table-responsive">
                    <table class="table">
                        <thead>
                            <tr>
                                <th>Scan ID</th>
                                <th>Target</th>
                                <th>Status</th>
                                <th>Date</th>
                                <th>Vulnerabilities</th>
                                <th>Risk Score</th>
                            </tr>
                        </thead>
                        <tbody id="scanHistory">
                            {% for scan in recent_scans %}
                            <tr>
                                <td><code>{{ scan[0] }}</code></td>
                                <td>{{ scan[1] }}</td>
                                <td>
                                    {% if scan[2] == 'completed' %}
                                        <span class="badge bg-success">Completed</span>
                                    {% elif scan[2] == 'running' %}
                                        <span class="badge bg-primary">Running</span>
                                    {% elif scan[2] == 'failed' %}
                                        <span class="badge bg-danger">Failed</span>
                                    {% else %}
                                        <span class="badge bg-secondary">{{ scan[2] }}</span>
                                    {% endif %}
                                </td>
                                <td>{{ scan[3] }}</td>
                                <td>
                                    {% if scan[4] > 0 %}
                                        <span class="badge bg-danger">{{ scan[4] }}</span>
                                    {% else %}
                                        <span class="badge bg-success">0</span>
                                    {% endif %}
                                </td>
                                <td>
                                    {% if scan[5] %}
                                        <span class="badge bg-warning">{{ "%.1f"|format(scan[5]) }}/10</span>
                                    {% else %}
                                        <span class="text-muted">N/A</span>
                                    {% endif %}
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Enhanced scan functionality with real-time updates
        document.getElementById('scanForm').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const url = document.getElementById('targetUrl').value;
            const timeout = document.getElementById('timeout').value;
            
            fetch('/scan', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({url: url, timeout: parseInt(timeout)})
            })
            .then(response => response.json())
            .then(data => {
                if (data.scan_id) {
                    createScanMonitor(data.scan_id, url);
                } else {
                    alert('Error starting scan: ' + (data.error || 'Unknown error'));
                }
            });
        });

        function createScanMonitor(scanId, url) {
            const activeScansDiv = document.getElementById('activeScans');
            
            const scanCard = document.createElement('div');
            scanCard.className = 'card mb-3';
            scanCard.id = 'scan-' + scanId;
            scanCard.innerHTML = `
                <div class="card-header d-flex justify-content-between align-items-center">
                    <div>
                        <strong>Scan ${scanId}</strong> - ${url}
                    </div>
                    <div class="btn-group" role="group" style="display: none;" id="actions-${scanId}">
                        <button class="btn btn-sm btn-outline-primary" onclick="downloadReport('${scanId}', 'json')">JSON</button>
                        <button class="btn btn-sm btn-outline-success" onclick="downloadReport('${scanId}', 'csv')">CSV</button>
                        <button class="btn btn-sm btn-outline-info" onclick="downloadReport('${scanId}', 'markdown')">MD</button>
                    </div>
                </div>
                <div class="card-body">
                    <div class="progress mb-2">
                        <div class="progress-bar" id="progress-${scanId}" style="width: 0%"></div>
                    </div>
                    <div id="status-${scanId}">Initializing...</div>
                    <div id="results-${scanId}" style="display: none;"></div>
                </div>
            `;
            
            activeScansDiv.appendChild(scanCard);
            
            // Start monitoring
            monitorScan(scanId);
        }

        function monitorScan(scanId) {
            const interval = setInterval(() => {
                fetch(`/api/scan/${scanId}/status`)
                .then(response => response.json())
                .then(data => {
                    updateScanProgress(scanId, data);
                    
                    if (data.status === 'completed' || data.status === 'failed') {
                        clearInterval(interval);
                        if (data.status === 'completed') {
                            loadScanResults(scanId);
                        }
                    }
                });
            }, 2000);
        }

        function updateScanProgress(scanId, data) {
            const progressBar = document.getElementById('progress-' + scanId);
            const statusDiv = document.getElementById('status-' + scanId);
            
            if (progressBar) progressBar.style.width = (data.progress || 0) + '%';
            
            let statusText = data.stage || data.status || 'Unknown';
            if (data.elapsed_time) statusText += ` (${data.elapsed_time})`;
            if (data.vulnerabilities_found !== undefined) {
                statusText += ` - ${data.vulnerabilities_found} vulnerabilities found`;
            }
            
            if (statusDiv) statusDiv.textContent = statusText;
            
            if (data.status === 'completed') {
                document.getElementById('actions-' + scanId).style.display = 'block';
            }
        }

        function loadScanResults(scanId) {
            fetch(`/api/scan/${scanId}/results`)
            .then(response => response.json())
            .then(data => {
                const resultsDiv = document.getElementById('results-' + scanId);
                if (data.vulnerabilities) {
                    let html = '<h6>Scan Results:</h6>';
                    html += `<p><strong>Total Vulnerabilities:</strong> ${data.vulnerabilities.length}</p>`;
                    
                    if (data.summary) {
                        html += '<strong>By Severity:</strong><br>';
                        for (const [severity, count] of Object.entries(data.summary.by_severity)) {
                            const badgeClass = severity === 'CRITICAL' ? 'danger' : 
                                              severity === 'HIGH' ? 'warning' : 
                                              severity === 'MEDIUM' ? 'info' : 'secondary';
                            html += `<span class="badge bg-${badgeClass} me-1">${severity}: ${count}</span>`;
                        }
                    }
                    
                    resultsDiv.innerHTML = html;
                    resultsDiv.style.display = 'block';
                }
            });
        }

        function downloadReport(scanId, format) {
            if (!scanId || scanId === '') {
                alert('Scan ID não encontrado. Execute um scan primeiro.');
                return;
            }
            console.log(`Downloading report for scan: ${scanId}, format: ${format}`);
            window.open(`/api/scan/${scanId}/report/${format}`, '_blank');
        }

        // Chart and Filter functionality
        let vulnerabilityChart = null;
        let riskChart = null;
        let currentFilter = 'all';

        // Initialize charts on page load
        document.addEventListener('DOMContentLoaded', function() {
            initCharts();
            loadDashboardData();
        });

        function initCharts() {
            // Vulnerability Distribution Pie Chart
            const ctx1 = document.getElementById('vulnerabilityChart').getContext('2d');
            vulnerabilityChart = new Chart(ctx1, {
                type: 'pie',
                data: {
                    labels: ['High Risk', 'Medium Risk', 'Low Risk', 'Info'],
                    datasets: [{
                        data: [0, 0, 0, 0],
                        backgroundColor: ['#dc3545', '#fd7e14', '#ffc107', '#17a2b8']
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: { position: 'bottom' }
                    }
                }
            });

            // Risk Trend Line Chart
            const ctx2 = document.getElementById('riskChart').getContext('2d');
            riskChart = new Chart(ctx2, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Vulnerabilities Found',
                        data: [],
                        borderColor: '#dc3545',
                        backgroundColor: 'rgba(220, 53, 69, 0.1)',
                        tension: 0.3
                    }]
                },
                options: {
                    responsive: true,
                    scales: {
                        y: { beginAtZero: true }
                    }
                }
            });
        }

        function loadDashboardData() {
            fetch('/api/dashboard/stats', {
                method: 'GET',
                credentials: 'same-origin',  // Include cookies for session
                headers: {
                    'Content-Type': 'application/json'
                }
            })
                .then(response => {
                    if (response.ok) {
                        return response.json();
                    } else {
                        throw new Error('API call failed');
                    }
                })
                .then(data => {
                    console.log('Dashboard data loaded:', data);
                    updateCharts(data);
                })
                .catch(error => {
                    console.log('Dashboard data not available, using demo data:', error);
                    updateChartsWithDemoData();
                });
        }

        function updateCharts(data) {
            if (!vulnerabilityChart || !riskChart) return;

            // Update vulnerability distribution
            vulnerabilityChart.data.datasets[0].data = [
                data.high_risk || 15,
                data.medium_risk || 28,
                data.low_risk || 42,
                data.info || 8
            ];
            vulnerabilityChart.update();

            // Update risk trend
            riskChart.data.labels = data.trend_labels || ['Scan 1', 'Scan 2', 'Scan 3', 'Scan 4', 'Scan 5'];
            riskChart.data.datasets[0].data = data.trend_data || [12, 19, 8, 25, 15];
            riskChart.update();
        }

        function updateChartsWithDemoData() {
            if (!vulnerabilityChart || !riskChart) return;

            // Demo vulnerability distribution
            vulnerabilityChart.data.datasets[0].data = [15, 28, 42, 8];
            vulnerabilityChart.update();

            // Demo risk trend
            riskChart.data.labels = ['Last Week', 'This Week', 'Today'];
            riskChart.data.datasets[0].data = [12, 19, 25];
            riskChart.update();
        }

        function filterScans(filter) {
            currentFilter = filter;
            
            // Update button styles
            document.querySelectorAll('.btn-group .btn').forEach(btn => {
                btn.classList.remove('active', 'btn-primary');
                btn.classList.add('btn-outline-primary');
            });
            
            // Find and activate the clicked button
            const clickedButton = Array.from(document.querySelectorAll('.btn-group .btn')).find(btn => {
                return btn.textContent.trim().toLowerCase() === filter || 
                       (filter === 'all' && btn.textContent.trim() === 'All') ||
                       (filter === 'completed' && btn.textContent.trim() === 'Completed') ||
                       (filter === 'running' && btn.textContent.trim() === 'Running') ||
                       (filter === 'failed' && btn.textContent.trim() === 'Failed');
            });
            
            if (clickedButton) {
                clickedButton.classList.remove('btn-outline-primary');
                clickedButton.classList.add('btn-primary');
            }

            // Filter table rows
            const tableBody = document.querySelector('#scanHistory');
            if (tableBody) {
                const tableRows = tableBody.querySelectorAll('tr');
                tableRows.forEach(row => {
                    if (filter === 'all') {
                        row.style.display = '';
                    } else {
                        const statusBadge = row.querySelector('.badge');
                        if (statusBadge) {
                            const status = statusBadge.textContent.trim().toLowerCase();
                            row.style.display = status === filter ? '' : 'none';
                        } else {
                            row.style.display = 'none';
                        }
                    }
                });
                console.log(`Filtered ${tableRows.length} rows for: ${filter}`);
            } else {
                console.log('Table body #scanHistory not found');
            }
        }
    </script>
</body>
</html>'''
    
    with open('templates/enhanced_dashboard.html', 'w', encoding='utf-8') as f:
        f.write(dashboard_html)

    # Login template
    login_html = '''<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enhanced Security Scanner - Login</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        body { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; }
        .login-card { margin-top: 10vh; }
    </style>
</head>
<body>
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-6 col-lg-4">
                <div class="card login-card">
                    <div class="card-body">
                        <div class="text-center mb-4">
                            <i class="fas fa-shield-alt fa-3x text-primary mb-3"></i>
                            <h3>Enhanced Security Scanner</h3>
                            <p class="text-muted">Conceito A - Advanced Dashboard</p>
                        </div>
                        
                        <form id="loginForm">
                            <div class="mb-3">
                                <input type="text" class="form-control" id="username" placeholder="Username" required>
                            </div>
                            <div class="mb-3">
                                <input type="password" class="form-control" id="password" placeholder="Password" required>
                            </div>
                            <button type="submit" class="btn btn-primary w-100 mb-3">Login</button>
                        </form>
                        
                        <div class="text-center">
                            <small class="text-muted">
                                Default: admin / admin123<br>
                                <a href="#" onclick="showRegister()">Create new account</a>
                            </small>
                        </div>
                        
                        <div id="registerForm" style="display: none;" class="mt-3">
                            <hr>
                            <h5>Register New User</h5>
                            <form id="regForm">
                                <div class="mb-2">
                                    <input type="text" class="form-control" id="regUsername" placeholder="New Username" required>
                                </div>
                                <div class="mb-2">
                                    <input type="password" class="form-control" id="regPassword" placeholder="New Password" required>
                                </div>
                                <button type="submit" class="btn btn-success w-100">Register</button>
                            </form>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        document.getElementById('loginForm').addEventListener('submit', function(e) {
            e.preventDefault();
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            
            fetch('/login', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({username, password})
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    window.location.href = data.redirect;
                } else {
                    alert(data.message || 'Login failed');
                }
            });
        });

        document.getElementById('regForm').addEventListener('submit', function(e) {
            e.preventDefault();
            const username = document.getElementById('regUsername').value;
            const password = document.getElementById('regPassword').value;
            
            fetch('/register', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({username, password})
            })
            .then(response => response.json())
            .then(data => {
                alert(data.message);
                if (data.success) {
                    document.getElementById('registerForm').style.display = 'none';
                    document.getElementById('username').value = username;
                }
            });
        });

        function showRegister() {
            const regForm = document.getElementById('registerForm');
            regForm.style.display = regForm.style.display === 'none' ? 'block' : 'none';
        }
    </script>
</body>
</html>'''
    
    with open('templates/login.html', 'w', encoding='utf-8') as f:
        f.write(login_html)

if __name__ == '__main__':
    # Initialize database and templates
    init_db()
    create_templates()
    
    print("Enhanced Web Security Scanner (Conceito A) - Starting...")
    print("Dashboard: http://localhost:5000")
    print("Default login: admin / admin123")
    print("Features: Advanced Analytics, Authentication, Risk Scoring")
    
    app.run(host='0.0.0.0', port=5000, debug=True)
