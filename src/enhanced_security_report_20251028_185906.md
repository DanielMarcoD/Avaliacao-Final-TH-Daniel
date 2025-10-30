# Enhanced Web Security Scan Report - Conceito A

## 🎯 Executive Summary

| Attribute | Value |
|-----------|-------|
| **Target URL** | http://testphp.vulnweb.com/artists.php?artist=1 |
| **Scan ID** | 4647b488 |
| **Scan Date** | 2025-10-28 18:58:23 |
| **Duration** | 32.10 seconds |
| **Total Vulnerabilities** | 60 |
| **Scanner Version** | v3.0-ConceptA |


## 📊 Risk Analysis

| Risk Level | Count | Score Range |
|------------|-------|-------------|
| 🚨 **Critical** | 44 | 9.0 - 10.0 |
| 🔴 **High** | 1 | 7.0 - 8.9 |
| 🟠 **Medium** | 15 | 4.0 - 6.9 |
| 🟡 **Low** | 0 | < 4.0 |

**Overall Risk Metrics:**
- Average Risk Score: **8.7/10**
- Maximum Risk Score: **10.0/10**


## 🔍 Vulnerability Details






### 🚨 CRITICAL Risk Vulnerabilities (44)


#### [3] XSS

| Attribute | Details |
|-----------|---------|
| **URL** | `http://testphp.vulnweb.com/artists.php?artist=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E` |
| **Payload** | `<script>alert('XSS')</script>` |
| **Risk Score** | 9.4/10 |
| **Description** | Cross-Site Scripting no parâmetro 'artist' |
| **Evidence** | Payload refletido na resposta. Confiança: 0.60 |
| **Confidence** | 0.60 |


#### [5] SQL Injection

| Attribute | Details |
|-----------|---------|
| **URL** | `http://testphp.vulnweb.com/artists.php?artist=%27+OR+%271%27%3D%271` |
| **Payload** | `' OR '1'='1` |
| **Risk Score** | 10.0/10 |
| **Description** | SQL Injection no parâmetro 'artist' |
| **Evidence** | Erro SQL detectado ou comportamento suspeito. Confiança: 0.30 |
| **Confidence** | 0.30 |


#### [6] XSS

| Attribute | Details |
|-----------|---------|
| **URL** | `http://testphp.vulnweb.com/artists.php?artist=%3Cimg+src%3Dx+onerror%3Dalert%28%27XSS%27%29%3E` |
| **Payload** | `<img src=x onerror=alert('XSS')>` |
| **Risk Score** | 9.4/10 |
| **Description** | Cross-Site Scripting no parâmetro 'artist' |
| **Evidence** | Payload refletido na resposta. Confiança: 0.30 |
| **Confidence** | 0.30 |


#### [13] SQL Injection

| Attribute | Details |
|-----------|---------|
| **URL** | `http://testphp.vulnweb.com/artists.php?artist=%27+OR+1%3D1--` |
| **Payload** | `' OR 1=1--` |
| **Risk Score** | 10.0/10 |
| **Description** | SQL Injection no parâmetro 'artist' |
| **Evidence** | Erro SQL detectado ou comportamento suspeito. Confiança: 0.30 |
| **Confidence** | 0.30 |


#### [14] XSS

| Attribute | Details |
|-----------|---------|
| **URL** | `http://testphp.vulnweb.com/artists.php?artist=%3Csvg+onload%3Dalert%28%27XSS%27%29%3E` |
| **Payload** | `<svg onload=alert('XSS')>` |
| **Risk Score** | 9.4/10 |
| **Description** | Cross-Site Scripting no parâmetro 'artist' |
| **Evidence** | Payload refletido na resposta. Confiança: 0.30 |
| **Confidence** | 0.30 |


#### [15] SQL Injection

| Attribute | Details |
|-----------|---------|
| **URL** | `http://testphp.vulnweb.com/artists.php?artist=%27+OR+%27x%27%3D%27x` |
| **Payload** | `' OR 'x'='x` |
| **Risk Score** | 10.0/10 |
| **Description** | SQL Injection no parâmetro 'artist' |
| **Evidence** | Erro SQL detectado ou comportamento suspeito. Confiança: 0.30 |
| **Confidence** | 0.30 |


#### [16] SQL Injection

| Attribute | Details |
|-----------|---------|
| **URL** | `http://testphp.vulnweb.com/artists.php?artist=%27%29+OR+%271%27%3D%271--` |
| **Payload** | `') OR '1'='1--` |
| **Risk Score** | 10.0/10 |
| **Description** | SQL Injection no parâmetro 'artist' |
| **Evidence** | Erro SQL detectado ou comportamento suspeito. Confiança: 0.30 |
| **Confidence** | 0.30 |


#### [17] XSS

| Attribute | Details |
|-----------|---------|
| **URL** | `http://testphp.vulnweb.com/artists.php?artist=%3Ciframe+src%3Djavascript%3Aalert%28%27XSS%27%29%3E` |
| **Payload** | `<iframe src=javascript:alert('XSS')>` |
| **Risk Score** | 9.4/10 |
| **Description** | Cross-Site Scripting no parâmetro 'artist' |
| **Evidence** | Payload refletido na resposta. Confiança: 0.90 |
| **Confidence** | 0.90 |


#### [18] SQL Injection

| Attribute | Details |
|-----------|---------|
| **URL** | `http://testphp.vulnweb.com/artists.php?artist=%27%29+OR+%28%271%27%3D%271--` |
| **Payload** | `') OR ('1'='1--` |
| **Risk Score** | 10.0/10 |
| **Description** | SQL Injection no parâmetro 'artist' |
| **Evidence** | Erro SQL detectado ou comportamento suspeito. Confiança: 0.30 |
| **Confidence** | 0.30 |


#### [19] XSS

| Attribute | Details |
|-----------|---------|
| **URL** | `http://testphp.vulnweb.com/artists.php?artist=%3Cbody+onload%3Dalert%28%27XSS%27%29%3E` |
| **Payload** | `<body onload=alert('XSS')>` |
| **Risk Score** | 9.4/10 |
| **Description** | Cross-Site Scripting no parâmetro 'artist' |
| **Evidence** | Payload refletido na resposta. Confiança: 0.30 |
| **Confidence** | 0.30 |


#### [20] SQL Injection

| Attribute | Details |
|-----------|---------|
| **URL** | `http://testphp.vulnweb.com/artists.php?artist=%27+OR+1%3D1%23` |
| **Payload** | `' OR 1=1#` |
| **Risk Score** | 10.0/10 |
| **Description** | SQL Injection no parâmetro 'artist' |
| **Evidence** | Erro SQL detectado ou comportamento suspeito. Confiança: 0.30 |
| **Confidence** | 0.30 |


#### [21] XSS

| Attribute | Details |
|-----------|---------|
| **URL** | `http://testphp.vulnweb.com/artists.php?artist=%3Cdiv+onclick%3Dalert%28%27XSS%27%29%3EClick%3C%2Fdiv%3E` |
| **Payload** | `<div onclick=alert('XSS')>Click</div>` |
| **Risk Score** | 9.4/10 |
| **Description** | Cross-Site Scripting no parâmetro 'artist' |
| **Evidence** | Payload refletido na resposta. Confiança: 0.30 |
| **Confidence** | 0.30 |


#### [22] SQL Injection

| Attribute | Details |
|-----------|---------|
| **URL** | `http://testphp.vulnweb.com/artists.php?artist=%22+OR+%221%22%3D%221` |
| **Payload** | `" OR "1"="1` |
| **Risk Score** | 10.0/10 |
| **Description** | SQL Injection no parâmetro 'artist' |
| **Evidence** | Erro SQL detectado ou comportamento suspeito. Confiança: 0.30 |
| **Confidence** | 0.30 |


#### [23] XSS

| Attribute | Details |
|-----------|---------|
| **URL** | `http://testphp.vulnweb.com/artists.php?artist=%3Cinput+onfocus%3Dalert%28%27XSS%27%29+autofocus%3E` |
| **Payload** | `<input onfocus=alert('XSS') autofocus>` |
| **Risk Score** | 9.4/10 |
| **Description** | Cross-Site Scripting no parâmetro 'artist' |
| **Evidence** | Payload refletido na resposta. Confiança: 0.30 |
| **Confidence** | 0.30 |


#### [24] SQL Injection

| Attribute | Details |
|-----------|---------|
| **URL** | `http://testphp.vulnweb.com/artists.php?artist=%22+OR+1%3D1--` |
| **Payload** | `" OR 1=1--` |
| **Risk Score** | 10.0/10 |
| **Description** | SQL Injection no parâmetro 'artist' |
| **Evidence** | Erro SQL detectado ou comportamento suspeito. Confiança: 0.30 |
| **Confidence** | 0.30 |


#### [25] XSS

| Attribute | Details |
|-----------|---------|
| **URL** | `http://testphp.vulnweb.com/artists.php?artist=%3Cselect+onfocus%3Dalert%28%27XSS%27%29+autofocus%3E` |
| **Payload** | `<select onfocus=alert('XSS') autofocus>` |
| **Risk Score** | 9.4/10 |
| **Description** | Cross-Site Scripting no parâmetro 'artist' |
| **Evidence** | Payload refletido na resposta. Confiança: 0.30 |
| **Confidence** | 0.30 |


#### [26] SQL Injection

| Attribute | Details |
|-----------|---------|
| **URL** | `http://testphp.vulnweb.com/artists.php?artist=or+1%3D1--` |
| **Payload** | `or 1=1--` |
| **Risk Score** | 10.0/10 |
| **Description** | SQL Injection no parâmetro 'artist' |
| **Evidence** | Erro SQL detectado ou comportamento suspeito. Confiança: 0.30 |
| **Confidence** | 0.30 |


#### [27] XSS

| Attribute | Details |
|-----------|---------|
| **URL** | `http://testphp.vulnweb.com/artists.php?artist=%3Ctextarea+onfocus%3Dalert%28%27XSS%27%29+autofocus%3E` |
| **Payload** | `<textarea onfocus=alert('XSS') autofocus>` |
| **Risk Score** | 9.4/10 |
| **Description** | Cross-Site Scripting no parâmetro 'artist' |
| **Evidence** | Payload refletido na resposta. Confiança: 0.30 |
| **Confidence** | 0.30 |


#### [28] SQL Injection

| Attribute | Details |
|-----------|---------|
| **URL** | `http://testphp.vulnweb.com/artists.php?artist=or+1%3D1%23` |
| **Payload** | `or 1=1#` |
| **Risk Score** | 10.0/10 |
| **Description** | SQL Injection no parâmetro 'artist' |
| **Evidence** | Erro SQL detectado ou comportamento suspeito. Confiança: 0.30 |
| **Confidence** | 0.30 |


#### [29] XSS

| Attribute | Details |
|-----------|---------|
| **URL** | `http://testphp.vulnweb.com/artists.php?artist=%3Ckeygen+onfocus%3Dalert%28%27XSS%27%29+autofocus%3E` |
| **Payload** | `<keygen onfocus=alert('XSS') autofocus>` |
| **Risk Score** | 9.4/10 |
| **Description** | Cross-Site Scripting no parâmetro 'artist' |
| **Evidence** | Payload refletido na resposta. Confiança: 0.30 |
| **Confidence** | 0.30 |


#### [30] SQL Injection

| Attribute | Details |
|-----------|---------|
| **URL** | `http://testphp.vulnweb.com/artists.php?artist=%27+or+1%3D1+or+%27%27%3D%27` |
| **Payload** | `' or 1=1 or ''='` |
| **Risk Score** | 10.0/10 |
| **Description** | SQL Injection no parâmetro 'artist' |
| **Evidence** | Erro SQL detectado ou comportamento suspeito. Confiança: 0.90 |
| **Confidence** | 0.90 |


#### [31] XSS

| Attribute | Details |
|-----------|---------|
| **URL** | `http://testphp.vulnweb.com/artists.php?artist=%3Cvideo%3E%3Csource+onerror%3Dalert%28%27XSS%27%29%3E` |
| **Payload** | `<video><source onerror=alert('XSS')>` |
| **Risk Score** | 9.4/10 |
| **Description** | Cross-Site Scripting no parâmetro 'artist' |
| **Evidence** | Payload refletido na resposta. Confiança: 0.30 |
| **Confidence** | 0.30 |


#### [32] XSS

| Attribute | Details |
|-----------|---------|
| **URL** | `http://testphp.vulnweb.com/artists.php?artist=%3Caudio+src%3Dx+onerror%3Dalert%28%27XSS%27%29%3E` |
| **Payload** | `<audio src=x onerror=alert('XSS')>` |
| **Risk Score** | 9.4/10 |
| **Description** | Cross-Site Scripting no parâmetro 'artist' |
| **Evidence** | Payload refletido na resposta. Confiança: 0.30 |
| **Confidence** | 0.30 |


#### [33] SQL Injection

| Attribute | Details |
|-----------|---------|
| **URL** | `http://testphp.vulnweb.com/artists.php?artist=%27+or+a%3Da--` |
| **Payload** | `' or a=a--` |
| **Risk Score** | 10.0/10 |
| **Description** | SQL Injection no parâmetro 'artist' |
| **Evidence** | Erro SQL detectado ou comportamento suspeito. Confiança: 0.30 |
| **Confidence** | 0.30 |


#### [34] XSS

| Attribute | Details |
|-----------|---------|
| **URL** | `http://testphp.vulnweb.com/artists.php?artist=%3Cobject+data%3Djavascript%3Aalert%28%27XSS%27%29%3E` |
| **Payload** | `<object data=javascript:alert('XSS')>` |
| **Risk Score** | 9.4/10 |
| **Description** | Cross-Site Scripting no parâmetro 'artist' |
| **Evidence** | Payload refletido na resposta. Confiança: 0.90 |
| **Confidence** | 0.90 |


#### [35] SQL Injection

| Attribute | Details |
|-----------|---------|
| **URL** | `http://testphp.vulnweb.com/artists.php?artist=%27+or+%27one%27%3D%27one` |
| **Payload** | `' or 'one'='one` |
| **Risk Score** | 10.0/10 |
| **Description** | SQL Injection no parâmetro 'artist' |
| **Evidence** | Erro SQL detectado ou comportamento suspeito. Confiança: 0.30 |
| **Confidence** | 0.30 |


#### [36] SQL Injection

| Attribute | Details |
|-----------|---------|
| **URL** | `http://testphp.vulnweb.com/artists.php?artist=%27+or+%27one%27%3D%27one--` |
| **Payload** | `' or 'one'='one--` |
| **Risk Score** | 10.0/10 |
| **Description** | SQL Injection no parâmetro 'artist' |
| **Evidence** | Erro SQL detectado ou comportamento suspeito. Confiança: 0.30 |
| **Confidence** | 0.30 |


#### [37] XSS

| Attribute | Details |
|-----------|---------|
| **URL** | `http://testphp.vulnweb.com/artists.php?artist=%3Cembed+src%3Djavascript%3Aalert%28%27XSS%27%29%3E` |
| **Payload** | `<embed src=javascript:alert('XSS')>` |
| **Risk Score** | 9.4/10 |
| **Description** | Cross-Site Scripting no parâmetro 'artist' |
| **Evidence** | Payload refletido na resposta. Confiança: 0.90 |
| **Confidence** | 0.90 |


#### [38] SQL Injection

| Attribute | Details |
|-----------|---------|
| **URL** | `http://testphp.vulnweb.com/artists.php?artist=hi%27+or+%27a%27%3D%27a` |
| **Payload** | `hi' or 'a'='a` |
| **Risk Score** | 10.0/10 |
| **Description** | SQL Injection no parâmetro 'artist' |
| **Evidence** | Erro SQL detectado ou comportamento suspeito. Confiança: 0.30 |
| **Confidence** | 0.30 |


#### [39] XSS

| Attribute | Details |
|-----------|---------|
| **URL** | `http://testphp.vulnweb.com/search.php?test=query` |
| **Payload** | `<script>alert('XSS')</script>` |
| **Risk Score** | 9.4/10 |
| **Description** | Cross-Site Scripting em formulário |
| **Evidence** | Payload refletido via formulário. Confiança: 0.60 |
| **Confidence** | 0.60 |


#### [40] SQL Injection

| Attribute | Details |
|-----------|---------|
| **URL** | `http://testphp.vulnweb.com/artists.php?artist=hi%27+or+1%3D1+--` |
| **Payload** | `hi' or 1=1 --` |
| **Risk Score** | 10.0/10 |
| **Description** | SQL Injection no parâmetro 'artist' |
| **Evidence** | Erro SQL detectado ou comportamento suspeito. Confiança: 0.30 |
| **Confidence** | 0.30 |


#### [41] SQL Injection

| Attribute | Details |
|-----------|---------|
| **URL** | `http://testphp.vulnweb.com/artists.php?artist=hi%27+or+%27a%27%3D%27a` |
| **Payload** | `hi' or 'a'='a` |
| **Risk Score** | 10.0/10 |
| **Description** | SQL Injection no parâmetro 'artist' |
| **Evidence** | Erro SQL detectado ou comportamento suspeito. Confiança: 0.30 |
| **Confidence** | 0.30 |


#### [42] XSS

| Attribute | Details |
|-----------|---------|
| **URL** | `http://testphp.vulnweb.com/search.php?test=query` |
| **Payload** | `<img src=x onerror=alert('XSS')>` |
| **Risk Score** | 9.4/10 |
| **Description** | Cross-Site Scripting em formulário |
| **Evidence** | Payload refletido via formulário. Confiança: 0.30 |
| **Confidence** | 0.30 |


#### [43] SQL Injection

| Attribute | Details |
|-----------|---------|
| **URL** | `http://testphp.vulnweb.com/artists.php?artist=%27%3B+waitfor+delay+%270%3A0%3A10%27--` |
| **Payload** | `'; waitfor delay '0:0:10'--` |
| **Risk Score** | 10.0/10 |
| **Description** | SQL Injection no parâmetro 'artist' |
| **Evidence** | Erro SQL detectado ou comportamento suspeito. Confiança: 0.30 |
| **Confidence** | 0.30 |


#### [44] XSS

| Attribute | Details |
|-----------|---------|
| **URL** | `http://testphp.vulnweb.com/search.php?test=query` |
| **Payload** | `<svg onload=alert('XSS')>` |
| **Risk Score** | 9.4/10 |
| **Description** | Cross-Site Scripting em formulário |
| **Evidence** | Payload refletido via formulário. Confiança: 0.30 |
| **Confidence** | 0.30 |


#### [45] SQL Injection

| Attribute | Details |
|-----------|---------|
| **URL** | `http://testphp.vulnweb.com/artists.php?artist=%27%3B+WAITFOR+DELAY+%2700%3A00%3A05%27--` |
| **Payload** | `'; WAITFOR DELAY '00:00:05'--` |
| **Risk Score** | 10.0/10 |
| **Description** | SQL Injection no parâmetro 'artist' |
| **Evidence** | Erro SQL detectado ou comportamento suspeito. Confiança: 0.30 |
| **Confidence** | 0.30 |


#### [46] SQL Injection

| Attribute | Details |
|-----------|---------|
| **URL** | `http://testphp.vulnweb.com/artists.php?artist=%27%3B+SELECT+SLEEP%285%29--` |
| **Payload** | `'; SELECT SLEEP(5)--` |
| **Risk Score** | 10.0/10 |
| **Description** | SQL Injection no parâmetro 'artist' |
| **Evidence** | Erro SQL detectado ou comportamento suspeito. Confiança: 0.30 |
| **Confidence** | 0.30 |


#### [47] XSS

| Attribute | Details |
|-----------|---------|
| **URL** | `http://testphp.vulnweb.com/search.php?test=query` |
| **Payload** | `javascript:alert('XSS')` |
| **Risk Score** | 9.4/10 |
| **Description** | Cross-Site Scripting em formulário |
| **Evidence** | Payload refletido via formulário. Confiança: 0.60 |
| **Confidence** | 0.60 |


#### [48] XSS

| Attribute | Details |
|-----------|---------|
| **URL** | `http://testphp.vulnweb.com/search.php?test=query` |
| **Payload** | `<iframe src=javascript:alert('XSS')>` |
| **Risk Score** | 9.4/10 |
| **Description** | Cross-Site Scripting em formulário |
| **Evidence** | Payload refletido via formulário. Confiança: 0.90 |
| **Confidence** | 0.90 |


#### [49] XSS

| Attribute | Details |
|-----------|---------|
| **URL** | `http://testphp.vulnweb.com/search.php?test=query` |
| **Payload** | `<body onload=alert('XSS')>` |
| **Risk Score** | 9.4/10 |
| **Description** | Cross-Site Scripting em formulário |
| **Evidence** | Payload refletido via formulário. Confiança: 0.30 |
| **Confidence** | 0.30 |


#### [50] XSS

| Attribute | Details |
|-----------|---------|
| **URL** | `http://testphp.vulnweb.com/search.php?test=query` |
| **Payload** | `<div onclick=alert('XSS')>Click</div>` |
| **Risk Score** | 9.4/10 |
| **Description** | Cross-Site Scripting em formulário |
| **Evidence** | Payload refletido via formulário. Confiança: 0.30 |
| **Confidence** | 0.30 |


#### [51] XSS

| Attribute | Details |
|-----------|---------|
| **URL** | `http://testphp.vulnweb.com/search.php?test=query` |
| **Payload** | `<input onfocus=alert('XSS') autofocus>` |
| **Risk Score** | 9.4/10 |
| **Description** | Cross-Site Scripting em formulário |
| **Evidence** | Payload refletido via formulário. Confiança: 0.30 |
| **Confidence** | 0.30 |


#### [52] XSS

| Attribute | Details |
|-----------|---------|
| **URL** | `http://testphp.vulnweb.com/search.php?test=query` |
| **Payload** | `<select onfocus=alert('XSS') autofocus>` |
| **Risk Score** | 9.4/10 |
| **Description** | Cross-Site Scripting em formulário |
| **Evidence** | Payload refletido via formulário. Confiança: 0.30 |
| **Confidence** | 0.30 |


#### [53] XSS

| Attribute | Details |
|-----------|---------|
| **URL** | `http://testphp.vulnweb.com/search.php?test=query` |
| **Payload** | `<textarea onfocus=alert('XSS') autofocus>` |
| **Risk Score** | 9.4/10 |
| **Description** | Cross-Site Scripting em formulário |
| **Evidence** | Payload refletido via formulário. Confiança: 0.30 |
| **Confidence** | 0.30 |







### 🔴 HIGH Risk Vulnerabilities (1)


#### [1] Security Misconfiguration

| Attribute | Details |
|-----------|---------|
| **URL** | `http://testphp.vulnweb.com/artists.php?artist=1` |
| **Payload** | `HTTP_ONLY` |
| **Risk Score** | 7.9/10 |
| **Description** | Site não utiliza HTTPS |
| **Evidence** | Conexão não criptografada detectada |








### 🟠 MEDIUM Risk Vulnerabilities (15)


#### [2] Cross-Site Request Forgery

| Attribute | Details |
|-----------|---------|
| **URL** | `http://testphp.vulnweb.com/search.php?test=query` |
| **Payload** | `NO_CSRF_TOKEN` |
| **Risk Score** | 6.0/10 |
| **Description** | Formulário sem proteção CSRF |
| **Evidence** | Token CSRF não encontrado em formulário POST |



#### [4] Security Misconfiguration

| Attribute | Details |
|-----------|---------|
| **URL** | `http://testphp.vulnweb.com/artists.php?artist=1` |
| **Payload** | `NO_FRAME_PROTECTION` |
| **Risk Score** | 6.6/10 |
| **Description** | Falta de proteção contra Clickjacking |
| **Evidence** | Headers X-Frame-Options ou CSP frame-ancestors não encontrados |



#### [7] Security Misconfiguration

| Attribute | Details |
|-----------|---------|
| **URL** | `http://testphp.vulnweb.com/artists.php?artist=1` |
| **Payload** | `MISSING_X_CONTENT_TYPE_OPTIONS` |
| **Risk Score** | 6.6/10 |
| **Description** | Cabeçalho de segurança ausente: X-Content-Type-Options |
| **Evidence** | O cabeçalho X-Content-Type-Options não foi encontrado na resposta |



#### [8] Security Misconfiguration

| Attribute | Details |
|-----------|---------|
| **URL** | `http://testphp.vulnweb.com/artists.php?artist=1` |
| **Payload** | `MISSING_X_XSS_PROTECTION` |
| **Risk Score** | 6.6/10 |
| **Description** | Cabeçalho de segurança ausente: X-XSS-Protection |
| **Evidence** | O cabeçalho X-XSS-Protection não foi encontrado na resposta |



#### [9] Security Misconfiguration

| Attribute | Details |
|-----------|---------|
| **URL** | `http://testphp.vulnweb.com/artists.php?artist=1` |
| **Payload** | `MISSING_X_FRAME_OPTIONS` |
| **Risk Score** | 6.6/10 |
| **Description** | Cabeçalho de segurança ausente: X-Frame-Options |
| **Evidence** | O cabeçalho X-Frame-Options não foi encontrado na resposta |



#### [10] Security Misconfiguration

| Attribute | Details |
|-----------|---------|
| **URL** | `http://testphp.vulnweb.com/artists.php?artist=1` |
| **Payload** | `MISSING_STRICT_TRANSPORT_SECURITY` |
| **Risk Score** | 6.6/10 |
| **Description** | Cabeçalho de segurança ausente: Strict-Transport-Security |
| **Evidence** | O cabeçalho Strict-Transport-Security não foi encontrado na resposta |



#### [11] Security Misconfiguration

| Attribute | Details |
|-----------|---------|
| **URL** | `http://testphp.vulnweb.com/artists.php?artist=1` |
| **Payload** | `MISSING_CONTENT_SECURITY_POLICY` |
| **Risk Score** | 6.6/10 |
| **Description** | Cabeçalho de segurança ausente: Content-Security-Policy |
| **Evidence** | O cabeçalho Content-Security-Policy não foi encontrado na resposta |



#### [12] Security Misconfiguration

| Attribute | Details |
|-----------|---------|
| **URL** | `http://testphp.vulnweb.com/artists.php?artist=1` |
| **Payload** | `MISSING_REFERRER_POLICY` |
| **Risk Score** | 6.6/10 |
| **Description** | Cabeçalho de segurança ausente: Referrer-Policy |
| **Evidence** | O cabeçalho Referrer-Policy não foi encontrado na resposta |



#### [54] ZAP_SIMULATED_MISSING_HEADER

| Attribute | Details |
|-----------|---------|
| **URL** | `http://testphp.vulnweb.com/artists.php?artist=1` |
| **Payload** | `X-Frame-Options` |
| **Risk Score** | 5.5/10 |
| **Description** | ZAP Simulated: Missing Security Header - X-Frame-Options |
| **Evidence** | Header X-Frame-Options not found in response |



#### [55] ZAP_SIMULATED_MISSING_HEADER

| Attribute | Details |
|-----------|---------|
| **URL** | `http://testphp.vulnweb.com/artists.php?artist=1` |
| **Payload** | `X-Content-Type-Options` |
| **Risk Score** | 5.5/10 |
| **Description** | ZAP Simulated: Missing Security Header - X-Content-Type-Options |
| **Evidence** | Header X-Content-Type-Options not found in response |



#### [56] ZAP_SIMULATED_MISSING_HEADER

| Attribute | Details |
|-----------|---------|
| **URL** | `http://testphp.vulnweb.com/artists.php?artist=1` |
| **Payload** | `X-XSS-Protection` |
| **Risk Score** | 5.5/10 |
| **Description** | ZAP Simulated: Missing Security Header - X-XSS-Protection |
| **Evidence** | Header X-XSS-Protection not found in response |



#### [57] ZAP_SIMULATED_SERVER_INFO

| Attribute | Details |
|-----------|---------|
| **URL** | `http://testphp.vulnweb.com/artists.php?artist=1` |
| **Payload** | `Server Header` |
| **Risk Score** | 5.5/10 |
| **Description** | ZAP Simulated: Server Information Disclosure |
| **Evidence** | Server header reveals: nginx/1.19.0 |



#### [58] NIKTO_SIMULATED_DIRECTORY

| Attribute | Details |
|-----------|---------|
| **URL** | `http://testphp.vulnweb.com/artists.php?artist=1admin/` |
| **Payload** | `GET` |
| **Risk Score** | 5.5/10 |
| **Description** | Nikto Simulated: Potentially interesting directory found - /admin/ |
| **Evidence** | HTTP 200 response for /admin/ |



#### [59] NIKTO_SIMULATED_DIRECTORY

| Attribute | Details |
|-----------|---------|
| **URL** | `http://testphp.vulnweb.com/artists.php?artist=1backup/` |
| **Payload** | `GET` |
| **Risk Score** | 5.5/10 |
| **Description** | Nikto Simulated: Potentially interesting directory found - /backup/ |
| **Evidence** | HTTP 200 response for /backup/ |



#### [60] NIKTO_SIMULATED_SERVER_VERSION

| Attribute | Details |
|-----------|---------|
| **URL** | `http://testphp.vulnweb.com/artists.php?artist=1` |
| **Payload** | `HEAD` |
| **Risk Score** | 5.5/10 |
| **Description** | Nikto Simulated: Server version disclosure |
| **Evidence** | Server header reveals version: nginx/1.19.0 |













## 🛡️ Security Recommendations


### Cross-Site Scripting (XSS) Mitigation
Implement input validation, output encoding, and Content Security Policy (CSP) headers.

**Priority:** HIGH
**Effort:** MEDIUM


### Security Configuration Hardening
Implement security headers, disable unused services, and follow security baselines.

**Priority:** MEDIUM
**Effort:** LOW


### CSRF Protection Implementation
Implement CSRF tokens, SameSite cookies, and origin validation.

**Priority:** HIGH
**Effort:** LOW


### SQL Injection Prevention
Use parameterized queries, prepared statements, and input validation.

**Priority:** CRITICAL
**Effort:** MEDIUM



## 📋 Compliance Status

| Framework | Status | Issues |
|-----------|--------|--------|

| OWASP Top 10 | ❌ Non-Compliant | 60 |

| PCI DSS | ❌ Non-Compliant | 44 |

| ISO 27001 | ❌ Non-Compliant | 8 |


## 📈 Scan Statistics

- **Total HTTP Requests:** 55
- **Scan Techniques Used:** Heuristic Analysis, Pattern Matching, Behavioral Analysis
- **Coverage:** SSL/TLS, Security Headers, Input Validation, Authentication

---
*Report generated by Enhanced Web Security Scanner (Conceito A) on 2025-10-28 18:58:55*