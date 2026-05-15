# Pentest Report — http://192.168.153.200/DVWA/
Date: 2026-05-15

## Executive Summary
This automated penetration test was conducted against the DVWA (Damn Vulnerable Web Application) lab environment. The pipeline included ZAP active scanning, IDOR semantic analysis, and targeted custom probing.

- **Scope**: 21 endpoints identified and tested.
- **Overall Risk Level**: CRITICAL
- **Critical/High Findings**: 7

## Confirmed Findings

### [CRITICAL] Remote OS Command Injection — /vulnerabilities/exec/
- **Endpoint**: http://192.168.153.200/DVWA/vulnerabilities/exec/
- **Parameter**: `ip`
- **Method**: POST
- **Payload**: `test&cat /etc/passwd&`
- **Evidence**: `root:x:0:0:root:/root:/bin/bash`
- **ZAP Signal**: severity=High, confidence=Medium
- **Fix**: Use a whitelist of allowed characters or a dedicated API for pinging; avoid direct shell execution of user input.

### [CRITICAL] SQL Injection (Error-based) — /vulnerabilities/sqli/
- **Endpoint**: http://192.168.153.200/DVWA/vulnerabilities/sqli/?Submit=Submit
- **Parameter**: `id`
- **Method**: GET
- **Payload**: `1' OR '1'='1`
- **Evidence**: `First name: admin<br />Surname: admin` (Multiple records returned)
- **ZAP Signal**: severity=High, confidence=Medium
- **Fix**: Use prepared statements (parameterized queries) with PDO or MySQLi.

### [CRITICAL] SQL Injection (Blind/Time-based) — /vulnerabilities/sqli_blind/
- **Endpoint**: http://192.168.153.200/DVWA/vulnerabilities/sqli_blind/?Submit=Submit
- **Parameter**: `id`
- **Method**: GET
- **Payload**: `1' AND (SELECT 44 FROM (SELECT(SLEEP(5)))a) AND '1'='1`
- **Evidence**: Response time: **5019ms** (Baseline: 16ms)
- **ZAP Signal**: severity=High, confidence=Medium
- **Fix**: Use prepared statements and implement strict input validation.

### [HIGH] Local File Inclusion (LFI) — /vulnerabilities/fi/
- **Endpoint**: http://192.168.153.200/DVWA/vulnerabilities/fi/
- **Parameter**: `page`
- **Method**: GET
- **Payload**: `../../../../../../etc/passwd`
- **Evidence**: `root:x:0:0:root:/root:/bin/bash`
- **ZAP Signal**: N/A (Confirmed via custom probe)
- **Fix**: Use a whitelist of allowed files or reference files by index/ID rather than direct paths.

### [HIGH] Cross-Site Scripting (Reflected) — /vulnerabilities/xss_r/
- **Endpoint**: http://192.168.153.200/DVWA/vulnerabilities/xss_r/
- **Parameter**: `name`
- **Method**: GET
- **Payload**: `<img src=x onerror=alert(1)>`
- **Evidence**: `<pre>Hello <img src=x onerror=alert(1)></pre>`
- **ZAP Signal**: severity=High, confidence=Medium
- **Fix**: Sanitize output using `htmlspecialchars()` and implement a strong Content Security Policy (CSP).

### [HIGH] SQL Injection — /vulnerabilities/brute/
- **Endpoint**: http://192.168.153.200/DVWA/vulnerabilities/brute/
- **Parameter**: `username`
- **Method**: GET
- **Payload**: `'`
- **Evidence**: `Uncaught mysqli_sql_exception: You have an error in your SQL syntax`
- **ZAP Signal**: severity=High, confidence=Medium
- **Fix**: Use parameterized queries for authentication logic.

### [MEDIUM] Directory Browsing — /hackable/
- **Endpoint**: http://192.168.153.200/DVWA/hackable/
- **Parameter**: N/A
- **Method**: GET
- **Payload**: N/A
- **Evidence**: `<title>Index of /DVWA/hackable</title>`
- **ZAP Signal**: severity=Medium, confidence=Medium
- **Fix**: Disable directory listing in web server configuration (e.g., `Options -Indexes` in Apache).

## IDOR Findings

### /vulnerabilities/view_help.php — IDOR Candidate
- **Object Reference**: `id` parameter (e.g., `id=xss_s`)
- **Reason**: Direct reference to resource identifiers. Potential to access unauthorized internal files.
- **Fix**: Implement server-side authorization check per resource access.

### /vulnerabilities/view_source.php — IDOR Candidate
- **Object Reference**: `id` parameter (e.g., `id=xss_s`)
- **Reason**: Direct reference to source file identifiers. Potential to view unauthorized source code.
- **Fix**: Use a whitelist of source files allowed for viewing.

## Suspected / Unconfirmed

### /vulnerabilities/upload/ — File Upload Bypass
- **Signal**: Application Error Disclosure (leakage of file structure in PHP Warnings).
- **Recommendation**: Manual follow-up to test for shell upload bypasses (extension spoofing, MIME-type bypass).

## Manual Verification Required
- `idor_candidates[]`: `/vulnerabilities/view_help.php`, `/vulnerabilities/view_source.php`, `/vulnerabilities/weak_id/`. (idor-check.py was unavailable).

## Endpoints with No Finding
- `/login.php`
- `/vulnerabilities/captcha/` (Only minor SRI/Domain issues)
- `/vulnerabilities/csrf/` (Confirmed reflection but bypass needs manual session state check)

## Out of Scope / Skipped
- Static images and CSS files.
