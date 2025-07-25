#!/usr/bin/env python3
"""
Módulo de Detecção de Vulnerabilidades
Engine avançado para identificação e classificação de vulnerabilidades
"""

import re
import json
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)

@dataclass
class Vulnerability:
    """Representa uma vulnerabilidade detectada"""
    name: str
    category: str
    severity: str
    confidence: float
    description: str
    evidence: str
    remediation: str
    cve_references: List[str]
    risk_score: float

class VulnerabilityEngine:
    def __init__(self):
        self.signatures = self._load_vulnerability_signatures()
        self.tech_specific_checks = self._load_tech_specific_checks()
        
    def _load_vulnerability_signatures(self) -> Dict:
        """Carrega assinaturas avançadas de vulnerabilidades"""
        return {
            "sql_injection": {
                "patterns": [
                    r"SQL syntax.*MySQL",
                    r"Warning.*mysql_",
                    r"valid MySQL result",
                    r"MySqlClient\.",
                    r"PostgreSQL.*ERROR",
                    r"Warning.*\Wpg_",
                    r"valid PostgreSQL result",
                    r"Npgsql\.",
                    r"Driver.*SQL.*Server",
                    r"OLE DB.*SQL Server",
                    r"SQLServer.*JDBC",
                    r"SqlException",
                    r"ORA-\d{4,5}",
                    r"Oracle error",
                    r"Oracle.*Driver",
                    r"Warning.*\Woci_",
                    r"SQLSTATE\[\w+\]",
                    r"Warning.*sqlite_",
                    r"SQLite.*error",
                    r"Unclosed quotation mark",
                    r"Syntax error.*query",
                    r"mysql_fetch_array\(\)",
                    r"mysql_result\(\)",
                    r"ORA-01756",
                    r"Microsoft.*ODBC.*Driver"
                ],
                "severity": "high",
                "confidence_threshold": 0.8,
                "description": "Possível vulnerabilidade de SQL Injection detectada",
                "remediation": "Use prepared statements, sanitize inputs, implement parameterized queries"
            },
            "xss": {
                "patterns": [
                    r"<script[^>]*>.*?</script>",
                    r"javascript:.*alert",
                    r"onload\s*=.*alert",
                    r"onerror\s*=.*alert",
                    r"onmouseover\s*=.*alert",
                    r"onclick\s*=.*alert",
                    r"onfocus\s*=.*alert",
                    r"<iframe[^>]*src\s*=\s*['\"]javascript:",
                    r"<object[^>]*data\s*=\s*['\"]javascript:",
                    r"<embed[^>]*src\s*=\s*['\"]javascript:",
                    r"eval\s*\([^)]*alert",
                    r"document\.write\s*\([^)]*alert",
                    r"innerHTML\s*=.*<script"
                ],
                "severity": "medium",
                "confidence_threshold": 0.7,
                "description": "Cross-Site Scripting (XSS) vulnerability detected",
                "remediation": "Escape output, validate and sanitize all user inputs, implement CSP"
            },
            "lfi": {
                "patterns": [
                    r"root:.*:0:0:",
                    r"daemon:.*:/usr/sbin/nologin",
                    r"bin:.*:/bin/false",
                    r"\[boot loader\]",
                    r"ECHO is on\.",
                    r"Volume.*Serial Number",
                    r"Directory of [A-Z]:\\",
                    r"<title>Index of /",
                    r"Index of /",
                    r"\.\./",
                    r"etc/passwd",
                    r"etc/shadow",
                    r"windows/system32",
                    r"Failed opening.*for inclusion",
                    r"Warning.*include\(",
                    r"Warning.*require\("
                ],
                "severity": "high",
                "confidence_threshold": 0.9,
                "description": "Local File Inclusion (LFI) vulnerability detected",
                "remediation": "Validate file paths, use whitelist approach, implement proper access controls"
            },
            "rfi": {
                "patterns": [
                    r"Warning.*include\(.*://",
                    r"Warning.*require\(.*://",
                    r"Failed opening.*http://",
                    r"Failed opening.*https://",
                    r"Failed opening.*ftp://",
                    r"allow_url_include.*On"
                ],
                "severity": "critical",
                "confidence_threshold": 0.9,
                "description": "Remote File Inclusion (RFI) vulnerability detected",
                "remediation": "Disable allow_url_include, validate all includes, use whitelist"
            },
            "rce": {
                "patterns": [
                    r"uid=\d+.*gid=\d+",
                    r"root:.*:0:0:",
                    r"sh:.*command not found",
                    r"'.*' is not recognized",
                    r"bin/bash",
                    r"total \d+",
                    r"drwx",
                    r"Volume in drive",
                    r"Microsoft Windows \[Version",
                    r"Linux.*\d+\.\d+\.\d+",
                    r"Darwin.*Kernel",
                    r"whoami",
                    r"Current user:",
                    r"COMPUTERNAME=",
                    r"PATH=.*bin"
                ],
                "severity": "critical",
                "confidence_threshold": 0.9,
                "description": "Remote Code Execution (RCE) vulnerability detected",
                "remediation": "Never execute user input, use whitelists, implement proper input validation"
            },
            "ssti": {
                "patterns": [
                    r"^49$",  # 7*7
                    r"^64$",  # 8*8
                    r"^81$",  # 9*9
                    r"<flask\.config\.Config object",
                    r"<class 'jinja2",
                    r"TemplateRuntimeError",
                    r"UndefinedError",
                    r"Traceback.*template",
                    r"jinja2\.exceptions",
                    r"Template.*Error"
                ],
                "severity": "high",
                "confidence_threshold": 0.8,
                "description": "Server-Side Template Injection (SSTI) vulnerability detected",
                "remediation": "Sanitize template inputs, use safe template engines, implement sandboxing"
            },
            "xxe": {
                "patterns": [
                    r"<!DOCTYPE.*\[.*<!ENTITY",
                    r"&\w+;.*root:",
                    r"&\w+;.*passwd",
                    r"ENTITY.*SYSTEM.*file:",
                    r"XML.*external entity"
                ],
                "severity": "high",
                "confidence_threshold": 0.9,
                "description": "XML External Entity (XXE) vulnerability detected",
                "remediation": "Disable external entity processing, use XML parsers safely"
            },
            "nosql_injection": {
                "patterns": [
                    r"MongoError",
                    r"MongoDB.*error",
                    r"CouchDB.*error",
                    r"Redis.*error",
                    r"Cassandra.*error",
                    r"\$where.*function",
                    r"\$regex.*\|\|",
                    r"this\..*==.*true"
                ],
                "severity": "high",
                "confidence_threshold": 0.7,
                "description": "NoSQL Injection vulnerability detected",
                "remediation": "Validate inputs, use parameterized queries, implement proper authentication"
            },
            "ldap_injection": {
                "patterns": [
                    r"LDAP.*error",
                    r"javax\.naming\.directory",
                    r"LdapException",
                    r"Invalid LDAP filter",
                    r"Bad search filter"
                ],
                "severity": "medium",
                "confidence_threshold": 0.7,
                "description": "LDAP Injection vulnerability detected",
                "remediation": "Escape LDAP special characters, validate inputs"
            },
            "xpath_injection": {
                "patterns": [
                    r"XPath.*error",
                    r"javax\.xml\.xpath",
                    r"XPathException",
                    r"Invalid XPath",
                    r"XPath.*syntax.*error"
                ],
                "severity": "medium",
                "confidence_threshold": 0.7,
                "description": "XPath Injection vulnerability detected",
                "remediation": "Use parameterized XPath queries, validate inputs"
            },
            "command_injection": {
                "patterns": [
                    r"sh:.*not found",
                    r"command not found",
                    r"'.*' is not recognized",
                    r"Bad command or file name",
                    r"Cannot run program",
                    r"java\.io\.IOException.*Cannot run"
                ],
                "severity": "critical",
                "confidence_threshold": 0.8,
                "description": "Command Injection vulnerability detected",
                "remediation": "Never execute user input as commands, use whitelists"
            },
            "info_disclosure": {
                "patterns": [
                    r"DEBUG.*=.*true",
                    r"APP_DEBUG.*=.*true",
                    r"display_errors.*=.*on",
                    r"Whoops\\",
                    r"Laravel.*error",
                    r"Symfony.*Exception",
                    r"Django.*DEBUG",
                    r"Traceback.*most recent call",
                    r"Fatal error:",
                    r"Warning:",
                    r"Notice:",
                    r"Parse error:",
                    r"MySQL.*denied",
                    r"PostgreSQL.*denied",
                    r"Access denied for user",
                    r"ORA-\d+:",
                    r"Microsoft.*Error",
                    r"ASP\.NET.*Error",
                    r"IIS.*Error"
                ],
                "severity": "low",
                "confidence_threshold": 0.6,
                "description": "Information disclosure detected",
                "remediation": "Disable debug mode in production, implement proper error handling"
            },
            "path_traversal": {
                "patterns": [
                    r"Directory of [A-Z]:\\",
                    r"\[DIR\].*\d+/\d+/\d+",
                    r"Index of /",
                    r"<title>Index of",
                    r"Parent Directory",
                    r"\.\./",
                    r"\.\.\\",
                    r"etc/passwd",
                    r"windows/system32",
                    r"boot\.ini"
                ],
                "severity": "medium",
                "confidence_threshold": 0.7,
                "description": "Path Traversal vulnerability detected",
                "remediation": "Validate file paths, use canonical paths, implement access controls"
            },
            "credential_exposure": {
                "patterns": [
                    r"API_KEY\s*[=:]\s*['\"][^'\"]+['\"]",
                    r"API_SECRET\s*[=:]\s*['\"][^'\"]+['\"]",
                    r"AWS_ACCESS_KEY_ID\s*[=:]\s*['\"][^'\"]+['\"]",
                    r"AWS_SECRET_ACCESS_KEY\s*[=:]\s*['\"][^'\"]+['\"]",
                    r"DATABASE_URL\s*[=:]\s*['\"][^'\"]+['\"]",
                    r"DB_PASSWORD\s*[=:]\s*['\"][^'\"]+['\"]",
                    r"SECRET_KEY\s*[=:]\s*['\"][^'\"]+['\"]",
                    r"PRIVATE_KEY\s*[=:]\s*['\"][^'\"]+['\"]",
                    r"password\s*[=:]\s*['\"][^'\"]+['\"]",
                    r"token\s*[=:]\s*['\"][^'\"]+['\"]",
                    r"-----BEGIN.*PRIVATE KEY-----",
                    r"-----BEGIN RSA PRIVATE KEY-----"
                ],
                "severity": "critical",
                "confidence_threshold": 0.9,
                "description": "Credential exposure detected",
                "remediation": "Remove exposed credentials, use environment variables, rotate keys"
            },
            "cors_misconfiguration": {
                "patterns": [
                    r"Access-Control-Allow-Origin:\s*\*",
                    r"Access-Control-Allow-Credentials:\s*true.*Access-Control-Allow-Origin:\s*\*"
                ],
                "severity": "medium",
                "confidence_threshold": 0.9,
                "description": "CORS misconfiguration detected",
                "remediation": "Configure CORS properly, avoid wildcard origins with credentials"
            },
            "csp_bypass": {
                "patterns": [
                    r"Content-Security-Policy:.*unsafe-inline",
                    r"Content-Security-Policy:.*unsafe-eval",
                    r"Content-Security-Policy:.*data:",
                    r"X-Content-Security-Policy:.*unsafe"
                ],
                "severity": "medium",
                "confidence_threshold": 0.8,
                "description": "Content Security Policy bypass detected",
                "remediation": "Implement strict CSP, avoid unsafe directives"
            }
        }
    
    def _load_tech_specific_checks(self) -> Dict:
        """Carrega verificações específicas por tecnologia"""
        return {
            "wordpress": {
                "version_disclosure": [
                    r"wp-includes/version\.php",
                    r"WordPress \d+\.\d+",
                    r"wp-content/themes/.*style\.css.*Version: \d+\.\d+"
                ],
                "plugin_vulnerabilities": [
                    r"wp-content/plugins/.*readme\.txt",
                    r"wp-content/plugins/.*/changelog",
                    r"wp-json/wp/v2/users"
                ],
                "config_exposure": [
                    r"wp-config\.php",
                    r"DB_PASSWORD",
                    r"AUTH_KEY",
                    r"SECURE_AUTH_KEY"
                ]
            },
            "drupal": {
                "version_disclosure": [
                    r"Drupal \d+\.\d+",
                    r"CHANGELOG\.txt",
                    r"drupal\.js"
                ],
                "admin_exposure": [
                    r"/user/1",
                    r"/admin/reports/status"
                ]
            },
            "joomla": {
                "version_disclosure": [
                    r"Joomla! \d+\.\d+",
                    r"/administrator/manifests/files/joomla\.xml",
                    r"com_content"
                ],
                "config_exposure": [
                    r"configuration\.php",
                    r"\$password.*=.*['\"]",
                    r"\$secret.*=.*['\"]"
                ]
            },
            "laravel": {
                "debug_mode": [
                    r"APP_DEBUG.*=.*true",
                    r"Whoops\\.*Laravel",
                    r"Illuminate\\.*Exception"
                ],
                "env_exposure": [
                    r"DB_PASSWORD.*=",
                    r"APP_KEY.*=",
                    r"MAIL_PASSWORD.*="
                ]
            },
            "django": {
                "debug_mode": [
                    r"DEBUG.*=.*True",
                    r"Django.*DEBUG",
                    r"Traceback.*django"
                ],
                "secret_exposure": [
                    r"SECRET_KEY.*=",
                    r"DATABASES.*PASSWORD"
                ]
            },
            "nodejs": {
                "package_info": [
                    r"package\.json",
                    r"package-lock\.json",
                    r"npm-debug\.log"
                ],
                "env_exposure": [
                    r"process\.env\.",
                    r"NODE_ENV.*development"
                ]
            }
        }
    
    def analyze_response(self, response, url: str = "", tech: str = "") -> List[Vulnerability]:
        """Analisa uma resposta HTTP em busca de vulnerabilidades"""
        vulnerabilities = []
        
        content = response.text if hasattr(response, 'text') else str(response)
        headers = dict(response.headers) if hasattr(response, 'headers') else {}
        status_code = getattr(response, 'status_code', 0)
        
        # Análise geral de vulnerabilidades
        for vuln_type, vuln_config in self.signatures.items():
            vuln = self._check_vulnerability_patterns(
                content, headers, vuln_type, vuln_config, url
            )
            if vuln:
                vulnerabilities.append(vuln)
        
        # Análise específica por tecnologia
        if tech and tech.lower() in self.tech_specific_checks:
            tech_vulns = self._check_tech_specific(content, headers, tech.lower(), url)
            vulnerabilities.extend(tech_vulns)
        
        # Análise de headers de segurança
        security_vulns = self._check_security_headers(headers, url)
        vulnerabilities.extend(security_vulns)
        
        # Remove duplicatas
        unique_vulns = self._deduplicate_vulnerabilities(vulnerabilities)
        
        return unique_vulns
    
    def _check_vulnerability_patterns(self, content: str, headers: Dict, 
                                    vuln_type: str, vuln_config: Dict, url: str) -> Optional[Vulnerability]:
        """Verifica padrões de vulnerabilidade"""
        patterns = vuln_config["patterns"]
        confidence_scores = []
        evidence_found = []
        
        # Verifica content
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
            if matches:
                confidence_scores.append(0.8)
                evidence_found.extend([match[:100] if len(match) > 100 else match for match in matches])
        
        # Verifica headers
        headers_str = json.dumps(headers).lower()
        for pattern in patterns:
            if re.search(pattern, headers_str, re.IGNORECASE):
                confidence_scores.append(0.9)
                evidence_found.append(f"Header pattern: {pattern}")
        
        if not confidence_scores:
            return None
        
        avg_confidence = sum(confidence_scores) / len(confidence_scores)
        
        if avg_confidence >= vuln_config["confidence_threshold"]:
            return Vulnerability(
                name=vuln_type.replace('_', ' ').title(),
                category=vuln_type,
                severity=vuln_config["severity"],
                confidence=avg_confidence,
                description=vuln_config["description"],
                evidence="; ".join(evidence_found[:3]),  # Primeiras 3 evidências
                remediation=vuln_config["remediation"],
                cve_references=[],  # Pode ser expandido
                risk_score=self._calculate_risk_score(vuln_config["severity"], avg_confidence)
            )
        
        return None
    
    def _check_tech_specific(self, content: str, headers: Dict, tech: str, url: str) -> List[Vulnerability]:
        """Verifica vulnerabilidades específicas da tecnologia"""
        vulnerabilities = []
        tech_checks = self.tech_specific_checks.get(tech, {})
        
        for check_type, patterns in tech_checks.items():
            evidence = []
            
            for pattern in patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    evidence.extend(matches[:2])  # Primeiras 2 evidências
            
            if evidence:
                severity = self._determine_tech_severity(check_type)
                vuln = Vulnerability(
                    name=f"{tech.title()} {check_type.replace('_', ' ').title()}",
                    category=f"{tech}_{check_type}",
                    severity=severity,
                    confidence=0.8,
                    description=f"{check_type.replace('_', ' ').title()} detected in {tech}",
                    evidence="; ".join(evidence),
                    remediation=self._get_tech_remediation(tech, check_type),
                    cve_references=[],
                    risk_score=self._calculate_risk_score(severity, 0.8)
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_security_headers(self, headers: Dict, url: str) -> List[Vulnerability]:
        """Verifica headers de segurança ausentes ou mal configurados"""
        vulnerabilities = []
        
        security_headers = {
            "X-Frame-Options": {
                "description": "Missing X-Frame-Options header",
                "severity": "low",
                "remediation": "Add X-Frame-Options: DENY or SAMEORIGIN"
            },
            "X-Content-Type-Options": {
                "description": "Missing X-Content-Type-Options header",
                "severity": "low",
                "remediation": "Add X-Content-Type-Options: nosniff"
            },
            "X-XSS-Protection": {
                "description": "Missing X-XSS-Protection header",
                "severity": "low",
                "remediation": "Add X-XSS-Protection: 1; mode=block"
            },
            "Strict-Transport-Security": {
                "description": "Missing HSTS header",
                "severity": "medium",
                "remediation": "Add Strict-Transport-Security header for HTTPS"
            },
            "Content-Security-Policy": {
                "description": "Missing Content Security Policy",
                "severity": "medium",
                "remediation": "Implement Content-Security-Policy header"
            }
        }
        
        for header, config in security_headers.items():
            if header not in headers:
                vuln = Vulnerability(
                    name=f"Missing {header}",
                    category="security_headers",
                    severity=config["severity"],
                    confidence=0.9,
                    description=config["description"],
                    evidence=f"Header {header} not found in response",
                    remediation=config["remediation"],
                    cve_references=[],
                    risk_score=self._calculate_risk_score(config["severity"], 0.9)
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _determine_tech_severity(self, check_type: str) -> str:
        """Determina severidade baseada no tipo de check"""
        severity_map = {
            "version_disclosure": "low",
            "config_exposure": "critical",
            "debug_mode": "medium",
            "env_exposure": "critical",
            "admin_exposure": "medium",
            "plugin_vulnerabilities": "medium",
            "package_info": "low",
            "secret_exposure": "critical"
        }
        return severity_map.get(check_type, "medium")
    
    def _get_tech_remediation(self, tech: str, check_type: str) -> str:
        """Obtém recomendação específica para tecnologia"""
        remediations = {
            "wordpress": {
                "version_disclosure": "Hide WordPress version, remove version from headers",
                "config_exposure": "Move wp-config.php outside web root, set proper permissions",
                "plugin_vulnerabilities": "Update plugins, remove unused plugins"
            },
            "drupal": {
                "version_disclosure": "Hide Drupal version, remove CHANGELOG.txt",
                "admin_exposure": "Restrict admin access, implement proper authentication"
            },
            "laravel": {
                "debug_mode": "Set APP_DEBUG=false in production",
                "env_exposure": "Secure .env file, move outside web root"
            },
            "django": {
                "debug_mode": "Set DEBUG=False in production",
                "secret_exposure": "Secure SECRET_KEY, use environment variables"
            }
        }
        
        tech_remediations = remediations.get(tech, {})
        return tech_remediations.get(check_type, "Follow security best practices for " + tech)
    
    def _calculate_risk_score(self, severity: str, confidence: float) -> float:
        """Calcula score de risco baseado em severidade e confiança"""
        severity_scores = {
            "critical": 9.0,
            "high": 7.0,
            "medium": 5.0,
            "low": 3.0,
            "info": 1.0
        }
        
        base_score = severity_scores.get(severity, 3.0)
        return min(10.0, base_score * confidence)
    
    def _deduplicate_vulnerabilities(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """Remove vulnerabilidades duplicadas"""
        seen = set()
        unique_vulns = []
        
        for vuln in vulnerabilities:
            # Cria uma chave única baseada no tipo e evidência
            key = f"{vuln.category}_{vuln.severity}_{hash(vuln.evidence)}"
            if key not in seen:
                seen.add(key)
                unique_vulns.append(vuln)
        
        return unique_vulns
    
    def analyze_payload_response(self, payload: str, response, injection_type: str) -> Optional[Vulnerability]:
        """Analisa resposta de payload de injeção"""
        if not response:
            return None
        
        content = response.text if hasattr(response, 'text') else str(response)
        
        # Verifica se payload foi refletido
        payload_reflected = payload in content
        
        # Verifica padrões específicos do tipo de injeção
        vuln_config = self.signatures.get(injection_type, {})
        if not vuln_config:
            return None
        
        patterns = vuln_config["patterns"]
        evidence = []
        
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                evidence.extend(matches[:2])
        
        # Calcula confiança baseada em evidências
        confidence = 0.0
        if payload_reflected:
            confidence += 0.3
        if evidence:
            confidence += 0.7
        
        if confidence >= 0.5:  # Threshold mínimo
            return Vulnerability(
                name=f"{injection_type.replace('_', ' ').title()} via Payload",
                category=injection_type,
                severity=vuln_config["severity"],
                confidence=confidence,
                description=f"Payload injection successful: {injection_type}",
                evidence=f"Payload: {payload[:50]}... | Evidence: {'; '.join(evidence[:2])}",
                remediation=vuln_config["remediation"],
                cve_references=[],
                risk_score=self._calculate_risk_score(vuln_config["severity"], confidence)
            )
        
        return None
    
    def generate_vulnerability_report(self, vulnerabilities: List[Vulnerability]) -> Dict:
        """Gera relatório de vulnerabilidades"""
        if not vulnerabilities:
            return {
                "summary": {"total": 0, "by_severity": {}},
                "vulnerabilities": [],
                "recommendations": []
            }
        
        # Agrupa por severidade
        by_severity = {}
        for vuln in vulnerabilities:
            if vuln.severity not in by_severity:
                by_severity[vuln.severity] = 0
            by_severity[vuln.severity] += 1
        
        # Ordena por risk score
        sorted_vulns = sorted(vulnerabilities, key=lambda v: v.risk_score, reverse=True)
        
        # Gera recomendações prioritárias
        recommendations = self._generate_priority_recommendations(sorted_vulns)
        
        return {
            "summary": {
                "total": len(vulnerabilities),
                "by_severity": by_severity,
                "avg_risk_score": sum(v.risk_score for v in vulnerabilities) / len(vulnerabilities),
                "critical_count": by_severity.get("critical", 0),
                "high_count": by_severity.get("high", 0)
            },
            "vulnerabilities": [
                {
                    "name": v.name,
                    "category": v.category,
                    "severity": v.severity,
                    "confidence": v.confidence,
                    "risk_score": v.risk_score,
                    "description": v.description,
                    "evidence": v.evidence,
                    "remediation": v.remediation
                }
                for v in sorted_vulns
            ],
            "recommendations": recommendations
        }
    
    def _generate_priority_recommendations(self, vulnerabilities: List[Vulnerability]) -> List[str]:
        """Gera recomendações prioritárias"""
        recommendations = []
        
        # Verifica vulnerabilidades críticas
        critical_vulns = [v for v in vulnerabilities if v.severity == "critical"]
        if critical_vulns:
            recommendations.append("🚨 PRIORIDADE MÁXIMA: Corrigir vulnerabilidades críticas imediatamente")
        
        # Verifica exposição de credenciais
        cred_vulns = [v for v in vulnerabilities if "credential" in v.category or "secret" in v.category]
        if cred_vulns:
            recommendations.append("🔑 Revogar e rotacionar todas as credenciais expostas")
        
        # Verifica RCE
        rce_vulns = [v for v in vulnerabilities if v.category == "rce" or v.category == "command_injection"]
        if rce_vulns:
            recommendations.append("⚡ Corrigir vulnerabilidades de execução de código remotamente")
        
        # Verifica SQL Injection
        sql_vulns = [v for v in vulnerabilities if "sql" in v.category]
        if sql_vulns:
            recommendations.append("🗃️ Implementar prepared statements para prevenir SQL Injection")
        
        # Verifica headers de segurança
        header_vulns = [v for v in vulnerabilities if v.category == "security_headers"]
        if len(header_vulns) >= 3:
            recommendations.append("🛡️ Implementar headers de segurança faltantes")
        
        # Recomendações gerais
        if len(vulnerabilities) > 10:
            recommendations.append("🔍 Implementar programa de segurança abrangente")
        
        recommendations.append("📋 Realizar testes de penetração regulares")
        recommendations.append("🎯 Implementar Web Application Firewall (WAF)")
        
        return recommendations[:7]  # Limita a 7 recomendações 