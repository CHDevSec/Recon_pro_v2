#!/usr/bin/env python3
"""
Recon Pro v2.0 - Professional Web Reconnaissance Tool
Ferramenta profissional de reconhecimento web modularizada

Author: Pentester Caio | CHDEVSEC
Version: 2.0.0
"""

import argparse
import time
import logging
import json
import sys
from datetime import datetime
from pathlib import Path

# Importa módulos customizados
from modules.discovery import AssetDiscovery
from modules.fuzzer import AdvancedFuzzer
from modules.vulnerabilities import VulnerabilityEngine
from modules.reporting import AdvancedReporting

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('recon_pro.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

class ReconProV2:
    def __init__(self, config_file: str = None):
        """Inicializa Recon Pro V2 com configurações"""
        self.config = self._load_config(config_file)
        self.discovery = AssetDiscovery(self.config)
        self.fuzzer = AdvancedFuzzer(self.config)
        self.vuln_engine = VulnerabilityEngine()
        self.reporter = AdvancedReporting(self.config.get('output_dir', 'recon_results'))
        
    def _load_config(self, config_file: str = None) -> dict:
        """Carrega configurações do arquivo ou usa padrões"""
        default_config = {
            "threads": 20,
            "timeout": 10,
            "output_dir": "recon_results",
            "api_keys": {
                "SECURITYTRAILS": "",
                "SHODAN": "",
                "VIRUSTOTAL": "",
                "GOOGLE_API_KEY": "",
                "GOOGLE_CSE_ID": "",
                "CENSYS_API_ID": "",
                "CENSYS_SECRET": "",
                "BING_API_KEY": ""
            },
            "user_agents": [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36"
            ],
            "common_subdomains": [
                "www", "mail", "ftp", "webmail", "admin", "portal", "api", "test", "dev", 
                "staging", "blog", "app", "mobile", "secure", "vpn", "crm", "shop", "cdn",
                "login", "auth", "oauth", "sso", "m", "web", "static", "assets", "beta",
                "support", "help", "docs", "forum", "community", "status", "monitor"
            ],
            "rate_limit": 0.5,
            "proxies": []
        }
        
        if config_file and Path(config_file).exists():
            try:
                with open(config_file, 'r') as f:
                    user_config = json.load(f)
                    default_config.update(user_config)
                    logger.info(f"Configuração carregada de {config_file}")
            except Exception as e:
                logger.warning(f"Erro ao carregar config: {e}. Usando configurações padrão.")
        
        return default_config
    
    def run_comprehensive_scan(self, domain: str, scan_type: str = "full") -> dict:
        """Executa scan completo do domínio"""
        start_time = time.time()
        
        logger.info(f"🚀 Iniciando scan completo para {domain}")
        self._print_banner()
        
        # Fase 1: Descoberta de Assets
        logger.info("📡 Fase 1: Descoberta de Subdomínios")
        subdomains = self.discovery.discover_subdomains(domain)
        
        if not subdomains:
            logger.warning("❌ Nenhum subdomínio encontrado. Verificando domínio principal...")
            subdomains = {domain}
        
        # Fase 2: Verificação de Hosts Ativos
        logger.info("🔍 Fase 2: Verificação de Hosts Ativos")
        active_hosts = self._check_active_hosts(subdomains)
        
        # Fase 3: Fuzzing Avançado
        logger.info("🎯 Fase 3: Fuzzing e Testes de Segurança")
        all_findings = self._run_advanced_fuzzing(active_hosts)
        
        # Fase 4: Análise de Vulnerabilidades
        logger.info("🛡️ Fase 4: Análise de Vulnerabilidades")
        vulnerabilities = self._analyze_vulnerabilities(active_hosts, all_findings)
        
        # Fase 5: Google Dorks
        logger.info("🔍 Fase 5: Google Dorks")
        dork_results = self._run_google_dorks(domain)
        
        # Compilação dos resultados
        scan_duration = time.time() - start_time
        
        scan_results = {
            "domain": domain,
            "scan_type": scan_type,
            "scan_duration": scan_duration,
            "timestamp": datetime.now().isoformat(),
            "subdomains": active_hosts,
            "findings": all_findings,
            "vulnerabilities": [
                {
                    "name": v.name,
                    "category": v.category,
                    "severity": v.severity,
                    "confidence": v.confidence,
                    "description": v.description,
                    "evidence": v.evidence,
                    "remediation": v.remediation,
                    "risk_score": v.risk_score
                } for v in vulnerabilities
            ],
            "dork_results": dork_results,
            "scan_stats": {
                "total_subdomains": len(subdomains),
                "active_hosts": len(active_hosts),
                "total_findings": len(all_findings),
                "vulnerabilities_found": len(vulnerabilities),
                "scan_duration_minutes": round(scan_duration / 60, 2)
            }
        }
        
        # Fase 6: Geração de Relatórios
        logger.info("📊 Fase 6: Geração de Relatórios")
        reports = self.reporter.generate_comprehensive_report(scan_results)
        scan_results["reports_generated"] = reports
        
        # Resumo final
        self._print_scan_summary(scan_results)
        
        return scan_results
    
    def _check_active_hosts(self, subdomains: set) -> list:
        """Verifica quais hosts estão ativos e coleta informações"""
        active_hosts = []
        
        logger.info(f"Verificando {len(subdomains)} subdomínios...")
        
        # Usa discovery module para obter informações detalhadas
        for subdomain in subdomains:
            subdomain_info = self.discovery.get_subdomain_info(subdomain)
            if subdomain_info["is_alive"]:
                # Tenta fazer request HTTP para mais informações
                try:
                    import requests
                    for protocol in ["https://", "http://"]:
                        url = f"{protocol}{subdomain}"
                        try:
                            headers = {"User-Agent": self.config["user_agents"][0]}
                            response = requests.get(
                                url, 
                                headers=headers, 
                                timeout=self.config["timeout"],
                                allow_redirects=True,
                                verify=False
                            )
                            
                            if response.status_code < 500:
                                host_info = {
                                    "url": url,
                                    "subdomain": subdomain,
                                    "status": response.status_code,
                                    "ip": subdomain_info["ip"],
                                    "tech": self._detect_technologies(response),
                                    "title": self._extract_title(response),
                                    "ssl_info": subdomain_info["ssl_info"],
                                    "cdn": subdomain_info["cdn"],
                                    "cloud_provider": subdomain_info["cloud_provider"],
                                    "login_detected": self._detect_login_page(response),
                                    "risk_score": self._calculate_host_risk(response, subdomain_info)
                                }
                                active_hosts.append(host_info)
                                logger.info(f"  ✅ {url} ({response.status_code})")
                                break
                        except requests.exceptions.SSLError:
                            continue
                        except:
                            continue
                except Exception as e:
                    logger.debug(f"Erro verificando {subdomain}: {e}")
        
        logger.info(f"✅ {len(active_hosts)} hosts ativos encontrados")
        return active_hosts
    
    def _run_advanced_fuzzing(self, active_hosts: list) -> list:
        """Executa fuzzing avançado em hosts ativos"""
        all_findings = []
        
        for host_info in active_hosts:
            logger.info(f"🎯 Fuzzing: {host_info['url']}")
            
            # Determina tecnologia para fuzzing específico
            tech = self._determine_main_tech(host_info.get('tech', ''))
            
            # Executa fuzzing
            findings = self.fuzzer.fuzz_comprehensive(host_info)
            
            # Adiciona contexto do host
            for finding in findings:
                finding['source_host'] = host_info['url']
                finding['host_tech'] = tech
            
            all_findings.extend(findings)
            
            # Rate limiting
            time.sleep(self.config.get('rate_limit', 0.5))
        
        logger.info(f"🔍 Total de {len(all_findings)} achados encontrados")
        return all_findings
    
    def _analyze_vulnerabilities(self, active_hosts: list, findings: list) -> list:
        """Analisa vulnerabilidades nos hosts e findings"""
        all_vulnerabilities = []
        
        # Analisa cada host individualmente
        for host_info in active_hosts:
            logger.debug(f"Analisando vulnerabilidades em {host_info['url']}")
            
            # Simula response para análise
            class MockResponse:
                def __init__(self, host_info):
                    self.text = f"Mock response for {host_info['url']}"
                    self.headers = {}
                    self.status_code = host_info.get('status', 200)
            
            mock_response = MockResponse(host_info)
            tech = self._determine_main_tech(host_info.get('tech', ''))
            
            host_vulns = self.vuln_engine.analyze_response(
                mock_response, 
                host_info['url'], 
                tech
            )
            all_vulnerabilities.extend(host_vulns)
        
        # Analisa findings específicos
        for finding in findings:
            if finding.get('payload') and finding.get('injection_type'):
                # Simula response para payload
                class MockPayloadResponse:
                    def __init__(self, finding):
                        self.text = finding.get('response_sample', '')
                        self.headers = {}
                        self.status_code = finding.get('status_code', 200)
                
                mock_response = MockPayloadResponse(finding)
                payload_vuln = self.vuln_engine.analyze_payload_response(
                    finding['payload'],
                    mock_response,
                    finding['injection_type']
                )
                
                if payload_vuln:
                    all_vulnerabilities.append(payload_vuln)
        
        logger.info(f"🛡️ {len(all_vulnerabilities)} vulnerabilidades detectadas")
        return all_vulnerabilities
    
    def _run_google_dorks(self, domain: str) -> list:
        """Executa Google Dorks"""
        logger.info("🔍 Executando Google Dorks...")
        
        # Google Dorks básicos
        dorks = [
            f'site:{domain} inurl:admin OR inurl:login OR inurl:panel',
            f'site:{domain} filetype:env OR filetype:sql OR filetype:log',
            f'site:{domain} "password" OR "secret" OR "api_key"',
            f'site:{domain} intitle:"index of" OR intitle:"directory listing"'
        ]
        
        dork_results = []
        
        for dork in dorks:
            try:
                # Simulação de resultados (para API real, usar Google Custom Search)
                result = {
                    "dork": dork,
                    "category": "Security Research",
                    "links": []  # Aqui seria feita a busca real
                }
                dork_results.append(result)
                
                time.sleep(2)  # Rate limiting
                
            except Exception as e:
                logger.debug(f"Erro com dork: {e}")
        
        return dork_results
    
    def _detect_technologies(self, response) -> str:
        """Detecta tecnologias do response"""
        techs = []
        headers = response.headers
        content = response.text.lower()
        
        # Headers
        if 'server' in headers:
            techs.append(headers['server'])
        if 'x-powered-by' in headers:
            techs.append(headers['x-powered-by'])
        
        # Content analysis
        tech_patterns = {
            "WordPress": ["wp-content", "wp-includes", "wordpress"],
            "Drupal": ["drupal", "sites/all"],
            "Joomla": ["joomla"],
            "Laravel": ["laravel"],
            "React": ["react", "_next"],
            "Vue.js": ["vue.js", "__nuxt"],
            "Angular": ["angular"],
            "Django": ["django"],
            "Flask": ["flask"],
            "Node.js": ["express"],
            "PHP": ["<?php", "x-powered-by: php"]
        }
        
        for tech, patterns in tech_patterns.items():
            if any(pattern in content for pattern in patterns):
                techs.append(tech)
        
        return ", ".join(list(set(techs))) if techs else "Unknown"
    
    def _extract_title(self, response) -> str:
        """Extrai título da página"""
        import re
        try:
            title_match = re.search(r'<title[^>]*>(.*?)</title>', response.text, re.IGNORECASE | re.DOTALL)
            if title_match:
                title = title_match.group(1).strip()
                return title[:100] + "..." if len(title) > 100 else title
        except:
            pass
        return "No Title"
    
    def _detect_login_page(self, response) -> bool:
        """Detecta se é uma página de login"""
        content = response.text.lower()
        login_indicators = [
            "login", "sign in", "username", "password", "email", 
            "log in", "signin", "auth", "authentication"
        ]
        
        return any(indicator in content for indicator in login_indicators)
    
    def _calculate_host_risk(self, response, subdomain_info) -> float:
        """Calcula risk score do host"""
        risk = 0.0
        
        # Baseado no status
        if response.status_code == 200:
            risk += 2.0
        elif response.status_code in [301, 302]:
            risk += 1.0
        
        # SSL presente
        if subdomain_info.get("ssl_info"):
            risk += 1.0
        
        # Login detectado
        if self._detect_login_page(response):
            risk += 3.0
        
        # Admin em URL
        if "admin" in response.url.lower():
            risk += 4.0
        
        return min(10.0, risk)
    
    def _determine_main_tech(self, tech_string: str) -> str:
        """Determina tecnologia principal"""
        if not tech_string or tech_string == "Unknown":
            return "generic"
        
        techs = tech_string.lower()
        
        if "wordpress" in techs:
            return "wordpress"
        elif "drupal" in techs:
            return "drupal"
        elif "joomla" in techs:
            return "joomla"
        elif "laravel" in techs:
            return "laravel"
        elif "django" in techs:
            return "django"
        elif "react" in techs or "next" in techs:
            return "nextjs"
        elif "angular" in techs:
            return "angular"
        elif "vue" in techs:
            return "vue"
        elif "node" in techs or "express" in techs:
            return "nodejs"
        elif "php" in techs:
            return "php"
        else:
            return "generic"
    
    def _print_banner(self):
        """Display tool banner"""
        # ANSI Colors
        RED = '\033[91m'
        GREEN = '\033[92m'
        YELLOW = '\033[93m'
        BLUE = '\033[94m'
        MAGENTA = '\033[95m'
        CYAN = '\033[96m'
        WHITE = '\033[97m'
        BOLD = '\033[1m'
        RESET = '\033[0m'
        
        banner = f"""
{RED}                                                                                    
{RED}    ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗    ██████╗ ██████╗  ██████╗ 
{RED}    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║    ██╔══██╗██╔══██╗██╔═══██╗
{RED}    ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║    ██████╔╝██████╔╝██║   ██║
{RED}    ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║    ██╔═══╝ ██╔══██╗██║   ██║
{RED}    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║    ██║     ██║  ██║╚██████╔╝
{RED}    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝    ╚═╝     ╚═╝  ╚═╝ ╚═════╝ 
{RESET}
{CYAN}    ╔═══════════════════════════════════════════════════════════════════════╗
{CYAN}    ║            {BOLD}{WHITE}Professional Web Reconnaissance Tool v2.0{RESET}{CYAN}                  ║
{CYAN}    ╠═══════════════════════════════════════════════════════════════════════╣
{CYAN}    ║                                                                       ║
{CYAN}    ║  {MAGENTA}🔍 Advanced Discovery Engine{RESET}{CYAN}     {GREEN}📊 Professional Reporting{RESET}{CYAN}           ║
{CYAN}    ║  {YELLOW}🎯 Intelligent Fuzzing System{RESET}{CYAN}    {RED}🛡️ Vulnerability Detection{RESET}{CYAN}           ║
{CYAN}    ║  {BLUE}🚀 Modular Architecture{RESET}{CYAN}          {WHITE}⚡ Expert-Level Analysis{RESET}{CYAN}            ║ 
{CYAN}    ║                                                                       ║
{CYAN}    ╠═══════════════════════════════════════════════════════════════════════╣
{CYAN}    ║  {BOLD}{WHITE}Author:{RESET}{CYAN} Pentester Caio | CHDEVSEC                                    ║
{CYAN}    ║  {BOLD}{WHITE}Date:{RESET}{CYAN} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}                                            ║
{CYAN}    ╚═══════════════════════════════════════════════════════════════════════╝{RESET}

{BOLD}{GREEN}    [+] {WHITE}6+ APIs Integration{RESET}        {BOLD}{RED}[+] {WHITE}15+ Vulnerability Types{RESET}
{BOLD}{BLUE}    [+] {WHITE}Multi-Format Reports{RESET}       {BOLD}{YELLOW}[+] {WHITE}Technology-Specific Payloads{RESET}
{BOLD}{MAGENTA}    [+] {WHITE}Modular Architecture{RESET}       {BOLD}{CYAN}[+] {WHITE}Executive Summary Reports{RESET}

{BOLD}{WHITE}    Ready for Professional Reconnaissance...{RESET}
        """
        print(banner)
    
    def _print_scan_summary(self, results: dict):
        """Display scan summary"""
        stats = results["scan_stats"]
        vulns = results["vulnerabilities"]
        
        critical_vulns = len([v for v in vulns if v["severity"] == "critical"])
        high_vulns = len([v for v in vulns if v["severity"] == "high"])
        
        print("\n" + "="*80)
        print("🎯 COMPLETE RECONNAISSANCE SUMMARY")
        print("="*80)
        print(f"🌐 Target Domain: {results['domain']}")
        print(f"⏱️  Scan Duration: {stats['scan_duration_minutes']} minutes")
        print(f"🔍 Subdomains Discovered: {stats['total_subdomains']}")
        print(f"✅ Active Hosts: {stats['active_hosts']}")
        print(f"📋 Total Findings: {stats['total_findings']}")
        print(f"🛡️ Vulnerabilities Found: {stats['vulnerabilities_found']}")
        
        if critical_vulns > 0:
            print(f"🚨 CRITICAL Vulnerabilities: {critical_vulns}")
        if high_vulns > 0:
            print(f"⚠️  HIGH RISK Vulnerabilities: {high_vulns}")
        
        print("\n📊 GENERATED REPORTS:")
        for report_type, path in results["reports_generated"].items():
            print(f"   {report_type.upper()}: {path}")
        
        print("\n💡 NEXT STEPS:")
        print("   1. Review complete HTML report")
        print("   2. Investigate critical vulnerabilities")
        print("   3. Manually verify high-risk findings")
        print("   4. Implement security fixes")
        
        print("="*80)
        print("🔒 Scan Completed Successfully!")
        print("="*80)

def main():
    """Main function"""
    
    # Help banner
    help_banner = """
\033[91m    ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗    ██████╗ ██████╗  ██████╗ \033[0m
\033[91m    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║    ██╔══██╗██╔══██╗██╔═══██╗\033[0m
\033[91m    ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║    ██████╔╝██████╔╝██║   ██║\033[0m
\033[91m    ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║    ██╔═══╝ ██╔══██╗██║   ██║\033[0m
\033[91m    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║    ██║     ██║  ██║╚██████╔╝\033[0m
\033[91m    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝    ╚═╝     ╚═╝  ╚═╝ ╚═════╝\033[0m 

\033[96m    ╔═══════════════════════════════════════════════════════════════════════╗\033[0m
\033[96m    ║            \033[1m\033[97mProfessional Web Reconnaissance Tool v2.0\033[0m\033[96m                  ║\033[0m
\033[96m    ║                     \033[1m\033[97mBy Pentester Caio | CHDEVSEC\033[0m\033[96m                      ║\033[0m
\033[96m    ╚═══════════════════════════════════════════════════════════════════════╝\033[0m

\033[1m\033[92m    🔍 ADVANCED FEATURES:\033[0m
    \033[95m[+]\033[0m \033[97m6+ APIs Integration\033[0m       \033[91m[+]\033[0m \033[97m15+ Vulnerability Types\033[0m
    \033[94m[+]\033[0m \033[97mMulti-Format Reports\033[0m      \033[93m[+]\033[0m \033[97mTechnology-Specific Payloads\033[0m
    \033[96m[+]\033[0m \033[97mModular Architecture\033[0m      \033[92m[+]\033[0m \033[97mExecutive Summary Reports\033[0m
    """
    
    examples = """
\033[1m\033[93mUSAGE EXAMPLES:\033[0m
  \033[96mpython recon_pro_v2.py example.com\033[0m
  \033[96mpython recon_pro_v2.py example.com --config config.json\033[0m
  \033[96mpython recon_pro_v2.py example.com --scan-type deep --threads 50\033[0m
  \033[96mpython recon_pro_v2.py microsoft.com --output-dir /tmp/results --verbose\033[0m

\033[1m\033[92mSCAN TYPES:\033[0m
  \033[93mquick\033[0m  - Fast scan with basic discovery
  \033[93mfull\033[0m   - Complete scan with all features (default)
  \033[93mdeep\033[0m   - Deep scan with intensive analysis

\033[1m\033[95mGENERATED REPORTS:\033[0m
  \033[97m📄 HTML Report\033[0m      - Main interactive report
  \033[97m📋 Executive Summary\033[0m - Summary for management/C-Level
  \033[97m📊 JSON Data\033[0m        - Structured data for automation
  \033[97m📈 CSV Analysis\033[0m     - Spreadsheet for data analysis

\033[1m\033[91m⚠️  DISCLAIMER:\033[0m \033[97mUse only on authorized systems!\033[0m
    """
    
    parser = argparse.ArgumentParser(
        description=help_banner,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=examples
    )
    
    parser.add_argument('domain', help='Target domain for reconnaissance')
    parser.add_argument('--config', '-c', help='JSON configuration file')
    parser.add_argument('--scan-type', choices=['quick', 'full', 'deep'], 
                       default='full', help='Scan type (default: full)')
    parser.add_argument('--output-dir', '-o', help='Output directory')
    parser.add_argument('--threads', '-t', type=int, help='Number of threads')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose mode')
    
    # If no arguments, show banner and help
    if len(sys.argv) == 1:
        # Special banner when run without arguments
        print(help_banner)
        print("\n\033[1m\033[91m❌ ERROR: Target domain is required!\033[0m")
        print("\033[97mUse: \033[96mpython recon_pro_v2.py --help\033[97m to see all options\033[0m")
        print("\033[97mExample: \033[96mpython recon_pro_v2.py example.com\033[0m\n")
        sys.exit(1)
    
    args = parser.parse_args()
    
    # Configure verbose logging if needed
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Sanitize domain
    domain = args.domain.lower().replace("https://", "").replace("http://", "").split("/")[0]
    
    try:
        # Initialize ReconPro
        recon = ReconProV2(args.config)
        
        # Apply command line arguments
        if args.output_dir:
            recon.config['output_dir'] = args.output_dir
        if args.threads:
            recon.config['threads'] = args.threads
        
        # Execute scan
        results = recon.run_comprehensive_scan(domain, args.scan_type)
        
        print(f"\n✅ Complete reconnaissance of {domain} finished successfully!")
        
    except KeyboardInterrupt:
        print("\n⚠️ Scan interrupted by user")
    except Exception as e:
        logger.error(f"Error during scan: {e}")
        print(f"\n❌ Error: {e}")

if __name__ == "__main__":
    main()