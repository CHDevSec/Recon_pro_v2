#!/usr/bin/env python3
"""
Módulo de Descoberta de Assets
Responsável por encontrar subdomínios, hosts e assets através de múltiplas fontes
"""

import subprocess
import requests
import concurrent.futures
import dns.resolver
import socket
import random
import time
from typing import Set, List, Dict, Optional
import logging

logger = logging.getLogger(__name__)

class AssetDiscovery:
    def __init__(self, config: Dict):
        self.config = config
        self.api_keys = config.get('api_keys', {})
        self.threads = config.get('threads', 20)
        self.timeout = config.get('timeout', 10)
        self.user_agents = config.get('user_agents', [])
        self.common_subdomains = config.get('common_subdomains', [])
        
    def discover_subdomains(self, domain: str) -> Set[str]:
        """Descoberta completa de subdomínios usando múltiplas técnicas"""
        logger.info(f"Iniciando descoberta para {domain}")
        subdomains = set()
        
        # Parallel execution de todas as fontes
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self._run_external_tools, domain): "external_tools",
                executor.submit(self._query_apis, domain): "apis", 
                executor.submit(self._certificate_transparency, domain): "ct_logs",
                executor.submit(self._dns_bruteforce, domain): "dns_brute",
                executor.submit(self._search_engines, domain): "search_engines"
            }
            
            for future in concurrent.futures.as_completed(futures):
                source = futures[future]
                try:
                    result = future.result()
                    if result:
                        subdomains.update(result)
                        logger.info(f"{source}: {len(result)} subdomínios encontrados")
                except Exception as e:
                    logger.error(f"Erro em {source}: {e}")
        
        # Garantir domínio principal
        subdomains.add(domain)
        
        # Filtrar e validar
        valid_subdomains = {s for s in subdomains if self._is_valid_subdomain(s, domain)}
        
        logger.info(f"Total: {len(valid_subdomains)} subdomínios válidos")
        return valid_subdomains
    
    def _run_external_tools(self, domain: str) -> Set[str]:
        """Executa ferramentas externas de descoberta"""
        subdomains = set()
        tools = {
            "subfinder": ["subfinder", "-d", domain, "-silent", "-all"],
            "assetfinder": ["assetfinder", "--subs-only", domain],
            "amass": ["amass", "enum", "-passive", "-d", domain, "-config", "/dev/null"],
            "findomain": ["findomain", "-t", domain, "--quiet"],
            "chaos": ["chaos", "-d", domain, "-silent"],
            "github-subdomains": ["github-subdomains", "-d", domain]
        }
        
        for tool_name, command in tools.items():
            if not self._is_tool_installed(command[0]):
                continue
                
            try:
                result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=180,
                    env={'PATH': '/usr/local/bin:/usr/bin:/bin'}
                )
                
                if result.stdout:
                    new_subs = {s.strip() for s in result.stdout.splitlines() 
                               if s.strip() and domain in s}
                    subdomains.update(new_subs)
                    
            except Exception as e:
                logger.warning(f"Erro com {tool_name}: {e}")
        
        return subdomains
    
    def _query_apis(self, domain: str) -> Set[str]:
        """Consulta múltiplas APIs para descoberta"""
        subdomains = set()
        
        # SecurityTrails
        if self.api_keys.get('SECURITYTRAILS'):
            subdomains.update(self._query_securitytrails(domain))
        
        # Shodan
        if self.api_keys.get('SHODAN'):
            subdomains.update(self._query_shodan(domain))
        
        # VirusTotal
        if self.api_keys.get('VIRUSTOTAL'):
            subdomains.update(self._query_virustotal(domain))
        
        # Censys
        if self.api_keys.get('CENSYS_API_ID') and self.api_keys.get('CENSYS_SECRET'):
            subdomains.update(self._query_censys(domain))
        
        return subdomains
    
    def _query_securitytrails(self, domain: str) -> Set[str]:
        """API SecurityTrails com paginação"""
        subdomains = set()
        try:
            headers = {
                "Accept": "application/json",
                "APIKEY": self.api_keys['SECURITYTRAILS']
            }
            
            # Subdomínios ativos
            url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
            params = {"children_only": "false", "include_inactive": "false"}
            
            response = requests.get(url, headers=headers, params=params, timeout=15)
            if response.status_code == 200:
                data = response.json()
                subs = data.get("subdomains", [])
                subdomains.update({f"{sub}.{domain}" for sub in subs})
            
            # Histórico DNS
            history_url = f"https://api.securitytrails.com/v1/history/{domain}/dns/a"
            response = requests.get(history_url, headers=headers, timeout=15)
            if response.status_code == 200:
                data = response.json()
                for record in data.get("records", []):
                    for value in record.get("values", []):
                        if "hostname" in value:
                            subdomains.add(value["hostname"])
            
        except Exception as e:
            logger.error(f"SecurityTrails error: {e}")
        
        return subdomains
    
    def _query_shodan(self, domain: str) -> Set[str]:
        """API Shodan melhorada"""
        subdomains = set()
        try:
            # DNS info
            url = f"https://api.shodan.io/dns/domain/{domain}"
            params = {"key": self.api_keys['SHODAN']}
            
            response = requests.get(url, params=params, timeout=15)
            if response.status_code == 200:
                data = response.json()
                if 'subdomains' in data:
                    subdomains.update({f"{sub}.{domain}" for sub in data['subdomains']})
            
            # Search for additional hosts
            search_url = "https://api.shodan.io/shodan/host/search"
            search_params = {
                "key": self.api_keys['SHODAN'],
                "query": f"hostname:{domain}",
                "facets": "hostname"
            }
            
            response = requests.get(search_url, params=search_params, timeout=15)
            if response.status_code == 200:
                data = response.json()
                for match in data.get('matches', []):
                    if 'hostnames' in match:
                        for hostname in match['hostnames']:
                            if domain in hostname:
                                subdomains.add(hostname)
            
        except Exception as e:
            logger.error(f"Shodan error: {e}")
        
        return subdomains
    
    def _query_virustotal(self, domain: str) -> Set[str]:
        """API VirusTotal"""
        subdomains = set()
        try:
            headers = {"x-apikey": self.api_keys['VIRUSTOTAL']}
            url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
            
            response = requests.get(url, headers=headers, timeout=15)
            if response.status_code == 200:
                data = response.json()
                for item in data.get('data', []):
                    subdomain = item.get('id')
                    if subdomain:
                        subdomains.add(subdomain)
            
        except Exception as e:
            logger.error(f"VirusTotal error: {e}")
        
        return subdomains
    
    def _query_censys(self, domain: str) -> Set[str]:
        """API Censys"""
        subdomains = set()
        try:
            import base64
            auth = base64.b64encode(
                f"{self.api_keys['CENSYS_API_ID']}:{self.api_keys['CENSYS_SECRET']}".encode()
            ).decode()
            
            headers = {"Authorization": f"Basic {auth}"}
            url = "https://search.censys.io/api/v2/certificates/search"
            
            params = {
                "q": f"names:{domain}",
                "per_page": 100
            }
            
            response = requests.get(url, headers=headers, params=params, timeout=15)
            if response.status_code == 200:
                data = response.json()
                for cert in data.get('result', {}).get('hits', []):
                    for name in cert.get('names', []):
                        if domain in name and '*' not in name:
                            subdomains.add(name)
            
        except Exception as e:
            logger.error(f"Censys error: {e}")
        
        return subdomains
    
    def _certificate_transparency(self, domain: str) -> Set[str]:
        """Certificate Transparency logs melhorado"""
        subdomains = set()
        
        ct_sources = [
            f"https://crt.sh/?q=%.{domain}&output=json",
            f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
        ]
        
        for url in ct_sources:
            try:
                response = requests.get(url, timeout=self.timeout)
                if response.status_code == 200:
                    data = response.json()
                    
                    if "crt.sh" in url:
                        for item in data:
                            name = item.get("name_value", "")
                            if name:
                                names = name.split('\n')
                                for n in names:
                                    n = n.strip()
                                    if domain in n and '*' not in n:
                                        subdomains.add(n)
                    
                    elif "certspotter" in url:
                        for item in data:
                            for name in item.get("dns_names", []):
                                if domain in name and '*' not in name:
                                    subdomains.add(name)
            
            except Exception as e:
                logger.warning(f"CT log error for {url}: {e}")
        
        return subdomains
    
    def _dns_bruteforce(self, domain: str) -> Set[str]:
        """DNS bruteforce inteligente"""
        subdomains = set()
        
        # Wordlist expandida
        extended_wordlist = self.common_subdomains + [
            f"{base}-{suffix}" for base in ["api", "admin", "test", "dev", "staging"] 
            for suffix in ["v1", "v2", "old", "new", "backup"]
        ]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self._resolve_dns, f"{sub}.{domain}"): sub 
                for sub in extended_wordlist
            }
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    subdomains.add(result)
        
        return subdomains
    
    def _search_engines(self, domain: str) -> Set[str]:
        """Busca em motores de pesquisa"""
        subdomains = set()
        
        # Google
        if self.api_keys.get('GOOGLE_API_KEY') and self.api_keys.get('GOOGLE_CSE_ID'):
            subdomains.update(self._google_search(domain))
        
        # Bing
        if self.api_keys.get('BING_API_KEY'):
            subdomains.update(self._bing_search(domain))
        
        return subdomains
    
    def _google_search(self, domain: str) -> Set[str]:
        """Google Custom Search API"""
        subdomains = set()
        try:
            url = "https://www.googleapis.com/customsearch/v1"
            params = {
                "key": self.api_keys['GOOGLE_API_KEY'],
                "cx": self.api_keys['GOOGLE_CSE_ID'],
                "q": f"site:*.{domain}",
                "num": 10
            }
            
            response = requests.get(url, params=params, timeout=15)
            if response.status_code == 200:
                data = response.json()
                for item in data.get("items", []):
                    link = item.get("link", "")
                    if domain in link:
                        # Extract subdomain from URL
                        from urllib.parse import urlparse
                        parsed = urlparse(link)
                        if parsed.hostname and domain in parsed.hostname:
                            subdomains.add(parsed.hostname)
            
        except Exception as e:
            logger.error(f"Google search error: {e}")
        
        return subdomains
    
    def _bing_search(self, domain: str) -> Set[str]:
        """Bing Search API"""
        subdomains = set()
        try:
            url = "https://api.bing.microsoft.com/v7.0/search"
            headers = {"Ocp-Apim-Subscription-Key": self.api_keys['BING_API_KEY']}
            params = {"q": f"site:*.{domain}", "count": 50}
            
            response = requests.get(url, headers=headers, params=params, timeout=15)
            if response.status_code == 200:
                data = response.json()
                for page in data.get("webPages", {}).get("value", []):
                    url_result = page.get("url", "")
                    if domain in url_result:
                        from urllib.parse import urlparse
                        parsed = urlparse(url_result)
                        if parsed.hostname and domain in parsed.hostname:
                            subdomains.add(parsed.hostname)
        
        except Exception as e:
            logger.error(f"Bing search error: {e}")
        
        return subdomains
    
    def _resolve_dns(self, hostname: str) -> Optional[str]:
        """DNS resolution otimizada"""
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2
            resolver.lifetime = 2
            resolver.nameservers = ['8.8.8.8', '1.1.1.1', '208.67.222.222']
            
            resolver.resolve(hostname, 'A')
            return hostname
        except:
            return None
    
    def _is_tool_installed(self, tool: str) -> bool:
        """Verifica se ferramenta está instalada"""
        import shutil
        return shutil.which(tool) is not None
    
    def _is_valid_subdomain(self, subdomain: str, domain: str) -> bool:
        """Valida se subdomínio é válido"""
        if not subdomain or not subdomain.endswith(domain):
            return False
        
        # Remove wildcards
        if subdomain.startswith('*.'):
            return False
        
        # Verifica formato
        parts = subdomain.split('.')
        if len(parts) < 2:
            return False
        
        return True
    
    def get_subdomain_info(self, subdomain: str) -> Dict:
        """Coleta informações detalhadas sobre um subdomínio"""
        info = {
            "subdomain": subdomain,
            "ip": None,
            "cname": None,
            "mx": [],
            "txt": [],
            "ns": [],
            "is_alive": False,
            "ssl_info": None,
            "cdn": None,
            "cloud_provider": None
        }
        
        try:
            # IP Resolution
            info["ip"] = socket.gethostbyname(subdomain)
            info["is_alive"] = True
            
            # DNS Records
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3
            
            # CNAME
            try:
                cname_result = resolver.resolve(subdomain, 'CNAME')
                info["cname"] = str(cname_result[0])
            except:
                pass
            
            # MX
            try:
                mx_result = resolver.resolve(subdomain, 'MX')
                info["mx"] = [str(mx) for mx in mx_result]
            except:
                pass
            
            # TXT
            try:
                txt_result = resolver.resolve(subdomain, 'TXT')
                info["txt"] = [str(txt) for txt in txt_result]
            except:
                pass
            
            # NS
            try:
                ns_result = resolver.resolve(subdomain, 'NS')
                info["ns"] = [str(ns) for ns in ns_result]
            except:
                pass
            
            # SSL Info
            info["ssl_info"] = self._get_ssl_info(subdomain)
            
            # CDN/Cloud Detection
            info["cdn"], info["cloud_provider"] = self._detect_cdn_cloud(subdomain, info["ip"])
            
        except Exception as e:
            logger.debug(f"Error getting info for {subdomain}: {e}")
        
        return info
    
    def _get_ssl_info(self, hostname: str) -> Optional[Dict]:
        """Informações SSL detalhadas"""
        try:
            import ssl
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    return {
                        "issuer": dict(x[0] for x in cert.get('issuer', [])),
                        "subject": dict(x[0] for x in cert.get('subject', [])),
                        "version": cert.get('version'),
                        "serial_number": cert.get('serialNumber'),
                        "not_before": cert.get('notBefore'),
                        "not_after": cert.get('notAfter'),
                        "san": cert.get('subjectAltName', [])
                    }
        except:
            return None
    
    def _detect_cdn_cloud(self, hostname: str, ip: str) -> tuple:
        """Detecta CDN e provedor de cloud"""
        cdn = None
        cloud = None
        
        cdn_indicators = {
            "cloudflare": ["cloudflare"],
            "fastly": ["fastly"],
            "akamai": ["akamai"],
            "amazon": ["cloudfront", "awsglobalconfig"],
            "microsoft": ["azureedge"],
            "google": ["googleusercontent"],
            "maxcdn": ["maxcdn"],
            "keycdn": ["keycdn"]
        }
        
        cloud_indicators = {
            "aws": ["amazon", "aws", "ec2"],
            "azure": ["microsoft", "azure"],
            "gcp": ["google", "gcp"],
            "digitalocean": ["digitalocean"],
            "vultr": ["vultr"],
            "linode": ["linode"]
        }
        
        # Check CNAME
        try:
            resolver = dns.resolver.Resolver()
            cname_result = resolver.resolve(hostname, 'CNAME')
            cname = str(cname_result[0]).lower()
            
            for provider, indicators in cdn_indicators.items():
                if any(indicator in cname for indicator in indicators):
                    cdn = provider
                    break
            
            for provider, indicators in cloud_indicators.items():
                if any(indicator in cname for indicator in indicators):
                    cloud = provider
                    break
        except:
            pass
        
        return cdn, cloud 