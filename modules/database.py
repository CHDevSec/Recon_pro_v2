#!/usr/bin/env python3
"""
Módulo de Database e Cache
Sistema de armazenamento para resultados históricos e análise de tendências
"""

import sqlite3
import json
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

class ReconDatabase:
    def __init__(self, db_path: str = "recon_data.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(exist_ok=True)
        self._init_database()
    
    def _init_database(self):
        """Inicializa as tabelas do banco de dados"""
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS domains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT UNIQUE NOT NULL,
                    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
                    total_scans INTEGER DEFAULT 0,
                    risk_score REAL DEFAULT 0.0,
                    technologies TEXT,
                    status TEXT DEFAULT 'active'
                );
                
                CREATE TABLE IF NOT EXISTS subdomains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain_id INTEGER,
                    subdomain TEXT NOT NULL,
                    ip_address TEXT,
                    status_code INTEGER,
                    technologies TEXT,
                    title TEXT,
                    ssl_info TEXT,
                    cdn_provider TEXT,
                    cloud_provider TEXT,
                    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                    is_active BOOLEAN DEFAULT TRUE,
                    risk_score REAL DEFAULT 0.0,
                    FOREIGN KEY (domain_id) REFERENCES domains (id),
                    UNIQUE(domain_id, subdomain)
                );
                
                CREATE TABLE IF NOT EXISTS scan_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain_id INTEGER,
                    scan_type TEXT NOT NULL,
                    scan_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                    findings_count INTEGER DEFAULT 0,
                    vulnerabilities_count INTEGER DEFAULT 0,
                    risk_score REAL DEFAULT 0.0,
                    scan_duration REAL,
                    results_json TEXT,
                    FOREIGN KEY (domain_id) REFERENCES domains (id)
                );
                
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER,
                    subdomain_id INTEGER,
                    url TEXT NOT NULL,
                    finding_type TEXT NOT NULL,
                    category TEXT,
                    severity TEXT,
                    risk_score REAL DEFAULT 0.0,
                    payload TEXT,
                    status_code INTEGER,
                    response_length INTEGER,
                    vulnerabilities TEXT,
                    first_found DATETIME DEFAULT CURRENT_TIMESTAMP,
                    last_confirmed DATETIME DEFAULT CURRENT_TIMESTAMP,
                    is_confirmed BOOLEAN DEFAULT TRUE,
                    false_positive BOOLEAN DEFAULT FALSE,
                    notes TEXT,
                    FOREIGN KEY (scan_id) REFERENCES scan_results (id),
                    FOREIGN KEY (subdomain_id) REFERENCES subdomains (id)
                );
                
                CREATE TABLE IF NOT EXISTS vulnerability_patterns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pattern_name TEXT UNIQUE NOT NULL,
                    pattern_regex TEXT NOT NULL,
                    category TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT,
                    remediation TEXT,
                    cve_references TEXT,
                    created_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                    is_active BOOLEAN DEFAULT TRUE
                );
                
                CREATE TABLE IF NOT EXISTS api_usage (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    api_name TEXT NOT NULL,
                    usage_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                    requests_made INTEGER DEFAULT 1,
                    rate_limit_hit BOOLEAN DEFAULT FALSE,
                    response_time REAL,
                    status_code INTEGER
                );
                
                CREATE TABLE IF NOT EXISTS notifications (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain_id INTEGER,
                    notification_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    message TEXT,
                    created_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                    is_read BOOLEAN DEFAULT FALSE,
                    webhook_sent BOOLEAN DEFAULT FALSE,
                    FOREIGN KEY (domain_id) REFERENCES domains (id)
                );
                
                -- Índices para performance
                CREATE INDEX IF NOT EXISTS idx_domains_domain ON domains(domain);
                CREATE INDEX IF NOT EXISTS idx_subdomains_domain_id ON subdomains(domain_id);
                CREATE INDEX IF NOT EXISTS idx_subdomains_subdomain ON subdomains(subdomain);
                CREATE INDEX IF NOT EXISTS idx_scan_results_domain_id ON scan_results(domain_id);
                CREATE INDEX IF NOT EXISTS idx_scan_results_date ON scan_results(scan_date);
                CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
                CREATE INDEX IF NOT EXISTS idx_findings_type ON findings(finding_type);
                CREATE INDEX IF NOT EXISTS idx_findings_risk_score ON findings(risk_score);
                CREATE INDEX IF NOT EXISTS idx_api_usage_date ON api_usage(usage_date);
                CREATE INDEX IF NOT EXISTS idx_notifications_read ON notifications(is_read);
            """)
            
            # Insere padrões de vulnerabilidade padrão
            self._insert_default_patterns(conn)
    
    def _insert_default_patterns(self, conn):
        """Insere padrões de vulnerabilidade padrão"""
        default_patterns = [
            ("SQL Error - MySQL", r"SQL syntax.*MySQL|Warning.*mysql_|valid MySQL result", "sql_injection", "high", 
             "Erro SQL exposto indicando possível vulnerabilidade", "Sanitizar entradas, usar prepared statements"),
            ("XSS Reflected", r"<script.*alert.*</script>|javascript:.*alert", "xss", "medium",
             "Cross-Site Scripting refletido detectado", "Escapar output, validar entradas"),
            ("Directory Traversal", r"root:.*:0:0:|Directory of [A-Z]:", "lfi", "high",
             "Traversal de diretório detectado", "Validar paths, usar whitelist"),
            ("Debug Info Exposed", r"DEBUG.*=.*true|APP_DEBUG.*=.*true", "info_disclosure", "medium",
             "Informações de debug expostas", "Desabilitar debug em produção"),
            ("Credentials Exposed", r"API_KEY|API_SECRET|AWS_ACCESS_KEY|password.*=", "credential_exposure", "critical",
             "Credenciais expostas publicamente", "Remover credenciais, usar variáveis de ambiente")
        ]
        
        for pattern in default_patterns:
            try:
                conn.execute("""
                    INSERT OR IGNORE INTO vulnerability_patterns 
                    (pattern_name, pattern_regex, category, severity, description, remediation)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, pattern)
            except sqlite3.IntegrityError:
                pass
    
    def save_domain_scan(self, domain: str, subdomains: List[Dict], findings: List[Dict], 
                         scan_type: str = "full", scan_duration: float = 0.0) -> int:
        """Salva resultado completo de um scan"""
        with sqlite3.connect(self.db_path) as conn:
            # Insere ou atualiza domínio
            domain_id = self._get_or_create_domain(conn, domain)
            
            # Cria registro do scan
            scan_id = conn.execute("""
                INSERT INTO scan_results 
                (domain_id, scan_type, findings_count, vulnerabilities_count, scan_duration, results_json)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                domain_id, scan_type, len(findings),
                len([f for f in findings if f.get('vulnerabilities')]),
                scan_duration, json.dumps({"subdomains": len(subdomains), "findings": len(findings)})
            )).lastrowid
            
            # Salva subdomínios
            for sub_info in subdomains:
                self._save_subdomain(conn, domain_id, sub_info)
            
            # Salva findings
            for finding in findings:
                self._save_finding(conn, scan_id, finding, domain_id)
            
            # Atualiza estatísticas do domínio
            self._update_domain_stats(conn, domain_id)
            
            # Verifica se deve gerar notificações
            self._check_for_notifications(conn, domain_id, findings)
            
            logger.info(f"Scan salvo: Domain={domain}, Scan_ID={scan_id}")
            return scan_id
    
    def _get_or_create_domain(self, conn, domain: str) -> int:
        """Obtém ou cria um domínio"""
        cursor = conn.execute("SELECT id FROM domains WHERE domain = ?", (domain,))
        row = cursor.fetchone()
        
        if row:
            # Atualiza last_updated e incrementa total_scans
            conn.execute("""
                UPDATE domains 
                SET last_updated = CURRENT_TIMESTAMP, total_scans = total_scans + 1
                WHERE id = ?
            """, (row[0],))
            return row[0]
        else:
            # Cria novo domínio
            return conn.execute("""
                INSERT INTO domains (domain, total_scans) VALUES (?, 1)
            """, (domain,)).lastrowid
    
    def _save_subdomain(self, conn, domain_id: int, sub_info: Dict):
        """Salva informações de subdomínio"""
        subdomain = sub_info.get('url', '').replace('http://', '').replace('https://', '').split('/')[0]
        
        conn.execute("""
            INSERT OR REPLACE INTO subdomains 
            (domain_id, subdomain, ip_address, status_code, technologies, title, 
             ssl_info, cdn_provider, cloud_provider, last_seen, risk_score)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?)
        """, (
            domain_id, subdomain, sub_info.get('ip'),
            sub_info.get('status'), sub_info.get('tech'),
            sub_info.get('title'), json.dumps(sub_info.get('ssl_info')),
            sub_info.get('cdn'), sub_info.get('cloud_provider', ''),
            sub_info.get('risk_score', 0.0)
        ))
    
    def _save_finding(self, conn, scan_id: int, finding: Dict, domain_id: int):
        """Salva um finding individual"""
        subdomain_id = self._get_subdomain_id(conn, domain_id, finding.get('url', ''))
        
        conn.execute("""
            INSERT INTO findings 
            (scan_id, subdomain_id, url, finding_type, category, severity, risk_score,
             payload, status_code, response_length, vulnerabilities)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_id, subdomain_id, finding.get('url'),
            finding.get('category', 'unknown'), finding.get('injection_type', finding.get('category')),
            self._calculate_severity(finding.get('risk_score', 0)),
            finding.get('risk_score', 0.0), finding.get('payload'),
            finding.get('status_code'), finding.get('content_length'),
            json.dumps(finding.get('vulnerabilities', []))
        ))
    
    def _get_subdomain_id(self, conn, domain_id: int, url: str) -> Optional[int]:
        """Obtém ID do subdomínio baseado na URL"""
        subdomain = url.replace('http://', '').replace('https://', '').split('/')[0]
        cursor = conn.execute("""
            SELECT id FROM subdomains WHERE domain_id = ? AND subdomain = ?
        """, (domain_id, subdomain))
        row = cursor.fetchone()
        return row[0] if row else None
    
    def _calculate_severity(self, risk_score: float) -> str:
        """Calcula severidade baseada no risk score"""
        if risk_score >= 8:
            return "critical"
        elif risk_score >= 6:
            return "high"
        elif risk_score >= 4:
            return "medium"
        elif risk_score >= 2:
            return "low"
        else:
            return "info"
    
    def _update_domain_stats(self, conn, domain_id: int):
        """Atualiza estatísticas do domínio"""
        cursor = conn.execute("""
            SELECT AVG(risk_score), COUNT(*), MAX(scan_date)
            FROM scan_results WHERE domain_id = ?
        """, (domain_id,))
        avg_risk, scan_count, last_scan = cursor.fetchone()
        
        # Detecta tecnologias mais comuns
        cursor = conn.execute("""
            SELECT technologies FROM subdomains 
            WHERE domain_id = ? AND technologies IS NOT NULL
        """, (domain_id,))
        
        all_techs = []
        for row in cursor.fetchall():
            if row[0]:
                all_techs.extend(row[0].split(', '))
        
        common_techs = ', '.join(list(set(all_techs))[:5])  # Top 5 tecnologias
        
        conn.execute("""
            UPDATE domains 
            SET risk_score = ?, technologies = ?
            WHERE id = ?
        """, (avg_risk or 0.0, common_techs, domain_id))
    
    def _check_for_notifications(self, conn, domain_id: int, findings: List[Dict]):
        """Verifica se deve gerar notificações"""
        high_risk_findings = [f for f in findings if f.get('risk_score', 0) >= 7]
        
        if high_risk_findings:
            conn.execute("""
                INSERT INTO notifications 
                (domain_id, notification_type, severity, title, message)
                VALUES (?, 'high_risk_findings', 'high', 'Vulnerabilidades de Alto Risco Detectadas', ?)
            """, (domain_id, f"{len(high_risk_findings)} vulnerabilidades de alto risco encontradas"))
        
        # Verifica novos subdomínios
        cursor = conn.execute("""
            SELECT COUNT(*) FROM subdomains 
            WHERE domain_id = ? AND first_seen >= datetime('now', '-1 hour')
        """, (domain_id,))
        new_subdomains = cursor.fetchone()[0]
        
        if new_subdomains > 5:
            conn.execute("""
                INSERT INTO notifications 
                (domain_id, notification_type, severity, title, message)
                VALUES (?, 'new_subdomains', 'medium', 'Novos Subdomínios Detectados', ?)
            """, (domain_id, f"{new_subdomains} novos subdomínios encontrados"))
    
    def get_domain_history(self, domain: str, days: int = 30) -> Dict:
        """Obtém histórico de um domínio"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            
            # Informações básicas do domínio
            cursor = conn.execute("""
                SELECT * FROM domains WHERE domain = ?
            """, (domain,))
            domain_info = cursor.fetchone()
            
            if not domain_info:
                return {}
            
            domain_id = domain_info['id']
            
            # Histórico de scans
            cursor = conn.execute("""
                SELECT * FROM scan_results 
                WHERE domain_id = ? AND scan_date >= datetime('now', '-{} days')
                ORDER BY scan_date DESC
            """.format(days), (domain_id,))
            scans = [dict(row) for row in cursor.fetchall()]
            
            # Subdomínios ativos
            cursor = conn.execute("""
                SELECT * FROM subdomains 
                WHERE domain_id = ? AND is_active = TRUE
                ORDER BY risk_score DESC
            """, (domain_id,))
            subdomains = [dict(row) for row in cursor.fetchall()]
            
            # Top findings por risco
            cursor = conn.execute("""
                SELECT f.*, s.subdomain FROM findings f
                LEFT JOIN subdomains s ON f.subdomain_id = s.id
                WHERE f.scan_id IN (
                    SELECT id FROM scan_results WHERE domain_id = ?
                ) AND f.risk_score >= 5
                ORDER BY f.risk_score DESC, f.last_confirmed DESC
                LIMIT 20
            """, (domain_id,))
            top_findings = [dict(row) for row in cursor.fetchall()]
            
            # Estatísticas de tendência
            cursor = conn.execute("""
                SELECT 
                    DATE(scan_date) as scan_day,
                    COUNT(*) as scans_count,
                    AVG(risk_score) as avg_risk,
                    SUM(findings_count) as total_findings,
                    SUM(vulnerabilities_count) as total_vulns
                FROM scan_results 
                WHERE domain_id = ? AND scan_date >= datetime('now', '-{} days')
                GROUP BY DATE(scan_date)
                ORDER BY scan_day
            """.format(days), (domain_id,))
            trends = [dict(row) for row in cursor.fetchall()]
            
            return {
                "domain_info": dict(domain_info),
                "scan_history": scans,
                "active_subdomains": subdomains,
                "top_findings": top_findings,
                "trends": trends,
                "summary": {
                    "total_scans": len(scans),
                    "active_subdomains_count": len(subdomains),
                    "high_risk_findings": len([f for f in top_findings if f['risk_score'] >= 7]),
                    "avg_risk_score": domain_info['risk_score']
                }
            }
    
    def get_subdomain_timeline(self, subdomain: str) -> List[Dict]:
        """Obtém timeline de um subdomínio específico"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            
            cursor = conn.execute("""
                SELECT 
                    s.*,
                    COUNT(f.id) as findings_count,
                    MAX(f.risk_score) as max_risk_score,
                    GROUP_CONCAT(DISTINCT f.finding_type) as finding_types
                FROM subdomains s
                LEFT JOIN findings f ON s.id = f.subdomain_id
                WHERE s.subdomain = ?
                GROUP BY s.id
                ORDER BY s.last_seen DESC
            """, (subdomain,))
            
            return [dict(row) for row in cursor.fetchall()]
    
    def get_vulnerability_stats(self, days: int = 30) -> Dict:
        """Obtém estatísticas de vulnerabilidades"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            
            # Contagem por tipo de vulnerability
            cursor = conn.execute("""
                SELECT 
                    finding_type,
                    COUNT(*) as count,
                    AVG(risk_score) as avg_risk,
                    MAX(risk_score) as max_risk
                FROM findings 
                WHERE first_found >= datetime('now', '-{} days')
                GROUP BY finding_type
                ORDER BY count DESC
            """.format(days))
            by_type = [dict(row) for row in cursor.fetchall()]
            
            # Contagem por severidade
            cursor = conn.execute("""
                SELECT 
                    severity,
                    COUNT(*) as count
                FROM findings 
                WHERE first_found >= datetime('now', '-{} days')
                GROUP BY severity
                ORDER BY 
                    CASE severity 
                        WHEN 'critical' THEN 1
                        WHEN 'high' THEN 2
                        WHEN 'medium' THEN 3
                        WHEN 'low' THEN 4
                        ELSE 5
                    END
            """.format(days))
            by_severity = [dict(row) for row in cursor.fetchall()]
            
            # Tendência temporal
            cursor = conn.execute("""
                SELECT 
                    DATE(first_found) as find_date,
                    COUNT(*) as daily_count,
                    AVG(risk_score) as daily_avg_risk
                FROM findings 
                WHERE first_found >= datetime('now', '-{} days')
                GROUP BY DATE(first_found)
                ORDER BY find_date
            """.format(days))
            trends = [dict(row) for row in cursor.fetchall()]
            
            return {
                "by_type": by_type,
                "by_severity": by_severity,
                "trends": trends,
                "total_findings": sum(item['count'] for item in by_type)
            }
    
    def get_unread_notifications(self) -> List[Dict]:
        """Obtém notificações não lidas"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            
            cursor = conn.execute("""
                SELECT n.*, d.domain 
                FROM notifications n
                JOIN domains d ON n.domain_id = d.id
                WHERE n.is_read = FALSE
                ORDER BY n.created_date DESC
            """)
            
            return [dict(row) for row in cursor.fetchall()]
    
    def mark_notification_read(self, notification_id: int):
        """Marca notificação como lida"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                UPDATE notifications SET is_read = TRUE WHERE id = ?
            """, (notification_id,))
    
    def log_api_usage(self, api_name: str, requests_made: int = 1, 
                     rate_limit_hit: bool = False, response_time: float = 0.0, 
                     status_code: int = 200):
        """Registra uso de API"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO api_usage 
                (api_name, requests_made, rate_limit_hit, response_time, status_code)
                VALUES (?, ?, ?, ?, ?)
            """, (api_name, requests_made, rate_limit_hit, response_time, status_code))
    
    def get_api_usage_stats(self, days: int = 7) -> Dict:
        """Obtém estatísticas de uso de APIs"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            
            cursor = conn.execute("""
                SELECT 
                    api_name,
                    SUM(requests_made) as total_requests,
                    AVG(response_time) as avg_response_time,
                    COUNT(CASE WHEN rate_limit_hit THEN 1 END) as rate_limit_hits,
                    COUNT(CASE WHEN status_code >= 400 THEN 1 END) as error_count
                FROM api_usage 
                WHERE usage_date >= datetime('now', '-{} days')
                GROUP BY api_name
                ORDER BY total_requests DESC
            """.format(days))
            
            return [dict(row) for row in cursor.fetchall()]
    
    def export_domain_data(self, domain: str, format: str = "json") -> str:
        """Exporta dados de um domínio"""
        data = self.get_domain_history(domain, days=365)  # 1 ano
        
        if format.lower() == "json":
            return json.dumps(data, indent=2, default=str)
        elif format.lower() == "csv":
            # Implementar export CSV se necessário
            pass
        
        return str(data)
    
    def cleanup_old_data(self, days: int = 90):
        """Remove dados antigos para manter performance"""
        with sqlite3.connect(self.db_path) as conn:
            # Remove scans antigos (mas mantém o mais recente de cada domínio)
            conn.execute("""
                DELETE FROM scan_results 
                WHERE scan_date < datetime('now', '-{} days')
                AND id NOT IN (
                    SELECT MAX(id) FROM scan_results GROUP BY domain_id
                )
            """.format(days))
            
            # Remove findings órfãos
            conn.execute("""
                DELETE FROM findings 
                WHERE scan_id NOT IN (SELECT id FROM scan_results)
            """)
            
            # Remove notificações antigas lidas
            conn.execute("""
                DELETE FROM notifications 
                WHERE is_read = TRUE AND created_date < datetime('now', '-{} days')
            """.format(days // 2))
            
            # Remove logs antigos de API
            conn.execute("""
                DELETE FROM api_usage 
                WHERE usage_date < datetime('now', '-{} days')
            """.format(days // 3))
            
            # Vacuum para recuperar espaço
            conn.execute("VACUUM")
            
            logger.info(f"Limpeza concluída: dados anteriores a {days} dias removidos")
    
    def get_database_stats(self) -> Dict:
        """Obtém estatísticas do banco de dados"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            
            stats = {}
            
            # Contagens por tabela
            tables = ['domains', 'subdomains', 'scan_results', 'findings', 'notifications']
            for table in tables:
                cursor = conn.execute(f"SELECT COUNT(*) as count FROM {table}")
                stats[f"{table}_count"] = cursor.fetchone()['count']
            
            # Tamanho do arquivo
            stats['db_size_mb'] = self.db_path.stat().st_size / (1024 * 1024)
            
            # Domínio com mais scans
            cursor = conn.execute("""
                SELECT d.domain, COUNT(s.id) as scans
                FROM domains d
                LEFT JOIN scan_results s ON d.id = s.domain_id
                GROUP BY d.domain
                ORDER BY scans DESC
                LIMIT 1
            """)
            top_domain = cursor.fetchone()
            stats['most_scanned_domain'] = dict(top_domain) if top_domain else None
            
            # Último scan
            cursor = conn.execute("""
                SELECT d.domain, s.scan_date
                FROM scan_results s
                JOIN domains d ON s.domain_id = d.id
                ORDER BY s.scan_date DESC
                LIMIT 1
            """)
            last_scan = cursor.fetchone()
            stats['last_scan'] = dict(last_scan) if last_scan else None
            
            return stats 