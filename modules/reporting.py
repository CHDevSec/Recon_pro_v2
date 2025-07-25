#!/usr/bin/env python3
"""
Módulo de Relatórios Avançados - CHDEVSEC Professional Edition
Gera relatórios profissionais de nível corporativo com design moderno e análises detalhadas
"""

import os
import json
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path
import base64
import logging

logger = logging.getLogger(__name__)

class AdvancedReporting:
    def __init__(self, output_dir: str = "recon_results"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.templates_dir = self.output_dir / "templates"
        self.templates_dir.mkdir(exist_ok=True)
        
    def generate_comprehensive_report(self, scan_data: Dict) -> Dict[str, str]:
        """Gera relatório completo em múltiplos formatos profissionais"""
        domain = scan_data.get('domain', 'unknown')
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        reports = {}
        
        # Relatório Técnico Completo (principal)
        technical_path = self.output_dir / f"recon_technical_report_{domain}_{timestamp}.html"
        reports['technical'] = str(technical_path)
        self._generate_technical_report(scan_data, technical_path)
        
        # Relatório Executivo (para gestão C-Level)
        executive_path = self.output_dir / f"executive_summary_{domain}_{timestamp}.html"
        reports['executive'] = str(executive_path)
        self._generate_executive_report(scan_data, executive_path)
        
        # JSON Report (dados estruturados para automação)
        json_path = self.output_dir / f"recon_data_{domain}_{timestamp}.json"
        reports['json'] = str(json_path)
        self._generate_json_report(scan_data, json_path)
        
        # CSV Report (para análise de dados)
        csv_path = self.output_dir / f"recon_findings_{domain}_{timestamp}.csv"
        reports['csv'] = str(csv_path)
        self._generate_csv_report(scan_data, csv_path)
        
        logger.info(f"Relatórios profissionais gerados para {domain}: {list(reports.keys())}")
        return reports
    
    def _calculate_comprehensive_metrics(self, scan_data: Dict) -> Dict:
        """Calcula métricas abrangentes para análise profissional"""
        subdomains = scan_data.get('subdomains', [])
        findings = scan_data.get('findings', [])
        vulnerabilities = scan_data.get('vulnerabilities', [])
        scan_stats = scan_data.get('scan_stats', {})
        
        # Métricas básicas
        total_subdomains = len(subdomains)
        active_subdomains = len([s for s in subdomains if s.get('status', 0) < 400])
        total_findings = len(findings)
        
        # Análise de severidade de vulnerabilidades
        vuln_by_severity = {
            'critical': len([v for v in vulnerabilities if v.get('severity') == 'critical']),
            'high': len([v for v in vulnerabilities if v.get('severity') == 'high']),
            'medium': len([v for v in vulnerabilities if v.get('severity') == 'medium']),
            'low': len([v for v in vulnerabilities if v.get('severity') == 'low']),
            'info': len([v for v in vulnerabilities if v.get('severity') == 'info'])
        }
        
        # Score de risco global
        risk_scores = []
        for finding in findings:
            if finding.get('risk_score'):
                risk_scores.append(float(finding['risk_score']))
        
        avg_risk_score = sum(risk_scores) / len(risk_scores) if risk_scores else 0
        max_risk_score = max(risk_scores) if risk_scores else 0
        
        # Análise de tecnologias
        all_techs = []
        tech_versions = {}
        
        for sub in subdomains:
            if sub.get('tech') and sub['tech'] != 'Unknown':
                techs = [t.strip() for t in sub['tech'].split(',')]
                all_techs.extend(techs)
                
                # Extrai versões de tecnologias
                for tech in techs:
                    tech_clean = tech.lower().strip()
                    if tech_clean and tech_clean != 'unknown':
                        tech_versions[tech_clean] = tech_versions.get(tech_clean, 0) + 1
        
        top_technologies = sorted(tech_versions.items(), key=lambda x: x[1], reverse=True)[:8]
        
        # Análise de superfície de ataque
        login_pages = len([s for s in subdomains if s.get('login_detected')])
        admin_panels = len([f for f in findings if 'admin' in f.get('category', '').lower()])
        api_endpoints = len([f for f in findings if 'api' in f.get('category', '').lower()])
        sensitive_files = len([f for f in findings if 'sensitive' in f.get('category', '').lower()])
        
        # Categorização de findings
        findings_by_category = {}
        for finding in findings:
            category = finding.get('category', 'other')
            findings_by_category[category] = findings_by_category.get(category, 0) + 1
        
        # Análise de SSL/TLS
        ssl_enabled = len([s for s in subdomains if s.get('ssl_info') and 'SSL' in str(s['ssl_info'])])
        ssl_coverage = (ssl_enabled / active_subdomains * 100) if active_subdomains > 0 else 0
        
        # Análise de tempo de scan
        scan_duration = scan_stats.get('scan_duration_minutes', 0)
        efficiency_score = (total_findings / scan_duration) if scan_duration > 0 else 0
        
        return {
            # Métricas básicas
            'total_subdomains': total_subdomains,
            'active_subdomains': active_subdomains,
            'total_findings': total_findings,
            'total_vulnerabilities': len(vulnerabilities),
            
            # Análise de risco
            'vulnerabilities_by_severity': vuln_by_severity,
            'avg_risk_score': round(avg_risk_score, 2),
            'max_risk_score': round(max_risk_score, 2),
            'overall_risk_level': self._calculate_overall_risk(vuln_by_severity, avg_risk_score),
            
            # Superfície de ataque
            'login_pages_found': login_pages,
            'admin_panels_found': admin_panels,
            'api_endpoints_found': api_endpoints,
            'sensitive_files_found': sensitive_files,
            'attack_surface_score': self._calculate_attack_surface_score(login_pages, admin_panels, api_endpoints),
            
            # Tecnologias
            'top_technologies': top_technologies,
            'unique_technologies': len(tech_versions),
            
            # Segurança
            'ssl_coverage_percent': round(ssl_coverage, 1),
            'ssl_enabled_hosts': ssl_enabled,
            
            # Findings
            'findings_by_category': findings_by_category,
            'high_risk_findings': len([f for f in findings if f.get('risk_score', 0) >= 7]),
            
            # Performance
            'scan_duration_minutes': scan_duration,
            'efficiency_score': round(efficiency_score, 2),
            'findings_per_host': round(total_findings / active_subdomains, 2) if active_subdomains > 0 else 0,
            
            # Timestamp
            'scan_timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'scan_date': datetime.now().strftime('%d/%m/%Y'),
            'scan_time': datetime.now().strftime('%H:%M:%S')
        }
    
    def _generate_technical_report(self, scan_data: Dict, output_path: Path):
        """Gera relatório técnico profissional completo"""
        domain = scan_data.get('domain', 'Unknown')
        subdomains = scan_data.get('subdomains', [])
        findings = scan_data.get('findings', [])
        dork_results = scan_data.get('dork_results', [])
        vulnerabilities = scan_data.get('vulnerabilities', [])
        
        # Calcula métricas abrangentes
        metrics = self._calculate_comprehensive_metrics(scan_data)
        
        # Gera seções do relatório
        html_content = f"""
        <!DOCTYPE html>
        <html lang="pt-BR">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Relatório Técnico de Segurança - {domain} | CHDEVSEC</title>
            {self._get_chdevsec_styles()}
            {self._get_javascript_libs()}
        </head>
        <body>
            <div class="main-container">
                {self._generate_technical_header(domain, metrics)}
                {self._generate_executive_dashboard(metrics)}
                {self._generate_technical_overview(metrics)}
                {self._generate_attack_surface_analysis(metrics, subdomains)}
                {self._generate_detailed_findings_section(findings)}
                {self._generate_vulnerability_analysis(vulnerabilities)}
                {self._generate_security_posture_section(metrics)}
                {self._generate_threat_intelligence_section(dork_results)}
                {self._generate_recommendations_matrix(vulnerabilities, findings, metrics)}
                {self._generate_technical_appendix(scan_data)}
                {self._generate_chdevsec_footer()}
            </div>
            {self._get_advanced_javascript(metrics)}
        </body>
        </html>
        """
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
    
    def _generate_executive_report(self, scan_data: Dict, output_path: Path):
        """Gera relatório executivo focado em business impact"""
        domain = scan_data.get('domain', 'Unknown')
        metrics = self._calculate_comprehensive_metrics(scan_data)
        vulnerabilities = scan_data.get('vulnerabilities', [])
        
        html_content = f"""
        <!DOCTYPE html>
        <html lang="pt-BR">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Relatório Executivo de Cibersegurança - {domain} | CHDEVSEC</title>
            {self._get_executive_styles()}
            {self._get_javascript_libs()}
        </head>
        <body>
            <div class="executive-container">
                {self._generate_executive_header(domain, metrics)}
                {self._generate_executive_summary_dashboard(metrics)}
                {self._generate_business_impact_analysis(metrics, vulnerabilities)}
                {self._generate_risk_matrix_section(metrics)}
                {self._generate_executive_recommendations(vulnerabilities, metrics)}
                {self._generate_budget_impact_section(metrics)}
                {self._generate_next_steps_timeline(metrics)}
                {self._generate_executive_footer()}
            </div>
                         {self._generate_executive_javascript(metrics)}
        </body>
        </html>
        """
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

    def _get_chdevsec_styles(self) -> str:
        """Retorna estilos CSS profissionais com tema CHDEVSEC azul escuro"""
        return """
        <style>
            :root {
                --chdevsec-primary: #1a237e;
                --chdevsec-secondary: #283593;
                --chdevsec-accent: #3f51b5;
                --chdevsec-light: #5c6bc0;
                --chdevsec-dark: #0d1457;
                --chdevsec-gradient: linear-gradient(135deg, #1a237e 0%, #283593 50%, #3f51b5 100%);
                --chdevsec-glass: rgba(26, 35, 126, 0.95);
                --danger-color: #f44336;
                --warning-color: #ff9800;
                --success-color: #4caf50;
                --info-color: #2196f3;
                --text-primary: #ffffff;
                --text-secondary: #e8eaf6;
                --bg-card: rgba(255, 255, 255, 0.1);
                --bg-glass: rgba(255, 255, 255, 0.05);
                --shadow-primary: 0 8px 32px rgba(26, 35, 126, 0.3);
                --shadow-glass: 0 8px 32px rgba(0, 0, 0, 0.3);
            }

            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }

            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif;
                background: var(--chdevsec-gradient);
                color: var(--text-primary);
                line-height: 1.5;
                min-height: 100vh;
                margin: 0;
                padding: 0;
            }

            .main-container {
                max-width: 1400px;
                margin: 0 auto;
                padding: 20px;
            }

            /* Header Styles - Otimizado */
            .technical-header {
                background: var(--chdevsec-dark);
                border: 1px solid rgba(255, 255, 255, 0.15);
                border-radius: 16px;
                padding: 30px;
                margin-bottom: 25px;
                box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
                border-top: 4px solid var(--chdevsec-accent);
            }

            .header-content {
                display: grid;
                grid-template-columns: 1fr auto;
                gap: 30px;
                align-items: center;
            }

            .header-info h1 {
                font-size: 2.5em;
                font-weight: 700;
                margin-bottom: 10px;
                background: linear-gradient(135deg, var(--text-primary), var(--chdevsec-light));
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
            }

            .domain-badge {
                display: inline-block;
                background: var(--chdevsec-accent);
                color: white;
                padding: 8px 20px;
                border-radius: 50px;
                font-weight: 600;
                font-size: 1.1em;
                margin: 10px 0;
                box-shadow: 0 4px 15px rgba(63, 81, 181, 0.3);
            }

            .scan-meta {
                display: flex;
                gap: 20px;
                margin-top: 15px;
                flex-wrap: wrap;
            }

            .meta-item {
                display: flex;
                align-items: center;
                gap: 8px;
                background: var(--bg-card);
                padding: 8px 16px;
                border-radius: 12px;
                border: 1px solid rgba(255, 255, 255, 0.1);
            }

            .risk-indicator {
                display: flex;
                flex-direction: column;
                align-items: center;
                text-align: center;
                min-width: 150px;
            }

            .risk-score-circle {
                width: 120px;
                height: 120px;
                border-radius: 50%;
                display: flex;
                flex-direction: column;
                align-items: center;
                justify-content: center;
                font-size: 1.8em;
                font-weight: 700;
                color: white;
                box-shadow: var(--shadow-primary);
                position: relative;
                overflow: hidden;
            }

            .risk-critical { background: linear-gradient(135deg, #d32f2f, #f44336); }
            .risk-high { background: linear-gradient(135deg, #f57c00, #ff9800); }
            .risk-medium { background: linear-gradient(135deg, #1976d2, #2196f3); }
            .risk-low { background: linear-gradient(135deg, #388e3c, #4caf50); }



            .risk-label {
                margin-top: 10px;
                font-weight: 600;
                text-transform: uppercase;
                letter-spacing: 1px;
                font-size: 0.9em;
            }

            /* Dashboard Grid - Versão Fixa */
            .executive-dashboard {
                display: grid;
                grid-template-columns: repeat(3, 1fr);
                gap: 25px;
                margin-bottom: 40px;
                max-width: 1200px;
                margin-left: auto;
                margin-right: auto;
            }

            .dashboard-card {
                background: var(--chdevsec-dark);
                border: 1px solid rgba(255, 255, 255, 0.2);
                border-radius: 12px;
                padding: 20px;
                box-shadow: 0 2px 10px rgba(0, 0, 0, 0.3);
                transition: transform 0.2s ease, box-shadow 0.2s ease;
                min-height: 160px;
                display: flex;
                flex-direction: column;
                justify-content: space-between;
                border-top: 3px solid var(--card-accent, var(--chdevsec-accent));
            }

            .dashboard-card:hover {
                transform: translateY(-2px);
                box-shadow: 0 4px 15px rgba(26, 35, 126, 0.4);
            }

            .card-critical::before { background: linear-gradient(90deg, var(--danger-color), #ff6b6b); }
            .card-warning::before { background: linear-gradient(90deg, var(--warning-color), #ffa726); }
            .card-success::before { background: linear-gradient(90deg, var(--success-color), #66bb6a); }
            .card-info::before { background: linear-gradient(90deg, var(--info-color), #42a5f5); }

            .card-header {
                display: flex;
                align-items: center;
                gap: 12px;
                margin-bottom: 15px;
            }

            .card-icon {
                width: 45px;
                height: 45px;
                border-radius: 12px;
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 1.3em;
                background: var(--card-accent, var(--chdevsec-accent));
                color: white;
                box-shadow: 0 4px 12px rgba(0, 0, 0, 0.25);
                flex-shrink: 0;
            }

            .card-title {
                font-size: 0.95em;
                font-weight: 600;
                color: var(--text-secondary);
                text-transform: uppercase;
                letter-spacing: 0.5px;
                line-height: 1.2;
            }

            .card-content {
                flex: 1;
                display: flex;
                flex-direction: column;
                justify-content: center;
            }

            .card-value {
                font-size: 2.2em;
                font-weight: 700;
                color: var(--text-primary);
                margin-bottom: 8px;
                line-height: 1.1;
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            }

            .card-subtitle {
                color: var(--text-secondary);
                font-size: 0.9em;
                opacity: 1;
                line-height: 1.4;
                font-weight: 400;
            }

            .progress-ring {
                display: none; /* Removido para melhor performance */
            }

            /* Section Styles - Otimizado */
            .report-section {
                background: var(--chdevsec-dark);
                border: 1px solid rgba(255, 255, 255, 0.15);
                border-radius: 12px;
                margin-bottom: 25px;
                overflow: hidden;
                box-shadow: 0 2px 10px rgba(0, 0, 0, 0.3);
            }

            .section-header {
                background: var(--chdevsec-secondary);
                padding: 25px 30px;
                border-bottom: 1px solid rgba(255, 255, 255, 0.1);
            }

            .section-title {
                font-size: 1.5em;
                font-weight: 600;
                display: flex;
                align-items: center;
                gap: 15px;
                color: var(--text-primary);
            }

            .section-title-icon {
                width: 40px;
                height: 40px;
                border-radius: 12px;
                background: var(--chdevsec-accent);
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 1.2em;
                box-shadow: 0 4px 12px rgba(63, 81, 181, 0.3);
            }

            .section-content {
                padding: 30px;
            }

            /* Tables - Melhor Legibilidade */
            .data-table {
                width: 100%;
                border-collapse: collapse;
                border-radius: 8px;
                overflow: hidden;
                box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3);
                font-size: 0.95em;
            }

            .data-table th {
                background: var(--chdevsec-secondary);
                color: var(--text-primary);
                padding: 16px 12px;
                text-align: left;
                font-weight: 600;
                text-transform: uppercase;
                letter-spacing: 0.5px;
                font-size: 0.85em;
                border-bottom: 2px solid var(--chdevsec-accent);
            }

            .data-table td {
                padding: 14px 12px;
                border-bottom: 1px solid rgba(255, 255, 255, 0.1);
                background: var(--chdevsec-dark);
                vertical-align: top;
                line-height: 1.4;
            }

            .data-table tr:hover td {
                background: rgba(255, 255, 255, 0.05);
            }

            .data-table td:first-child {
                font-weight: 500;
                color: var(--chdevsec-light);
            }

            .data-table tr.high-risk td {
                border-left: 4px solid var(--danger-color);
                background: rgba(244, 67, 54, 0.1);
            }

            .data-table tr.medium-risk td {
                border-left: 4px solid var(--warning-color);
                background: rgba(255, 152, 0, 0.1);
            }

            .data-table tr.low-risk td {
                border-left: 4px solid var(--success-color);
                background: rgba(76, 175, 80, 0.1);
            }

            /* Status badges - Melhor Legibilidade */
            .status-badge {
                padding: 8px 16px;
                border-radius: 6px;
                font-size: 0.85em;
                font-weight: 600;
                text-transform: uppercase;
                letter-spacing: 0.5px;
                border: none;
                color: white;
                display: inline-block;
                min-width: 60px;
                text-align: center;
                font-family: monospace;
            }

            .status-200 { background: #2e7d32; }
            .status-300 { background: #1976d2; }
            .status-400 { background: #f57c00; }
            .status-500 { background: #d32f2f; }

            .vulnerability-badge {
                padding: 6px 12px;
                border-radius: 6px;
                font-size: 0.8em;
                font-weight: 600;
                text-transform: uppercase;
                margin: 2px;
                display: inline-block;
                border: none;
                color: white;
                min-width: 80px;
                text-align: center;
            }

            .vuln-critical { background: #d32f2f; }
            .vuln-high { background: #f57c00; }
            .vuln-medium { background: #1976d2; }
            .vuln-low { background: #2e7d32; }

            /* Links */
            .external-link {
                color: var(--chdevsec-light);
                text-decoration: none;
                font-weight: 500;
                transition: all 0.2s ease;
            }

            .external-link:hover {
                color: var(--text-primary);
                text-shadow: 0 0 10px var(--chdevsec-light);
            }

            /* Footer */
            .chdevsec-footer {
                background: var(--chdevsec-dark);
                padding: 40px;
                margin-top: 50px;
                border-radius: 20px;
                text-align: center;
                border: 1px solid rgba(255, 255, 255, 0.1);
            }

            .footer-logo {
                font-size: 2em;
                font-weight: 700;
                background: linear-gradient(135deg, var(--chdevsec-accent), var(--chdevsec-light));
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
                margin-bottom: 15px;
            }

            .footer-content p {
                margin: 10px 0;
                color: var(--text-secondary);
            }

            .disclaimer {
                background: rgba(244, 67, 54, 0.1);
                border: 1px solid var(--danger-color);
                border-radius: 12px;
                padding: 20px;
                margin-top: 20px;
                font-style: italic;
                color: var(--text-secondary);
            }

            /* Animations */
            @keyframes rotate {
                from { transform: rotate(0deg); }
                to { transform: rotate(360deg); }
            }

            @keyframes progressAnim {
                to { stroke-dashoffset: 0; }
            }

            @keyframes fadeInUp {
                from {
                    opacity: 0;
                    transform: translateY(30px);
                }
                to {
                    opacity: 1;
                    transform: translateY(0);
                }
            }

            .fade-in-up {
                animation: fadeInUp 0.6s ease-out forwards;
            }

                         /* Responsive Design - Totalmente Corrigido */
             @media (max-width: 1200px) {
                 .main-container, .executive-container {
                     max-width: 100%;
                     padding: 20px 15px;
                 }
                 
                 .chart-grid {
                     max-width: 100%;
                     gap: 20px;
                 }
             }

             @media (max-width: 1024px) {
                 .executive-dashboard {
                     grid-template-columns: repeat(2, 1fr);
                     gap: 20px;
                 }
                 
                 .chart-grid {
                     grid-template-columns: 1fr;
                     gap: 25px;
                 }

                 .chart-container {
                     min-height: 320px;
                     padding: 20px;
                 }

                 .chart-container canvas {
                     max-height: 220px !important;
                 }
             }

             @media (max-width: 768px) {
                 .main-container, .executive-container {
                     padding: 15px 10px;
                 }
                 
                 .header-content {
                     grid-template-columns: 1fr;
                     text-align: center;
                     gap: 20px;
                 }
                 
                 .executive-dashboard {
                     grid-template-columns: 1fr;
                     gap: 15px;
                 }
                 
                 .chart-grid {
                     grid-template-columns: 1fr;
                     gap: 20px;
                     margin: 20px 0;
                 }
                 
                 .dashboard-card {
                     min-height: 140px;
                     padding: 20px;
                 }
                 
                 .chart-container {
                     min-height: 280px;
                     padding: 20px;
                 }

                 .chart-container canvas {
                     max-height: 180px !important;
                 }
                 
                 .card-value {
                     font-size: 2em;
                 }
                 
                 .technical-header {
                     padding: 20px;
                 }
                 
                 .scan-meta {
                     flex-direction: column;
                     gap: 10px;
                 }
                 
                 .meta-item {
                     padding: 6px 12px;
                 }
                 
                 .risk-score-circle {
                     width: 100px;
                     height: 100px;
                     font-size: 1.5em;
                 }
             }

             @media (max-width: 480px) {
                 .main-container, .executive-container {
                     padding: 10px 8px;
                 }

                 .executive-dashboard {
                     gap: 12px;
                 }
                 
                 .chart-grid {
                     gap: 15px;
                     margin: 15px 0;
                 }
                 
                 .dashboard-card {
                     min-height: 120px;
                     padding: 15px;
                 }

                 .chart-container {
                     min-height: 250px;
                     padding: 15px;
                 }

                 .chart-container canvas {
                     max-height: 150px !important;
                 }

                 .chart-title {
                     font-size: 1em;
                     margin-bottom: 15px;
                 }
                 
                 .card-value {
                     font-size: 1.8em;
                 }
                 
                 .card-icon {
                     width: 35px;
                     height: 35px;
                     font-size: 1.1em;
                 }
                 
                 .card-title {
                     font-size: 0.8em;
                 }

                 .technical-header {
                     padding: 15px;
                 }

                 .technical-header h1 {
                     font-size: 1.8em;
                 }
             }

            /* Chart containers - Totalmente Reformulados */
            .chart-grid {
                display: grid;
                grid-template-columns: repeat(2, 1fr);
                gap: 25px;
                margin: 30px 0;
                max-width: 1200px;
                margin-left: auto;
                margin-right: auto;
            }

            .chart-container {
                background: var(--chdevsec-dark);
                border: 1px solid rgba(255, 255, 255, 0.2);
                border-radius: 12px;
                padding: 20px;
                box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3);
                min-height: 320px;
                height: auto;
                display: flex;
                flex-direction: column;
                transition: box-shadow 0.2s ease;
            }

            .chart-container:hover {
                box-shadow: 0 4px 12px rgba(26, 35, 126, 0.4);
            }

            .chart-title {
                font-size: 1.1em;
                font-weight: 600;
                margin-bottom: 20px;
                color: var(--text-primary);
                text-align: center;
                text-transform: uppercase;
                letter-spacing: 1px;
                border-bottom: 2px solid var(--chdevsec-accent);
                padding-bottom: 12px;
                position: relative;
                flex-shrink: 0;
            }

            .chart-title::after {
                content: '';
                position: absolute;
                bottom: -2px;
                left: 50%;
                transform: translateX(-50%);
                width: 60px;
                height: 2px;
                background: linear-gradient(90deg, var(--chdevsec-accent), var(--chdevsec-light));
                border-radius: 2px;
            }

            /* Canvas específico para Chart.js */
            .chart-container canvas {
                max-height: 250px !important;
                flex: 1;
                margin: auto;
            }

            /* Container de conteúdo dos gráficos */
            .chart-content {
                flex: 1;
                display: flex;
                align-items: center;
                justify-content: center;
                min-height: 250px;
                padding: 10px;
            }

            /* Tech stack visualization */
            .tech-stack {
                display: grid;
                grid-template-columns: repeat(auto-fill, minmax(120px, 1fr));
                gap: 15px;
                margin-top: 20px;
            }

            .tech-item {
                background: var(--bg-card);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 12px;
                padding: 15px;
                text-align: center;
                transition: all 0.3s ease;
            }

            .tech-item:hover {
                transform: translateY(-3px);
                box-shadow: 0 8px 25px rgba(0, 0, 0, 0.2);
                border-color: var(--chdevsec-accent);
            }

            .tech-name {
                font-weight: 600;
                color: var(--text-primary);
                margin-bottom: 5px;
            }

            .tech-count {
                color: var(--text-secondary);
                font-size: 0.9em;
            }
        </style>
        """
    

    
    def _format_technologies(self, tech_string: str) -> str:
        """Formata string de tecnologias em pills"""
        if not tech_string or tech_string == 'Unknown':
            return '<span class="tech-pill unknown">Unknown</span>'
        
        techs = [t.strip() for t in tech_string.split(',') if t.strip()]
        pills = []
        
        for tech in techs[:3]:  # Máximo 3 pills
            pills.append(f'<span class="tech-pill">{tech}</span>')
        
        if len(techs) > 3:
            pills.append(f'<span class="tech-pill more">+{len(techs)-3}</span>')
        
        return "".join(pills)
    
    def _get_risk_level(self, risk_score: float) -> str:
        """Determina nível de risco baseado no score"""
        if risk_score >= 8:
            return "CRÍTICO"
        elif risk_score >= 6:
            return "ALTO"
        elif risk_score >= 4:
            return "MÉDIO"
        elif risk_score >= 2:
            return "BAIXO"
        else:
            return "MÍNIMO"
    
    def _get_risk_color(self, risk_level: str) -> str:
        """Retorna classe CSS para cor do risco"""
        colors = {
            "CRÍTICO": "critical",
            "ALTO": "high",
            "MÉDIO": "medium",
            "BAIXO": "low",
            "MÍNIMO": "low"
        }
        return colors.get(risk_level, "low")
    
    def _get_risk_class(self, risk_score: float) -> str:
        """Retorna classe CSS baseada no risk score"""
        if risk_score >= 7:
            return "high-risk"
        elif risk_score >= 4:
            return "medium-risk"
        else:
            return "low-risk"
    
    def _generate_json_report(self, scan_data: Dict, output_path: Path):
        """Gera relatório em formato JSON"""
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(scan_data, f, indent=2, ensure_ascii=False, default=str)
    
    def _generate_csv_report(self, scan_data: Dict, output_path: Path):
        """Gera relatório em formato CSV"""
        import csv
        
        findings = scan_data.get('findings', [])
        if not findings:
            return
        
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            fieldnames = ['url', 'category', 'status_code', 'risk_score', 'vulnerabilities', 'tech']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            
            writer.writeheader()
            for finding in findings:
                writer.writerow({
                    'url': finding.get('url', ''),
                    'category': finding.get('category', ''),
                    'status_code': finding.get('status_code', ''),
                    'risk_score': finding.get('risk_score', 0),
                    'vulnerabilities': '; '.join(finding.get('vulnerabilities', [])),
                    'tech': finding.get('tech', '')
                })
    
    def _generate_executive_summary(self, scan_data: Dict, output_path: Path):
        """Gera sumário executivo"""
        metrics = self._calculate_comprehensive_metrics(scan_data)
        domain = scan_data.get('domain', 'Unknown')
        
        summary_html = f"""
        <!DOCTYPE html>
        <html lang="pt-BR">
        <head>
            <meta charset="UTF-8">
            <title>Sumário Executivo - {domain}</title>
            {self._get_executive_styles()}
            {self._get_javascript_libs()}
        </head>
        <body>
            <div class="executive-container">
                {self._generate_executive_header(domain, metrics)}
                {self._generate_executive_summary_dashboard(metrics)}
                {self._generate_business_impact_analysis(metrics, scan_data.get('vulnerabilities', []))}
                {self._generate_executive_recommendations(scan_data.get('vulnerabilities', []), metrics)}
                {self._generate_executive_footer()}
            </div>
            {self._generate_executive_javascript(metrics)}
        </body>
        </html>
        """
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(summary_html)
    
    def _generate_executive_risks(self, scan_data: Dict) -> str:
        """Gera seção de riscos para executivos"""
        vulnerabilities = scan_data.get('vulnerabilities', [])
        findings = scan_data.get('findings', [])
        
        high_risk_items = []
        
        # Vulnerabilidades críticas
        critical_vulns = [v for v in vulnerabilities if v.get('severity') == 'critical']
        if critical_vulns:
            high_risk_items.append(f"🚨 <strong>{len(critical_vulns)} vulnerabilidades críticas</strong> que podem comprometer completamente o sistema")
        
        # Exposição de credenciais
        cred_vulns = [v for v in vulnerabilities if 'credential' in v.get('category', '')]
        if cred_vulns:
            high_risk_items.append(f"🔑 <strong>Credenciais expostas</strong> detectadas em {len(cred_vulns)} locais")
        
        # Painéis administrativos expostos
        admin_findings = [f for f in findings if 'admin' in f.get('category', '')]
        if admin_findings:
            high_risk_items.append(f"🛡️ <strong>{len(admin_findings)} painéis administrativos</strong> potencialmente acessíveis")
        
        if not high_risk_items:
            return "<p>✅ Nenhum risco crítico imediato identificado.</p>"
        
        items_html = "".join([f"<li>{item}</li>" for item in high_risk_items])
        return f"<ul class='risk-list'>{items_html}</ul>"
    
    def _generate_old_executive_recommendations(self, scan_data: Dict) -> str:
        """Gera recomendações para executivos"""
        recommendations = [
            "🎯 <strong>Ação Imediata:</strong> Corrigir vulnerabilidades críticas identificadas",
            "🔒 <strong>Autenticação:</strong> Implementar autenticação multifator (MFA)",
            "🛡️ <strong>WAF:</strong> Instalar Web Application Firewall",
            "📊 <strong>Monitoramento:</strong> Implementar SOC/SIEM para detecção de ameaças",
            "👥 <strong>Treinamento:</strong> Capacitar equipe em segurança cibernética",
            "📋 <strong>Política:</strong> Estabelecer política de segurança da informação"
        ]
        
        items_html = "".join([f"<li>{rec}</li>" for rec in recommendations])
        return f"<ul class='recommendations-list'>{items_html}</ul>"
    
    # Métodos auxiliares para cálculos
    def _calculate_overall_risk(self, vuln_by_severity: Dict, avg_risk: float) -> str:
        """Calcula o nível de risco geral"""
        critical = vuln_by_severity.get('critical', 0)
        high = vuln_by_severity.get('high', 0)
        
        if critical > 0 or avg_risk >= 8:
            return "CRÍTICO"
        elif high > 2 or avg_risk >= 6:
            return "ALTO"
        elif avg_risk >= 4:
            return "MÉDIO"
        elif avg_risk >= 2:
            return "BAIXO"
        else:
            return "MÍNIMO"

    def _calculate_attack_surface_score(self, login_pages: int, admin_panels: int, api_endpoints: int) -> float:
        """Calcula score da superfície de ataque"""
        score = 0.0
        score += login_pages * 2.5  # Login pages são críticos
        score += admin_panels * 4.0  # Admin panels são muito críticos
        score += api_endpoints * 1.5  # APIs aumentam superfície
        return min(10.0, score)

    # Métodos para geração do relatório técnico
    def _generate_technical_header(self, domain: str, metrics: Dict) -> str:
        """Gera cabeçalho técnico profissional"""
        risk_level = metrics.get('overall_risk_level', 'BAIXO')
        risk_class = f"risk-{risk_level.lower()}"
        
        return f"""
        <div class="technical-header fade-in-up">
            <div class="header-content">
                <div class="header-info">
                    <h1>🛡️ Relatório Técnico de Segurança</h1>
                    <div class="domain-badge">{domain}</div>
                    <div class="scan-meta">
                        <div class="meta-item">
                            <span>📅</span>
                            <span>{metrics['scan_date']}</span>
                        </div>
                        <div class="meta-item">
                            <span>⏰</span>
                            <span>{metrics['scan_time']}</span>
                        </div>
                        <div class="meta-item">
                            <span>⚡</span>
                            <span>{metrics['scan_duration_minutes']} min</span>
                        </div>
                        <div class="meta-item">
                            <span>🔍</span>
                            <span>{metrics['total_findings']} achados</span>
                        </div>
                    </div>
                </div>
                <div class="risk-indicator">
                    <div class="risk-score-circle {risk_class}">
                        <div>{metrics['avg_risk_score']}</div>
                        <small>/10</small>
                    </div>
                    <div class="risk-label">{risk_level}</div>
                </div>
            </div>
        </div>
        """

    def _generate_executive_dashboard(self, metrics: Dict) -> str:
        """Gera dashboard executivo com métricas principais"""
        return f"""
        <div class="executive-dashboard">
            <div class="dashboard-card card-info fade-in-up">
                <div class="card-header">
                    <div class="card-icon" style="background: var(--info-color)">🌐</div>
                    <div class="card-title">Descoberta</div>
                </div>
                <div class="card-content">
                    <div class="card-value">{metrics['total_subdomains']}</div>
                    <div class="card-subtitle">Subdomínios descobertos</div>
                </div>
                <div class="progress-ring">
                    <svg>
                        <circle class="progress-bg" cx="30" cy="30" r="25"></circle>
                        <circle class="progress-fg" cx="30" cy="30" r="25" 
                                style="stroke-dashoffset: {157 - (metrics['active_subdomains'] / max(metrics['total_subdomains'], 1) * 157)}"></circle>
                    </svg>
                </div>
            </div>
            
            <div class="dashboard-card card-success fade-in-up">
                <div class="card-header">
                    <div class="card-icon" style="background: var(--success-color)">✅</div>
                    <div class="card-title">Hosts Ativos</div>
                </div>
                <div class="card-content">
                    <div class="card-value">{metrics['active_subdomains']}</div>
                    <div class="card-subtitle">{round((metrics['active_subdomains'] / max(metrics['total_subdomains'], 1)) * 100, 1)}% ativos</div>
                </div>
            </div>
            
            <div class="dashboard-card card-warning fade-in-up">
                <div class="card-header">
                    <div class="card-icon" style="background: var(--warning-color)">🔍</div>
                    <div class="card-title">Achados</div>
                </div>
                <div class="card-content">
                    <div class="card-value">{metrics['total_findings']}</div>
                    <div class="card-subtitle">{metrics['findings_per_host']} por host</div>
                </div>
            </div>
            
            <div class="dashboard-card card-critical fade-in-up">
                <div class="card-header">
                    <div class="card-icon" style="background: var(--danger-color)">🚨</div>
                    <div class="card-title">Vulnerabilidades</div>
                </div>
                <div class="card-content">
                    <div class="card-value">{metrics['total_vulnerabilities']}</div>
                    <div class="card-subtitle">{metrics['vulnerabilities_by_severity'].get('critical', 0)} críticas</div>
                </div>
            </div>
            
            <div class="dashboard-card fade-in-up">
                <div class="card-header">
                    <div class="card-icon" style="background: var(--chdevsec-accent)">🔐</div>
                    <div class="card-title">Segurança SSL</div>
                </div>
                <div class="card-content">
                    <div class="card-value">{metrics['ssl_coverage_percent']}%</div>
                    <div class="card-subtitle">Cobertura SSL/TLS</div>
                </div>
            </div>
            
            <div class="dashboard-card fade-in-up">
                <div class="card-header">
                    <div class="card-icon" style="background: var(--chdevsec-light)">⚡</div>
                    <div class="card-title">Performance</div>
                </div>
                <div class="card-content">
                    <div class="card-value">{metrics['efficiency_score']}</div>
                    <div class="card-subtitle">Achados por minuto</div>
                </div>
            </div>
        </div>
        """

    def _generate_technical_overview(self, metrics: Dict) -> str:
        """Gera seção de overview técnico"""
        vuln_severity = metrics['vulnerabilities_by_severity']
        
        return f"""
        <div class="report-section fade-in-up">
            <div class="section-header">
                <div class="section-title">
                    <div class="section-title-icon">📊</div>
                    <span>Visão Geral Técnica</span>
                </div>
            </div>
            <div class="section-content">
                <div class="chart-grid">
                    <div class="chart-container">
                        <div class="chart-title">Distribuição de Vulnerabilidades</div>
                        <div class="chart-content">
                            <canvas id="vulnerabilityChart"></canvas>
                        </div>
                    </div>
                    <div class="chart-container">
                        <div class="chart-title">Superfície de Ataque</div>
                        <div class="chart-content" style="text-align: center;">
                            <div>
                                <div style="font-size: 3em; margin-bottom: 15px; opacity: 0.8;">🎯</div>
                                <div style="font-size: 2.2em; font-weight: bold; color: var(--text-primary); margin-bottom: 20px;">
                                    {metrics['attack_surface_score']}/10
                                </div>
                                <div style="display: grid; gap: 12px; max-width: 250px; margin: 0 auto;">
                                    <div style="display: flex; justify-content: space-between; align-items: center; padding: 8px 15px; background: var(--bg-card); border-radius: 8px;">
                                        <span>🔐 Páginas Login</span>
                                        <span style="font-weight: bold; color: var(--warning-color);">{metrics['login_pages_found']}</span>
                                    </div>
                                    <div style="display: flex; justify-content: space-between; align-items: center; padding: 8px 15px; background: var(--bg-card); border-radius: 8px;">
                                        <span>⚙️ Painéis Admin</span>
                                        <span style="font-weight: bold; color: var(--danger-color);">{metrics['admin_panels_found']}</span>
                                    </div>
                                    <div style="display: flex; justify-content: space-between; align-items: center; padding: 8px 15px; background: var(--bg-card); border-radius: 8px;">
                                        <span>🔌 APIs</span>
                                        <span style="font-weight: bold; color: var(--info-color);">{metrics['api_endpoints_found']}</span>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="tech-stack">
                    {self._generate_tech_stack_visualization(metrics['top_technologies'])}
                </div>
            </div>
        </div>
        """

    def _generate_tech_stack_visualization(self, technologies: List[tuple]) -> str:
        """Gera visualização do stack tecnológico"""
        if not technologies:
            return "<div style='text-align: center; color: var(--text-secondary);'>Nenhuma tecnologia detectada</div>"
        
        tech_items = []
        for tech, count in technologies[:8]:  # Top 8 tecnologias
            tech_items.append(f"""
                <div class="tech-item">
                    <div class="tech-name">{tech.title()}</div>
                    <div class="tech-count">{count} hosts</div>
                </div>
            """)
        
        return "".join(tech_items)

    def _generate_attack_surface_analysis(self, metrics: Dict, subdomains: List[Dict]) -> str:
        """Gera análise da superfície de ataque"""
        # Análise por tipo de serviço
        web_services = len([s for s in subdomains if s.get('status', 0) in [200, 301, 302]])
        admin_services = len([s for s in subdomains if s.get('login_detected')])
        
        return f"""
        <div class="report-section fade-in-up">
            <div class="section-header">
                <div class="section-title">
                    <div class="section-title-icon">🎯</div>
                    <span>Análise da Superfície de Ataque</span>
                </div>
            </div>
            <div class="section-content">
                <div class="chart-grid">
                    <div class="chart-container">
                        <div class="chart-title">Serviços Expostos</div>
                        <div class="chart-content">
                            <div style="width: 100%; max-width: 300px;">
                                <div style="margin: 15px 0; display: flex; justify-content: space-between; align-items: center; padding: 12px 20px; background: var(--bg-card); border-radius: 12px; border: 1px solid rgba(255,255,255,0.1);">
                                    <span style="display: flex; align-items: center; gap: 10px;"><span>🌐</span> Serviços Web</span>
                                    <span style="background: var(--success-color); padding: 6px 16px; border-radius: 20px; color: white; font-weight: bold; font-size: 0.9em;">
                                        {web_services}
                                    </span>
                                </div>
                                <div style="margin: 15px 0; display: flex; justify-content: space-between; align-items: center; padding: 12px 20px; background: var(--bg-card); border-radius: 12px; border: 1px solid rgba(255,255,255,0.1);">
                                    <span style="display: flex; align-items: center; gap: 10px;"><span>🔐</span> Painéis Login</span>
                                    <span style="background: var(--warning-color); padding: 6px 16px; border-radius: 20px; color: white; font-weight: bold; font-size: 0.9em;">
                                        {admin_services}
                                    </span>
                                </div>
                                <div style="margin: 15px 0; display: flex; justify-content: space-between; align-items: center; padding: 12px 20px; background: var(--bg-card); border-radius: 12px; border: 1px solid rgba(255,255,255,0.1);">
                                    <span style="display: flex; align-items: center; gap: 10px;"><span>🔌</span> APIs</span>
                                    <span style="background: var(--info-color); padding: 6px 16px; border-radius: 20px; color: white; font-weight: bold; font-size: 0.9em;">
                                        {metrics['api_endpoints_found']}
                                    </span>
                                </div>
                                <div style="margin: 15px 0; display: flex; justify-content: space-between; align-items: center; padding: 12px 20px; background: var(--bg-card); border-radius: 12px; border: 1px solid rgba(255,255,255,0.1);">
                                    <span style="display: flex; align-items: center; gap: 10px;"><span>📁</span> Arquivos Sensíveis</span>
                                    <span style="background: var(--danger-color); padding: 6px 16px; border-radius: 20px; color: white; font-weight: bold; font-size: 0.9em;">
                                        {metrics['sensitive_files_found']}
                                    </span>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="chart-container">
                        <div class="chart-title">Score de Exposição</div>
                        <div class="chart-content" style="text-align: center;">
                            <div>
                                <div style="width: 120px; height: 120px; border-radius: 50%; 
                                            background: conic-gradient(var(--danger-color) 0deg {metrics['attack_surface_score'] * 36}deg, 
                                                                      rgba(255,255,255,0.15) {metrics['attack_surface_score'] * 36}deg 360deg);
                                            display: flex; align-items: center; justify-content: center; margin: 0 auto 20px; 
                                            color: white; font-weight: bold; font-size: 1.4em; 
                                            box-shadow: 0 8px 25px rgba(0,0,0,0.3);
                                            position: relative; overflow: hidden;">
                                    <div style="background: var(--chdevsec-dark); width: 80px; height: 80px; border-radius: 50%; 
                                                display: flex; flex-direction: column; align-items: center; justify-content: center;">
                                        <div style="font-size: 1.5em;">{metrics['attack_surface_score']}</div>
                                        <div style="font-size: 0.7em; opacity: 0.8;">/10</div>
                                    </div>
                                </div>
                                <div style="color: var(--text-secondary); font-size: 1em; font-weight: 500;">
                                    Superfície de Ataque
                                </div>
                                <div style="margin-top: 15px; padding: 10px 20px; background: var(--bg-card); border-radius: 12px; border: 1px solid rgba(255,255,255,0.1);">
                                    <div style="font-size: 0.85em; color: var(--text-secondary);">
                                        {"🔴 Alto Risco" if metrics['attack_surface_score'] >= 7 else "🟡 Médio Risco" if metrics['attack_surface_score'] >= 4 else "🟢 Baixo Risco"}
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        """

    def _generate_detailed_findings_section(self, findings: List[Dict]) -> str:
        """Gera seção detalhada de achados"""
        if not findings:
            return """
            <div class="report-section fade-in-up">
                <div class="section-header">
                    <div class="section-title">
                        <div class="section-title-icon">✅</div>
                        <span>Achados de Segurança - Nenhum encontrado</span>
                    </div>
                </div>
            </div>
            """
        
        # Ordena por risk score
        sorted_findings = sorted(findings, key=lambda x: x.get('risk_score', 0), reverse=True)
        
        # Gera linhas da tabela
        table_rows = []
        for finding in sorted_findings[:50]:  # Limita a 50 para performance
            risk_score = finding.get('risk_score', 0)
            risk_class = self._get_risk_class(risk_score)
            
            category = finding.get('category', 'unknown').replace('_', ' ').title()
            status_code = finding.get('status_code', 'N/A')
            status_class = f"status-{str(status_code)[0]}00" if str(status_code).isdigit() else ""
            
            payload_info = ""
            if finding.get('payload'):
                payload_info = f"<br><small style='color: var(--text-secondary);'><strong>Payload:</strong> <code>{finding['payload'][:80]}...</code></small>"
            
            vulns_info = ""
            if finding.get('vulnerabilities'):
                vulns = finding['vulnerabilities'][:3]  # Primeiras 3 vulnerabilidades
                vuln_badges = [f'<span class="vulnerability-badge vuln-high">{v}</span>' for v in vulns]
                vulns_info = "<br>" + "".join(vuln_badges)
                if len(finding['vulnerabilities']) > 3:
                    vulns_info += f'<span class="vulnerability-badge">+{len(finding["vulnerabilities"])-3}</span>'
            
            table_rows.append(f"""
                <tr class="{risk_class}">
                    <td>
                        <a href="{finding['url']}" target="_blank" class="external-link">
                            {finding['url']}
                        </a>
                        {payload_info}
                    </td>
                    <td>
                        <span class="status-badge {status_class}">{category}</span>
                    </td>
                    <td>
                        <span class="status-badge {status_class}">{status_code}</span>
                    </td>
                    <td>{finding.get('content_length', 0)} bytes</td>
                    <td>
                        {finding.get('tech', 'N/A')}
                        {vulns_info}
                    </td>
                    <td>
                        <span style="background: {'var(--danger-color)' if risk_score >= 7 else 'var(--warning-color)' if risk_score >= 4 else 'var(--success-color)'}; 
                                     color: white; padding: 5px 10px; border-radius: 12px; font-weight: bold;">
                            {risk_score}
                        </span>
                    </td>
                </tr>
            """)
        
        return f"""
        <div class="report-section fade-in-up">
            <div class="section-header">
                <div class="section-title">
                    <div class="section-title-icon">🔍</div>
                    <span>Achados Detalhados ({len(findings)})</span>
                </div>
            </div>
            <div class="section-content">
                <div style="overflow-x: auto;">
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>URL / Endpoint</th>
                                <th>Categoria</th>
                                <th>Status</th>
                                <th>Tamanho</th>
                                <th>Tecnologia / Vulnerabilidades</th>
                                <th>Risk Score</th>
                            </tr>
                        </thead>
                        <tbody>
                            {"".join(table_rows)}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        """

    def _generate_vulnerability_analysis(self, vulnerabilities: List[Dict]) -> str:
        """Gera análise detalhada de vulnerabilidades"""
        if not vulnerabilities:
            return """
            <div class="report-section fade-in-up">
                <div class="section-header">
                    <div class="section-title">
                        <div class="section-title-icon">✅</div>
                        <span>Análise de Vulnerabilidades - Nenhuma detectada</span>
                    </div>
                </div>
            </div>
            """
        
        # Agrupa por severidade
        vuln_by_severity = {}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'unknown')
            if severity not in vuln_by_severity:
                vuln_by_severity[severity] = []
            vuln_by_severity[severity].append(vuln)
        
        severity_sections = []
        severity_order = ['critical', 'high', 'medium', 'low', 'info']
        severity_icons = {'critical': '🚨', 'high': '⚠️', 'medium': '🔶', 'low': '🔸', 'info': 'ℹ️'}
        
        for severity in severity_order:
            if severity not in vuln_by_severity:
                continue
            
            vulns = vuln_by_severity[severity]
            icon = severity_icons.get(severity, '❓')
            
            vuln_rows = []
            for vuln in vulns:
                evidence = vuln.get('evidence', 'N/A')[:100] + '...' if len(str(vuln.get('evidence', ''))) > 100 else vuln.get('evidence', 'N/A')
                
                vuln_rows.append(f"""
                    <tr class="severity-{severity}">
                        <td><strong>{vuln.get('name', 'Unknown')}</strong></td>
                        <td><span class="vulnerability-badge vuln-{severity}">{vuln.get('category', 'unknown')}</span></td>
                        <td><span style="color: var(--text-primary); font-weight: bold;">{vuln.get('confidence', 0):.1f}</span></td>
                        <td style="max-width: 300px; word-wrap: break-word;">{vuln.get('description', 'N/A')}</td>
                        <td><code style="background: var(--bg-card); padding: 5px; border-radius: 5px; font-size: 0.8em;">{evidence}</code></td>
                        <td style="max-width: 250px; word-wrap: break-word;">{vuln.get('remediation', 'N/A')}</td>
                        <td>
                            <span style="background: var(--danger-color); color: white; padding: 5px 10px; border-radius: 12px; font-weight: bold;">
                                {vuln.get('risk_score', 0)}
                            </span>
                        </td>
                    </tr>
                """)
            
            severity_sections.append(f"""
                <div class="vulnerability-group" style="margin-bottom: 30px; border-radius: 15px; overflow: hidden; border: 1px solid rgba(255,255,255,0.1);">
                    <div style="background: var(--chdevsec-secondary); padding: 20px; border-bottom: 1px solid rgba(255,255,255,0.1);">
                        <h3 style="margin: 0; color: var(--text-primary); display: flex; align-items: center; gap: 10px;">
                            {icon} {severity.title()} ({len(vulns)})
                        </h3>
                    </div>
                    <div style="overflow-x: auto;">
                        <table class="data-table" style="margin: 0;">
                            <thead>
                                <tr>
                                    <th>Vulnerabilidade</th>
                                    <th>Categoria</th>
                                    <th>Confiança</th>
                                    <th>Descrição</th>
                                    <th>Evidência</th>
                                    <th>Remediação</th>
                                    <th>Score</th>
                                </tr>
                            </thead>
                            <tbody>
                                {"".join(vuln_rows)}
                            </tbody>
                        </table>
                    </div>
                </div>
            """)
        
        return f"""
        <div class="report-section fade-in-up">
            <div class="section-header">
                <div class="section-title">
                    <div class="section-title-icon">🛡️</div>
                    <span>Análise de Vulnerabilidades ({len(vulnerabilities)})</span>
                </div>
            </div>
            <div class="section-content">
                {"".join(severity_sections)}
            </div>
        </div>
        """

    def _generate_security_posture_section(self, metrics: Dict) -> str:
        """Gera seção de postura de segurança"""
        ssl_score = metrics['ssl_coverage_percent']
        attack_score = metrics['attack_surface_score']
        
        return f"""
        <div class="report-section fade-in-up">
            <div class="section-header">
                <div class="section-title">
                    <div class="section-title-icon">🔒</div>
                    <span>Postura de Segurança</span>
                </div>
            </div>
            <div class="section-content">
                <div class="chart-grid">
                    <div class="chart-container">
                        <div class="chart-title">Cobertura SSL/TLS</div>
                        <div class="chart-content" style="text-align: center;">
                            <div>
                                <div style="width: 130px; height: 130px; border-radius: 50%; 
                                            background: conic-gradient(var(--success-color) 0deg {ssl_score * 3.6}deg, 
                                                                      rgba(255,255,255,0.15) {ssl_score * 3.6}deg 360deg);
                                            display: flex; align-items: center; justify-content: center; margin: 0 auto 20px; 
                                            color: white; font-weight: bold; font-size: 1.6em;
                                            box-shadow: 0 8px 25px rgba(0,0,0,0.3);
                                            position: relative; overflow: hidden;">
                                    <div style="background: var(--chdevsec-dark); width: 90px; height: 90px; border-radius: 50%; 
                                                display: flex; flex-direction: column; align-items: center; justify-content: center;">
                                        <div style="font-size: 1.3em;">{ssl_score}%</div>
                                        <div style="font-size: 0.6em; opacity: 0.8;">SSL/TLS</div>
                                    </div>
                                </div>
                                <div style="color: var(--text-secondary); font-size: 0.95em; margin-bottom: 15px;">
                                    {metrics['ssl_enabled_hosts']} de {metrics['active_subdomains']} hosts
                                </div>
                                <div style="padding: 10px 20px; background: var(--bg-card); border-radius: 12px; border: 1px solid rgba(255,255,255,0.1);">
                                    <div style="font-size: 0.85em; color: var(--text-secondary);">
                                        {"🟢 Excelente" if ssl_score >= 90 else "🟡 Bom" if ssl_score >= 70 else "🔴 Precisa Melhorar"}
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="chart-container">
                        <div class="chart-title">Resumo de Segurança</div>
                        <div class="chart-content">
                            <div style="width: 100%; max-width: 300px;">
                                <div style="margin: 15px 0; display: flex; justify-content: space-between; align-items: center; padding: 12px 20px; background: var(--bg-card); border-radius: 12px; border: 1px solid rgba(255,255,255,0.1);">
                                    <span style="display: flex; align-items: center; gap: 10px;"><span>🛡️</span> Nível Risco</span>
                                    <span style="background: {'var(--danger-color)' if metrics['avg_risk_score'] >= 7 else 'var(--warning-color)' if metrics['avg_risk_score'] >= 4 else 'var(--success-color)'}; 
                                                 padding: 6px 16px; border-radius: 20px; color: white; font-weight: bold; font-size: 0.9em;">
                                        {metrics['overall_risk_level']}
                                    </span>
                                </div>
                                <div style="margin: 15px 0; display: flex; justify-content: space-between; align-items: center; padding: 12px 20px; background: var(--bg-card); border-radius: 12px; border: 1px solid rgba(255,255,255,0.1);">
                                    <span style="display: flex; align-items: center; gap: 10px;"><span>🔍</span> Achados Críticos</span>
                                    <span style="background: var(--danger-color); padding: 6px 16px; border-radius: 20px; color: white; font-weight: bold; font-size: 0.9em;">
                                        {metrics['high_risk_findings']}
                                    </span>
                                </div>
                            <div style="margin: 15px 0; display: flex; justify-content: space-between; align-items: center;">
                                <span>🌐 Tecnologias Únicas</span>
                                <span style="background: var(--info-color); padding: 5px 15px; border-radius: 15px; color: white; font-weight: bold;">
                                    {metrics['unique_technologies']}
                                </span>
                            </div>
                            <div style="margin: 15px 0; display: flex; justify-content: space-between; align-items: center;">
                                <span>⚡ Eficiência do Scan</span>
                                <span style="background: var(--success-color); padding: 5px 15px; border-radius: 15px; color: white; font-weight: bold;">
                                    {metrics['efficiency_score']}
                                </span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        """

    def _generate_threat_intelligence_section(self, dork_results: List[Dict]) -> str:
        """Gera seção de threat intelligence"""
        if not dork_results:
            return """
            <div class="report-section fade-in-up">
                <div class="section-header">
                    <div class="section-title">
                        <div class="section-title-icon">🔍</div>
                        <span>Threat Intelligence - Nenhum resultado encontrado</span>
                    </div>
                </div>
            </div>
            """
        
        dork_sections = []
        for result in dork_results:
            links_count = len(result.get('links', []))
            
            dork_sections.append(f"""
                <div style="background: var(--bg-card); border: 1px solid rgba(255,255,255,0.1); 
                           border-radius: 15px; padding: 20px; margin-bottom: 20px;">
                    <h4 style="color: var(--text-primary); margin-bottom: 15px; display: flex; align-items: center; gap: 10px;">
                        🔍 {result['category']}
                        <span style="background: var(--chdevsec-accent); color: white; padding: 2px 8px; 
                                     border-radius: 10px; font-size: 0.8em;">{links_count} resultados</span>
                    </h4>
                    <div style="background: var(--chdevsec-dark); color: var(--text-primary); 
                               padding: 15px; border-radius: 10px; margin: 15px 0; 
                               font-family: monospace; word-break: break-all; font-size: 0.9em;">
                        {result['dork']}
                    </div>
                    {f'<div style="color: var(--text-secondary); font-style: italic;">Pesquisa realizada - {links_count} resultados encontrados</div>' if links_count > 0 else '<div style="color: var(--text-secondary); font-style: italic;">Nenhum resultado público encontrado</div>'}
                </div>
            """)
        
        return f"""
        <div class="report-section fade-in-up">
            <div class="section-header">
                <div class="section-title">
                    <div class="section-title-icon">🔍</div>
                    <span>Threat Intelligence ({len(dork_results)})</span>
                </div>
            </div>
            <div class="section-content">
                {"".join(dork_sections)}
            </div>
        </div>
        """

    def _generate_recommendations_matrix(self, vulnerabilities: List[Dict], findings: List[Dict], metrics: Dict) -> str:
        """Gera matriz de recomendações priorizadas"""
        recommendations = []
        
        # Recomendações baseadas em vulnerabilidades críticas
        critical_vulns = [v for v in vulnerabilities if v.get('severity') == 'critical']
        if critical_vulns:
            recommendations.append({
                'priority': 'CRÍTICA',
                'icon': '🚨',
                'title': 'Correção Imediata de Vulnerabilidades Críticas',
                'description': f'{len(critical_vulns)} vulnerabilidades críticas requerem atenção imediata',
                'timeline': '24-48 horas',
                'impact': 'Muito Alto'
            })
        
        # Recomendações baseadas em superfície de ataque
        if metrics['attack_surface_score'] >= 7:
            recommendations.append({
                'priority': 'ALTA',
                'icon': '🛡️',
                'title': 'Redução da Superfície de Ataque',
                'description': 'Múltiplos pontos de entrada detectados, implementar controles de acesso',
                'timeline': '1-2 semanas',
                'impact': 'Alto'
            })
        
        # Recomendações baseadas em SSL
        if metrics['ssl_coverage_percent'] < 80:
            recommendations.append({
                'priority': 'MÉDIA',
                'icon': '🔒',
                'title': 'Melhoria da Cobertura SSL/TLS',
                'description': f'Apenas {metrics["ssl_coverage_percent"]}% dos hosts possuem SSL configurado',
                'timeline': '2-4 semanas',
                'impact': 'Médio'
            })
        
        # Recomendações gerais
        recommendations.extend([
            {
                'priority': 'ALTA',
                'icon': '🔍',
                'title': 'Implementação de Monitoramento Contínuo',
                'description': 'Estabelecer scanning automatizado e alertas de segurança',
                'timeline': '2-3 semanas',
                'impact': 'Alto'
            },
            {
                'priority': 'MÉDIA',
                'icon': '👥',
                'title': 'Treinamento da Equipe',
                'description': 'Capacitar equipe técnica em práticas de segurança',
                'timeline': '1 mês',
                'impact': 'Médio'
            },
            {
                'priority': 'BAIXA',
                'icon': '📋',
                'title': 'Documentação de Segurança',
                'description': 'Criar políticas e procedimentos de segurança',
                'timeline': '6-8 semanas',
                'impact': 'Baixo'
            }
        ])
        
        rec_items = []
        for rec in recommendations:
            priority_color = {
                'CRÍTICA': 'var(--danger-color)',
                'ALTA': 'var(--warning-color)', 
                'MÉDIA': 'var(--info-color)',
                'BAIXA': 'var(--success-color)'
            }.get(rec['priority'], 'var(--chdevsec-accent)')
            
            rec_items.append(f"""
                <div style="background: var(--bg-card); border: 1px solid rgba(255,255,255,0.1); 
                           border-left: 4px solid {priority_color}; border-radius: 15px; 
                           padding: 25px; margin-bottom: 20px; transition: all 0.3s ease;">
                    <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 15px;">
                        <div style="display: flex; align-items: center; gap: 15px;">
                            <div style="font-size: 2em;">{rec['icon']}</div>
                            <div>
                                <h4 style="color: var(--text-primary); margin-bottom: 5px;">
                                    {rec['title']}
                                </h4>
                                <span style="background: {priority_color}; color: white; padding: 4px 12px; 
                                             border-radius: 15px; font-size: 0.8em; font-weight: bold;">
                                    {rec['priority']}
                                </span>
                            </div>
                        </div>
                        <div style="text-align: right; color: var(--text-secondary); font-size: 0.9em;">
                            <div><strong>Timeline:</strong> {rec['timeline']}</div>
                            <div><strong>Impacto:</strong> {rec['impact']}</div>
                        </div>
                    </div>
                    <p style="color: var(--text-secondary); line-height: 1.6;">
                        {rec['description']}
                    </p>
                </div>
            """)
        
        return f"""
        <div class="report-section fade-in-up">
            <div class="section-header">
                <div class="section-title">
                    <div class="section-title-icon">💡</div>
                    <span>Matriz de Recomendações Priorizadas</span>
                </div>
            </div>
            <div class="section-content">
                {"".join(rec_items)}
            </div>
        </div>
        """

    def _generate_technical_appendix(self, scan_data: Dict) -> str:
        """Gera apêndice técnico"""
        return f"""
        <div class="report-section fade-in-up">
            <div class="section-header">
                <div class="section-title">
                    <div class="section-title-icon">📋</div>
                    <span>Apêndice Técnico</span>
                </div>
            </div>
            <div class="section-content">
                <div style="background: var(--bg-card); padding: 25px; border-radius: 15px; border: 1px solid rgba(255,255,255,0.1);">
                    <h4 style="color: var(--text-primary); margin-bottom: 20px;">Metodologia e Ferramentas</h4>
                    <div style="color: var(--text-secondary); line-height: 1.6;">
                        <p><strong>🔍 Descoberta de Subdomínios:</strong> Múltiplas fontes incluindo DNS brute force, Certificate Transparency logs, e APIs especializadas.</p>
                        <p><strong>🎯 Fuzzing Inteligente:</strong> Wordlists específicas por tecnologia e testes de injeção adaptivos.</p>
                        <p><strong>🛡️ Análise de Vulnerabilidades:</strong> Engine proprietário com mais de 50 patterns de detecção.</p>
                        <p><strong>📊 Scoring de Risco:</strong> Algoritmo baseado em CVSS 3.1 adaptado para reconhecimento web.</p>
                    </div>
                </div>
                
                <div style="background: var(--bg-card); padding: 25px; border-radius: 15px; border: 1px solid rgba(255,255,255,0.1); margin-top: 20px;">
                    <h4 style="color: var(--text-primary); margin-bottom: 20px;">Estatísticas do Scan</h4>
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px;">
                        <div>
                            <div style="color: var(--text-secondary);">Duração Total</div>
                            <div style="color: var(--text-primary); font-weight: bold; font-size: 1.2em;">
                                {scan_data.get('scan_stats', {}).get('scan_duration_minutes', 0):.1f} minutos
                            </div>
                        </div>
                        <div>
                            <div style="color: var(--text-secondary);">Requests Realizados</div>
                            <div style="color: var(--text-primary); font-weight: bold; font-size: 1.2em;">
                                ~{len(scan_data.get('findings', [])) * 3} requests
                            </div>
                        </div>
                        <div>
                            <div style="color: var(--text-secondary);">Dados Processados</div>
                            <div style="color: var(--text-primary); font-weight: bold; font-size: 1.2em;">
                                ~{sum(f.get('content_length', 0) for f in scan_data.get('findings', [])) / 1024:.0f} KB
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        """

    def _generate_chdevsec_footer(self) -> str:
        """Gera rodapé profissional CHDEVSEC"""
        return f"""
        <div class="chdevsec-footer">
            <div class="footer-logo">CHDEVSEC</div>
            <div class="footer-content">
                <p><strong>Relatório gerado por Recon Pro v2.0</strong></p>
                <p>Pentester Caio | Especialista em Segurança Cibernética</p>
                <p>Data de geração: {datetime.now().strftime('%d/%m/%Y às %H:%M:%S')}</p>
                
                <div class="disclaimer">
                    <strong>⚠️ DISCLAIMER IMPORTANTE:</strong><br>
                    Este relatório é destinado exclusivamente para testes autorizados em sistemas próprios ou com autorização expressa. 
                    O uso inadequado das informações contidas neste documento pode constituir atividade ilegal. 
                    O CHDEVSEC não se responsabiliza pelo uso indevido das informações fornecidas.
                </div>
                
                <div style="margin-top: 25px; padding-top: 20px; border-top: 1px solid rgba(255,255,255,0.1);">
                    <p style="font-size: 0.9em; color: var(--text-secondary);">
                        🔒 Este relatório contém informações sensíveis de segurança - Mantenha confidencial<br>
                        📧 Para consultoria em segurança, entre em contato: contato@chdevsec.com
                    </p>
                </div>
            </div>
        </div>
        """

    def _get_executive_styles(self) -> str:
        """Retorna estilos CSS para relatório executivo"""
        return self._get_chdevsec_styles().replace('.main-container', '.executive-container')

    def _get_javascript_libs(self) -> str:
        """Retorna bibliotecas JavaScript"""
        return """
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        """

    def _get_advanced_javascript(self, metrics: Dict) -> str:
        """JavaScript avançado com gráficos interativos"""
        vuln_data = metrics.get('vulnerabilities_by_severity', {})
        category_data = metrics.get('findings_by_category', {})
        
        # Converte dados Python para formato JavaScript válido
        vuln_labels = json.dumps(list(vuln_data.keys()))
        vuln_values = json.dumps(list(vuln_data.values()))
        
        return f"""
        <script>
            // Aguarda o DOM estar carregado
            document.addEventListener('DOMContentLoaded', function() {{
                
                // Configuração global dos gráficos
                Chart.defaults.color = '#ffffff';
                Chart.defaults.borderColor = 'rgba(255, 255, 255, 0.1)';
                Chart.defaults.backgroundColor = 'rgba(255, 255, 255, 0.05)';
                
                // Gráfico de Vulnerabilidades - Dados convertidos corretamente
                const vulnCtx = document.getElementById('vulnerabilityChart');
                if (vulnCtx) {{
                    // Verifica se há dados para mostrar
                    const vulnLabels = {vuln_labels};
                    const vulnValues = {vuln_values};
                    
                    if (vulnLabels.length > 0 && vulnValues.some(v => v > 0)) {{
                        new Chart(vulnCtx, {{
                            type: 'doughnut',
                            data: {{
                                labels: vulnLabels,
                                datasets: [{{
                                    data: vulnValues,
                                    backgroundColor: [
                                        '#f44336', '#ff9800', '#2196f3', '#4caf50', '#9e9e9e'
                                    ],
                                    borderWidth: 3,
                                    borderColor: 'rgba(255, 255, 255, 0.2)',
                                    hoverBorderWidth: 4,
                                    hoverBorderColor: '#ffffff'
                                }}]
                            }},
                            options: {{
                                responsive: true,
                                maintainAspectRatio: false,
                                layout: {{
                                    padding: 20
                                }},
                                plugins: {{
                                    legend: {{ 
                                        position: 'bottom',
                                        labels: {{
                                            padding: 20,
                                            usePointStyle: true,
                                            color: '#ffffff',
                                            font: {{
                                                size: 12,
                                                weight: 'bold'
                                            }}
                                        }}
                                    }},
                                    tooltip: {{
                                        backgroundColor: 'rgba(26, 35, 126, 0.95)',
                                        titleColor: '#ffffff',
                                        bodyColor: '#e8eaf6',
                                        borderColor: 'rgba(255, 255, 255, 0.2)',
                                        borderWidth: 2,
                                        cornerRadius: 8,
                                        titleFont: {{
                                            size: 14,
                                            weight: 'bold'
                                        }},
                                        bodyFont: {{
                                            size: 12
                                        }}
                                    }}
                                }},
                                elements: {{
                                    arc: {{
                                        borderJoinStyle: 'round'
                                    }}
                                }}
                            }}
                        }});
                    }} else {{
                        // Mostra mensagem quando não há dados
                        vulnCtx.parentElement.innerHTML = `
                            <div class="chart-title">Distribuição de Vulnerabilidades</div>
                            <div style="display: flex; align-items: center; justify-content: center; height: 200px; flex-direction: column; text-align: center;">
                                <div style="font-size: 3em; margin-bottom: 15px; opacity: 0.5;">📊</div>
                                <div style="color: var(--text-secondary); font-size: 1.1em;">Nenhuma vulnerabilidade detectada</div>
                                <div style="color: var(--success-color); font-size: 0.9em; margin-top: 10px;">✅ Excelente postura de segurança!</div>
                            </div>
                        `;
                    }}
                }}
                
                // Animações simples e leves
                const observer = new IntersectionObserver((entries) => {{
                    entries.forEach(entry => {{
                        if (entry.isIntersecting) {{
                            entry.target.style.opacity = '1';
                        }}
                    }});
                }}, {{ threshold: 0.1 }});
                
                // Aplica fade-in simples
                document.querySelectorAll('.report-section, .dashboard-card').forEach(el => {{
                    el.style.opacity = '0.8';
                    el.style.transition = 'opacity 0.3s ease';
                    observer.observe(el);
                }});
                
            }});
        </script>
        """

    def _generate_executive_header(self, domain: str, metrics: Dict) -> str:
        """Gera cabeçalho para relatório executivo"""
        risk_level = metrics.get('overall_risk_level', 'BAIXO')
        risk_class = f"risk-{risk_level.lower()}"
        
        return f"""
        <div class="technical-header fade-in-up">
            <div class="header-content">
                <div class="header-info">
                    <h1>📊 Relatório Executivo de Cibersegurança</h1>
                    <div class="domain-badge">{domain}</div>
                    <div class="scan-meta">
                        <div class="meta-item">
                            <span>📅</span>
                            <span>Análise: {metrics['scan_date']}</span>
                        </div>
                        <div class="meta-item">
                            <span>💼</span>
                            <span>Nível Executivo</span>
                        </div>
                        <div class="meta-item">
                            <span>🎯</span>
                            <span>Foco: Business Impact</span>
                        </div>
                    </div>
                </div>
                <div class="risk-indicator">
                    <div class="risk-score-circle {risk_class}">
                        <div>{metrics['avg_risk_score']}</div>
                        <small>/10</small>
                    </div>
                    <div class="risk-label">RISCO {risk_level}</div>
                </div>
            </div>
        </div>
        """

    def _generate_executive_summary_dashboard(self, metrics: Dict) -> str:
        """Dashboard executivo simplificado"""
        return f"""
        <div class="executive-dashboard">
            <div class="dashboard-card card-info fade-in-up">
                <div class="card-header">
                    <div class="card-icon" style="background: var(--info-color)">🌐</div>
                    <div class="card-title">Exposição Digital</div>
                </div>
                <div class="card-value">{metrics['total_subdomains']}</div>
                <div class="card-subtitle">Pontos de entrada descobertos</div>
            </div>
            
            <div class="dashboard-card card-critical fade-in-up">
                <div class="card-header">
                    <div class="card-icon" style="background: var(--danger-color)">🚨</div>
                    <div class="card-title">Riscos Críticos</div>
                </div>
                <div class="card-value">{metrics['vulnerabilities_by_severity'].get('critical', 0)}</div>
                <div class="card-subtitle">Requerem ação imediata</div>
            </div>
            
            <div class="dashboard-card card-warning fade-in-up">
                <div class="card-header">
                    <div class="card-icon" style="background: var(--warning-color)">⚠️</div>
                    <div class="card-title">Superfície de Ataque</div>
                </div>
                <div class="card-value">{metrics['attack_surface_score']}/10</div>
                <div class="card-subtitle">Score de exposição</div>
            </div>
            
            <div class="dashboard-card card-success fade-in-up">
                <div class="card-header">
                    <div class="card-icon" style="background: var(--success-color)">🛡️</div>
                    <div class="card-title">Postura SSL</div>
                </div>
                <div class="card-value">{metrics['ssl_coverage_percent']}%</div>
                <div class="card-subtitle">Cobertura de criptografia</div>
            </div>
        </div>
        """

    def _generate_business_impact_analysis(self, metrics: Dict, vulnerabilities: List[Dict]) -> str:
        """Análise de impacto no negócio"""
        critical_vulns = len([v for v in vulnerabilities if v.get('severity') == 'critical'])
        high_vulns = len([v for v in vulnerabilities if v.get('severity') == 'high'])
        
        business_risk = "BAIXO"
        if critical_vulns > 0:
            business_risk = "CRÍTICO"
        elif high_vulns > 2:
            business_risk = "ALTO"
        elif metrics['attack_surface_score'] > 6:
            business_risk = "MÉDIO"
        
        return f"""
        <div class="report-section fade-in-up">
            <div class="section-header">
                <div class="section-title">
                    <div class="section-title-icon">💼</div>
                    <span>Análise de Impacto no Negócio</span>
                </div>
            </div>
            <div class="section-content">
                <div style="background: var(--bg-card); padding: 30px; border-radius: 15px; border: 1px solid rgba(255,255,255,0.1); margin-bottom: 25px;">
                    <h3 style="color: var(--text-primary); margin-bottom: 20px; display: flex; align-items: center; gap: 15px;">
                        🎯 Risco para o Negócio: 
                        <span style="background: {'var(--danger-color)' if business_risk == 'CRÍTICO' else 'var(--warning-color)' if business_risk == 'ALTO' else 'var(--success-color)'}; 
                                     color: white; padding: 8px 20px; border-radius: 25px; font-size: 0.9em;">
                            {business_risk}
                        </span>
                    </h3>
                    
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-top: 25px;">
                        <div style="background: rgba(244, 67, 54, 0.1); padding: 20px; border-radius: 12px; border-left: 4px solid var(--danger-color);">
                            <h4 style="color: var(--text-primary); margin-bottom: 10px;">💸 Impacto Financeiro</h4>
                            <p style="color: var(--text-secondary); font-size: 0.9em;">
                                {'Risco de perda financeira significativa devido a vulnerabilidades críticas' if critical_vulns > 0 else 
                                 'Risco financeiro moderado, monitoramento necessário' if high_vulns > 0 else
                                 'Risco financeiro controlado, manter vigilância'}
                            </p>
                        </div>
                        
                        <div style="background: rgba(255, 152, 0, 0.1); padding: 20px; border-radius: 12px; border-left: 4px solid var(--warning-color);">
                            <h4 style="color: var(--text-primary); margin-bottom: 10px;">🏢 Reputação Corporativa</h4>
                            <p style="color: var(--text-secondary); font-size: 0.9em;">
                                {'Alta exposição pode comprometer a confiança dos clientes' if metrics['attack_surface_score'] > 7 else
                                 'Exposição moderada requer atenção para manter confiança' if metrics['attack_surface_score'] > 4 else
                                 'Postura de segurança adequada para manter reputação'}
                            </p>
                        </div>
                        
                        <div style="background: rgba(33, 150, 243, 0.1); padding: 20px; border-radius: 12px; border-left: 4px solid var(--info-color);">
                            <h4 style="color: var(--text-primary); margin-bottom: 10px;">⚖️ Conformidade Regulatória</h4>
                            <p style="color: var(--text-secondary); font-size: 0.9em;">
                                {'Possível não conformidade com LGPD/GDPR devido às exposições' if critical_vulns > 0 or metrics['ssl_coverage_percent'] < 70 else
                                 'Conformidade parcial, melhorias necessárias' if metrics['ssl_coverage_percent'] < 90 else
                                 'Boa postura para conformidade regulatória'}
                            </p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        """

    def _generate_risk_matrix_section(self, metrics: Dict) -> str:
        """Gera matriz de risco executiva"""
        return f"""
        <div class="report-section fade-in-up">
            <div class="section-header">
                <div class="section-title">
                    <div class="section-title-icon">📊</div>
                    <span>Matriz de Risco Executiva</span>
                </div>
            </div>
            <div class="section-content">
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 25px;">
                    <div style="background: var(--bg-card); padding: 25px; border-radius: 15px; border: 1px solid rgba(255,255,255,0.1);">
                        <h4 style="color: var(--text-primary); margin-bottom: 20px; text-align: center;">Probabilidade vs Impacto</h4>
                        <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; text-align: center;">
                            <div style="background: var(--success-color); padding: 15px; border-radius: 8px; color: white; font-weight: bold;">BAIXO</div>
                            <div style="background: var(--warning-color); padding: 15px; border-radius: 8px; color: white; font-weight: bold;">MÉDIO</div>
                            <div style="background: var(--danger-color); padding: 15px; border-radius: 8px; color: white; font-weight: bold;">ALTO</div>
                        </div>
                        <div style="margin-top: 15px; text-align: center; color: var(--text-secondary);">
                            Seu domínio está na categoria: 
                            <strong style="color: var(--text-primary);">{metrics.get('overall_risk_level', 'BAIXO')}</strong>
                        </div>
                    </div>
                    
                    <div style="background: var(--bg-card); padding: 25px; border-radius: 15px; border: 1px solid rgba(255,255,255,0.1);">
                        <h4 style="color: var(--text-primary); margin-bottom: 20px; text-align: center;">Tempo para Remediação</h4>
                        <div style="space-y: 10px;">
                            <div style="display: flex; justify-content: space-between; align-items: center; padding: 10px; background: rgba(244, 67, 54, 0.2); border-radius: 8px; margin-bottom: 10px;">
                                <span>🚨 Crítico</span>
                                <span style="font-weight: bold;">24-48h</span>
                            </div>
                            <div style="display: flex; justify-content: space-between; align-items: center; padding: 10px; background: rgba(255, 152, 0, 0.2); border-radius: 8px; margin-bottom: 10px;">
                                <span>⚠️ Alto</span>
                                <span style="font-weight: bold;">1-2 semanas</span>
                            </div>
                            <div style="display: flex; justify-content: space-between; align-items: center; padding: 10px; background: rgba(33, 150, 243, 0.2); border-radius: 8px;">
                                <span>🔸 Médio/Baixo</span>
                                <span style="font-weight: bold;">1-2 meses</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        """

    def _generate_executive_recommendations(self, vulnerabilities: List[Dict], metrics: Dict) -> str:
        """Recomendações executivas focadas em ROI"""
        critical_vulns = len([v for v in vulnerabilities if v.get('severity') == 'critical'])
        
        recommendations = []
        
        if critical_vulns > 0:
            recommendations.append({
                'priority': 'IMEDIATA',
                'investment': 'Baixo',
                'roi': 'Muito Alto',
                'action': 'Correção de Vulnerabilidades Críticas',
                'description': 'Investimento mínimo com retorno máximo em segurança'
            })
        
        if metrics['ssl_coverage_percent'] < 90:
            recommendations.append({
                'priority': 'CURTO PRAZO',
                'investment': 'Baixo',
                'roi': 'Alto',
                'action': 'Implementação SSL/TLS Completa',
                'description': 'Melhora conformidade e confiança do cliente'
            })
        
        if metrics['attack_surface_score'] > 6:
            recommendations.append({
                'priority': 'MÉDIO PRAZO',
                'investment': 'Médio',
                'roi': 'Alto',
                'action': 'WAF e Controles de Acesso',
                'description': 'Reduz significativamente a superfície de ataque'
            })
        
        recommendations.append({
            'priority': 'LONGO PRAZO',
            'investment': 'Alto',
            'roi': 'Muito Alto',
            'action': 'SOC e Monitoramento 24/7',
            'description': 'Detecção proativa de ameaças'
        })
        
        rec_html = []
        for rec in recommendations:
            priority_color = {
                'IMEDIATA': 'var(--danger-color)',
                'CURTO PRAZO': 'var(--warning-color)',
                'MÉDIO PRAZO': 'var(--info-color)',
                'LONGO PRAZO': 'var(--success-color)'
            }.get(rec['priority'])
            
            rec_html.append(f"""
                <div style="background: var(--bg-card); border-left: 4px solid {priority_color}; 
                           padding: 25px; border-radius: 15px; margin-bottom: 20px;">
                    <div style="display: flex; justify-content: between; align-items: center; margin-bottom: 15px;">
                        <h4 style="color: var(--text-primary);">{rec['action']}</h4>
                        <div style="display: flex; gap: 10px;">
                            <span style="background: {priority_color}; color: white; padding: 4px 12px; border-radius: 12px; font-size: 0.8em;">
                                {rec['priority']}
                            </span>
                        </div>
                    </div>
                    <p style="color: var(--text-secondary); margin-bottom: 15px;">{rec['description']}</p>
                    <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 15px;">
                        <div>
                            <span style="color: var(--text-secondary);">💰 Investimento:</span>
                            <span style="color: var(--text-primary); font-weight: bold;"> {rec['investment']}</span>
                        </div>
                        <div>
                            <span style="color: var(--text-secondary);">📈 ROI:</span>
                            <span style="color: var(--text-primary); font-weight: bold;"> {rec['roi']}</span>
                        </div>
                    </div>
                </div>
            """)
        
        return f"""
        <div class="report-section fade-in-up">
            <div class="section-header">
                <div class="section-title">
                    <div class="section-title-icon">💡</div>
                    <span>Recomendações Estratégicas</span>
                </div>
            </div>
            <div class="section-content">
                {"".join(rec_html)}
            </div>
        </div>
        """

    def _generate_budget_impact_section(self, metrics: Dict) -> str:
        """Seção de impacto orçamentário"""
        return f"""
        <div class="report-section fade-in-up">
            <div class="section-header">
                <div class="section-title">
                    <div class="section-title-icon">💰</div>
                    <span>Impacto Orçamentário</span>
                </div>
            </div>
            <div class="section-content">
                <div style="background: var(--bg-card); padding: 25px; border-radius: 15px; border: 1px solid rgba(255,255,255,0.1);">
                    <h4 style="color: var(--text-primary); margin-bottom: 20px;">Estimativa de Investimento em Segurança</h4>
                    
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 25px;">
                        <div style="text-align: center; padding: 20px; background: rgba(76, 175, 80, 0.1); border-radius: 12px;">
                            <div style="font-size: 2em;">🛡️</div>
                            <div style="color: var(--text-primary); font-weight: bold; font-size: 1.2em;">R$ 5-15k</div>
                            <div style="color: var(--text-secondary); font-size: 0.9em;">Correções Básicas</div>
                        </div>
                        
                        <div style="text-align: center; padding: 20px; background: rgba(33, 150, 243, 0.1); border-radius: 12px;">
                            <div style="font-size: 2em;">🔒</div>
                            <div style="color: var(--text-primary); font-weight: bold; font-size: 1.2em;">R$ 20-50k</div>
                            <div style="color: var(--text-secondary); font-size: 0.9em;">WAF + Monitoramento</div>
                        </div>
                        
                        <div style="text-align: center; padding: 20px; background: rgba(255, 152, 0, 0.1); border-radius: 12px;">
                            <div style="font-size: 2em;">🏢</div>
                            <div style="color: var(--text-primary); font-weight: bold; font-size: 1.2em;">R$ 80-200k</div>
                            <div style="color: var(--text-secondary); font-size: 0.9em;">SOC Completo</div>
                        </div>
                    </div>
                    
                    <div style="background: rgba(244, 67, 54, 0.1); padding: 20px; border-radius: 12px; border-left: 4px solid var(--danger-color);">
                        <h5 style="color: var(--text-primary); margin-bottom: 10px;">💡 Retorno do Investimento</h5>
                        <p style="color: var(--text-secondary); font-size: 0.9em;">
                            Cada R$ 1 investido em segurança cibernética economiza em média R$ 4-7 em custos de incidentes.
                            Com {metrics['vulnerabilities_by_severity'].get('critical', 0)} vulnerabilidades críticas identificadas, 
                            o ROI do investimento em correções é imediato.
                        </p>
                    </div>
                </div>
            </div>
        </div>
        """

    def _generate_next_steps_timeline(self, metrics: Dict) -> str:
        """Timeline de próximos passos"""
        return f"""
        <div class="report-section fade-in-up">
            <div class="section-header">
                <div class="section-title">
                    <div class="section-title-icon">📅</div>
                    <span>Roadmap de Implementação</span>
                </div>
            </div>
            <div class="section-content">
                <div style="position: relative;">
                    <div style="position: absolute; left: 50px; top: 0; bottom: 0; width: 2px; background: var(--chdevsec-accent);"></div>
                    
                    <div style="display: flex; align-items: center; margin-bottom: 30px; position: relative;">
                        <div style="width: 40px; height: 40px; background: var(--danger-color); border-radius: 50%; 
                                   display: flex; align-items: center; justify-content: center; color: white; font-weight: bold; z-index: 1;">1</div>
                        <div style="margin-left: 30px; background: var(--bg-card); padding: 20px; border-radius: 12px; flex: 1;">
                            <h5 style="color: var(--text-primary);">Primeiras 48 horas</h5>
                            <p style="color: var(--text-secondary); margin: 0;">Correção de vulnerabilidades críticas e implementação de patches de segurança</p>
                        </div>
                    </div>
                    
                    <div style="display: flex; align-items: center; margin-bottom: 30px; position: relative;">
                        <div style="width: 40px; height: 40px; background: var(--warning-color); border-radius: 50%; 
                                   display: flex; align-items: center; justify-content: center; color: white; font-weight: bold; z-index: 1;">2</div>
                        <div style="margin-left: 30px; background: var(--bg-card); padding: 20px; border-radius: 12px; flex: 1;">
                            <h5 style="color: var(--text-primary);">Primeira semana</h5>
                            <p style="color: var(--text-secondary); margin: 0;">Implementação de SSL/TLS completo e hardening básico dos serviços</p>
                        </div>
                    </div>
                    
                    <div style="display: flex; align-items: center; margin-bottom: 30px; position: relative;">
                        <div style="width: 40px; height: 40px; background: var(--info-color); border-radius: 50%; 
                                   display: flex; align-items: center; justify-content: center; color: white; font-weight: bold; z-index: 1;">3</div>
                        <div style="margin-left: 30px; background: var(--bg-card); padding: 20px; border-radius: 12px; flex: 1;">
                            <h5 style="color: var(--text-primary);">Primeiro mês</h5>
                            <p style="color: var(--text-secondary); margin: 0;">Implementação de WAF, controles de acesso e políticas de segurança</p>
                        </div>
                    </div>
                    
                    <div style="display: flex; align-items: center; position: relative;">
                        <div style="width: 40px; height: 40px; background: var(--success-color); border-radius: 50%; 
                                   display: flex; align-items: center; justify-content: center; color: white; font-weight: bold; z-index: 1;">4</div>
                        <div style="margin-left: 30px; background: var(--bg-card); padding: 20px; border-radius: 12px; flex: 1;">
                            <h5 style="color: var(--text-primary);">Trimestre</h5>
                            <p style="color: var(--text-secondary); margin: 0;">SOC, monitoramento 24/7 e programa de conscientização</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        """

    def _generate_executive_footer(self) -> str:
        """Rodapé executivo"""
        return f"""
        <div class="chdevsec-footer">
            <div class="footer-logo">CHDEVSEC</div>
            <div class="footer-content">
                <p><strong>Relatório Executivo de Cibersegurança</strong></p>
                <p>Consultoria Especializada em Segurança Digital</p>
                <p>Pentester Caio | CHDEVSEC Security Solutions</p>
                <p>Gerado em: {datetime.now().strftime('%d/%m/%Y às %H:%M:%S')}</p>
                
                <div style="margin-top: 25px; padding: 20px; background: rgba(33, 150, 243, 0.1); border-radius: 12px; border-left: 4px solid var(--info-color);">
                    <h5 style="color: var(--text-primary); margin-bottom: 10px;">📞 Próximos Passos</h5>
                    <p style="color: var(--text-secondary); margin: 0;">
                        Para implementar as recomendações deste relatório ou obter consultoria especializada,
                        entre em contato conosco para agendar uma reunião estratégica.
                    </p>
                </div>
                
                <div class="disclaimer">
                    <strong>⚠️ CONFIDENCIAL:</strong><br>
                    Este relatório executivo contém informações estratégicas de segurança. 
                    Distribuição restrita à alta gestão e equipes autorizadas.
                </div>
            </div>
        </div>
        """

    def _generate_executive_javascript(self, metrics: Dict) -> str:
        """JavaScript para relatório executivo"""
        return f"""
        <script>
            // Animações suaves para o relatório executivo
            const observerOptions = {{
                threshold: 0.1,
                rootMargin: '0px 0px -50px 0px'
            }};
            
            const observer = new IntersectionObserver((entries) => {{
                entries.forEach(entry => {{
                    if (entry.isIntersecting) {{
                        entry.target.style.opacity = '1';
                        entry.target.style.transform = 'translateY(0)';
                    }}
                }});
            }}, observerOptions);
            
            // Aplica animações a todos os elementos
            document.querySelectorAll('.report-section, .dashboard-card').forEach(el => {{
                el.style.opacity = '0';
                el.style.transform = 'translateY(30px)';
                el.style.transition = 'all 0.6s ease-out';
                observer.observe(el);
            }});
            
            // Efeitos especiais para o risk score
            const riskCircle = document.querySelector('.risk-score-circle');
            if (riskCircle) {{
                riskCircle.addEventListener('mouseenter', () => {{
                    riskCircle.style.transform = 'scale(1.1) rotate(5deg)';
                }});
                
                riskCircle.addEventListener('mouseleave', () => {{
                    riskCircle.style.transform = 'scale(1) rotate(0deg)';
                }});
            }}
        </script>
        """ 