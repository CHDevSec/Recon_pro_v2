# 🔍 Recon Pro v2.0

<div align="center">

![Version](https://img.shields.io/badge/version-2.0.0-blue)
![Python](https://img.shields.io/badge/python-3.8+-green)
![License](https://img.shields.io/badge/license-MIT-orange)
![Status](https://img.shields.io/badge/status-Professional-success)

**Ferramenta Profissional de Reconhecimento Web**

*Developed by Pentester Caio | CHDEVSEC*

</div>

## 📋 Índice

- [Visão Geral](#-visão-geral)
- [Características](#-características)
- [Arquitetura Modular](#-arquitetura-modular)
- [Instalação](#-instalação)
- [Configuração](#-configuração)
- [Uso](#-uso)
- [Exemplos](#-exemplos)
- [Relatórios](#-relatórios)
- [APIs Suportadas](#-apis-suportadas)
- [Contribuição](#-contribuição)
- [Disclaimer](#-disclaimer)

## 🎯 Visão Geral

O **Recon Pro v2.0** é uma ferramenta profissional de reconhecimento web completamente redesenhada com arquitetura modular, focada em descoberta de assets, fuzzing avançado, detecção de vulnerabilidades e geração de relatórios executivos.

### 🚀 Principais Melhorias v2.0

- **Arquitetura Modular**: Código organizado em módulos especializados
- **Descoberta Avançada**: Múltiplas fontes de intelligence (APIs, CT logs, ferramentas externas)
- **Fuzzing Inteligente**: Payloads específicos por tecnologia
- **Engine de Vulnerabilidades**: Detecção automática de 15+ tipos de vulnerabilidades
- **Relatórios Profissionais**: HTML, JSON, CSV e sumário executivo
- **Configuração Flexível**: Sistema de configuração JSON completo

## ✨ Características

### 🔍 Descoberta de Assets
- **Ferramentas Externas**: Subfinder, Assetfinder, Amass, Findomain, Chaos
- **APIs Premium**: SecurityTrails, Shodan, VirusTotal, Censys
- **Certificate Transparency**: crt.sh, Certspotter
- **DNS Bruteforce**: Wordlists otimizadas + DNS inteligente
- **Motores de Busca**: Google, Bing (com APIs oficiais)

### 🎯 Fuzzing Avançado
- **Painéis Administrativos**: 50+ paths comuns
- **Arquivos Sensíveis**: .env, configs, backups, logs
- **Endpoints API**: REST, GraphQL, SOAP, WebSocket
- **Bypass de Autenticação**: Headers customizados, IP spoofing
- **Payloads por Tecnologia**: WordPress, Laravel, Django, Node.js, etc.

### 🛡️ Detecção de Vulnerabilidades
- **Injeções**: SQL, XSS, LFI, RFI, RCE, SSTI, XXE
- **Exposição de Dados**: Credenciais, debug info, paths
- **Configurações**: CORS, CSP, Headers de segurança
- **Tecnologias Específicas**: WordPress, Drupal, Joomla, Laravel
- **Análise de Contexto**: Confidence scoring, risk assessment

### 📊 Relatórios Profissionais
- **HTML Interativo**: Gráficos, métricas, drill-down
- **Sumário Executivo**: Para gestão e tomada de decisão
- **JSON Estruturado**: Para integração e automação  
- **CSV Analítico**: Para análise de dados
- **Visualizações**: Charts.js, gauges, progress bars

## 🏗️ Arquitetura Modular

```
recon_pro_v2/
├── modules/
│   ├── __init__.py          # Package initialization
│   ├── discovery.py         # Asset discovery engine
│   ├── fuzzer.py           # Advanced fuzzing module
│   ├── vulnerabilities.py  # Vulnerability detection
│   └── reporting.py        # Professional reporting
├── recon_pro_v2.py         # Main application
├── config.json             # Configuration file
└── requirements.txt        # Dependencies
```

### 📦 Módulos

| Módulo | Responsabilidade | Principais Classes |
|--------|------------------|-------------------|
| `discovery.py` | Descoberta de subdomínios e assets | `AssetDiscovery` |
| `fuzzer.py` | Fuzzing e testes de penetração | `AdvancedFuzzer` |
| `vulnerabilities.py` | Detecção e análise de vulnerabilidades | `VulnerabilityEngine` |
| `reporting.py` | Geração de relatórios profissionais | `AdvancedReporting` |

## 🔧 Instalação

### Pré-requisitos
- Python 3.8+
- pip
- Git

### Dependências Python
```bash
pip install -r requirements.txt
```

### Ferramentas Externas (Opcionais)
```bash
# Subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Assetfinder  
go install github.com/tomnomnom/assetfinder@latest

# Amass
snap install amass

# Findomain
wget https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux
chmod +x findomain-linux && sudo mv findomain-linux /usr/local/bin/findomain
```

## ⚙️ Configuração

### 1. Arquivo de Configuração

Copie e edite o arquivo `config.json`:

```bash
cp config.json my_config.json
```

### 2. APIs (Opcionais mas Recomendadas)

Adicione suas chaves de API em `config.json`:

```json
{
  "api_keys": {
    "SECURITYTRAILS": "sua_api_key_aqui",
    "SHODAN": "sua_api_key_aqui",
    "VIRUSTOTAL": "sua_api_key_aqui",
    "GOOGLE_API_KEY": "sua_api_key_aqui",
    "GOOGLE_CSE_ID": "seu_cse_id_aqui"
  }
}
```

### 3. Variáveis de Ambiente (Alternativa)

```bash
export SECURITYTRAILS_API_KEY="sua_chave"
export SHODAN_API_KEY="sua_chave"
export VIRUSTOTAL_API_KEY="sua_chave"
```

## 🚀 Uso

### Uso Básico

```bash
# Scan completo padrão
python recon_pro_v2.py example.com

# Com arquivo de configuração
python recon_pro_v2.py example.com --config my_config.json

# Scan rápido
python recon_pro_v2.py example.com --scan-type quick

# Scan profundo
python recon_pro_v2.py example.com --scan-type deep
```

### Opções Avançadas

```bash
# Customizar threads e timeout
python recon_pro_v2.py example.com --threads 30 --verbose

# Diretório de saída específico
python recon_pro_v2.py example.com --output-dir /path/to/results

# Modo verbose para debugging
python recon_pro_v2.py example.com --verbose
```

### Parâmetros

| Parâmetro | Descrição | Padrão |
|-----------|-----------|---------|
| `domain` | Domínio alvo (obrigatório) | - |
| `--config` | Arquivo de configuração JSON | `config.json` |
| `--scan-type` | Tipo de scan: quick/full/deep | `full` |
| `--output-dir` | Diretório de saída | `recon_results` |
| `--threads` | Número de threads | `20` |
| `--verbose` | Modo debug/verbose | `False` |

## 💡 Exemplos

### Exemplo 1: Scan Básico

```bash
python recon_pro_v2.py tesla.com
```

**Saída:**
- `recon_report_tesla.com_20240101_120000.html` - Relatório principal
- `recon_data_tesla.com_20240101_120000.json` - Dados estruturados
- `executive_summary_tesla.com_20240101_120000.html` - Sumário executivo

### Exemplo 2: Scan Personalizado

```bash
python recon_pro_v2.py microsoft.com \
  --config enterprise_config.json \
  --scan-type deep \
  --threads 50 \
  --output-dir ./microsoft_recon \
  --verbose
```

### Exemplo 3: Configuração Específica

```json
{
  "threads": 30,
  "timeout": 20,
  "rate_limit": 0.2,
  "api_keys": {
    "SECURITYTRAILS": "st_api_key_here",
    "SHODAN": "shodan_key_here"
  },
  "advanced_options": {
    "stealth_mode": true,
    "custom_headers": {
      "X-Forwarded-For": "127.0.0.1"
    }
  }
}
```

## 📊 Relatórios

### 📄 Relatório HTML Principal

O relatório HTML inclui:

- **Dashboard Executivo**: Métricas principais e risk score
- **Subdomínios Descobertos**: Tabela interativa com tecnologias
- **Achados Sensíveis**: URLs de alto risco com evidências
- **Vulnerabilidades**: Detalhadas por severidade com remediação
- **Google Dorks**: Resultados de intelligence gathering
- **Recomendações**: Priorizadas por impacto

### 📈 Visualizações

- **Gráficos de Pizza**: Distribuição de vulnerabilidades
- **Gráficos de Barras**: Achados por categoria
- **Gauge de Risco**: Score visual de 0-10
- **Barras de Tecnologia**: Tecnologias mais encontradas

### 📋 Sumário Executivo

Versão condensada focada em:
- Riscos de negócio
- Impacto financeiro
- Recomendações estratégicas
- Timeline de correção

## 🔗 APIs Suportadas

| API | Funcionalidade | Status | Documentação |
|-----|----------------|--------|--------------|
| **SecurityTrails** | Subdomínios + Histórico DNS | ✅ | [Docs](https://docs.securitytrails.com/) |
| **Shodan** | Hosts + Portas + Banners | ✅ | [Docs](https://developer.shodan.io/) |
| **VirusTotal** | Subdomínios + Reputação | ✅ | [Docs](https://developers.virustotal.com/) |
| **Censys** | Certificados + Hosts | ✅ | [Docs](https://search.censys.io/api) |
| **Google CSE** | Search Engine Intelligence | ✅ | [Docs](https://developers.google.com/custom-search) |
| **Bing Search** | Search Engine Results | ✅ | [Docs](https://docs.microsoft.com/bing-web-search/) |

### 🔑 Obtendo APIs Gratuitas

1. **SecurityTrails**: 50 queries/mês grátis
2. **Shodan**: 100 queries/mês grátis  
3. **VirusTotal**: 1000 requests/dia grátis
4. **Google CSE**: 100 queries/dia grátis

## 🏆 Comparação de Versões

| Característica | v1.0 | v2.0 |
|----------------|------|------|
| Arquitetura | Monolítica | Modular |
| APIs | 3 | 6+ |
| Tipos de Vuln | 7 | 15+ |
| Relatórios | HTML básico | HTML + JSON + CSV + Executive |
| Configuração | Hardcoded | JSON flexível |
| Fuzzing | Básico | Inteligente por tecnologia |
| Performance | Threading simples | Otimizado + Rate limiting |
| Detecção Tech | Headers apenas | Headers + Content + Context |

## 🤝 Contribuição

Contribuições são bem-vindas! Para contribuir:

1. Fork o projeto
2. Crie uma branch para sua feature (`git checkout -b feature/AmazingFeature`)
3. Commit suas mudanças (`git commit -m 'Add some AmazingFeature'`)
4. Push para a branch (`git push origin feature/AmazingFeature`)
5. Abra um Pull Request

### 🛠️ Desenvolvimento

```bash
# Clone o repositório
git clone https://github.com/seuusuario/recon-pro-v2.git

# Instale dependências de desenvolvimento
pip install -r requirements-dev.txt

# Execute testes
python -m pytest tests/

# Linting
flake8 modules/ recon_pro_v2.py
```

## ⚖️ Disclaimer

**⚠️ IMPORTANTE**: Este software é destinado EXCLUSIVAMENTE para:

- ✅ Testes autorizados em sistemas próprios
- ✅ Pentests com autorização por escrito
- ✅ Bug bounty programs
- ✅ Pesquisa de segurança ética
- ✅ Educação em segurança cibernética

**❌ NÃO utilize para:**
- ❌ Ataques não autorizados
- ❌ Sistemas que não são seus
- ❌ Atividades ilegais
- ❌ Violação de termos de serviço

O autor não se responsabiliza pelo uso indevido desta ferramenta. O usuário é totalmente responsável por garantir que possui autorização adequada antes de executar qualquer teste.

## 📄 Licença

Este projeto está licenciado sob a Licença MIT - veja o arquivo [LICENSE](LICENSE) para detalhes.

## 👨‍💻 Autor

**Pentester Caio | CHDEVSEC**

- 🐙 GitHub: [@seuusuario](https://github.com/seuusuario)
- 🐦 Twitter: [@seutwitter](https://twitter.com/seutwitter)
- 💼 LinkedIn: [Seu LinkedIn](https://linkedin.com/in/seuperfil)
- 📧 Email: seu@email.com

---

<div align="center">

**Se esta ferramenta foi útil, considere dar uma ⭐ no repositório!**

Made with ❤️ by [Pentester Caio](https://github.com/seuusuario)

</div> 