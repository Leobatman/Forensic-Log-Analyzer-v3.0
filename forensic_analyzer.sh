#!/bin/bash
# ====================================================================================================
# FORENSIC LOG ANALYZER v2.0 
# ====================================================================================================
# Autor: Leonardo Pereira - Engenheiro da Computação
# Versão: 3.0 - Production Ready
# Descrição: Análise forense de logs com detecção de ameaças 
# ====================================================================================================

set -o pipefail 2>/dev/null || true
shopt -s nullglob 2>/dev/null || true

VERSION="3.0.0"
TIMESTAMP=$(date +%Y%m%d_%H%M%S 2>/dev/null || echo "00000000_000000")
CASE_ID="FORENSIC_${TIMESTAMP}"
LOG_FILE=""
OUTPUT_DIR="./forensic_analysis_${TIMESTAMP}"
EVIDENCE_DIR="${OUTPUT_DIR}/evidence"
REPORTS_DIR="${OUTPUT_DIR}/reports"
IOCS_DIR="${OUTPUT_DIR}/iocs"
STATS_DIR="${OUTPUT_DIR}/statistics"
LOGS_DIR="${OUTPUT_DIR}/logs"

# Cores
RED='\033[0;91m'
GREEN='\033[0;92m'
YELLOW='\033[0;93m'
BLUE='\033[0;94m'
PURPLE='\033[0;95m'
CYAN='\033[0;96m'
WHITE='\033[0;97m'
BOLD='\033[1m'
NC='\033[0m'


# SQL Injection patterns
SQL_PATTERNS="union.*select|select.*from.*where|insert.*into|delete.*from|drop.*table|exec.*xp_|waitfor.*delay|sleep\\(|benchmark\\(|information_schema"

# XSS patterns
XSS_PATTERNS="<script[^>]*>.*?</script>|alert\\s*\\(|prompt\\s*\\(|confirm\\s*\\(|onerror\\s*=|onload\\s*=|onclick\\s*=|eval\\s*\\(|document\\.cookie|javascript:"

# LFI patterns
LFI_PATTERNS="\\.\\./|\\.\\.\\\\|/etc/passwd|/etc/shadow|/proc/self|/var/log/|C:\\\\Windows|php://filter|file://"

# RCE patterns
RCE_PATTERNS="cmd\\.exe|/bin/bash|/bin/sh|whoami|id|uname|system\\s*\\(|exec\\s*\\(|passthru\\s*\\(|shell_exec\\s*\\(|popen\\s*\\("

# Scanner patterns
SCANNER_PATTERNS="nmap|sqlmap|nikto|nessus|openvas|gobuster|dirb|wfuzz|burpsuite|zap|arachni|masscan|hydra"

# Brute force patterns
BRUTE_PATTERNS="failed password|authentication failure|invalid user|login failed|access denied|too many failures"

# Sensitive paths
SENSITIVE_PATHS="admin|wp-admin|administrator|login|config|\\.env|backup|phpmyadmin|password|\\.git|\\.svn"

# Path traversal
TRAVERSAL_PATTERNS="\\.\\./\\.\\./|\\.\\.\\\\\\.\\.\\\\|%2e%2e%2f%2e%2e%2f"

declare -A THREAT_LEVELS
declare -A ATTACK_VECTORS
declare -A IP_COUNTS
declare -A HOURLY_COUNTS
declare -A MALICIOUS_IPS

THREAT_LEVELS["CRITICAL"]=0
THREAT_LEVELS["HIGH"]=0
THREAT_LEVELS["MEDIUM"]=0
THREAT_LEVELS["LOW"]=0

ATTACK_VECTORS["SQLi"]=0
ATTACK_VECTORS["XSS"]=0
ATTACK_VECTORS["LFI"]=0
ATTACK_VECTORS["RCE"]=0
ATTACK_VECTORS["SCANNER"]=0
ATTACK_VECTORS["BRUTE_FORCE"]=0
ATTACK_VECTORS["SENSITIVE"]=0

TOTAL_LINES=0
UNIQUE_IPS=0
START_TIME=$(date +%s 2>/dev/null || echo "0")


log_message() {
    local level="$1"
    local message="$2"
    local color="$3"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "1970-01-01 00:00:00")
    
    echo -e "${color}[${level}]${NC} ${timestamp} - ${message}"
    
    if [[ -d "$LOGS_DIR" ]]; then
        echo "[${level}] ${timestamp} - ${message}" >> "${LOGS_DIR}/forensic.log" 2>/dev/null || true
    fi
}

log_critical() { log_message "CRITICAL" "$1" "${RED}${BOLD}"; ((THREAT_LEVELS["CRITICAL"]++)); }
log_high() { log_message "HIGH" "$1" "${RED}"; ((THREAT_LEVELS["HIGH"]++)); }
log_medium() { log_message "MEDIUM" "$1" "${YELLOW}"; ((THREAT_LEVELS["MEDIUM"]++)); }
log_low() { log_message "LOW" "$1" "${GREEN}"; ((THREAT_LEVELS["LOW"]++)); }
log_info() { log_message "INFO" "$1" "${CYAN}"; }
log_success() { log_message "SUCCESS" "$1" "${GREEN}${BOLD}"; }
log_warning() { log_message "WARNING" "$1" "${YELLOW}"; }

print_section() {
    local title="$1"
    echo ""
    echo -e "${PURPLE}${BOLD}================================================================================${NC}"
    echo -e "${PURPLE}${BOLD}  ${title}${NC}"
    echo -e "${PURPLE}${BOLD}================================================================================${NC}"
}

print_subsection() {
    echo ""
    echo -e "${CYAN}${BOLD}  --- ${1} ---${NC}"
}

print_banner() {
    clear 2>/dev/null || true
    echo -e "${PURPLE}${BOLD}"
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                                                                              ║"
    echo "║              FORENSIC LOG ANALYZER v3.0 - ENTERPRISE EDITION                 ║"
    echo "║                                                                              ║"
    echo "║                   Digital Forensics & Incident Response                      ║"
    echo "║                                                                              ║"
    echo "║                     Author: Leonardo Pereira                                 ║"
    echo "║                            Engineer of Computer                              ║"
    echo "║                                                                              ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
    echo -e "${WHITE}Case ID: ${CYAN}${CASE_ID}${NC}"
    echo -e "${WHITE}Target:  ${CYAN}${LOG_FILE}${NC}"
    echo -e "${WHITE}Started: ${CYAN}$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo 'Unknown')${NC}"
    echo ""
}

# ====================================================================================================
# VALIDAÇÃO DO AMBIENTE

validate_environment() {
    print_section "VALIDANDO AMBIENTE FORENSE"
    
    # Verificar dependências
    local deps="awk grep sed sort uniq wc cut head tail date"
    local missing=""
    
    for dep in $deps; do
        if ! command -v "$dep" >/dev/null 2>&1; then
            missing="$missing $dep"
        fi
    done
    
    if [[ -n "$missing" ]]; then
        log_critical "Dependências faltando:$missing"
        return 1
    fi
    
    # Verificar arquivo de log
    if [[ -z "$LOG_FILE" ]] || [[ ! -f "$LOG_FILE" ]]; then
        log_critical "Arquivo não encontrado: $LOG_FILE"
        return 1
    fi
    
    if [[ ! -r "$LOG_FILE" ]]; then
        log_critical "Sem permissão de leitura: $LOG_FILE"
        return 1
    fi
    
    local file_size=$(stat -c%s "$LOG_FILE" 2>/dev/null || stat -f%z "$LOG_FILE" 2>/dev/null || echo "0")
    local size_mb=$((file_size / 1048576))
    
    log_success "Arquivo validado: $LOG_FILE (${size_mb}MB)"
    
    if [[ $EUID -eq 0 ]]; then
        log_success "Executando com privilégios de root"
    else
        log_warning "Executando sem root - algumas operações limitadas"
    fi
    
    return 0
}

# ====================================================================================================
# CRIAÇÃO DE DIRETÓRIOS


setup_directories() {
    print_section "CRIANDO ESTRUTURA FORENSE"
    
    local dirs="$OUTPUT_DIR $EVIDENCE_DIR $REPORTS_DIR $IOCS_DIR $STATS_DIR $LOGS_DIR"
    
    for dir in $dirs; do
        if mkdir -p "$dir" 2>/dev/null; then
            log_success "Diretório criado: $dir"
        else
            log_critical "Falha ao criar: $dir"
            return 1
        fi
    done
    
    return 0
}


collect_basic_forensics() {
    print_section "EVIDÊNCIAS FORENSES BÁSICAS"
    
    local file_hash=$(sha256sum "$LOG_FILE" 2>/dev/null | cut -d' ' -f1 || echo "N/A")
    local file_size=$(du -h "$LOG_FILE" 2>/dev/null | cut -f1 || echo "N/A")
    local modified_time=$(stat -c %y "$LOG_FILE" 2>/dev/null || stat -f %Sm "$LOG_FILE" 2>/dev/null || echo "N/A")
    
    TOTAL_LINES=$(wc -l < "$LOG_FILE" 2>/dev/null || echo "0")
    
    log_info "Hash SHA256: $file_hash"
    log_info "Tamanho: $file_size"
    log_info "Modificação: $modified_time"
    log_info "Total de entradas: $TOTAL_LINES"
    
    cat > "${EVIDENCE_DIR}/basic_forensics.txt" << EOF
=== EVIDÊNCIAS FORENSES ===
Case ID: ${CASE_ID}
Arquivo: ${LOG_FILE}
Hash SHA256: ${file_hash}
Tamanho: ${file_size}
Modificação: ${modified_time}
Total Linhas: ${TOTAL_LINES}
Data Análise: $(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo 'Unknown')
EOF
}


extract_ips() {
    print_section "ANÁLISE DE ENDEREÇOS IP"
    
    print_subsection "Extraindo IPs"
    
    # Extrair IPs usando regex
    grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' "$LOG_FILE" 2>/dev/null | \
        sort | uniq -c | sort -nr > "${STATS_DIR}/all_ips.txt"
    
    # Top 20 IPs
    print_subsection "Top 20 IPs por volume"
    head -20 "${STATS_DIR}/all_ips.txt" | while read count ip; do
        IP_COUNTS["$ip"]=$count
        echo -e "${CYAN}${count}${NC} ${ip}"
    done | tee -a "${REPORTS_DIR}/analysis.txt"
    
    UNIQUE_IPS=$(wc -l < "${STATS_DIR}/all_ips.txt" 2>/dev/null || echo "0")
    log_info "Total de IPs únicos: ${UNIQUE_IPS}"
    
    # Detectar IPs suspeitos
    print_subsection "Detectando IPs suspeitos"
    
    local total=$(awk '{sum+=$1} END {print sum}' "${STATS_DIR}/all_ips.txt" 2>/dev/null || echo "0")
    local avg=$((total / UNIQUE_IPS))
    local threshold=$((avg * 3))
    
    [[ $threshold -lt 100 ]] && threshold=100
    
    awk -v thresh="$threshold" '$1 > thresh {print $2, $1}' "${STATS_DIR}/all_ips.txt" 2>/dev/null | \
        while read ip count; do
            log_high "IP suspeito: ${ip} (${count} requisições)"
            echo "$ip" >> "${EVIDENCE_DIR}/suspicious_ips.txt"
        done
}


analyze_http_methods() {
    print_section "ANÁLISE DE MÉTODOS HTTP"
    
    # Extrair métodos HTTP
    grep -oE '"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)"' "$LOG_FILE" 2>/dev/null | \
        tr -d '"' | sort | uniq -c | sort -nr > "${STATS_DIR}/methods.txt"
    
    print_subsection "Distribuição de métodos"
    
    if [[ -s "${STATS_DIR}/methods.txt" ]]; then
        cat "${STATS_DIR}/methods.txt" | while read count method; do
            echo -e "${CYAN}${count}${NC} ${method}"
        done | tee -a "${REPORTS_DIR}/analysis.txt"
    else
        log_info "Nenhum método HTTP encontrado"
    fi
}


analyze_status_codes() {
    print_section "ANÁLISE DE STATUS CODES"
    
    # Extrair status codes
    grep -oE ' [45][0-9]{2} ' "$LOG_FILE" 2>/dev/null | tr -d ' ' | sort | uniq -c | sort -nr > "${STATS_DIR}/status.txt"
    
    print_subsection "Distribuição de status"
    
    if [[ -s "${STATS_DIR}/status.txt" ]]; then
        cat "${STATS_DIR}/status.txt" | while read count status; do
            echo -e "${YELLOW}${count}${NC} ${status}"
        done | tee -a "${REPORTS_DIR}/analysis.txt"
    fi
    
    local client_errors=$(grep -cE ' 4[0-9]{2} ' "$LOG_FILE" 2>/dev/null || echo "0")
    local server_errors=$(grep -cE ' 5[0-9]{2} ' "$LOG_FILE" 2>/dev/null || echo "0")
    
    log_info "Erros 4xx: ${client_errors}"
    log_info "Erros 5xx: ${server_errors}"
    
    if [[ $server_errors -gt 100 ]]; then
        log_high "Alto volume de erros 5xx: ${server_errors}"
    fi
}

analyze_user_agents() {
    print_section "ANÁLISE DE USER AGENTS"
    
    # Extrair User-Agents (último campo entre aspas)
    awk -F'"' '{if(NF>=6) print $(NF-1)}' "$LOG_FILE" 2>/dev/null | \
        sort | uniq -c | sort -nr > "${STATS_DIR}/user_agents.txt"
    
    print_subsection "Top 15 User Agents"
    head -15 "${STATS_DIR}/user_agents.txt" | while read count ua; do
        local ua_short=$(echo "$ua" | cut -c1-60)
        echo -e "${CYAN}${count}${NC} ${ua_short}..."
    done | tee -a "${REPORTS_DIR}/analysis.txt"
    
    # Detectar scanners
    print_subsection "Detectando scanners"
    
    for agent in nmap sqlmap nikto nessus gobuster dirb wfuzz burpsuite zap; do
        local count=$(grep -ci "$agent" "$LOG_FILE" 2>/dev/null || echo "0")
        if [[ $count -gt 0 ]]; then
            log_high "Scanner detectado: ${agent} (${count} ocorrências)"
            ((ATTACK_VECTORS["SCANNER"]+=count))
        fi
    done
}


analyze_temporal_patterns() {
    print_section "ANÁLISE DE PADRÕES TEMPORAIS"
    
    print_subsection "Distribuição por horário"
    
    # Tentar extrair horas de diferentes formatos
    grep -oE '\[[0-9]{2}/[A-Za-z]{3}/[0-9]{4}:[0-9]{2}:[0-9]{2}' "$LOG_FILE" 2>/dev/null | \
        cut -d: -f2 | sort | uniq -c > "${STATS_DIR}/hourly.txt" 2>/dev/null || true
    
    if [[ ! -s "${STATS_DIR}/hourly.txt" ]]; then
        # Tentar formato ISO
        grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}' "$LOG_FILE" 2>/dev/null | \
            cut -dT -f2 | sort | uniq -c > "${STATS_DIR}/hourly.txt" 2>/dev/null || true
    fi
    
    local max_count=0
    local max_hour=0
    
    for hour in 00 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16 17 18 19 20 21 22 23; do
        local count=$(grep -c " $hour" "${STATS_DIR}/hourly.txt" 2>/dev/null || echo "0")
        HOURLY_COUNTS[$hour]=$count
        local bar_len=$((count / 50))
        [[ $bar_len -gt 30 ]] && bar_len=30
        local bar=$(printf '%*s' "$bar_len" | tr ' ' '█')
        echo -e "${CYAN}${hour}:00${NC} ${bar} (${count})"
        
        if [[ $count -gt $max_count ]]; then
            max_count=$count
            max_hour=$hour
        fi
    done
    
    if [[ $max_count -gt 500 ]]; then
        log_medium "Pico de atividade: ${max_hour}:00 (${max_count} requisições)"
    fi
}

# ====================================================================================================
# DETECÇÃO DE AMEAÇAS
# ====================================================================================================

detect_threats() {
    print_section "DETECÇÃO DE AMEAÇAS"
    
    # SQL Injection
    local sqli=$(grep -Eic "$SQL_PATTERNS" "$LOG_FILE" 2>/dev/null || echo "0")
    if [[ $sqli -gt 0 ]]; then
        log_critical "SQL Injection: ${sqli} ocorrências"
        ATTACK_VECTORS["SQLi"]=$sqli
        grep -Ei "$SQL_PATTERNS" "$LOG_FILE" 2>/dev/null | head -50 > "${EVIDENCE_DIR}/sqli_attacks.txt"
    fi
    
    # XSS
    local xss=$(grep -Eic "$XSS_PATTERNS" "$LOG_FILE" 2>/dev/null || echo "0")
    if [[ $xss -gt 0 ]]; then
        log_high "XSS: ${xss} ocorrências"
        ATTACK_VECTORS["XSS"]=$xss
        grep -Ei "$XSS_PATTERNS" "$LOG_FILE" 2>/dev/null | head -50 > "${EVIDENCE_DIR}/xss_attacks.txt"
    fi
    
    # LFI
    local lfi=$(grep -Eic "$LFI_PATTERNS" "$LOG_FILE" 2>/dev/null || echo "0")
    if [[ $lfi -gt 0 ]]; then
        log_high "LFI/RFI: ${lfi} ocorrências"
        ATTACK_VECTORS["LFI"]=$lfi
        grep -Ei "$LFI_PATTERNS" "$LOG_FILE" 2>/dev/null | head -50 > "${EVIDENCE_DIR}/lfi_attacks.txt"
    fi
    
    # RCE
    local rce=$(grep -Eic "$RCE_PATTERNS" "$LOG_FILE" 2>/dev/null || echo "0")
    if [[ $rce -gt 0 ]]; then
        log_critical "RCE: ${rce} ocorrências"
        ATTACK_VECTORS["RCE"]=$rce
        grep -Ei "$RCE_PATTERNS" "$LOG_FILE" 2>/dev/null | head -50 > "${EVIDENCE_DIR}/rce_attacks.txt"
    fi
    
    # Brute Force
    local brute=$(grep -Eic "$BRUTE_PATTERNS" "$LOG_FILE" 2>/dev/null || echo "0")
    if [[ $brute -gt 0 ]]; then
        log_high "Brute Force: ${brute} ocorrências"
        ATTACK_VECTORS["BRUTE_FORCE"]=$brute
        grep -Ei "$BRUTE_PATTERNS" "$LOG_FILE" 2>/dev/null | head -50 > "${EVIDENCE_DIR}/brute_force.txt"
    fi
    
    # Path Traversal
    local traversal=$(grep -Eic "$TRAVERSAL_PATTERNS" "$LOG_FILE" 2>/dev/null || echo "0")
    if [[ $traversal -gt 0 ]]; then
        log_high "Path Traversal: ${traversal} tentativas"
    fi
    
    # Sensitive Paths
    local sensitive=$(grep -Eic "/($SENSITIVE_PATHS)[/?]" "$LOG_FILE" 2>/dev/null || echo "0")
    if [[ $sensitive -gt 0 ]]; then
        log_medium "Acessos a paths sensíveis: ${sensitive}"
        ATTACK_VECTORS["SENSITIVE"]=$sensitive
    fi
}

# ====================================================================================================
# GERAÇÃO DE IOCS

generate_iocs() {
    print_section "INTELIGÊNCIA DE AMEAÇAS"
    
    # Consolidar IPs maliciosos
    cat "${EVIDENCE_DIR}"/*_ips.txt 2>/dev/null | sort -u > "${IOCS_DIR}/malicious_ips.txt"
    
    local malicious_count=$(wc -l < "${IOCS_DIR}/malicious_ips.txt" 2>/dev/null || echo "0")
    
    if [[ $malicious_count -gt 0 ]]; then
        log_high "IPs maliciosos identificados: ${malicious_count}"
        
        # Gerar lista de bloqueio
        cat > "${IOCS_DIR}/ip_blocklist.txt" << EOF
# Forensic Log Analyzer - IP Blocklist
# Case ID: ${CASE_ID}
# Generated: $(date '+%Y-%m-%d %H:%M:%S')
# Total IPs: ${malicious_count}
# =========================================

EOF
        cat "${IOCS_DIR}/malicious_ips.txt" >> "${IOCS_DIR}/ip_blocklist.txt"
        
        # Salvar IPs de scanners
        if [[ -f "${EVIDENCE_DIR}/scanner_ips.txt" ]]; then
            sort -u "${EVIDENCE_DIR}/scanner_ips.txt" >> "${IOCS_DIR}/malicious_ips.txt" 2>/dev/null || true
        fi
    else
        log_success "Nenhum IP malicioso identificado"
    fi
    
    # Gerar IOCs JSON
    cat > "${IOCS_DIR}/iocs.json" << EOF
{
  "case_id": "${CASE_ID}",
  "generated": "$(date '+%Y-%m-%d %H:%M:%S')",
  "malicious_ips": $(cat "${IOCS_DIR}/malicious_ips.txt" 2>/dev/null | jq -R -s -c 'split("\n") | map(select(. != ""))' 2>/dev/null || echo "[]"),
  "attack_vectors": {
    "SQLi": ${ATTACK_VECTORS["SQLi"]},
    "XSS": ${ATTACK_VECTORS["XSS"]},
    "LFI": ${ATTACK_VECTORS["LFI"]},
    "RCE": ${ATTACK_VECTORS["RCE"]},
    "Scanner": ${ATTACK_VECTORS["SCANNER"]},
    "BruteForce": ${ATTACK_VECTORS["BRUTE_FORCE"]}
  }
}
EOF
}

# ====================================================================================================
# RELATÓRIO EXECUTIVO

generate_executive_report() {
    print_section "RELATÓRIO EXECUTIVO"
    
    local total_time=$(( $(date +%s 2>/dev/null || echo "0") - START_TIME ))
    local minutes=$((total_time / 60))
    local seconds=$((total_time % 60))
    
    cat > "${REPORTS_DIR}/executive_summary.txt" << EOF
================================================================================
                    EXECUTIVE SUMMARY - FORENSIC ANALYSIS
================================================================================

CASE ID: ${CASE_ID}
INVESTIGATOR: Leonardo Pereira - DFIR Specialist
ANALYSIS DATE: $(date '+%Y-%m-%d %H:%M:%S')
EVIDENCE FILE: ${LOG_FILE}
TOTAL ENTRIES: ${TOTAL_LINES}
UNIQUE IPS: ${UNIQUE_IPS}
ANALYSIS TIME: ${minutes}m ${seconds}s

================================================================================
THREAT LANDSCAPE
================================================================================

CRITICAL INCIDENTS: ${THREAT_LEVELS["CRITICAL"]}
HIGH SEVERITY: ${THREAT_LEVELS["HIGH"]}
MEDIUM SEVERITY: ${THREAT_LEVELS["MEDIUM"]}
LOW SEVERITY: ${THREAT_LEVELS["LOW"]}

================================================================================
ATTACK VECTORS DETECTED
================================================================================

SQL Injection: ${ATTACK_VECTORS["SQLi"]}
XSS: ${ATTACK_VECTORS["XSS"]}
LFI/RFI: ${ATTACK_VECTORS["LFI"]}
RCE: ${ATTACK_VECTORS["RCE"]}
Scanner Activity: ${ATTACK_VECTORS["SCANNER"]}
Brute Force: ${ATTACK_VECTORS["BRUTE_FORCE"]}
Sensitive Access: ${ATTACK_VECTORS["SENSITIVE"]}

================================================================================
RECOMMENDATIONS
================================================================================

EOF
    
    if [[ ${THREAT_LEVELS["CRITICAL"]} -gt 0 ]]; then
        cat >> "${REPORTS_DIR}/executive_summary.txt" << EOF
🔴 IMMEDIATE ACTION REQUIRED
   → Critical incidents detected (SQL Injection / RCE)
   → Isolate affected systems immediately
   → Block identified malicious IPs
   → Initiate incident response protocol

EOF
    fi
    
    if [[ ${THREAT_LEVELS["HIGH"]} -gt 0 ]]; then
        cat >> "${REPORTS_DIR}/executive_summary.txt" << EOF
🟠 HIGH SEVERITY ATTENTION
   → XSS, LFI or brute force attacks detected
   → Review WAF/IDS configurations
   → Increase monitoring on affected endpoints

EOF
    fi
    
    if [[ -s "${IOCS_DIR}/ip_blocklist.txt" ]]; then
        local ip_count=$(grep -c '^[0-9]' "${IOCS_DIR}/ip_blocklist.txt" 2>/dev/null || echo "0")
        cat >> "${REPORTS_DIR}/executive_summary.txt" << EOF
🚫 IP BLOCKLIST GENERATED
   → ${ip_count} malicious IPs identified
   → Blocklist: ${IOCS_DIR}/ip_blocklist.txt

EOF
    fi
    
    if [[ ${THREAT_LEVELS["CRITICAL"]} -eq 0 && ${THREAT_LEVELS["HIGH"]} -eq 0 ]]; then
        cat >> "${REPORTS_DIR}/executive_summary.txt" << EOF
🟢 NORMAL SITUATION
   → No critical or high severity threats detected
   → Maintain standard monitoring procedures

EOF
    fi
    
    log_success "Relatório executivo: ${REPORTS_DIR}/executive_summary.txt"
}

generate_html_report() {
    print_section "GERANDO RELATÓRIO HTML"
    
    local critical=${THREAT_LEVELS["CRITICAL"]}
    local high=${THREAT_LEVELS["HIGH"]}
    local medium=${THREAT_LEVELS["MEDIUM"]}
    local low=${THREAT_LEVELS["LOW"]}
    local total=$((critical + high + medium + low))
    
    local crit_pct=0
    local high_pct=0
    local med_pct=0
    local low_pct=0
    
    if [[ $total -gt 0 ]]; then
        crit_pct=$((critical * 100 / total))
        high_pct=$((high * 100 / total))
        med_pct=$((medium * 100 / total))
        low_pct=$((low * 100 / total))
    fi
    
    # Top IPs table
    local top_ips_html=""
    head -10 "${STATS_DIR}/all_ips.txt" 2>/dev/null | while read count ip; do
        local malicious=""
        if grep -q "^${ip}$" "${IOCS_DIR}/malicious_ips.txt" 2>/dev/null; then
            malicious="🔴 MALICIOSO"
        else
            malicious="🟢 LIMPO"
        fi
        top_ips_html="${top_ips_html}<tr><td>${ip}</td><td>${count}</td><td>${malicious}</td></tr>"
    done
    
    # Attack vectors table
    local attack_html=""
    [[ ${ATTACK_VECTORS["SQLi"]} -gt 0 ]] && attack_html="${attack_html}<tr><td>SQL Injection</td><td>${ATTACK_VECTORS["SQLi"]}</td></tr>"
    [[ ${ATTACK_VECTORS["XSS"]} -gt 0 ]] && attack_html="${attack_html}<tr><td>XSS</td><td>${ATTACK_VECTORS["XSS"]}</td></tr>"
    [[ ${ATTACK_VECTORS["LFI"]} -gt 0 ]] && attack_html="${attack_html}<tr><td>LFI/RFI</td><td>${ATTACK_VECTORS["LFI"]}</td></tr>"
    [[ ${ATTACK_VECTORS["RCE"]} -gt 0 ]] && attack_html="${attack_html}<tr><td>RCE</td><td>${ATTACK_VECTORS["RCE"]}</td></tr>"
    [[ ${ATTACK_VECTORS["SCANNER"]} -gt 0 ]] && attack_html="${attack_html}<tr><td>Scanner</td><td>${ATTACK_VECTORS["SCANNER"]}</td></tr>"
    [[ ${ATTACK_VECTORS["BRUTE_FORCE"]} -gt 0 ]] && attack_html="${attack_html}<tr><td>Brute Force</td><td>${ATTACK_VECTORS["BRUTE_FORCE"]}</td></tr>"
    
    cat > "${REPORTS_DIR}/forensic_report.html" << EOF
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Relatório Forense - ${CASE_ID}</title>
    <style>
        body {
            font-family: monospace;
            background: #0a0e27;
            color: #e0e0e0;
            padding: 20px;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 10px;
            padding: 20px;
            text-align: center;
        }
        .grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 15px;
            margin: 20px 0;
        }
        .card {
            background: #1a1f3a;
            border-radius: 10px;
            padding: 15px;
            text-align: center;
        }
        .card-number { font-size: 2em; font-weight: bold; color: #667eea; }
        .section {
            background: #1a1f3a;
            border-radius: 10px;
            padding: 20px;
            margin: 20px 0;
        }
        .section h2 { color: #667eea; margin-bottom: 15px; }
        .threat-bar {
            background: #2a2f4a;
            border-radius: 8px;
            overflow: hidden;
            margin: 10px 0;
        }
        .bar {
            height: 35px;
            display: inline-block;
            text-align: center;
            line-height: 35px;
            color: white;
        }
        .critical { background: #dc3545; width: ${crit_pct}%; }
        .high { background: #fd7e14; width: ${high_pct}%; }
        .medium { background: #ffc107; width: ${med_pct}%; color: #333; }
        .low { background: #28a745; width: ${low_pct}%; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #2a2f4a; }
        th { background: #0f1328; color: #667eea; }
        .footer { text-align: center; margin-top: 20px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Forensic Log Analyzer v3.0</h1>
            <p>Case ID: ${CASE_ID}</p>
            <p>File: ${LOG_FILE}</p>
        </div>
        
        <div class="grid">
            <div class="card"><div class="card-number">${TOTAL_LINES}</div><div>Entries</div></div>
            <div class="card"><div class="card-number">${UNIQUE_IPS}</div><div>Unique IPs</div></div>
            <div class="card"><div class="card-number">${total}</div><div>Threats</div></div>
            <div class="card"><div class="card-number">$(wc -l < "${IOCS_DIR}/malicious_ips.txt" 2>/dev/null || echo "0")</div><div>Malicious IPs</div></div>
        </div>
        
        <div class="section">
            <h2>Threat Levels</h2>
            <div class="threat-bar">
                <div class="bar critical">CRITICAL: ${critical}</div>
                <div class="bar high">HIGH: ${high}</div>
                <div class="bar medium">MEDIUM: ${medium}</div>
                <div class="bar low">LOW: ${low}</div>
            </div>
        </div>
        
        <div class="section">
            <h2>Attack Vectors</h2>
            <table>
                <tr><th>Type</th><th>Count</th></tr>
                ${attack_html}
            </table>
        </div>
        
        <div class="section">
            <h2>Top 10 Suspicious IPs</h2>
            <table>
                <tr><th>IP</th><th>Requests</th><th>Status</th></tr>
                $(head -10 "${STATS_DIR}/all_ips.txt" 2>/dev/null | while read count ip; do
                    if grep -q "^${ip}$" "${IOCS_DIR}/malicious_ips.txt" 2>/dev/null; then
                        echo "<tr><td>${ip}</td><td>${count}</td><td>🔴 MALICIOUS</td></tr>"
                    else
                        echo "<tr><td>${ip}</td><td>${count}</td><td>🟢 CLEAN</td></tr>"
                    fi
                done)
            </table>
        </div>
        
        <div class="footer">
            <p>Generated: $(date '+%Y-%m-%d %H:%M:%S') | Analysis Time: ${minutes}m ${seconds}s</p>
        </div>
    </div>
</body>
</html>
EOF
    
    log_success "Relatório HTML: ${REPORTS_DIR}/forensic_report.html"
}

cleanup_and_exit() {
    local exit_code=$1
    
    print_section "FINALIZANDO ANÁLISE"
    
    cd "$(dirname "$OUTPUT_DIR")" 2>/dev/null || true
    
    if [[ -d "$OUTPUT_DIR" ]]; then
        tar -czf "${CASE_ID}.tar.gz" "$(basename "$OUTPUT_DIR")" 2>/dev/null && \
            log_success "Arquivo compactado: ${CASE_ID}.tar.gz"
    fi
    
    local total_time=$(( $(date +%s 2>/dev/null || echo "0") - START_TIME ))
    local minutes=$((total_time / 60))
    local seconds=$((total_time % 60))
    
    echo ""
    echo -e "${GREEN}${BOLD}"
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                    FORENSIC ANALYSIS COMPLETED SUCCESSFULLY                  ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
    echo -e "${WHITE}Case ID:     ${CYAN}${CASE_ID}${NC}"
    echo -e "${WHITE}Output:      ${CYAN}${OUTPUT_DIR}${NC}"
    echo -e "${WHITE}Archive:     ${CYAN}${CASE_ID}.tar.gz${NC}"
    echo -e "${WHITE}Time:        ${CYAN}${minutes}m ${seconds}s${NC}"
    echo -e "${WHITE}Entries:     ${CYAN}${TOTAL_LINES}${NC}"
    echo -e "${WHITE}IPs:         ${CYAN}${UNIQUE_IPS}${NC}"
    echo ""
    
    exit "$exit_code"
}

# ====================================================================================================
# FUNÇÃO PRINCIPAL
# ====================================================================================================

main() {
    trap 'cleanup_and_exit 1' INT TERM
    
    # Verificar argumentos
    if [[ $# -lt 1 ]]; then
        echo -e "${RED}Uso: $0 <arquivo_de_log>${NC}"
        echo ""
        echo "Exemplos:"
        echo "  $0 /var/log/apache2/access.log"
        echo "  $0 /var/log/nginx/access.log"
        echo "  $0 /var/log/auth.log"
        echo "  $0 qualquer_arquivo.log"
        exit 1
    fi
    
    LOG_FILE="$1"
    
    print_banner
    
    # Executar análise
    validate_environment || exit 1
    setup_directories || exit 1
    collect_basic_forensics
    extract_ips
    analyze_http_methods
    analyze_status_codes
    analyze_user_agents
    analyze_temporal_patterns
    detect_threats
    generate_iocs
    generate_executive_report
    generate_html_report
    
    cleanup_and_exit 0
}

main "$@"
