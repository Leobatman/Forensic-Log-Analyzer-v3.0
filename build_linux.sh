#!/bin/bash
set -e

echo "==================================================="
echo "  Compilando Forensic Log Analyzer para Linux/Mac"
echo "==================================================="
echo ""

# Verifica dependencias
if ! command -v pyinstaller &> /dev/null; then
    echo "[INFO] PyInstaller não detectado. Instalando via pip..."
    pip3 install pyinstaller
fi

echo "[INFO] Iniciando Build nativo..."
echo "[INFO] Incorporando assets web do Analytics Dashboard..."

pyinstaller --noconfirm --log-level=WARN \
    --onefile \
    --name "forensic-analyzer" \
    --add-data "dashboard:dashboard" \
    forensic_analyzer.py

echo ""
echo "==================================================="
echo "Build Concluído com Sucesso!"
echo "==================================================="
echo "O binário nativo standalone está localizado em:"
echo "$(pwd)/dist/forensic-analyzer"
echo ""
