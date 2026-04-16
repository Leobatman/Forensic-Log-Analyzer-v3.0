@echo off
setlocal
echo ===================================================
echo   Compilando Forensic Log Analyzer para Windows
echo ===================================================
echo.

REM Verifica se PyInstaller esta instalado
python -c "import pyinstaller" >nul 2>&1
if %errorlevel% neq 0 (
    echo [INFO] PyInstaller nao detectado. Instalando...
    pip install pyinstaller
)

echo [INFO] Iniciando PyInstaller Build Step...
echo [INFO] Incluindo componentes de Dashboard Web UI...

pyinstaller --noconfirm --log-level=WARN ^
    --onefile ^
    --name "ForensicAnalyzer" ^
    --add-data "dashboard;dashboard" ^
    --icon "NONE" ^
    forensic_analyzer.py

if %errorlevel% neq 0 (
    echo [ERRO] Falha durante o build!
    exit /b %errorlevel%
)

echo.
echo ===================================================
echo Build Concluido com Sucesso!
echo ===================================================
echo O executavel nativo standalone esta localizado em:
echo %CD%\dist\ForensicAnalyzer.exe
echo.
pause
