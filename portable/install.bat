@echo off
setlocal
REM Instalador manual de Sentinel IP (modo demo) para Windows.
REM No instala servicios, no genera autorrun ni persistencia oculta.

set "SRC=%~dp0"
set "DEST=%LOCALAPPDATA%\SentinelIP"

echo [*] Instalando Sentinel IP en %DEST%
if not exist "%DEST%" mkdir "%DEST%"

where py >nul 2>nul
if %ERRORLEVEL%==0 (
  set "PY=py -3"
) else (
  where python >nul 2>nul
  if %ERRORLEVEL%==0 (
    set "PY=python"
  ) else (
    echo [!] Se necesita Python 3.11+ instalado. Descargalo de python.org
    pause
    exit /b 1
  )
)

%PY% -c "import sys; sys.exit(0 if sys.version_info>=(3,11) else 1)"
if errorlevel 1 (
  echo [!] Se necesita Python 3.11 o superior.
  pause
  exit /b 1
)

%PY% -m venv "%DEST%\venv"
echo [*] Instalando dependencias desde ruedas offline...
"%DEST%\venv\Scripts\python.exe" -m pip install --no-index --find-links="%SRC%\demo\wheels" -r "%SRC%\demo\requirements-demo.txt"
if errorlevel 1 (
  echo [*] Ruedas incompatibles con tu version de Python; usando PyPI...
  "%DEST%\venv\Scripts\python.exe" -m pip install -r "%SRC%\demo\requirements-demo.txt"
  if errorlevel 1 (
    echo [!] Fallo la instalacion de dependencias. Revisa tu conexion.
    pause
    exit /b 1
  )
)

xcopy /E /I /Y /Q "%SRC%\demo\app" "%DEST%\app" >nul
copy /Y "%SRC%\demo\sentinel.py" "%DEST%\sentinel.py" >nul

(
  echo @echo off
  echo cd /d "%DEST%"
  echo "%DEST%\venv\Scripts\python.exe" sentinel.py --demo --port 8000
  echo pause
) > "%DEST%\sentinel-demo.bat"

echo [+] Instalado. Ejecuta: %DEST%\sentinel-demo.bat
echo [+] Modo real NO disponible en Windows (requiere Linux con raw sockets).
pause
