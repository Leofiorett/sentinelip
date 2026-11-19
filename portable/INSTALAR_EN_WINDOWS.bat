@echo off
setlocal
REM Doble clic: extrae el paquete en TEMP y ejecuta el instalador demo.
REM No modifica el pendrive mas alla de leer el tarball.

set "SRC=%~dp0"
set "TMP=%TEMP%\SentinelIP-portable"

echo [*] Extrayendo paquete en %TMP%
if exist "%TMP%" rmdir /s /q "%TMP%"
mkdir "%TMP%"
if errorlevel 1 goto :fail

tar -xf "%SRC%SENTINEL-IP-1.0.tar.gz" -C "%TMP%"
if errorlevel 1 goto :notar

call "%TMP%\install.bat"
goto :end

:notar
echo [!] No se pudo extraer. Necesitas Windows 10 1803+ (incluye tar.exe).
echo     Alternativa: extrae SENTINEL-IP-1.0.tar.gz con 7-Zip y ejecuta install.bat.
pause
exit /b 1

:fail
echo [!] No se pudo crear el directorio temporal.
pause
exit /b 1

:end
