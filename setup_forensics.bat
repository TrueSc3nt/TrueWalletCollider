@echo off
setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0"

echo =============================================
echo  TrueWalletCollider - setup_forensics
echo  Fetches Hashcat into third_party\hashcat
echo  (authorized recovery / DFIR use only)
echo =============================================
echo.

set "HC_DIR=%~dp0third_party\hashcat"
set "HC_EXE=%HC_DIR%\hashcat.exe"
set "STAGING=%~dp0third_party\_staging"
set "ZIP=%STAGING%\hashcat.zip"

if exist "%HC_EXE%" (
  echo [+] Hashcat already present:
  "%HC_EXE%" --version 2>nul
  if errorlevel 1 echo [!] hashcat.exe exists but --version failed
  echo.
  echo Done. Open TrueWalletCollider.exe - Hashcat Bridge should find third_party\hashcat.
  exit /b 0
)

where powershell >nul 2>&1
if errorlevel 1 (
  echo [E] PowerShell required to download Hashcat.
  echo     Manually unpack official Hashcat Windows binaries to:
  echo       %HC_DIR%
  exit /b 1
)

if not exist "%STAGING%" mkdir "%STAGING%"
if not exist "%~dp0third_party" mkdir "%~dp0third_party"

echo [*] Downloading official Hashcat Windows release...
echo     Source: https://hashcat.net/hashcat/
echo.

REM Prefer known release asset; update URL/version when bumping.
set "HC_URL=https://hashcat.net/files/hashcat-6.2.6.7z"
set "HC_URL_ZIP=https://github.com/hashcat/hashcat/releases/download/v6.2.6/hashcat-6.2.6.7z"

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$ProgressPreference='SilentlyContinue';" ^
  "$urls=@('%HC_URL%','%HC_URL_ZIP%');" ^
  "$out='%ZIP%';" ^
  "$ok=$false;" ^
  "foreach($u in $urls){" ^
  "  try {" ^
  "    Write-Host ('[*] GET ' + $u);" ^
  "    Invoke-WebRequest -Uri $u -OutFile $out -UseBasicParsing;" ^
  "    if ((Test-Path $out) -and ((Get-Item $out).Length -gt 1000000)) { $ok=$true; break }" ^
  "  } catch { Write-Host ('[!] ' + $_.Exception.Message) }" ^
  "};" ^
  "if(-not $ok){ exit 2 }"

if errorlevel 1 (
  echo.
  echo [E] Automated download failed.
  echo     1. Download Hashcat Windows binaries from https://hashcat.net/hashcat/
  echo     2. Extract so that hashcat.exe sits at:
  echo          %HC_EXE%
  echo     3. Re-run this script or start TrueWalletCollider.exe
  exit /b 2
)

echo [*] Extracting...
REM .7z needs tar (Win10+) or 7-Zip; try tar first then Expand if zip
where tar >nul 2>&1
if not errorlevel 1 (
  if not exist "%HC_DIR%" mkdir "%HC_DIR%"
  tar -xf "%ZIP%" -C "%STAGING%" 2>nul
)

REM Locate extracted hashcat.exe and copy tree into third_party\hashcat
set "FOUND="
for /r "%STAGING%" %%F in (hashcat.exe) do (
  if not defined FOUND set "FOUND=%%~dpF"
)
if not defined FOUND (
  echo [E] hashcat.exe not found after extract.
  echo     If the archive is .7z, install 7-Zip and extract manually to %HC_DIR%
  echo     Or place hashcat.exe there and re-run.
  exit /b 3
)

echo [*] Installing from !FOUND!
if exist "%HC_DIR%" rmdir /s /q "%HC_DIR%" 2>nul
mkdir "%HC_DIR%" 2>nul
xcopy /E /I /Y "!FOUND!*" "%HC_DIR%\" >nul
if not exist "%HC_EXE%" (
  echo [E] Copy failed — %HC_EXE% missing
  exit /b 4
)

echo [+] Installed:
"%HC_EXE%" --version 2>nul
echo.
echo [*] Cleanup staging (optional keep for cache^)
rmdir /s /q "%STAGING%" 2>nul

echo.
echo =============================================
echo  Setup complete. Launch:
echo    TrueWalletCollider.exe
echo  Hashcat Bridge will detect third_party\hashcat.
echo =============================================
exit /b 0
