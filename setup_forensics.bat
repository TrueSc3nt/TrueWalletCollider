@echo off
setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0"

echo =============================================
echo  TrueWalletCollider - setup_forensics
echo  Bundles Hashcat + Python + BTCRecover + John
echo  Made by TrueScent — authorized use only
echo =============================================
echo.

set "ROOT=%~dp0"
set "TP=%ROOT%third_party"
set "STAGING=%TP%\_staging"
set "HC_DIR=%TP%\hashcat"
set "HC_EXE=%HC_DIR%\hashcat.exe"
set "PY_DIR=%TP%\python"
set "PY_EXE=%PY_DIR%\python.exe"
set "BTC_DIR=%TP%\btcrecover"
set "JOHN_DIR=%TP%\john"
set "ERR=0"

where powershell >nul 2>&1
if errorlevel 1 (
  echo [E] PowerShell required.
  exit /b 1
)

if not exist "%TP%" mkdir "%TP%"
if not exist "%STAGING%" mkdir "%STAGING%"

set "SEVEN="
if exist "%ProgramFiles%\7-Zip\7z.exe" set "SEVEN=%ProgramFiles%\7-Zip\7z.exe"
if exist "%ProgramFiles(x86)%\7-Zip\7z.exe" set "SEVEN=%ProgramFiles(x86)%\7-Zip\7z.exe"

echo.
echo --- [1/4] Hashcat ---
if exist "%HC_EXE%" (
  echo [+] Hashcat already present:
  "%HC_EXE%" --version 2>nul
) else (
  set "HC_ZIP=%STAGING%\hashcat.7z"
  powershell -NoProfile -ExecutionPolicy Bypass -File "%ROOT%scripts\fetch_file.ps1" -Url "https://hashcat.net/files/hashcat-6.2.6.7z" -OutFile "!HC_ZIP!"
  if errorlevel 1 powershell -NoProfile -ExecutionPolicy Bypass -File "%ROOT%scripts\fetch_file.ps1" -Url "https://github.com/hashcat/hashcat/releases/download/v6.2.6/hashcat-6.2.6.7z" -OutFile "!HC_ZIP!"
  if errorlevel 1 (
    echo [!] Hashcat download failed — place hashcat.exe under third_party\hashcat\
    set "ERR=1"
  ) else (
    if exist "%STAGING%\hashcat_extract" rmdir /s /q "%STAGING%\hashcat_extract" 2>nul
    mkdir "%STAGING%\hashcat_extract" 2>nul
    if defined SEVEN (
      "%SEVEN%" x "!HC_ZIP!" -o"%STAGING%\hashcat_extract" -y >nul
    ) else if exist "%ProgramFiles%\7-Zip\7z.exe" (
      "%ProgramFiles%\7-Zip\7z.exe" x "!HC_ZIP!" -o"%STAGING%\hashcat_extract" -y >nul
    ) else (
      where tar >nul 2>&1 && tar -xf "!HC_ZIP!" -C "%STAGING%\hashcat_extract" 2>nul
    )
    set "FOUND="
    for /r "%STAGING%\hashcat_extract" %%F in (hashcat.exe) do (
      if not defined FOUND set "FOUND=%%~dpF"
    )
    if not defined FOUND (
      echo [E] hashcat.exe not found after extract — install 7-Zip and re-run
      set "ERR=1"
    ) else (
      if exist "%HC_DIR%" rmdir /s /q "%HC_DIR%" 2>nul
      mkdir "%HC_DIR%" 2>nul
      xcopy /E /I /Y "!FOUND!*" "%HC_DIR%\" >nul
      if exist "%HC_EXE%" (
        echo [+] Installed Hashcat:
        "%HC_EXE%" --version 2>nul
      ) else (
        echo [E] Hashcat copy failed
        set "ERR=1"
      )
    )
  )
)

echo.
echo --- [2/4] Embeddable Python ---
if exist "%PY_EXE%" (
  echo [+] Python already present:
  "%PY_EXE%" --version 2>nul
) else (
  set "PY_ZIP=%STAGING%\python-embed.zip"
  powershell -NoProfile -ExecutionPolicy Bypass -File "%ROOT%scripts\fetch_file.ps1" -Url "https://www.python.org/ftp/python/3.12.8/python-3.12.8-embed-amd64.zip" -OutFile "!PY_ZIP!"
  if errorlevel 1 (
    echo [!] Python embed download failed
    set "ERR=1"
  ) else (
    if exist "%PY_DIR%" rmdir /s /q "%PY_DIR%" 2>nul
    mkdir "%PY_DIR%" 2>nul
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Expand-Archive -LiteralPath '!PY_ZIP!' -DestinationPath '%PY_DIR%' -Force"
    if not exist "%PY_EXE%" (
      echo [E] python.exe missing after extract
      set "ERR=1"
    ) else (
      for %%F in ("%PY_DIR%\python*._pth") do (
        >"%%~fF" echo python312.zip
        >>"%%~fF" echo .
        >>"%%~fF" echo Lib\site-packages
        >>"%%~fF" echo import site
      )
      REM Disable isolated ._pth so BTCRecover imports + PYTHONPATH work
      for %%F in ("%PY_DIR%\python*._pth") do move /y "%%~fF" "%%~fF.disabled" >nul 2>&1
      set "GETPIP=%STAGING%\get-pip.py"
      powershell -NoProfile -ExecutionPolicy Bypass -File "%ROOT%scripts\fetch_file.ps1" -Url "https://bootstrap.pypa.io/get-pip.py" -OutFile "!GETPIP!"
      if not errorlevel 1 "%PY_EXE%" "!GETPIP!" --no-warn-script-location
      echo [+] Python:
      "%PY_EXE%" --version 2>nul
    )
  )
)

echo.
echo --- [3/4] BTCRecover ---
if exist "%BTC_DIR%\btcrecover.py" (
  echo [+] BTCRecover already present
) else (
  set "BTC_ZIP=%STAGING%\btcrecover.zip"
  powershell -NoProfile -ExecutionPolicy Bypass -File "%ROOT%scripts\fetch_file.ps1" -Url "https://github.com/3rdIteration/btcrecover/archive/refs/heads/master.zip" -OutFile "!BTC_ZIP!"
  if errorlevel 1 (
    echo [!] BTCRecover download failed
    set "ERR=1"
  ) else (
    if exist "%STAGING%\btc_extract" rmdir /s /q "%STAGING%\btc_extract" 2>nul
    mkdir "%STAGING%\btc_extract" 2>nul
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Expand-Archive -LiteralPath '!BTC_ZIP!' -DestinationPath '%STAGING%\btc_extract' -Force"
    set "FOUND="
    for /d %%D in ("%STAGING%\btc_extract\btcrecover*") do (
      if exist "%%~D\btcrecover.py" set "FOUND=%%~D"
    )
    if not defined FOUND (
      echo [E] btcrecover.py not found after extract
      set "ERR=1"
    ) else (
      if exist "%BTC_DIR%" rmdir /s /q "%BTC_DIR%" 2>nul
      mkdir "%BTC_DIR%" 2>nul
      xcopy /E /I /Y "!FOUND!\*" "%BTC_DIR%\" >nul
      echo [+] BTCRecover installed
    )
  )
)

if exist "%PY_EXE%" if exist "%BTC_DIR%\requirements.txt" (
  echo [*] pip install btcrecover requirements (best-effort)...
  "%PY_EXE%" -m pip install -r "%BTC_DIR%\requirements.txt" --no-warn-script-location
)

echo.
echo --- [4/4] John the Ripper (jumbo) ---
set "JOHN_EXE="
if exist "%JOHN_DIR%\run\john.exe" set "JOHN_EXE=%JOHN_DIR%\run\john.exe"
if exist "%JOHN_DIR%\john.exe" set "JOHN_EXE=%JOHN_DIR%\john.exe"
if defined JOHN_EXE (
  echo [+] John already present: !JOHN_EXE!
) else (
  set "JOHN_ZIP=%STAGING%\john_win.zip"
  powershell -NoProfile -ExecutionPolicy Bypass -File "%ROOT%scripts\fetch_file.ps1" -Url "https://github.com/openwall/john-packages/releases/download/1.9.0-jumbo-1/x64_win.zip" -OutFile "!JOHN_ZIP!"
  if errorlevel 1 (
    echo [!] John download failed
    set "ERR=1"
  ) else (
    if exist "%STAGING%\john_extract" rmdir /s /q "%STAGING%\john_extract" 2>nul
    mkdir "%STAGING%\john_extract" 2>nul
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Expand-Archive -LiteralPath '!JOHN_ZIP!' -DestinationPath '%STAGING%\john_extract' -Force"
    set "FOUND="
    for /r "%STAGING%\john_extract" %%F in (john.exe) do (
      if not defined FOUND set "FOUND=%%~dpF"
    )
    if not defined FOUND (
      echo [E] john.exe not found after extract
      set "ERR=1"
    ) else (
      if exist "%JOHN_DIR%" rmdir /s /q "%JOHN_DIR%" 2>nul
      mkdir "%JOHN_DIR%" 2>nul
      set "SRC=!FOUND!"
      echo !FOUND! | findstr /i "\\run\\" >nul
      if not errorlevel 1 for %%P in ("!FOUND!..") do set "SRC=%%~fP"
      xcopy /E /I /Y "!SRC!\*" "%JOHN_DIR%\" >nul
      if exist "%JOHN_DIR%\run\john.exe" (
        echo [+] John installed
      ) else if exist "%JOHN_DIR%\john.exe" (
        echo [+] John installed
      ) else (
        echo [E] John copy layout unexpected
        set "ERR=1"
      )
    )
  )
)

if not exist "%ROOT%data\bip39_english.txt" (
  if not exist "%ROOT%data" mkdir "%ROOT%data"
  powershell -NoProfile -ExecutionPolicy Bypass -File "%ROOT%scripts\fetch_file.ps1" -Url "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt" -OutFile "%ROOT%data\bip39_english.txt"
)

(
  echo @echo off
  echo cd /d "%%~dp0"
  echo if exist "hashcat\hashcat.exe" ^("hashcat\hashcat.exe" %%* ^& exit /b %%ERRORLEVEL%%^)
  echo echo [E] hashcat missing — run setup_forensics.bat
  echo exit /b 1
) > "%TP%\run_hashcat.bat"

(
  echo @echo off
  echo cd /d "%%~dp0"
  echo set "PYTHONPATH=%%~dp0btcrecover"
  echo if not exist "python\python.exe" ^(echo [E] python missing ^& exit /b 1^)
  echo if not exist "btcrecover\btcrecover.py" ^(echo [E] btcrecover missing ^& exit /b 1^)
  echo cd /d "%%~dp0btcrecover"
  echo "%%~dp0python\python.exe" btcrecover.py %%*
) > "%TP%\run_btcrecover.bat"

(
  echo @echo off
  echo cd /d "%%~dp0"
  echo if exist "john\run\john.exe" ^("john\run\john.exe" %%* ^& exit /b %%ERRORLEVEL%%^)
  echo if exist "john\john.exe" ^("john\john.exe" %%* ^& exit /b %%ERRORLEVEL%%^)
  echo echo [E] john missing — run setup_forensics.bat
  echo exit /b 1
) > "%TP%\run_john.bat"

(
  echo TrueWalletCollider forensic bundle status
  echo Made by TrueScent
  echo.
  if exist "%HC_EXE%" (echo HASHCAT=OK) else (echo HASHCAT=MISSING)
  if exist "%PY_EXE%" (echo PYTHON=OK) else (echo PYTHON=MISSING)
  if exist "%BTC_DIR%\btcrecover.py" (echo BTCRECOVER=OK) else (echo BTCRECOVER=MISSING)
  if exist "%JOHN_DIR%\run\john.exe" (echo JOHN=OK) else if exist "%JOHN_DIR%\john.exe" (echo JOHN=OK) else (echo JOHN=MISSING)
) > "%TP%\FORENSICS_STATUS.txt"

echo.
echo =============================================
echo  Smoke checks
echo =============================================
if exist "%HC_EXE%" (
  echo [hashcat --version]
  "%HC_EXE%" --version
) else echo [!] hashcat missing

if exist "%PY_EXE%" if exist "%BTC_DIR%\btcrecover.py" (
  echo [btcrecover --help]
  "%PY_EXE%" "%BTC_DIR%\btcrecover.py" --help 2>&1 | more +0
) else echo [!] btcrecover / python missing

if exist "%JOHN_DIR%\run\john.exe" (
  echo [john]
  "%JOHN_DIR%\run\john.exe" 2>&1 | findstr /i "John"
) else if exist "%JOHN_DIR%\john.exe" (
  "%JOHN_DIR%\john.exe" 2>&1 | findstr /i "John"
) else echo [!] john missing

echo.
echo Launchers: third_party\run_hashcat.bat / run_btcrecover.bat / run_john.bat
echo Status:    third_party\FORENSICS_STATUS.txt
echo Telegram:  https://t.me/TrueScent
exit /b 0
