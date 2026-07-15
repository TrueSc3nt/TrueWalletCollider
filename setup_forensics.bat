@echo off
setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0"

echo =============================================
echo  TrueWalletCollider - setup_forensics
echo  Maximalist DFIR pack: Hashcat/John/BTCRecover
echo  + pywallet, Volatility3, MetaMask/Exodus tools,
echo  + seed/OCR clones, aLEAPP/iLEAPP, carvers, more
echo  Made by TrueScent — authorized use only
echo  https://t.me/TrueScent
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

where git >nul 2>&1
set "HASGIT=%ERRORLEVEL%"

goto :clone_helper_defined
:clone_repo
rem %1=dir name under third_party  %2=git url
set "TARGET=%TP%\%~1"
if exist "%TARGET%\.git" (
  echo [+] %~1 already cloned
  exit /b 0
)
if exist "%TARGET%" (
  echo [+] %~1 folder present
  exit /b 0
)
if not "%HASGIT%"=="0" (
  echo [!] git missing — skip clone %~1
  set "ERR=1"
  exit /b 1
)
echo [*] Cloning %~1 ...
git clone --depth 1 "%~2" "%TARGET%"
if errorlevel 1 (
  echo [!] clone failed %~1
  set "ERR=1"
  exit /b 1
)
echo [+] Cloned %~1
exit /b 0

:clone_helper_defined

echo.
echo --- [1/N] Hashcat ---
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
echo --- [2/N] Embeddable Python ---
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
echo --- [3/N] BTCRecover ---
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
  echo [*] pip install btcrecover requirements - best effort
  "%PY_EXE%" -m pip install -r "%BTC_DIR%\requirements.txt" --no-warn-script-location
)

echo.
echo --- [4/N] John the Ripper jumbo ---
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

echo.
echo --- [5/N] pywallet + forensic Python clones ---
call :clone_repo pywallet https://github.com/jackjack-jj/pywallet.git
call :clone_repo pywallet-gsc https://github.com/Great-Software-Company/pywallet.git
call :clone_repo metamask_pwn https://github.com/cyclone-github/metamask_pwn.git
call :clone_repo hashcat_26620_kernel https://github.com/cyclone-github/hashcat_26620_kernel.git
call :clone_repo metamask-leveldb-forensic-tools https://github.com/alibabahalalmeat/metamask-leveldb-forensic-tools.git
call :clone_repo seed-sweep https://github.com/freeide/seed-sweep.git
call :clone_repo Image-Seed-Phrase-Finder https://github.com/Lahwom/Image-Seed-Phrase-Finder.git
call :clone_repo seed_parser https://github.com/xironix/seed_parser.git
call :clone_repo seed-phrase-scanner https://github.com/Arien10/seed-phrase-scanner.git
call :clone_repo cupp https://github.com/Mebus/cupp.git
call :clone_repo Autopsy-Plugins https://github.com/markmckinnon/Autopsy-Plugins.git

echo.
echo --- [6/N] Volatility3 via pip into embed python ---
if exist "%PY_EXE%" (
  echo [*] pip install volatility3 - best effort
  "%PY_EXE%" -m pip install volatility3 --no-warn-script-location
  if not exist "%TP%\volatility3" mkdir "%TP%\volatility3"
  (
    echo @echo off
    echo "%%~dp0..\python\python.exe" -m volatility3 %%*
  ) > "%TP%\volatility3\run_vol.bat"
  echo [+] volatility3 launcher: third_party\volatility3\run_vol.bat
) else (
  echo [!] Python missing - skip volatility3
  set "ERR=1"
)

echo.
echo --- [7/N] Mobile LEAPP + experimental GPU seed repos ---
call :clone_repo iLEAPP https://github.com/abrignoni/iLEAPP.git
call :clone_repo aLEAPP https://github.com/abrignoni/ALEAPP.git
call :clone_repo seedcat https://github.com/seed-cat/seedcat.git
call :clone_repo Hydra https://github.com/Julienbxl/Hydra.git
call :clone_repo CUDA_Mnemonic_Recovery https://github.com/XopMC/CUDA_Mnemonic_Recovery.git
call :clone_repo WalletForge https://github.com/morningstarnasser/WalletForge.git
call :clone_repo BitcoinCarver https://github.com/Haniamin90/BitcoinCarver.git
call :clone_repo bip39-brute https://github.com/georg95/bip39-brute.git
call :clone_repo bitcoin_electrum_cracking https://github.com/ipsbruno3/bitcoin_electrum_cracking.git
call :clone_repo Exodus-Seco-To-Passphrase https://github.com/KaratelSH/Exodus-Seco-To-Passphrase.git
call :clone_repo kwprocessor https://github.com/hashcat/kwprocessor.git
call :clone_repo princeprocessor https://github.com/hashcat/princeprocessor.git
call :clone_repo CeWL https://github.com/digininja/CeWL.git
call :clone_repo plaso https://github.com/log2timeline/plaso.git

echo.
echo --- [8/N] PhotoRec/TestDisk portable - best effort ---
if exist "%TP%\testdisk\photorec_win.exe" (
  echo [+] PhotoRec already present
) else if exist "%TP%\testdisk\photorec.exe" (
  echo [+] PhotoRec already present
) else (
  set "TD_ZIP=%STAGING%\testdisk.zip"
  powershell -NoProfile -ExecutionPolicy Bypass -File "%ROOT%scripts\fetch_file.ps1" -Url "https://www.cgsecurity.org/testdisk-7.2.win64.zip" -OutFile "!TD_ZIP!"
  if errorlevel 1 (
    echo [!] TestDisk/PhotoRec download failed — optional carve lane
  ) else (
    if exist "%STAGING%\td_extract" rmdir /s /q "%STAGING%\td_extract" 2>nul
    mkdir "%STAGING%\td_extract" 2>nul
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Expand-Archive -LiteralPath '!TD_ZIP!' -DestinationPath '%STAGING%\td_extract' -Force"
    set "FOUND="
    for /r "%STAGING%\td_extract" %%F in (photorec*.exe) do (
      if not defined FOUND set "FOUND=%%~dpF"
    )
    if defined FOUND (
      if exist "%TP%\testdisk" rmdir /s /q "%TP%\testdisk" 2>nul
      mkdir "%TP%\testdisk" 2>nul
      xcopy /E /I /Y "!FOUND!*" "%TP%\testdisk\" >nul
      echo [+] TestDisk/PhotoRec installed
    ) else (
      echo [!] photorec exe not found after extract
    )
  )
)

echo.
echo --- [9/N] Launchers + status ---
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
  echo @echo off
  echo cd /d "%%~dp0"
  echo if not exist "python\python.exe" ^(echo [E] python missing ^& exit /b 1^)
  echo if exist "pywallet\pywallet.py" ^("python\python.exe" "pywallet\pywallet.py" %%* ^& exit /b %%ERRORLEVEL%%^)
  echo echo [E] pywallet missing
  echo exit /b 1
) > "%TP%\run_pywallet.bat"

(
  echo TrueWalletCollider forensic bundle status
  echo Made by TrueScent — https://t.me/TrueScent
  echo.
  if exist "%HC_EXE%" (echo HASHCAT=OK) else (echo HASHCAT=MISSING)
  if exist "%PY_EXE%" (echo PYTHON=OK) else (echo PYTHON=MISSING)
  if exist "%BTC_DIR%\btcrecover.py" (echo BTCRECOVER=OK) else (echo BTCRECOVER=MISSING)
  if exist "%JOHN_DIR%\run\john.exe" (echo JOHN=OK) else if exist "%JOHN_DIR%\john.exe" (echo JOHN=OK) else (echo JOHN=MISSING)
  if exist "%TP%\pywallet\pywallet.py" (echo PYWALLET=OK) else (echo PYWALLET=MISSING)
  if exist "%TP%\metamask_pwn" (echo METAMASK_PWN=OK) else (echo METAMASK_PWN=MISSING)
  if exist "%TP%\volatility3\run_vol.bat" (echo VOLATILITY3=OK) else (echo VOLATILITY3=MISSING)
  if exist "%TP%\iLEAPP" (echo ILEAPP=OK) else (echo ILEAPP=MISSING)
  if exist "%TP%\aLEAPP" (echo ALEAPP=OK) else (echo ALEAPP=MISSING)
  if exist "%TP%\seedcat" (echo SEEDCAT=OK) else (echo SEEDCAT=MISSING)
  if exist "%TP%\Hydra" (echo HYDRA=OK) else (echo HYDRA=MISSING)
  if exist "%TP%\CUDA_Mnemonic_Recovery" (echo CUDA_MNEMONIC=OK) else (echo CUDA_MNEMONIC=MISSING)
  if exist "%TP%\testdisk" (echo PHOTOREC=OK) else (echo PHOTOREC=MISSING)
  if exist "%HC_DIR%\tools\exodus2hashcat.py" (echo EXODUS2HASHCAT=OK) else (echo EXODUS2HASHCAT=CHECK_HASHCAT_TOOLS)
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
echo Launchers: third_party\run_*.bat
echo Status:    third_party\FORENSICS_STATUS.txt
echo Catalog:   TrueWalletCollider.exe --catalog-count / --tools-status
echo GUI:       Tool Bay tab
echo Commercial tools: install licensed copies separately ^(Integration Hub^)
echo Telegram:  https://t.me/TrueScent
exit /b 0
