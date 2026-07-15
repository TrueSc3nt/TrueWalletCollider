@echo off
setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0"

echo =============================================
echo  TrueWalletCollider - one-click install
echo  Made by TrueScent
echo  Telegram: https://t.me/TrueScent
echo =============================================
echo.
echo  This will:
echo    1) Run setup_forensics.bat (fetch Hashcat, Python,
echo       BTCRecover, John, clones into third_party\)
echo    2) Optionally build TrueWalletCollider.exe
echo       ^(needs VS C++ tools + CUDA Toolkit + CMake^)
echo.
echo  Authorized use only.
echo.

set "SETUP_RC=0"
set "BUILD_RC=0"
set "DID_BUILD=0"

echo ---------------------------------------------
echo  [1/2] Fetching forensic tools...
echo ---------------------------------------------
call "%~dp0setup_forensics.bat"
set "SETUP_RC=!ERRORLEVEL!"
if not "!SETUP_RC!"=="0" (
  echo.
  echo [!] setup_forensics finished with warnings/errors ^(code !SETUP_RC!^).
  echo     Core GUI may still work; check third_party\FORENSICS_STATUS.txt
) else (
  echo.
  echo [+] Forensic tools setup finished.
)

echo.
echo ---------------------------------------------
echo  [2/2] Optional: build TrueWalletCollider.exe
echo ---------------------------------------------
if exist "%~dp0TrueWalletCollider.exe" (
  echo [i] TrueWalletCollider.exe is already present in this folder.
)
echo.
choice /C YN /M "Build TrueWalletCollider.exe now"
if errorlevel 2 goto :after_build
if errorlevel 1 goto :do_build
goto :after_build

:do_build
set "DID_BUILD=1"
echo.
echo [*] Building via build_cuda.bat ...
call "%~dp0build_cuda.bat"
set "BUILD_RC=!ERRORLEVEL!"
if not "!BUILD_RC!"=="0" (
  echo.
  echo [E] Build failed ^(code !BUILD_RC!^).
  echo     Install Visual Studio C++ tools, CUDA Toolkit 12.x/13.x, and CMake,
  echo     then re-run build_cuda.bat ^(or this INSTALL.bat^).
) else (
  echo.
  echo [+] Build succeeded.
)

:after_build
echo.
echo =============================================
echo  INSTALL COMPLETE
echo =============================================
echo  Made by TrueScent  ^|  https://t.me/TrueScent
echo.
if exist "%~dp0TrueWalletCollider.exe" (
  echo  Launch the GUI:
  echo    TrueWalletCollider.exe
  echo.
  echo  Or double-click TrueWalletCollider.exe in this folder.
  echo.
  echo  Useful checks:
  echo    TrueWalletCollider.exe --tools-status
  echo    TrueWalletCollider.exe --catalog-count
) else (
  echo  TrueWalletCollider.exe not found yet.
  if "!DID_BUILD!"=="0" (
    echo  Run build_cuda.bat when VS + CUDA + CMake are installed,
    echo  or re-run INSTALL.bat and answer Y to build.
  ) else (
    echo  Fix the build errors above, then re-run build_cuda.bat.
  )
)
echo.
echo  Forensic bundle status: third_party\FORENSICS_STATUS.txt
echo  Docs: docs\QUICKSTART.md
echo  License: LICENSE ^(MIT^) — see THIRD_PARTY_NOTICES.md for deps
echo =============================================
echo.

if not "!SETUP_RC!"=="0" if not "!BUILD_RC!"=="0" (
  pause
  exit /b 1
)
if not "!BUILD_RC!"=="0" if "!DID_BUILD!"=="1" (
  pause
  exit /b !BUILD_RC!
)
if not "!SETUP_RC!"=="0" (
  pause
  exit /b !SETUP_RC!
)
pause
exit /b 0
