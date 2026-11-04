@echo off
chcp 65001 >nul
echo ============================================================
echo   BINARY ADVISOR — BUILD RELEASE .EXE
echo ============================================================
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0publish_release.ps1" -Mode All
if %ERRORLEVEL% EQU 0 (
    echo.
    echo [OK] Build hoan tat! File .EXE nam tai thu muc: dist\BinaryAdvisor_Standalone\BinaryAdvisor.exe
) else (
    echo.
    echo [ERROR] Co loi xay ra trong qua trinh build.
)
pause
