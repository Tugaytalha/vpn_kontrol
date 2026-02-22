@echo off
cd /d "%~dp0"

REM Read python executable from config.json (default: python)
set PYTHON_CMD=python
if exist config.json (
    for /f "tokens=2 delims=:, " %%a in ('findstr /c:"python_executable" config.json') do (
        set PYTHON_CMD=%%~a
    )
)

echo VPN Kontrol Uygulamasi Baslatiliyor...
echo Tarayicidan erisebilirsiniz: http://localhost:5000
echo Pencereyi kapatirsaniz uygulama kapanir.
echo Arka planda calistirmak icin 'arkaplanda_baslat.vbs' dosyasini kullanin.
echo.
%PYTHON_CMD% app.py
pause
