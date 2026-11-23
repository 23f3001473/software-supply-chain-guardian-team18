@echo off
REM Scans Juice Shop, runs the tests, then opens the dashboard.
setlocal
cd /d "%~dp0"
call .venv\Scripts\activate.bat || (echo Run setup.bat first. & exit /b 1)
set PYTHONUTF8=1

if exist target\juice-shop-scenario rmdir /s /q target\juice-shop-scenario
if exist reports\scenario rmdir /s /q reports\scenario

echo ==^> Scan: OWASP Juice Shop
python -m guardian.cli --repo target\juice-shop --out reports

echo.
echo ==^> Tests
python -m pytest -q

echo.
echo ==^> Dashboard on http://localhost:8501  (Ctrl+C to stop)
streamlit run app.py
endlocal
