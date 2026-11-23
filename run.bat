@echo off
REM Builds and serves the React dashboard using the local Guardian API.
setlocal
cd /d "%~dp0"
call .venv\Scripts\activate.bat || (echo Run setup.bat first. & exit /b 1)
set PYTHONUTF8=1

if not exist frontend\node_modules\.bin\vite.cmd (
  call npm --prefix frontend ci || exit /b 1
)
if not exist guardian\source_scanner\node_modules\typescript\lib\typescript.js (
  call npm ci --prefix guardian/source_scanner --ignore-scripts --no-audit --no-fund || exit /b 1
)
call npm --prefix frontend run build || exit /b 1

echo.
echo ==^> Dashboard on http://localhost:8501  (Ctrl+C to stop)
python app.py
endlocal
