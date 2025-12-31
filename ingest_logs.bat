@echo off
if "%~1" == "" (
    echo Usage: ingest_logs.bat ^<path_to_log_file^>
    echo Example: ingest_logs.bat "c:\logs\huge_log_file.log"
    pause
    exit /b 1
)

echo Starting ingestion for: %~1
echo Ensuring dependencies are installed (tqdm is optional but recommended)
pip install tqdm >nul 2>&1

python ingest_pega_logs.py "%~1"
pause
