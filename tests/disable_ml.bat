@echo off
echo Setting NEXUS_DISABLE_ML environment variable to disable ML temporarily...
set NEXUS_DISABLE_ML=true
echo ML disabled for this session. Run your NEXUS commands now.
echo To re-enable ML, close this terminal and open a new one.
echo.
echo Example usage:
echo   python src\cli\nexus_cli.py ssh --port 8022 --llm-provider openai
echo   python src\cli\nexus_cli.py ftp --port 2121 --llm-provider gemini
echo.
cmd /k
