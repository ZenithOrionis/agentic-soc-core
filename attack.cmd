@echo off
setlocal
python "%~dp0tools\demo-attack-runner\attack_runner.py" %*
exit /b %ERRORLEVEL%

