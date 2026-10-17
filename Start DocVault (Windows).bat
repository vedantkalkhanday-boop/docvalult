@echo off
rem Opens Vedant's Doc Vault on this PC.
rem It starts a tiny private server (reachable only from this PC) and opens the app in Microsoft Edge.
rem In Edge, click the "App available - Install Vedant's Doc Vault" icon in the address bar once.
rem After that, open Vedant's Doc Vault from the Start menu: it works fully offline and this file is no longer needed.
cd /d "%~dp0"
powershell -NoProfile -Command "try { (New-Object Net.Sockets.TcpClient('localhost', 8765)).Close(); exit 0 } catch { exit 1 }"
if errorlevel 1 start "Doc Vault server" /min powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0windows\serve.ps1" -Root "%~dp0."
timeout /t 2 /nobreak >nul
start "" msedge http://localhost:8765/
