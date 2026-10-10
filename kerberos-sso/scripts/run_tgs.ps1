# Launch Kerberos TGS (Group 3 — Bhumika) on Port 8002
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Resolve-Path "$ScriptDir\.."

Write-Host "Starting Kerberos Ticket Granting Server (TGS) on port 8002..." -ForegroundColor Cyan
Set-Location "$ProjectRoot\backend\kerberos-tgs"
python -m uvicorn main:app --reload --port 8002
