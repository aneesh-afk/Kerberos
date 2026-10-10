# Launch Kerberos AS (Group 3 — Sahil) on Port 8001
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Resolve-Path "$ScriptDir\.."

Write-Host "Starting Kerberos Authentication Server (AS) on port 8001..." -ForegroundColor Cyan
Set-Location "$ProjectRoot\backend\kerberos-as"
python -m uvicorn main:app --reload --port 8001
