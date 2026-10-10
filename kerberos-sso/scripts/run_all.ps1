# Launch all Kerberos Backend Servers in separate PowerShell windows
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Resolve-Path "$ScriptDir\.."

Write-Host "Launching Kerberos AS, TGS, and Service Server..." -ForegroundColor Green

Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$ProjectRoot\backend\kerberos-as'; Write-Host 'Kerberos AS running on http://127.0.0.1:8001' -ForegroundColor Cyan; python -m uvicorn main:app --reload --port 8001"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$ProjectRoot\backend\kerberos-tgs'; Write-Host 'Kerberos TGS running on http://127.0.0.1:8002' -ForegroundColor Magenta; python -m uvicorn main:app --reload --port 8002"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$ProjectRoot\backend\service-server'; Write-Host 'Service Server running on http://127.0.0.1:8003' -ForegroundColor Yellow; python -m uvicorn main:app --reload --port 8003"

Write-Host "All three services have been launched in separate windows!" -ForegroundColor Green
Write-Host "You can verify the live pipeline anytime with: python scripts/verify_kerberos_pipeline.py --live" -ForegroundColor Cyan
