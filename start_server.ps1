$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
if (-not (Get-Command node -ErrorAction SilentlyContinue)) { Write-Host "Node.js not found"; exit 1 }
if (Test-Path package.json) { npm install }
npm start