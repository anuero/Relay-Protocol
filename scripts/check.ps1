# Run every check the CI runs. Usage: powershell -File scripts/check.ps1
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

Write-Host "==> ruff check"
ruff check .

Write-Host "==> ruff format --check"
ruff format --check .

Write-Host "==> mypy"
mypy

Write-Host "==> bandit (src)"
bandit -r src -q

Write-Host "==> pip-audit"
pip-audit

Write-Host "==> pytest + coverage"
pytest -q --cov=securews --cov-report=term-missing --cov-fail-under=90

Write-Host "All checks passed."
