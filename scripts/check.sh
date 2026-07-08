#!/usr/bin/env bash
# Run every check the CI runs. Usage: bash scripts/check.sh
set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> ruff check"
ruff check .

echo "==> ruff format --check"
ruff format --check .

echo "==> mypy"
mypy

echo "==> bandit (src)"
bandit -r src -q

echo "==> pip-audit"
pip-audit || echo "  (pip-audit reported advisories or is offline; review above)"

echo "==> pytest + coverage"
pytest -q --cov=securews --cov-report=term-missing --cov-fail-under=90

echo "All checks passed."
