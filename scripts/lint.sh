#!/usr/bin/env bash

set -euo pipefail

echo "Running code quality checks..."

echo -e "\nRunning Black (code formatting)..."
pdm run black --check src tests

echo -e "\nRunning Ruff (linting)..."
pdm run ruff check src tests

echo -e "\nRunning Pyright (type checking)..."
pdm run pyright src

echo -e "\nRunning Import Checker..."
python scripts/import_checker.py --check-all src

echo -e "\nAll checks passed successfully!"
