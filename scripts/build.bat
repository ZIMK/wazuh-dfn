@echo off
setlocal enabledelayedexpansion

REM Install build tools first
python -m pip install --upgrade pip wheel setuptools pdm

REM Build package
pdm build
pdm install

pdm export -f requirements --output requirements.txt --without-hashes

pip install -e .
