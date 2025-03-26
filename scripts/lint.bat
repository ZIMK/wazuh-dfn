@echo off
setlocal EnableDelayedExpansion

echo Running code quality checks...

echo.
echo Running Black (code formatting)...
pdm run black src
if %ERRORLEVEL% neq 0 (
    echo Black check failed!
    exit /b 1
)

echo.
echo Running Ruff (linting)...
pdm run ruff check src
if %ERRORLEVEL% neq 0 (
    echo Ruff check failed!
    exit /b 1
)

echo.
echo Running Pyright (type checking)...
pdm run pyright src
if %ERRORLEVEL% neq 0 (
    echo Pyright check failed!
    exit /b 1
)

echo.
echo Running Import Checker...
python scripts\import_checker.py --check-all src
if %ERRORLEVEL% neq 0 (
    echo Import Checker found issues!
    exit /b 1
)

echo.
echo All checks passed successfully!
exit /b 0
