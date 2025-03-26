@echo off
setlocal EnableDelayedExpansion

echo Running code quality checks for tests...

echo.
echo Running Black (code formatting)...
pdm run black tests
if %ERRORLEVEL% neq 0 (
    echo Black check failed!
    exit /b 1
)

echo.
echo Running Ruff (linting)...
pdm run ruff check tests
if %ERRORLEVEL% neq 0 (
    echo Ruff check failed!
    exit /b 1
)

echo.
echo Running Pyright (type checking)...
pdm run pyright tests
if %ERRORLEVEL% neq 0 (
    echo Pyright check failed!
    exit /b 1
)

echo.
echo All checks passed successfully for tests!
exit /b 0
