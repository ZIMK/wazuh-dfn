@echo off

REM Update dependencies within constraints
pdm update

REM Export updated dependencies to requirements.txt
pdm export -f requirements --output requirements.txt --without-hashes

REM Show what was updated
echo Updated dependencies:
pdm outdated
