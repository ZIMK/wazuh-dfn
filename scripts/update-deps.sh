#!/bin/bash

# Update dependencies within constraints
pdm update

# Export updated dependencies to requirements.txt
pdm export -f requirements --output requirements.txt --without-hashes

# Show what was updated
pdm outdated
