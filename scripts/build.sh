# Install build tools first
python3 -m pip install --upgrade pip wheel setuptools pdm

# Clean and rebuild
pdm install
pdm build

pdm export -f requirements --output requirements.txt --without-hashes

pip install -e .
