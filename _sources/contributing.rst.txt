Contributing to wazuh-dfn
=========================

Thank you for your interest in contributing to wazuh-dfn! This document provides guidelines and instructions for contributing to the project.

Development Setup
-----------------

1. Clone the repository:

.. code-block:: bash

   git clone https://github.com/ZIMK/wazuh-dfn.git
   cd wazuh-dfn

2. Install PDM (Python Dependency Manager):

.. code-block:: bash

   pip install pdm

3. Install project with development dependencies:

.. code-block:: bash

   pdm install

Code Style
----------

- Follow PEP 8 guidelines with a line length of 120 characters
- Use type hints for all function parameters and return values
- Write docstrings for all public functions and classes (Google docstring format)
- Use black for code formatting
- Use ruff for linting
- Properly type all async functions with appropriate return types

Testing
-------

1. Run the test suite:

.. code-block:: bash

   pdm run pytest

2. Ensure test coverage:

.. code-block:: bash

   pdm run pytest --cov=src/wazuh_dfn

3. Run async-specific tests:

.. code-block:: bash

   pdm run pytest --asyncio-mode=auto tests/

Pull Request Process
-------------------

1. Fork the repository
2. Create a feature branch (``git checkout -b feature/amazing-feature``)
3. Make your changes
4. Run the test suite and linting tools
5. Update documentation if needed
6. Commit your changes (``git commit -m 'Add amazing feature'``)
7. Push to your fork (``git push origin feature/amazing-feature``)
8. Open a Pull Request

Commit Messages
~~~~~~~~~~~~~~~

- Use the present tense ("Add feature" not "Added feature")
- Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
- Limit the first line to 72 characters
- Reference issues and pull requests in the body

Development Workflow
-------------------

1. Pick an issue to work on or create a new one
2. Discuss the proposed changes in the issue
3. Fork and clone the repository
4. Create a new branch for your changes
5. Make your changes
6. Write or update tests
7. Update documentation
8. Submit a pull request

Code Review Process
------------------

1. At least one maintainer must review and approve the changes
2. All automated checks must pass
3. Documentation must be updated if needed
4. Test coverage should not decrease

Release Process
--------------

1. Update version in pyproject.toml
2. Update CHANGELOG