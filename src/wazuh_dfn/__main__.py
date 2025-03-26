#
# Project name: Wazuh DFN
# Project URL: https://github.com/ZIMK/wazuh-dfn

"""
Wazuh DFN script.

This script provides functionality for running the Wazuh DFN service.
"""

from wazuh_dfn.main import main

if __name__ == "__main__":
    if __package__ is None:
        import sys
        from pathlib import Path

        sys.path.append(str(Path(__file__).parent.parent))
        del sys, Path

    main()
