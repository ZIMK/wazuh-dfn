# -*- coding: utf-8 -*-
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
        from os import path, sys

        sys.path.append(path.dirname(path.dirname(path.abspath(__file__))))
        del sys, path

    main()
