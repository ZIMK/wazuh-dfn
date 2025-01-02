.. wazuh-dfn documentation master file, created by
   sphinx-quickstart on Thu Jan  2 09:32:54 2025.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

wazuh-dfn documentation
=======================

The **wazuh-dfn** is a specialized daemon that integrates Wazuh with DFN-CERT services. It monitors Wazuh alert files and forwards relevant security events to the DFN SOC (Security Operations Center) for advanced analysis and threat detection.

.. note:: **wazuh-dfn** requires at least Python 3.12. Python 2 is not supported.

User Guide
----------

This sections explains how to install and configure **wazuh-dfn**.

.. toctree::
   :maxdepth: 2

   about
   installation
   configuration
   troubleshooting
