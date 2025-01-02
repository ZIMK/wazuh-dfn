# wazuh-dfn <!-- omit in toc -->

[![GitHub releases](https://img.shields.io/github/release-pre/ZIMK/wazuh-dfn.svg)](https://github.com/ZIMK/wazuh-dfn/releases)

The `wazuh-dfn` is a specialized daemon that integrates Wazuh with DFN-CERT services. It monitors Wazuh alert files and forwards relevant security events to the DFN SOC (Security Operations Center) for advanced analysis and threat detection.

## Table of Contents <!-- omit in toc -->

- [Documentation](#documentation)
- [Installation](#installation)
  - [Requirements](#requirements)
  - [Install using pip](#install-using-pip)
- [Support](#support)
- [Maintainer](#maintainer)
- [Contributing](#contributing)
- [License](#license)


## Documentation

The documentation for wazuh-dfn can be found at
[https://zimk.github.io/wazuh-dfn/](https://zimk.github.io/wazuh-dfn/).
Please always take a look at the documentation for further details. This
**README** just gives you a short overview.

## Installation

### Requirements

Python 3.12 and later is supported.

### Install using pip

You can install the latest stable release of wazuh-dfn from the Python Package
Index using [pip](https://pip.pypa.io/):

    python3 -m pip install wazuh-dfn

## Support
If you found a problem with the software, please
[create an issue](https://github.com/ZIMK/wazuh-dfn/issues)
on GitHub.


## Maintainer

This project is maintained by [University of Trier - ZIMK](http://zimk.uni-trier.de/).

## Contributing

Your contributions are highly appreciated. Please
[create a pull request](https://github.com/ZIMK/wazuh-dfn/pulls) on GitHub.
For bigger changes, please discuss it first in the
[issues](https://github.com/ZIMK/wazuh-dfn/issues).

For development you should use [flit](https://flit.pypa.io)
to keep you python packages separated in different environments. First install
poetry via pip

```shell
python3 -m pip install --user flit
```

Afterwards run

```shell
flit build --no-use-vcs
flit install
```

## License

This project is licensed under the GNU Affero General Public License v3.0 - see the LICENSE file for details.
