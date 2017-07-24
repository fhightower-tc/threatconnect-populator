# -*- coding: utf-8 -*-
"""ThreatConnect Populator.

Usage:
  tc_populate [-c|--cleanup] <path_to_api_conf_file> <owner> 
  tc_populate -h | --help
  tc_populate --version

Options:
  -h, --help     Show this screen.
  --version     Show version.
  -c, --cleanup  Delete items after creation
"""

from docopt import docopt

from .__init__ import __version__ as VERSION
import tc_populate


def main(args=None):
    """Console script for python_boilerplate"""
    arguments = docopt(__doc__, version=VERSION)
    tc_populate.main(arguments)


if __name__ == "__main__":
    main()
