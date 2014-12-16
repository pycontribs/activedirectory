#!/usr/bin/env python
from __future__ import absolute_import

__author__ = "Sorin Sbarnea"
__copyright__ = "Copyright 2014, Sorin Sbarnea"
__email__ = "sorin(dot)sbarnea(at)gmail.com"
__status__ = "Production"
from . import version
__date__ = "2014-12-16"
__all__ = ['version']

import sys
if sys.hexversion < 0x02050000:
    sys.exit("Python 2.5 or newer is required by tendo module.")

from .activedirectory import ActiveDirectory
