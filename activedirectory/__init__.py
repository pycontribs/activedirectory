#!/usr/bin/env python
from __future__ import absolute_import
import sys
from . import version
from .activedirectory import ActiveDirectory

__author__ = "Sorin Sbarnea"
__copyright__ = "Copyright 2014, Sorin Sbarnea"
__email__ = "sorin(dot)sbarnea(at)gmail.com"
__status__ = "Production"
__date__ = "2014-12-16"
__all__ = ['version']

if sys.hexversion < 0x02050000:
    sys.exit("Python 2.5 or newer is required by tendo module.")
