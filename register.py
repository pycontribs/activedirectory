#!/usr/bin/env python
#import pandoc
import os
import logging

#pandoc.core.PANDOC_PATH = 'python -m pandoc'

try:
   import pypandoc
   description = pypandoc.convert('README.md', 'rst')
except (IOError, ImportError) as e:
   logging.warn(e)
   description = open('README.md').read()

f = open('README.txt','w+')
f.write(description)
f.close()

"""
doc = pandoc.Document()
doc.markdown = open('README.md').read()
f = open('README.txt','w+')
print doc
print doc.rst
f.write(doc.rst)
f.close()
os.system("setup.py register")
os.remove('README.txt')
"""