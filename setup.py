#!/usr/bin/env python2

from distutils.core import setup

setup(name='getnetguids',
      version='1.1.0',
      description='Extracts Typelib IDs and MVIDs from .NET assemblies.',
      author='Brian Wallace',
      url='https://github.com/bwall/getnetguids',
      py_modules=['getnetguids'],
      scripts=['getnetguids.py'],
      install_requires=['pefile', 'argparse'],
     )