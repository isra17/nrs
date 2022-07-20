#!/usr/bin/env python

from setuptools import setup, Extension

bzlib = Extension('nrs.ext.bzlib._bzlib', [
    'nrs/ext/bzlib/bzlib.i',
    'nrs/ext/bzlib/bzlib.c',
    'nrs/ext/bzlib/decompress.c',
    'nrs/ext/bzlib/huffman.c'
], depends=['nrs/ext/bzlib/bzlib.h'])

setup(name='nrs',
      version='0.2.5',
      description='NSIS Reversing Suite',
      long_description='',
      author='isra17',
      author_email='isra017@gmail.com',
      url='https://github.com/isra17/nrs',
      packages=['nrs','nrs.ext', 'nrs.ext.bzlib', 'nrs.ida', \
                'nrs.strings'],

      install_requires=['future'],
      setup_requires=['pytest-runner'],
      tests_require=['pytest'],
      ext_modules=[bzlib]
    )

