#!/usr/bin/env python

from setuptools import setup, Extension

bzip2 = Extension('_bzip2', [
    'ext/bzip2/bzlib.i',
    'ext/bzip2/bzlib.c',
    'ext/bzip2/decompress.c',
    'ext/bzip2/huffman.c'
])

setup(name='NRS',
      version='0.1',
      description='NSIS Reversing Suite',
      author='isra17',
      author_email='isra017@gmail.com',
      packages=['nrs'],

      setup_requires=['pytest-runner'],
      tests_require=['pytest'],
      ext_modules=[bzip2]
    )

