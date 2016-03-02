#!/usr/bin/env python

from setuptools import setup, Extension

bzip2 = Extension('libnsis-bzip2', [
    'src/nsis/bzip2/bzlib.c',
    'src/nsis/bzip2/decompress.c',
    'src/nsis/bzip2/huffman.c'
])

setup(name='NRS',
      version='0.1',
      description='NSIS Reversing Suite',
      author='isra17',
      author_email='isra017@gmail.com',
      packages=['nrs', 'libnsis'],

      setup_requires=['pytest-runner'],
      tests_require=['pytest'],
      ext_modules=[bzip2]
    )

