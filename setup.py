#!/usr/bin/env python

from setuptools import setup

setup(name='NRS',
      version='0.1',
      description='NSIS Reversing Suite',
      author='isra17',
      author_email='isra017@gmail.com',
      packages=['nrs'],

      setup_requires=['pytest-runner'],
      tests_require=['pytest'],
    )

