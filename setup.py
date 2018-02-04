#!/usr/bin/env python
from setuptools import setup, find_packages

setup(name='ioc-regex',
      version='1.0',
      description='ioc regex extractor',
      author='Adam Pridgen',
      author_email='adpridge@opendns.com',
      install_requires=['regex', 'bs4', 'requests'],
      packages=find_packages('src'),
      package_dir={'': 'src'},)
