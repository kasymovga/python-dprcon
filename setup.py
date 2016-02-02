#!/usr/bin/env python2

from distutils.core import setup

_version = '1.1.1'

setup(
    name='dprcon',
    version=_version,
    description='A simple DarkPlaces RCON client library',
    author='Andrew "Akari" Alexeyew',
    author_email='akari@alienslab.net',
    py_modules=['dprcon'],
    url='https://github.com/nexAkari/python-dprcon',
    download_url='https://github.com/nexAkari/python-dprcon/tarball/%s' % _version,
    keywords=['networking', 'rcon', 'remote', 'admin', 'darkplaces', 'quake', 'rocketminsta', 'nexuiz', 'game'],
)
