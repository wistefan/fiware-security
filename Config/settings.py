#!/usr/bin/env python
# -*- encoding: utf-8 -*-
##
# Copyright 2019 FIWARE Foundation, e.V.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
##
from configparser import ConfigParser
from os.path import join, exists, dirname, abspath
from os import environ

__author__ = 'fla'

__version__ = '1.3.0'


"""
Default configuration.

The configuration `cfg_defaults` are loaded from `cfg_filename`, if file exists in
/etc/fiware.d/management.ini

Optionally, user can specify the file location manually using an Environment variable called CONFIG_FILE.
"""

name = 'FIWARE Security SCAN'

cfg_dir = "/etc/fiware.d"

if environ.get("CONFIG_FILE"):
    cfg_filename = environ.get("CONFIG_FILE")

else:
    cfg_filename = join(cfg_dir, '%s.ini' % name)

Config = ConfigParser()

Config.read(cfg_filename)


def config_section_map(section):
    dict1 = {}
    options = Config.options(section)

    for option in options:
        try:
            dict1[option] = Config.get(section, option)
            if dict1[option] == -1:
                print("skip: %s" % option)
        except Exception as e:
            print("exception on %s!" % option)
            print(e)
            dict1[option] = None

    return dict1


if Config.sections():
    # Nexus data section
    nexus_section = config_section_map("nexus")
    NEXUS_URL = nexus_section['url']
    NEXUS_USER = nexus_section['user']
    NEXUS_PASSWORD = nexus_section['password']

    # Logging data section
    logging_section = config_section_map("logging")
    LOGGING_LEVEL = logging_section['level']
    LOGGING_FILE = logging_section['file']

else:
    msg = '\nERROR: There is not defined CONFIG_FILE environment variable ' \
            '\n       pointing to configuration file or there is no management.ini file' \
            '\n       in the /etd/init.d directory.' \
            '\n\n       Please correct at least one of them to execute the program.\n\n\n'

    exit(msg)

# Settings file is inside Basics directory, therefore I have to go back to the parent directory
# to have the Code Home directory
CODEHOME = dirname(dirname(abspath(__file__)))
LOGHOME = join(CODEHOME, 'logs')
