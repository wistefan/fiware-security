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

__author__ = 'fla'

"""File with Constants used in DesksReminder project.
"""

VERBOSE = '2>/dev/null >/dev/null'

MESSAGE = 'Dear FIWARE GE owner,' + \
          '\n\nHow result of the Security Analysis task force, we have identified' + \
          '\na set of posible security issues in your FIWARE GE component' + \
          '\n({}), based on the docker images analysed. We recommend to take' + \
          '\na deep view on the attached files and try to resolve them as soon' + \
          '\nas possible.' + \
          '\n\nThanks in advance for your cooperation!' + \
          '\n\nKind Regards,' + \
          '\nFernando'

SUBJECT = '[Security Analysis] Analysis of docker image: {}'

SIGNATURE = '\n\n------------------------' +\
            '\nFernando Lopez' +\
            '\nInterim FIWARE Security Analyst'

GOOGLE_ACCOUNTS_BASE_URL = 'https://accounts.google.com'
