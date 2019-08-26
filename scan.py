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
from argparse import ArgumentParser
from Common.security_scan import SecurityScan

__author__ = 'Fernando López'


def generate_argparser():
    """
    Generate arguments parser
    :return:
    """
    parser = ArgumentParser(description='Perform security analysis of the FIWARE GE docker images.')

    parser.add_argument('-v', '--verbose', action="store_true", dest="verbose", required=False, default=False,
                        help="Verbose screen output")

    parser.add_argument('-p', '--pull', action="store_true", dest="pull", required=False, default=False,
                        help="Pull the docker image from Docker Hub")

    parser.add_argument('-s', '--summary', action="store_true", dest="summarize", required=False, default=False,
                        help="Create a summary of the security analysis.")

    parser.add_argument('-d', '--docker_image', action="store", dest="docker_image", required=False, default='',
                        help="Name of the Docker Image to be analysed. If it is not provided the Docker images "
                             "are obtained from the enablers.json file.")

    return parser


if __name__ == "__main__":
    p1 = generate_argparser()

    arguments = p1.parse_args()

    scan = SecurityScan(verbose=arguments.verbose)
    results = scan.analysis(enabler=arguments.docker_image)

    SecurityScan.summarize(args=arguments, files=results)
