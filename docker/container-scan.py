#!/usr/bin/env python
# -*- encoding: utf-8 -*-
##
# Copyright 2017 FIWARE Foundation, e.V.
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
import argparse
from pathlib import Path
import requests
from os.path import join, dirname
import subprocess
from os import system, getcwd, chdir
import json
from datetime import datetime
from http import HTTPStatus

NEXUS_USERNAME = "security"
NEXUS_PASSWORD = "7amtDUqr1#2P"


def generate_argparser():
    """
    Generate arguments parser
    :return:
    """
    parser = argparse.ArgumentParser(description='Perform security analysis of the FIWARE GE docker images.')

    parser.add_argument('-p', '--pull', action="store_true", dest="pull", required=False, default=False,
                        help="Pull the docker image from Docker Hub")

    parser.add_argument('-v', '--verbose', action="store_true", dest="verbose", required=False, default=False,
                        help="Verbose screen output")

    parser.add_argument('-d', '--docker_image', action="store", dest="docker_image", required=False, default='',
                        help="Name of the Docker Image to be analysed. If it is not provided the Docker images "
                             "are obtained from the enablers.json file.")

    return parser


def init(verbose):
    """
    Initialize the process, downloading the corresponding files
    :return: Enabler's map
    """
    base_clair_repo = "https://raw.githubusercontent.com/flopezag/fiware-clair/develop/docker"
    data = ''

    if Path('docker-compose.yml').exists() is False:
        print("Getting docker-compose.yml file from repository...")

        r = requests.get(join(base_clair_repo, "docker-compose.yml"))

        with open("docker-compose.yml", 'w') as fd:
            fd.write(r.text)

    if Path('enablers.json').exists() is False:
        print("Getting enablers.json file from repository...")

        r = requests.get(join(base_clair_repo, "enablers.json"))

        with open("enablers.json", 'w') as fd:
            fd.write(r.text)

        # Parse json file to generate the map
        data = r.json()
    else:
        # Read the content of the json file
        with open("enablers.json", 'r') as fd:
            data = json.load(fd)

    if Path('../docker-bench-security').exists() is False:
        print("Cloning docker-bench-security from GitHub...")
        # change directory to the parents
        current_dir = getcwd()
        chdir(dirname(current_dir))
        system("git clone https://github.com/docker/docker-bench-security.git")
        chdir(current_dir)

    return data


def post_data(enabler, filename, verbose):
    nexus_url = 'https://nexus.lab.fiware.org/repository/security/check/{}/cve/{}'.format(enabler['name'], filename)

    file = {'file': open(filename, 'r')}

    r = requests.put(nexus_url, auth=(NEXUS_USERNAME, NEXUS_PASSWORD), files=file)

    if r.status_code != HTTPStatus.CREATED:
        print('ERROR Uploading the content to Nexus')


def clair_analysis(enabler, verbose):
    """
    Execute the Clair Scan analysis over an image
    :param enabler: The data (name and docker image) of the FIWARE GE to analyse
    :return: The result of the analysis
    """
    name = enabler['name']
    image = enabler['image']

    print("    Pulling from {} ...\n".format(image))
    system("docker pull {} {}".format(image, verbose))
    print()

    # labels=$(docker inspect --type=image "$@" 2>/dev/null | jq .[].Config.Labels)

    print("Security analysis of {} image ...\n".format(image))
    extension = datetime.now().strftime('%Y%m%d_%H%m') + '.json'
    filename = name + '_' + extension

    system("docker-compose run --rm scanner {} > '{}'".format(image, filename))

    # Just to finish, send the data to the nexus instance
    # post_data(enabler=enabler, filename=filename, verbose=verbose)

    # Send an email to the owner of the FIWARE GE


def docker_bench_analysis(enabler, verbose):
    """
    Execute the Docker Bench Security Scan over an image
    :param enabler: The data (name and docker image) of the FIWARE GE to analyse
    :return: The result of the analysis
    """
    name = enabler['name']
    image = enabler['image']

    print("Docker bench analysis of {} image ...\n".format(image))

    current_dir = getcwd()
    chdir(join(dirname(current_dir), 'docker-bench-security'))

    aux = subprocess.run(["docker images | grep -E {} | awk -e '{{print $3}}' ".format(image)],
                         shell=True,
                         capture_output=True)

    command = "./docker-bench-security.sh  -t {} -c container_images,container_runtime,docker_security_operations"\
        .format(image)

    extension = datetime.now().strftime('%Y%m%d_%H%m') + '.json'
    filename = name + '_' + extension

    system(command)

    system("mv docker-bench-security.sh.log.json {}".format(filename))

    # Just to finish, send the data to the nexus instance
    # post_data(enabler=enabler, filename=filename, verbose=verbose)

    '''
    redirect_all ./docker-bench-security.sh  -t "$@" -c container_images,container_runtime,docker_security_operations

    extension="$(date +%Y%m%d_%H%M%S).json"
    filename=$(echo "$@" | awk -F '/' -v a="$extension" '{print $2 a}')
    enabler=$(echo "$@" | awk -F '/' '{print $2}')

    mv docker-bench-security.sh.log.json ${filename}

    redirect_all echo "Clean up the docker image..."
    redirect_all docker rmi ${id}
    redirect_all echo

    redirect_all curl -v -u ${user}':'${password} --upload-file ${filename}  https://nexus.lab.fiware.org/repository/security/check/${enabler}/bench-security/${filename}

    cd ../clair-container-scan
    '''
    chdir(current_dir)

    return "a filename"


def security_scan(enabler, verbose):
    """
    Process the security scan of the corresponding FIWARE GE
    :param enabler: The data (name and docker image) of the FIWARE GE to analyse
    :return:
    """

    # clair_analysis(enabler=enabler, verbose=verbose)
    docker_bench_analysis(enabler=enabler, verbose=verbose)

    # Delete the docker image analised
    print("Delete docker image ...\n".format(enabler['image']))
    system("docker rmi {} {}".format(enabler['image'], verbose))


def scan(args):
    """

    :param args:
    :return:
    """
    args.docker_image = 'fiware/orion'

    if args.verbose is False:
        verbose = '2>/dev/null >/dev/null'

    if len(args.docker_image) == 0:
        # The docker image is not specified, therefore we make the complete analysis of the docker images in the
        # enablers.json file
        print("\nPulling Clair content ...")
        system("docker-compose pull {}".format(verbose))

        print("\nMaking a complete security analysis of the FIWARE GEs")

        list(map(lambda x: security_scan(enabler=x, verbose=verbose), enablers['enablers']))
    else:
        # Check that the specified docker image is really a FIWARE GE
        enabler = list(filter(lambda x: x['image'] == args.docker_image, enablers['enablers']))

        if len(enabler) == 0:
            print("\nERROR: {} is not a FIWARE GE or the docker image is not the expected one.".format(args.docker_image))
            exit(1)
        else:
            print("\nPulling Clair content ...")
            system("docker-compose pull {}".format(verbose))

            print("\nMaking a security analysis of the FIWARE GE: {}".format(enabler[0]['name']))

            list(map(lambda x: security_scan(enabler=x, verbose=verbose), enabler))


if __name__ == "__main__":
    p1 = generate_argparser()

    args = p1.parse_args()

    enablers = init(verbose=args.verbose)

    scan(args=args)

    print('Finished')
