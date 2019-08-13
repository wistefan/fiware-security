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
from os import system, getcwd, chdir, mkdir
import json
from datetime import datetime
from http import HTTPStatus

NEXUS_USERNAME = "****"
NEXUS_PASSWORD = "****"


def generate_argparser():
    """
    Generate arguments parser
    :return:
    """
    parser = argparse.ArgumentParser(description='Perform security analysis of the FIWARE GE docker images.')

    parser.add_argument('-p', '--pull',         action="store_true", dest="pull",         required=False, default=False,
                        help="Pull the docker image from Docker Hub")

    parser.add_argument('-v', '--verbose',      action="store_true", dest="verbose",      required=False, default=False,
                        help="Verbose screen output")

    parser.add_argument('-d', '--docker_image', action="store",      dest="docker_image", required=False, default='',
                        help="Name of the Docker Image to be analysed. If it is not provided the Docker images "
                             "are obtained from the enablers.json file.")

    parser.add_argument('-s', '--summarize',    action="store_true", dest="summarize",    required=False, default=False,
                        help="Create a summary of the security analysis.")

    return parser


def init(verbose):
    """
    Initialize the process, downloading the corresponding files
    :return: Enabler's map
    """
    base_clair_repo = "https://raw.githubusercontent.com/flopezag/fiware-clair/develop/docker"
    data = ''

    if Path('docker-compose.yml').exists() is False:
        print("\nGetting docker-compose.yml file from repository...")

        r = requests.get(join(base_clair_repo, "docker-compose.yml"))

        with open("docker-compose.yml", 'w') as fd:
            fd.write(r.text)

    if Path('enablers.json').exists() is False:
        print("\nGetting enablers.json file from repository...")

        r = requests.get(join(base_clair_repo, "enablers.json"))

        with open("enablers.json", 'w') as fd:
            fd.write(r.text)

        # Parse json file to generate the map
        data = r.json()
    else:
        # Read the content of the json file
        with open("enablers.json", 'r') as fd:
            data = json.load(fd)

    if Path('docker-bench-security').exists() is False:
        print("\nCloning docker-bench-security from GitHub...")
        system("git clone https://github.com/docker/docker-bench-security.git")

    if Path('results').exists() is False:
        print("\nCreating the results directory...")
        mkdir(join(getcwd(), 'results'))

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

    # labels=$(docker inspect --type=image "$@" 2>/dev/null | jq .[].Config.Labels)

    print("\nSecurity analysis of {} image ...\n".format(image))
    extension = datetime.now().strftime('%Y%m%d_%H%M') + '_clair.json'
    filename = name + '_' + extension
    filename = filename.replace(" ", "_")

    system("docker-compose run --rm scanner {} > './results/{}'".format(image, filename))

    # Just to finish, send the data to the nexus instance
    # post_data(enabler=enabler, filename=filename, verbose=verbose)

    # Send an email to the owner of the FIWARE GE

    return filename


def docker_bench_analysis(enabler, verbose):
    """
    Execute the Docker Bench Security Scan over an image
    :param enabler: The data (name and docker image) of the FIWARE GE to analyse
    :return: The result of the analysis
    """
    name = enabler['name']
    image = enabler['image']

    print("\nDocker bench analysis of {} image ...\n".format(image))

    current_dir = getcwd()
    # chdir(join(dirname(current_dir), 'docker-bench-security'))
    chdir(join(current_dir, 'docker-bench-security'))

    # aux = subprocess.run(["docker images | grep -E {} | awk -e '{{print $3}}' ".format(image)],
    #                      shell=True,
    #                      capture_output=True)

    # docker-bench-security search by default the script/programm ss to work
    system("touch ss")
    system("chmod 764 ss")

    # In case of MacOS, change the "sed -r" command by the "sed -E" command
    command = "grep -rnw . -e 'sed -r' | sed 's/:/ /g' | awk '{print $1}'"
    aux = subprocess.run([command], shell=True, capture_output=True)
    aux = aux.stdout.decode().rstrip()

    command = "sed -i .bk 's/sed -r/sed -E/g' {}".format(aux)
    system(command)

    command = "./docker-bench-security.sh  -t {} -c container_images,container_runtime,docker_security_operations"\
        .format(image)

    extension = datetime.now().strftime('%Y%m%d_%H%M') + '_bech.json'
    filename = name + '_' + extension
    filename = filename.replace(" ", "_")

    system(command)

    system("mv docker-bench-security.sh.log.json ../results/{}".format(filename))

    # Just to finish, send the data to the nexus instance
    # post_data(enabler=enabler, filename=filename, verbose=verbose)

    '''
    redirect_all curl -v -u ${user}':'${password} --upload-file ${filename}  
                       https://nexus.lab.fiware.org/repository/security/check/${enabler}/bench-security/${filename}

    cd ../clair-container-scan
    '''
    system("rm ss")
    chdir(current_dir)

    return filename


def security_scan(enabler, verbose):
    """
    Process the security scan of the corresponding FIWARE GE
    :param enabler: The data (name and docker image) of the FIWARE GE to analyse
    :return:
    """

    filename1 = clair_analysis(enabler=enabler, verbose=verbose)
    filename2 = docker_bench_analysis(enabler=enabler, verbose=verbose)

    # Delete the docker image analised
    print("\nDelete docker image ...\n".format(enabler['image']))
    system("docker rmi {} {}".format(enabler['image'], verbose))

    return {'clair': filename1, 'bench': filename2}


def scan(args, enablers):
    """

    :param args:
    :return:
    """
    if args.verbose is False:
        verbose = '2>/dev/null >/dev/null'
    else:
        verbose = ''

    if len(args.docker_image) == 0:
        # The docker image is not specified, therefore we make the complete analysis of the docker images in the
        # enablers.json file
        print("\nPulling Clair content ...")
        system("docker-compose pull {}".format(verbose))

        print("\nMaking a complete security analysis of the FIWARE GEs")

        files = list(map(lambda x: security_scan(enabler=x, verbose=verbose), enablers['enablers']))

        return files
    else:
        # Check that the specified docker image is really a FIWARE GE
        enabler = list(filter(lambda x: x['image'] == args.docker_image, enablers['enablers']))

        if len(enabler) == 0:
            print("\nERROR: {} is not a FIWARE GE or the docker image is not the expected one."
                  .format(args.docker_image))
            exit(1)
        else:
            print("\nPulling Clair content ...")
            system("docker-compose pull {}".format(verbose))

            print("\nMaking a security analysis of the FIWARE GE: {}".format(enabler[0]['name']))

            files = list(map(lambda x: security_scan(enabler=x, verbose=verbose), enabler))

            return files


def clean():
    """
    Delete the dockers related to the Clair process and the corresponding images associated to them
    :return:
    """
    containers = ['arminc/clair-local-scan', 'arminc/clair-db', 'quay.io/usr42/clair-container-scan']

    docker_ps = 'docker ps --filter ancestor={} --format {{{{.ID}}}}'
    docker_images = 'docker images {} --format {{{{.ID}}}}'
    docker_stop = 'docker stop {}'
    docker_rm = 'docker rm {}'
    docker_rmi = 'docker rmi {}'

    # Delete the containers finished
    print("\nDelete the finished containers")
    for container in containers:
        aux = subprocess.run([docker_ps.format(container)], shell=True, capture_output=True)
        aux = aux.stdout.decode().rstrip()

        if len(aux) != 0:
            system(docker_stop.format(aux))
            system(docker_rm.format(aux))

        aux = subprocess.run([docker_images.format(container)], shell=True, capture_output=True)
        aux = aux.stdout.decode().rstrip()

        if len(aux) != 0:
            system(docker_rmi.format(aux))


def print_data(ge, severities, best_practices):
    print("\n{}".format(ge['clair']))
    print("    CVE Severity")
    command_severity = 'more {} | jq ".[].vulnerabilities[].severity | select (.==\\\"{}\\\")" | wc -l'
    command_practices = 'more {} | jq ".tests[].results[].result | select (.==\\\"{}\\\")" | wc -l'

    for severity in severities:
        aux = subprocess.run([command_severity.format(ge['clair'], severity)], shell=True, capture_output=True)
        aux = aux.stdout.decode().rstrip().replace(" ", "")
        print("        {}: {}".format(severity, aux))

    print("\n    CIS Docker Benchmark")
    for best_practice in best_practices:
        aux = subprocess.run([command_practices.format(ge['bench'], best_practice)], shell=True, capture_output=True)
        aux = aux.stdout.decode().rstrip().replace(" ", "")
        print("        {}: {}".format(best_practice, aux))


def summarize(args, files):
    if args.summarize is True:
        chdir(join(getcwd(), 'results'))

        # CVE Vulnerabilities
        severities = ['Low', 'Medium', 'High']
        results = ['PASS', 'INFO', 'NOTE', 'WARN']
        list(map(lambda ge: print_data(ge=ge, severities=severities, best_practices=results), files))


if __name__ == "__main__":
    p1 = generate_argparser()

    args = p1.parse_args()

    enablers = init(verbose=args.verbose)

    files = scan(args=args, enablers=enablers)

    clean()

    summarize(args=args, files=files)

    print('\nFinished')
