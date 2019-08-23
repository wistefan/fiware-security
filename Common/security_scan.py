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
from pathlib import Path
from requests import get, put
from os.path import join
from subprocess import run
from os import system, getcwd, chdir, mkdir
from shutil import rmtree
from json import load
from datetime import datetime
from http import HTTPStatus
from logging import info, error
from Common.config_logging import LoggingConf

__author__ = 'Fernando López'


class SecurityScan(LoggingConf):
    def __init__(self, verbose):
        """
        Initialize the process, downloading the corresponding files
        :param verbose: Provide detailed information during the exeution, default True
        :return: Enabler's map
        """
        super(SecurityScan, self).__init__()

        if verbose is False:
            self.verbose = '2>/dev/null >/dev/null'
        else:
            self.verbose = ''

        self.NEXUS_USERNAME = '***'
        self.NEXUS_PASSWORD = '***'

        base_clair_repo = "https://raw.githubusercontent.com/flopezag/fiware-clair/develop/Common"
        current_directory = getcwd()
        common_directory = join(current_directory, 'Common')

        path_enablers_file = join(common_directory, 'enablers.json')
        self.path_docker_compose_file = join(common_directory, 'cve_severity_scan.yml')
        data = ''

        if Path(self.path_docker_compose_file).exists() is False:
            info("\nGetting CVE Severity Scan Compose file from repository...")

            r = get(join(base_clair_repo, 'cve_severity_scan.yml'))

            with open(self.path_docker_compose_file, 'w') as fd:
                fd.write(r.text)

        if Path(path_enablers_file).exists() is False:
            info("\nGetting enablers.json file from repository...")

            r = get(join(base_clair_repo, "enablers.json"))

            with open(path_enablers_file, 'w') as fd:
                fd.write(r.text)

            # Parse json file to generate the map
            data = r.json()
        else:
            # Read the content of the json file
            with open(path_enablers_file, 'r') as fd:
                data = load(fd)

        if Path('docker-bench-security').exists() is False:
            info("\nCloning CIS Docker Benchmark content from GitHub...")
            system("git clone https://github.com/docker/docker-bench-security.git {}".format(self.verbose))

        if Path('results').exists() is False:
            info("\nCreating the results directory...")
            mkdir(join(getcwd(), 'results'))

        self.enablers = data

    def post_data(self, filename):
        nexus_url = \
            'https://nexus.lab.fiware.org/repository/security/check/{}/cve/{}'.format(self.enablers['name'], filename)

        file = {'file': open(filename, 'r')}

        r = put(nexus_url, auth=(self.NEXUS_USERNAME, self.NEXUS_PASSWORD), files=file)

        if r.status_code != HTTPStatus.CREATED:
            error('Error uploading the content to Nexus')

    def __cve_severity__(self, enabler):
        """
        Execute the Clair Scan analysis over an image
        :param enabler: The data (name and docker image) of the FIWARE GE to analyse
        :return: The result of the analysis
        """
        name = enabler['name']
        image = enabler['image']

        info("    Pulling from {} ...\n".format(image))
        system("docker pull {} {}".format(image, self.verbose))

        # labels=$(docker inspect --type=image "$@" 2>/dev/null | jq .[].Config.Labels)

        info("\nSecurity analysis of {} image ...\n".format(image))
        extension = datetime.now().strftime('%Y%m%d_%H%M') + '_clair.json'
        filename = name + '_' + extension
        filename = filename.replace(" ", "_")

        system("docker-compose -f {} run --rm scanner {} > './results/{}'"
               .format(self.path_docker_compose_file, image, filename))

        # Just to finish, send the data to the nexus instance
        # post_data(enabler=enabler, filename=filename, verbose=verbose)

        # Send an email to the owner of the FIWARE GE

        return filename

    def __cis_docker_benchmark__(self, enabler):
        """
        Execute the Docker Bench Security Scan over an image
        :param enabler: The data (name and docker image) of the FIWARE GE to analyse
        :return: The result of the analysis
        """
        name = enabler['name']
        image = enabler['image']

        info("\nDocker bench analysis of {} image ...\n".format(image))

        current_dir = getcwd()
        chdir(join(current_dir, 'docker-bench-security'))

        # aux = subprocess.run(["docker images | grep -E {} | awk -e '{{print $3}}' ".format(image)],
        #                      shell=True,
        #                      capture_output=True)

        # docker-bench-security search by default the script/programm ss to work
        system("touch ss")
        system("chmod 764 ss")

        # In case of MacOS, change the "sed -r" command by the "sed -E" command
        command = "grep -rnw . -e 'sed -r' | sed 's/:/ /g' | awk '{print $1}'"
        aux = run([command], shell=True, capture_output=True)
        aux = aux.stdout.decode().rstrip()

        command = "sed -i .bk 's/sed -r/sed -E/g' {}".format(aux)
        system(command)

        command = "./docker-bench-security.sh  -t {} -c container_images,container_runtime,docker_security_operations" \
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

    def __security_scan__(self, enabler):
        """
        Process the security scan of the corresponding FIWARE GE
        :param enabler: The data (name and docker image) of the FIWARE GE to analyse
        :return:
        """

        filename1 = self.__cve_severity__(enabler=enabler)
        filename2 = self.__cis_docker_benchmark__(enabler=enabler)

        # Delete the docker image analysed
        info("\nDelete docker image ...\n".format(enabler['image']))
        system("docker rmi {} {}".format(enabler['image'], self.verbose))

        return {'clair': filename1, 'bench': filename2}

    def analysis(self, enabler):
        """
        Security Scan of the FIWARE GEs
        :param enabler: list of arguments, specially the enabler to be analysed
        :return:
        """
        result_files = list()

        if len(enabler) == 0:
            # The docker image is not specified, therefore we make the complete analysis of the docker images in the
            # enablers.json file
            info("\nPulling CVE Severity Scan content ...")
            system("docker-compose -f {} pull {}".format(self.path_docker_compose_file, self.verbose))

            info("\nMaking a complete security analysis of the FIWARE GEs")

            result_files = list(map(lambda x: self.__security_scan__(enabler=x), self.enablers['enablers']))
        else:
            # Check that the specified docker image is really a FIWARE GE
            fiware_enabler = list(filter(lambda x: x['image'] == enabler, self.enablers['enablers']))

            if len(fiware_enabler) == 0:
                error("\n{} is not a FIWARE GE or the docker image is not the expected one."
                      .format(enabler))
                exit(1)
            else:
                info("\nPulling CVE Severity Scan content ...")
                system("docker-compose -f {} pull {}".format(self.path_docker_compose_file, self.verbose))

                info("\nMaking a security analysis of the FIWARE GE: {}".format(fiware_enabler[0]['name']))

                result_files = list(map(lambda x: self.__security_scan__(enabler=x), fiware_enabler))

        self.__clean__()

        return result_files

    def __clean__(self):
        """
        Delete the dockers related to the Clair process and the corresponding images associated to them
        :return:
        """
        containers = ['arminc/clair-local-scan', 'arminc/clair-db', 'quay.io/usr42/clair-container-scan']

        docker_ps = 'docker ps --filter ancestor={} --format {{{{.ID}}}}'
        docker_images = 'docker images {} --format {{{{.ID}}}}'
        docker_stop = 'docker stop {} {}'
        docker_rm = 'docker rm {} {}'
        docker_rmi = 'docker rmi {} {}'

        # Delete the containers finished
        info("\nDelete the finished containers")
        for container in containers:
            aux = run([docker_ps.format(container)], shell=True, capture_output=True)
            aux = aux.stdout.decode().rstrip()

            if len(aux) != 0:
                system(docker_stop.format(aux, self.verbose))
                system(docker_rm.format(aux, self.verbose))

            aux = run([docker_images.format(container)], shell=True, capture_output=True)
            aux = aux.stdout.decode().rstrip()

            if len(aux) != 0:
                system(docker_rmi.format(aux, self.verbose))

        # Delete the folder in which was installed the docker-bench-security
        directory = Path('docker-bench-security')
        if directory.exists() is True:
            rmtree(directory)

    @staticmethod
    def print_data(ge, severities, best_practices):
        print("\n{}".format(ge['clair']))
        print("    CVE Severity")
        command_severity = 'more {} | jq ".[].vulnerabilities[].severity | select (.==\\\"{}\\\")" | wc -l'
        command_practices = 'more {} | jq ".tests[].results[].result | select (.==\\\"{}\\\")" | wc -l'

        for severity in severities:
            aux = run([command_severity.format(ge['clair'], severity)], shell=True, capture_output=True)
            aux = aux.stdout.decode().rstrip().replace(" ", "")
            print("        {}: {}".format(severity, aux))

        print("\n    CIS Docker Benchmark")
        for best_practice in best_practices:
            aux = run([command_practices.format(ge['bench'], best_practice)], shell=True, capture_output=True)
            aux = aux.stdout.decode().rstrip().replace(" ", "")
            print("        {}: {}".format(best_practice, aux))

    def summarize(self, args, files):
        if args.summarize is True:
            chdir(join(getcwd(), 'results'))

            # CVE Vulnerabilities
            severities = ['Low', 'Medium', 'High']
            results = ['PASS', 'INFO', 'NOTE', 'WARN']

            list(map(lambda ge: self.print_data(ge=ge, severities=severities, best_practices=results), files))
