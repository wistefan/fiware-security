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
from os import system, getcwd, chdir, mkdir, rename, remove
from shutil import rmtree
from json import load
from datetime import datetime
from http import HTTPStatus
from logging import info, error
from Common.config_logging import LoggingConf
from Config.constants import SUBJECT, MESSAGE
from Config.settings import CODEHOME, NEXUS_URL, NEXUS_PASSWORD, NEXUS_USER
from docker import from_env
from git.repo.base import Repo
from yaml import dump
from Common.emailer import Emailer
from pathlib import Path

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

        self.NEXUS_USERNAME = NEXUS_USER
        self.NEXUS_PASSWORD = NEXUS_PASSWORD
        self.NEXUS_URL = NEXUS_URL

        base_clair_repo = "https://raw.githubusercontent.com/flopezag/fiware-clair/develop/Common"
        current_directory = getcwd()

        if 'fiware-clair' in current_directory:
            common_directory = join(current_directory, 'Common')
        else:
            common_directory = join(join(current_directory, 'fiware-clair'), 'Common')

        path_enablers_file = join(common_directory, 'enablers.json')
        self.path_docker_compose_file = join(common_directory, 'cve_severity_scan.yml')

        if Path(self.path_docker_compose_file).exists() is False:
            info("Getting CVE Severity Scan Compose file from repository...")

            r = get(join(base_clair_repo, 'cve_severity_scan.yml'))

            with open(self.path_docker_compose_file, 'w') as fd:
                fd.write(r.text)

        if Path(path_enablers_file).exists() is False:
            info("Getting enablers.json file from repository...")

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
            info("Cloning CIS Docker Benchmark content from GitHub...")
            Repo.clone_from("https://github.com/docker/docker-bench-security.git", "./docker-bench-security")

        if Path('results').exists() is False:
            info("Creating the results directory...")
            mkdir(join(getcwd(), 'results'))

        self.enablers = data
        self.client = from_env()
        self.emailer = Emailer()

    def __post_data__(self, enabler, folder, filename):
        nexus_url = join(self.NEXUS_URL, '{}/{}/{}')
        nexus_url = nexus_url.format(enabler['name'], folder, filename)

        path_filename = join(CODEHOME, join('results', filename))

        file = {'file': open(path_filename, 'r')}

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

        info("Pulling from {} ...".format(image))
        self.client.images.pull(image)

        info("Security analysis of {} image ...".format(image))
        extension = datetime.now().strftime('%Y%m%d_%H%M') + '_clair.json'
        filename = name + '_' + extension
        filename = filename.replace(" ", "_")

        command = "docker-compose -f {} run --rm scanner {} > ./results/{} 2>/dev/null" \
            .format(self.path_docker_compose_file, image, filename)
        aux = run([command], shell=True, capture_output=True)
        info(aux)

        # Just to finish, send the data to the nexus instance
        self.__post_data__(enabler=enabler, folder='cve', filename=filename)

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

        info("Docker bench analysis of {} image ...".format(image))

        current_dir = getcwd()
        chdir(join(current_dir, 'docker-bench-security'))

        # docker-bench-security search by default the script/programm ss to work
        Path('ss').touch(mode=0o764)

        # In case of MacOS, change the "sed -r" command by the "sed -E" command
        command = "grep -rnw . -e 'sed -r' | sed 's/:/ /g' | awk '{print $1}'"
        aux = run([command], shell=True, capture_output=True)
        info(aux)
        aux = aux.stdout.decode().rstrip()

        command = "sed -i .bk 's/sed -r/sed -E/g' {}".format(aux)
        aux = run([command], shell=True, capture_output=True)
        info(aux)

        command = \
            "docker-bench-security.sh  -t {} -c container_images,container_runtime,docker_security_operations {}" \
            .format(image, self.verbose)

        aux = run([command], shell=True, capture_output=True)
        info(aux)

        extension = datetime.now().strftime('%Y%m%d_%H%M') + '_bench.json'
        filename = name + '_' + extension
        filename = filename.replace(" ", "_")

        rename('docker-bench-security.sh.log.json', '../results/{}'.format(filename))

        # Just to finish, send the data to the nexus instance
        self.__post_data__(enabler=enabler, folder='cis', filename=filename)

        remove('ss')
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
        info("Delete docker image ...".format(enabler['image']))
        self.client.images.remove(enabler['image'])

        return {'clair': filename1, 'bench': filename2, 'name': enabler['name']}

    def analysis(self, enabler):
        """
        Security Scan of the FIWARE GEs
        :param enabler: list of arguments, specially the enabler to be analysed
        :return:
        """
        info("Starting analysis ...")
        result_files = list()

        if len(enabler) == 0:
            # The docker image is not specified, therefore we make the complete analysis of the docker images in the
            # enablers.json file
            info("Pulling CVE Severity Scan content ...")
            system("docker-compose -f {} pull {}".format(self.path_docker_compose_file, self.verbose))

            info("Making a complete security analysis of the FIWARE GEs")

            result_files = list(map(lambda x: self.__security_scan__(enabler=x), self.enablers['enablers']))
        else:
            # Check that the specified docker image is really a FIWARE GE
            fiware_enabler = list(filter(lambda x: x['image'] == enabler, self.enablers['enablers']))

            if len(fiware_enabler) == 0:
                error("{} is not a FIWARE GE or the docker image is not the expected one."
                      .format(enabler))
                exit(1)
            else:
                info("Pulling CVE Severity Scan content ...")
                system("docker-compose -f {} pull {}".format(self.path_docker_compose_file, self.verbose))

                info("Making a security analysis of the FIWARE GE: {}".format(fiware_enabler[0]['name']))

                result_files = list(map(lambda x: self.__security_scan__(enabler=x), fiware_enabler))

        self.__clean__()

        self.__send_emails__(data=result_files)

        return result_files

    def __send_emails__(self, data):
        def __send__(ge):
            # Just for now all the emails are sent to fernando, pending to add the email information in the
            # enablers.json and in future in the scripts to get the data from Google
            ge['email'] = 'fernando.lopez@fiware.org'

            current_wd = getcwd()
            if 'results' not in current_wd:
                chdir(join(current_wd, 'results'))

            subject = SUBJECT.format(ge['name'])
            message = MESSAGE.format(ge['name'])
            to = ge['email']
            attachments = [ge['bench'], ge['clair']]

            self.emailer.send_msg_attachment(to=to,
                                             subject=subject,
                                             body=message,
                                             attachments=attachments)

        list(map(lambda ge: __send__(ge=ge), data))

    def __clean__(self):
        """
        Delete the dockers related to the Clair process and the corresponding images associated to them
        :return:
        """
        containers = ['arminc/clair-local-scan', 'arminc/clair-db', 'quay.io/usr42/clair-container-scan']

        # Delete the containers finished
        info("Delete the finished containers")
        for container in containers:
            aux = self.client.containers.list(all=True, filters={'ancestor': '{}'.format(container)})
            aux = list(map(lambda x: x.id, aux))

            if len(aux) != 0:
                # docker_stop = 'docker stop {} {}'
                list(map(lambda x: self.client.containers.get(x).stop(), aux))

                # docker_rm = 'docker rm {} {}'
                list(map(lambda x: self.client.containers.get(x).remove(), aux))

            # docker_images = 'docker images {} --format {{{{.ID}}}}'
            b = self.client.images.get(container)

            # docker_rmi = 'docker rmi {} {}'
            self.client.images.remove(b.id)

        # Delete the folder in which was installed the docker-bench-security
        directory = Path('docker-bench-security')
        if directory.exists() is True:
            rmtree(directory)

    @staticmethod
    def summarize(args, files):
        def print_data(ge, stdout=True):
            def count_data(items):
                dat_counts = [{x: items.count(x)} for x in set(items)]
                dat_counts = dict((key, d[key]) for d in dat_counts for key in d)

                return dat_counts

            def extract_result(items):
                desc = items['desc']
                result_items = list(map(lambda x: x['result'], items['results']))

                counts_items = count_data(result_items)

                return {desc: counts_items}

            # String to send the results to the log file
            output1 = ge['name'] + " - (CVE Severity)"
            # String to send the results to the usual output screen
            output2 = '\n{}'.format(ge['name']) + "\n    CVE Severity"

            with open(ge['clair'], 'r') as fd:
                data = load(fd)

            aux = list(map(lambda x: x['severity'], data[0]['vulnerabilities']))
            counts = count_data(aux)

            output1 = output1 + ": " + str(counts)
            aux = dump(counts, default_flow_style=False).replace('\n', '\n\t')
            output2 = output2 + "\n\t" + aux
            fd.close()

            info(output1)

            output1 = ge['name'] + ' - ' + "(CIS Docker Benchmark)"
            output2 = output2 + "\n    CIS Docker Benchmark"

            with open(ge['bench'], 'r') as fd:
                data = load(fd)

            result = list(map(lambda x: extract_result(x), data['tests']))
            result = dict((key, d[key]) for d in result for key in d)

            output1 = output1 + ": " + str(result)
            aux = dump(result, default_flow_style=False).replace('\n', '\n\t')
            output2 = output2 + "\n\t" + aux
            fd.close()

            output2 = output2 + "\n\n ... Finished"

            info(output1)

            if stdout is True:
                print(output2)

            info("... Finished")

        # Starting the summarize method ...
        current_wd = getcwd()
        if 'results' not in current_wd:
            chdir(join(current_wd, 'results'))

        list(map(lambda ge: print_data(ge=ge, stdout=args.summarize), files))
