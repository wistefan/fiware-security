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

import subprocess
import os
import shutil
import sys
import argparse
from jinja2 import Template
from config.settings import USERNAME, TENANT_NAME, PASSWORD, AUTH_URL, REGION, DOMAIN_NAME, FLAVOR


def get_dynamic_inventory():
    with open("../ansible/inventory.ini", "w") as f:
        NAME_SERVER = "Security_Scan"
        cmd = ["/usr/local/bin/terraform", "output", NAME_SERVER]
        working_directory = os.getcwd()
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, cwd=working_directory)

        output_fixed = '''# Contains the web servers at backend network\n'''

        output_dynamic_name_server = NAME_SERVER

        output_dynamic_information_server = \
            "{}    ansible_host={}    ansible_user=ubuntu    ansible_connection=ssh"

        output_main_1 = ''
        output_main_2 = ''

        output_main = '''[secscan]'''

        for line in proc.stdout.readlines():
            data = line.decode("utf-8").split()
            if len(data) == 4:
                output_main_1 = output_main_1 + output_dynamic_name_server + '\n'
                output_main_2 = output_main_2 + output_dynamic_information_server.format(NAME_SERVER, data[0]) + '\n'

        output_fixed = output_fixed + \
                       output_main + '\n' + output_main_1 + output_main_2 + \
                       '\n'

        f.write(output_fixed)


def get_keypair():
    with open("tf_keypair_sec_scan", "w") as f:
        subprocess.check_call(["/usr/local/bin/terraform", "output", "Keypair"], stdout=f)

    os.chmod('tf_keypair_sec_scan', 0o600)

    source = './tf_keypair_sec_scan'
    target1 = '../ansible'

    # adding exception handling
    try:
        shutil.copy(source, target1)
    except IOError as e:
        print("Unable to copy file. %s" % e)
    except:
        print("Unexpected error:", sys.exc_info())


def cli():
    # create parser
    parser = argparse.ArgumentParser()

    # add arguments to the parser
    parser.add_argument('option',
                        help='''\
                        (instance) Generate the inventory.ini file and the corresponding Keypair.
                        (init) Init the terraform.tfvars files''')

    # parse the arguments
    args = parser.parse_args()

    if args.option is None:
        parser.print_help()
    elif args.option != "instance" and args.option != "init":
        parser.print_help()
    else:
        return args.option


def init_tfvars():
    with open('terraform.tfvars.j2', 'r') as out:
        template = out.read()

    tm = Template(template)
    msg = tm.render(USERNAME=USERNAME,
                    TENANT_NAME=TENANT_NAME,
                    PASSWORD=PASSWORD,
                    AUTH_URL=AUTH_URL,
                    REGION=REGION,
                    DOMAIN_NAME=DOMAIN_NAME,
                    FLAVOR=FLAVOR
    )

    with open('terraform.tfvars', 'w') as out:
        out.write(msg)


def get_dict_id(text):
    out_dict = dict()

    # Check if we have values
    if len(text) % 3 == 0:
        for i in range(0, int(len(text)/3)):
            out_dict[text[i * 3]] = text[i * 3 + 2]

    return out_dict


if __name__ == "__main__":
    option = cli()

    if option == 'instance':
        get_dynamic_inventory()
        get_keypair()
    elif option == 'init':
        init_tfvars()
