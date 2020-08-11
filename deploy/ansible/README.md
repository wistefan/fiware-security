# Deploy FIWARE Docker Security Scan into a FIWARE Lab instance

This is the option when you want to deploy the solution using a FIWARE Lab instance.
Using Ansible and Ansible Roles, it is deploy a complete virtual machine in one FIWARE
Lab region and configure it in order to launch the dockers to obtain the security scan
over the images.

## Prerequisites

* Python v3.7
* pip
* virtualenv

## Execution

The first steps is the creation of the proper virtualenv:

```bash
virtualenv -p python3.7 env
```

Activate the virtual environment:

```bash
source env/bin/activate
```

Once we have it, we can install the dependencies, that in this case are the 
[OpenStack SDK](https://docs.openstack.org/openstacksdk) and the 
[Ansible](https://www.ansible.com/).

```bash
pip install -r ../requirements.txt
```

Keep in mind that the requirements file is located in the root folder. Before executing
the Ansible playbook, it is needed to define some variables inside the roles:

- [FIWARE Lab user credentials](roles/openstack-instance-deploy/defaults/main.yml). These is
the user account information in order to access [FIWARE Lab](https://cloud.lab.fiware.org). 
If you have questions about this information send us an email to <fiware-lab-help@lists.fiware.org>.
- [FIWARE Nexus user credentials](roles/clair-docker/defaults/main.yml). These are the user 
credentials needed to upload the security scan results into the corresponding FIWARE Nexus instance.

Afterthat, just execute the corresponding playbook with the following command:

```bash
ansible-playbook scan-deploy.yml 
```