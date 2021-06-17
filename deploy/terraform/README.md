## How to start it

* Create virtualenv and activate it:

      virtualenv -p python3.8 $NAME_VIRTUAL_ENV
      source $NAME_VIRTUAL_ENV/bin/activate

* Install the requirements:

      pip install -r requirements.txt

* Edit the setup variables to fit your setup. Open `vars/data.yml` and setup
  the variables as explained there.

* One all the variables are in place you should now be able to deploy and
  configure the service. Just run the following command:

      ansible-playbook -vvvv -i inventory.ini \
      --private-key=(Key pair to access to the instance) \
      provision.yml


# Generate public-private key
/terraform

    terraform-inventory.py init

If the plugin openstack is not installed (only the first time):

terraform init

terraform plan

terraform apply -auto-approve  

The process to create the network, subnetwork and VM need some times. 
Therefore, the associate floating IP can fail, need to wait a little.

(terraform destroy -auto-approve)

/ansible

We need to wait a little in order that the IP access is available to the
machine

ansible-playbook -vvvv -i inventory.ini \
--private-key=(Key pair to access to the instance) \
scan-deploy.yml

if we want to execute only the tasks for a proper hosts:

ansible-playbook -vvvv -i inventory.ini \
--private-key=(Key pair to access to the instance) \
scan-deploy.yml --tags mail-conf