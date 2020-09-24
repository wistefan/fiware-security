#
# Create a security group
#
resource "openstack_compute_secgroup_v2" "sec_group" {
    region = ""
    name = "secscan_sec_group"
    description = "Security Group Via Terraform for SecScan"
    rule {
        from_port = 22
        to_port = 22
        ip_protocol = "tcp"
        cidr = "0.0.0.0/0"
    }
}

#
# Create a keypair
#
resource "openstack_compute_keypair_v2" "secscan_keypair" {
  region = var.openstack_region
  name = "tf_keypair_sec_scan"
}


#
# Create network interface
#
resource "openstack_networking_network_v2" "network" {
  name = "secscan_network"
  admin_state_up = "true"
  region = var.openstack_region
}

resource "openstack_networking_subnet_v2" "subnetwork" {
  name = "secscan_subnetwork"
  network_id = openstack_networking_network_v2.network.id
  cidr = "10.0.0.0/24"
  ip_version = 4
  dns_nameservers = ["8.8.8.8","8.8.4.4"]
  region = var.openstack_region
}

resource "openstack_networking_router_v2" "router" {
  name = "secscan_router"
  admin_state_up = "true"
  region = var.openstack_region
  external_network_id = data.openstack_networking_network_v2.network.id
}

resource "openstack_networking_router_interface_v2" "router_interface" {
  router_id = openstack_networking_router_v2.router.id
  subnet_id = openstack_networking_subnet_v2.subnetwork.id
  region = var.openstack_region
}

#
# Create an Openstack Floating IP for the Main VM
#
resource "openstack_compute_floatingip_v2" "secscan_floating_ip" {
    region = var.openstack_region
    pool = "public-ext-net-01"
}


#
# Create the VM Instance for Security Scan
#
resource "openstack_compute_instance_v2" "security_scan" {
  name = "SecScan"
  image_name = var.image
  availability_zone = var.availability_zone
  flavor_name = var.openstack_flavor
  key_pair = openstack_compute_keypair_v2.secscan_keypair.name
  security_groups = [openstack_compute_secgroup_v2.sec_group.name]
  network {
    uuid = openstack_networking_network_v2.network.id
  }
}

#
# Associate public IPs to the VMs
#
resource "openstack_compute_floatingip_associate_v2" "associate_fip" {
  floating_ip = openstack_compute_floatingip_v2.secscan_floating_ip.address
  instance_id = openstack_compute_instance_v2.security_scan.id
}

# Generate the output files (keypair and inventory) for ansible
locals {
  template_keypair_init = templatefile("${path.module}/templates/keypair.tpl", {
    keypair = openstack_compute_keypair_v2.secscan_keypair.private_key
  }
  )

  template_inventory_init = templatefile("${path.module}/templates/ansible_inventory.tpl", {
    connection_strings = join("\n",
           formatlist("%s ansible_ssh_host=%s ansible_ssh_user=ubuntu ansible_connection=ssh",
                        openstack_compute_instance_v2.security_scan.name,
                        openstack_compute_floatingip_v2.secscan_floating_ip.address))

    list_nodes = openstack_compute_instance_v2.security_scan.name
  }
  )

}

resource "local_file" "keypair_file" {
  content = local.template_keypair_init
  filename = "../ansible/keypair"
  file_permission = "0600"
}

resource "local_file" "ansible_inventory" {
  content = local.template_inventory_init
  filename = "../ansible/inventory.ini"
  file_permission = "0600"
}