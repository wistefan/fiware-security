#
# Create a security group
#
resource "openstack_compute_secgroup_v2" "sec_group" {
    region = ""
    name = "tf_sec_group"
    description = "Security Group Via Terraform"
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
resource "openstack_compute_keypair_v2" "keypair" {
  region = var.openstack_region
  name = "tf_keypair_sec_scan"
}


#
# Create network interface
#
resource "openstack_networking_network_v2" "network" {
  name = "tf_network"
  admin_state_up = "true"
  region = var.openstack_region
}

resource "openstack_networking_subnet_v2" "subnetwork" {
  name = "tf_subnetwork"
  network_id = openstack_networking_network_v2.network.id
  cidr = "10.0.0.0/24"
  ip_version = 4
  dns_nameservers = ["8.8.8.8","8.8.4.4"]
  region = var.openstack_region
}

resource "openstack_networking_router_v2" "router" {
  name = "tf_router"
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
resource "openstack_compute_floatingip_v2" "floating_ip" {
    region = var.openstack_region
    pool = "public-ext-net-01"
}


#
# Create the VM Instance for Security Scan
#
resource "openstack_compute_instance_v2" "security_scan" {
  name = "tf_SecScan"
  image_name = var.image
  availability_zone = var.availability_zone
  flavor_name = var.openstack_flavor
  key_pair = openstack_compute_keypair_v2.keypair.name
  security_groups = [openstack_compute_secgroup_v2.sec_group.name]
  network {
    uuid = openstack_networking_network_v2.network.id
  }
}

#
# Associate public IPs to the VMs
#
resource "openstack_compute_floatingip_associate_v2" "associate_fip" {
  floating_ip = openstack_compute_floatingip_v2.floating_ip.address
  instance_id = openstack_compute_instance_v2.security_scan.id
}
