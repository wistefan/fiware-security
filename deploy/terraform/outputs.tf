#
# show the Public and Private IP addresses of the virtual machines
#
output "Security_Scan"	{
	value = "${openstack_compute_floatingip_v2.secscan_floating_ip.address} initialized with success"
}

output "Keypair" {
	value = openstack_compute_keypair_v2.secscan_keypair.private_key
}
