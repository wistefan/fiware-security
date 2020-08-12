data "openstack_networking_network_v2" "network" {
  name = var.external_pool
}