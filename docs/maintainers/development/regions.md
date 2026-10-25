# region catalog

[`internal/region/catalog.json`](../../../internal/region/catalog.json) maps provider
compute-region identifiers to approximate tnl locations. provider regions in one
city can share a tnl code; this says nothing about network paths, billing, or
failure boundaries. the catalog includes historical DigitalOcean aliases for
existing workloads. only registered ingress and relay processes are eligible for
placement; adding a catalog entry never enables a server location.

verify new or changed aliases against provider inventories before editing the
catalog. the current mappings were checked on 2026-10-24 against:

- [AWS regions](https://docs.aws.amazon.com/global-infrastructure/latest/regions/aws-regions.html)
- [Google Cloud regions and zones](https://cloud.google.com/compute/docs/regions-zones)
- [Azure regions](https://learn.microsoft.com/en-us/azure/reliability/regions-list)
- [Fly regions](https://fly.io/docs/reference/regions/)
- [DigitalOcean datacenters](https://docs.digitalocean.com/platform/regional-availability/)
- [Hetzner locations](https://docs.hetzner.com/cloud/general/locations/)
- [Akamai/Linode region API](https://api.linode.com/v4/regions?page_size=500)
- [Vultr region API](https://api.vultr.com/v2/regions?per_page=500)
- [Oracle Cloud regions](https://docs.oracle.com/en-us/iaas/Content/General/Concepts/regions.htm)
- [Scaleway availability](https://www.scaleway.com/en/product-availability-by-region/)
