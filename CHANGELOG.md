# Changelog

Each release has a section; its text becomes the GitHub release notes and the Marketplace's
"what's new". New entries are fragments in `changelog.d/`: `python scripts/changelog.py collect`
adds them under `## [Unreleased]`, and `mason bump` turns that into the version.

## 1.0.0

- First release: a pfSense (REST API package) or OPNsense firewall on the health wall (gateways,
  CPU and memory, DHCP pools on pfSense) and in the inventory.
