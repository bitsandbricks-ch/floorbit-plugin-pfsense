# pfSense / OPNsense for Floorbit

[![Test and release](https://github.com/bitsandbricks-ch/floorbit-plugin-pfsense/actions/workflows/release.yml/badge.svg?branch=main)](https://github.com/bitsandbricks-ch/floorbit-plugin-pfsense/actions/workflows/release.yml?query=branch%3Amain)

The `pfsense` plugin for [Floorbit](https://github.com/bitsandbricks-ch/floorbit): a pfSense or OPNsense firewall on the health wall (gateways, CPU and memory, DHCP pools) and in the inventory.
Install it under Settings > Plugins > Marketplace; how to set it up is in Floorbit's
[docs/plugins.md](https://github.com/bitsandbricks-ch/floorbit/blob/master/docs/plugins.md).

## Firewalls

| Firewall | How it reads | Settings |
| --- | --- | --- |
| pfSense CE / Plus | The [REST API package](https://pfrest.org) (API v2): `status/system`, `system/hostname`, `system/version`, `status/gateways`, `services/dhcp_servers`, `status/dhcp_server/leases` | URL and an API key (System > REST API > Keys) of a user with read access. |
| OPNsense | Its own API: `routes/gateway/status`, `diagnostics/system/system_information`, `diagnostics/system/system_resources` | URL, API key and secret of a user with read access to those pages. |

On the health wall:

- **The firewall** (kind firewall): CPU and memory, amber from 90%. OPNsense: memory only.
- **Each gateway** (kind uplink): delay and loss; amber on loss or delay, red when down.
- **Each DHCP pool** (kind dhcp, pfSense only): free addresses, amber from the warning setting (80%), red from 95%.

The firewall also goes into the inventory with the role `firewall`, so the
[firewall view](https://github.com/bitsandbricks-ch/floorbit/blob/master/docs/firewalls.md) can use
it. IP to MAC for check-in comes from the firewall's DHCP syslog, not from this plugin
([docs/syslog.md](https://github.com/bitsandbricks-ch/floorbit/blob/master/docs/syslog.md)).

Only names and counts leave the hall: never a lease's address, MAC or host name.

<!-- TODO(Mike): checked against the pfrest.org and OPNsense API docs, not yet against a real
firewall. Run the Test button on one at the next event and report what it says. -->

## What is where

| File | What |
| --- | --- |
| `plugin.yaml` | The manifest: settings and what it may touch. |
| `plugin.py` | The plugin. Floorbit runs it on the local agent in the hall, which reaches the firewall on the event network. |
| `tests/` | Tests against a fake pfSense and OPNsense, with Floorbit at the commit in `FLOORBIT_REF`. No network. |

## Testing

```
git clone https://github.com/bitsandbricks-ch/floorbit ../floorbit
git -C ../floorbit checkout "$(cat FLOORBIT_REF)"
pip install -r ../floorbit/requirements.txt pytest ruff
ruff check --config ../floorbit/pyproject.toml --config 'lint.isort.known-third-party=["floorbit"]' .
PYTHONPATH=../floorbit python -m pytest -q tests
```

## Releasing

Put the new version into `plugin.yaml`, add a `## <version>` section to `CHANGELOG.md`, merge, then
push the tag (or `mason release tag floorbit-plugin-pfsense`):

```
git tag v1.0.0 && git push origin v1.0.0
```

The [workflow](.github/workflows/release.yml) tests it, signs `pfsense-<version>.tar.gz` with the
Floorbit plugin key (environment `plugin-signing`, secret `FLOORBIT_PLUGIN_SIGNING_KEY`) and
attaches it to the GitHub release. The Marketplace picks it up within the hour. A version is
withdrawn in [floorbit-plugins](https://github.com/bitsandbricks-ch/floorbit-plugins)' `plugins.yaml`,
never by deleting the release.
