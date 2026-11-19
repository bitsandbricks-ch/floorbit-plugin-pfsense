"""A pfSense or OPNsense firewall for Floorbit's health wall and inventory.

pfSense has no API of its own: it needs the REST API package (pfrest.org, API v2), which answers
``{"code", "status", "data"}`` with an ``X-API-Key`` header. Read here:
``status/system`` (CPU, memory, platform, serial), ``system/hostname``, ``system/version``,
``status/gateways``, and for the pools ``services/dhcp_servers`` and ``status/dhcp_server/leases``.

OPNsense answers its own API with the key pair as basic auth: ``routes/gateway/status``,
``diagnostics/system/system_information`` and ``diagnostics/system/system_resources``.

Floorbit runs this on the local agent in the hall. Only counts and names leave: lease numbers per
pool, never a lease's address, MAC or host name.
"""
import ipaddress
import re
from urllib.parse import urlsplit

from floorbit.plugins.base import Plugin as Base
from floorbit.plugins.base import PluginError

POOL_FULL = 95           # % at which a pool turns red
BUSY = 90                # % CPU or memory at which the firewall turns amber
# pfSense: online, none (no monitoring), loss, delay, highloss, highdelay, down.
# OPNsense: none (online), loss, delay, delay+loss, down, force_down.
GW_DOWN = ('down', 'force_down', 'offline')
GW_WARN = ('loss', 'delay', 'highloss', 'highdelay', 'delay+loss')


def _num(value):
    """12.3 from 12.3, "12.3ms" or "12.3 %"; None when there's no number."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    found = re.search(r'-?\d+(?:\.\d+)?', str(value or ''))
    return float(found.group()) if found else None


def _round(value):
    return None if value is None else round(value, 1)


def _ip(text):
    try:
        return ipaddress.ip_address(str(text or '').strip())
    except ValueError:
        return None


class Plugin(Base):
    def _platform(self):
        return 'opnsense' if self.settings.get('platform') == 'opnsense' else 'pfsense'

    def _http(self):
        url = self.settings.get('url')
        key, secret = self.settings.get('api_key'), self.settings.get('api_secret')
        if self._platform() == 'opnsense':
            if not (url and key and secret):
                raise PluginError('Set the firewall URL, API key and API secret under Settings > Plugins first.')
            return self.ctx.http(url, timeout=15, auth=(key, secret))
        if not (url and key):
            raise PluginError('Set the firewall URL and API key under Settings > Plugins first.')
        return self.ctx.http(url, timeout=15, headers={'X-API-Key': key})

    def _get(self, http, path):
        resp = http.get(path, headers={'Accept': 'application/json'})
        if resp.status_code in (401, 403):
            raise PluginError('The firewall refused the API key.')
        if resp.status_code == 404 and self._platform() == 'pfsense':
            raise PluginError('The firewall has no REST API at /api/v2. Is the REST API package installed?')
        if resp.status_code >= 400:
            raise PluginError(f'The firewall answered {resp.status_code}.')
        try:
            body = resp.json()
        except ValueError as exc:
            raise PluginError("The firewall's answer isn't JSON. Is the URL the firewall?") from exc
        if self._platform() == 'pfsense':
            return body.get('data') if isinstance(body, dict) else None
        return body

    # What the firewall says ------------------------------------------------------------------
    def _read(self):
        """{'name', 'os', 'model', 'serial', 'cpu', 'cores', 'cpu_pct', 'mem_pct', 'gateways', 'pools'}"""
        http = self._http()
        return self._read_opnsense(http) if self._platform() == 'opnsense' else self._read_pfsense(http)

    def _read_pfsense(self, http):
        system = self._get(http, '/api/v2/status/system') or {}
        host = self._get(http, '/api/v2/system/hostname') or {}
        version = self._get(http, '/api/v2/system/version') or {}
        gateways = [{'name': g.get('name'), 'status': str(g.get('status') or '').lower(),
                     'delay': _num(g.get('delay')), 'loss': _num(g.get('loss'))}
                    for g in self._get(http, '/api/v2/status/gateways') or [] if isinstance(g, dict)]
        return {'name': host.get('hostname') or '', 'os': f"pfSense {version.get('version') or ''}".strip(),
                'model': system.get('platform') or '', 'serial': system.get('serial') or '',
                'cpu': system.get('cpu_model') or '', 'cores': system.get('cpu_count'),
                'cpu_pct': _num(system.get('cpu_usage')), 'mem_pct': _num(system.get('mem_usage')),
                'gateways': gateways, 'pools': self._pools(http)}

    def _pools(self, http):
        servers = [s for s in self._get(http, '/api/v2/services/dhcp_servers') or []
                   if isinstance(s, dict) and s.get('enable') and s.get('range_from') and s.get('range_to')]
        if not servers:
            return []
        active = [_ip(lease.get('ip')) for lease in self._get(http, '/api/v2/status/dhcp_server/leases') or []
                  if isinstance(lease, dict) and str(lease.get('active_status') or 'active').lower() == 'active']
        pools = []
        for s in servers:
            start, end = _ip(s['range_from']), _ip(s['range_to'])
            if start is None or end is None or start.version != end.version or end < start:
                continue
            size = int(end) - int(start) + 1
            used = sum(1 for ip in active if ip is not None and ip.version == start.version and start <= ip <= end)
            pools.append({'id': str(s.get('id') or s.get('interface') or start), 'interface':
                          str(s.get('interface') or s.get('id') or ''), 'range': f'{start} - {end}',
                          'size': size, 'used': min(used, size)})
        return pools

    def _read_opnsense(self, http):
        info = self._get(http, '/api/diagnostics/system/system_information') or {}
        resources = self._get(http, '/api/diagnostics/system/system_resources') or {}
        gateways = self._get(http, '/api/routes/gateway/status') or {}
        memory = resources.get('memory') or {}
        total, used = _num(memory.get('total')), _num(memory.get('used'))
        versions = info.get('versions') or []
        return {'name': info.get('name') or '', 'os': str(versions[0]) if versions else 'OPNsense',
                'model': '', 'serial': '', 'cpu': '', 'cores': None, 'cpu_pct': None,
                'mem_pct': used * 100 / total if total and used is not None else None,
                'gateways': [{'name': g.get('name'), 'status': str(g.get('status') or '').lower(),
                              'delay': _num(g.get('delay')), 'loss': _num(g.get('loss'))}
                             for g in gateways.get('items') or [] if isinstance(g, dict)],
                'pools': []}

    def _name(self, read):
        return (self.settings.get('name') or '').strip() or read['name'] or 'Firewall'

    # Floorbit's areas ------------------------------------------------------------------------
    def health_checks(self):
        read = self._read()
        name = self._name(read)
        checks = [self._firewall_check(name, read)]
        for g in read['gateways']:
            if not g['name']:
                continue
            status = 'down' if g['status'] in GW_DOWN else 'warn' if g['status'] in GW_WARN else 'up'
            delay, loss = _round(g['delay']), _round(g['loss'])
            summary = ', '.join(p for p in (f'{delay:g} ms' if delay is not None else '',
                                            f'{loss:g}% loss' if loss is not None else '') if p)
            checks.append({'id': f"gw-{g['name']}", 'name': f"{name} {g['name']}", 'kind': 'uplink', 'status': status,
                           'summary': 'down' if status == 'down' else summary,
                           'metrics': [{'label': 'Delay', 'value': delay, 'unit': 'ms'},
                                       {'label': 'Loss', 'value': loss, 'unit': '%',
                                        'tone': 'warn' if loss else ''}]})
        warn = self._pool_warn()
        for p in read['pools']:
            pct = p['used'] * 100 / p['size']
            free = p['size'] - p['used']
            status = 'down' if pct >= POOL_FULL else 'warn' if pct >= warn else 'up'
            tone = {'down': 'err', 'warn': 'warn'}.get(status, '')
            checks.append({'id': f"dhcp-{p['id']}", 'name': f"DHCP {p['interface'] or p['id']}", 'kind': 'dhcp',
                           'status': status, 'summary': f'{free} of {p["size"]} addresses free',
                           'metrics': [{'label': 'Free', 'value': free, 'tone': tone},
                                       {'label': 'In use', 'value': round(pct), 'unit': '%', 'tone': tone},
                                       {'label': 'Range', 'value': p['range']}]})
        return checks

    def _pool_warn(self):
        try:
            return min(POOL_FULL, max(1, int(self.settings.get('pool_warn') or 80)))
        except (TypeError, ValueError):
            return 80

    def _firewall_check(self, name, read):
        cpu, mem = _round(read['cpu_pct']), _round(read['mem_pct'])
        busy = any(v is not None and v >= BUSY for v in (cpu, mem))
        metrics = [{'label': 'CPU', 'value': cpu, 'unit': '%', 'tone': 'warn' if cpu and cpu >= BUSY else ''},
                   {'label': 'Memory', 'value': mem, 'unit': '%', 'tone': 'warn' if mem and mem >= BUSY else ''}]
        return {'id': 'firewall', 'name': name, 'kind': 'firewall', 'status': 'warn' if busy else 'up',
                'summary': read['os'], 'metrics': [m for m in metrics if m['value'] is not None]}

    def inventory(self):
        read = self._read()
        host = urlsplit(str(self.settings.get('url') or '')).hostname
        device = {'id': 'firewall', 'name': self._name(read), 'role': 'firewall', 'status': 'active',
                  'model': read['model'], 'serial': read['serial'], 'platform': self._platform(),
                  'os': read['os'], 'cpu': read['cpu']}
        if isinstance(read['cores'], int) and read['cores'] > 0:
            device['cores'] = read['cores']
        if _ip(host):
            device['mgmt_ip'] = host
        return [{k: v for k, v in device.items() if v not in ('', None)}]

    def test(self):
        read = self._read()
        return (f"Connected to {self._name(read)} ({read['os']}): {len(read['gateways'])} gateways, "
                f"{len(read['pools'])} DHCP pools.")
