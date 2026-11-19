"""pfSense (REST API v2) and OPNsense against fake firewalls, never a real one."""
import pytest
import requests
from floorbit import health, inventory
from floorbit.plugins.base import PluginError


class Answer:
    def __init__(self, body=None, status=200):
        self.status_code = status
        self._body = body

    def json(self):
        if isinstance(self._body, str):
            raise ValueError("not JSON")
        return self._body


def envelope(data):
    return {"code": 200, "status": "ok", "response_id": "SUCCESS", "message": "", "data": data}


PFSENSE = {
    "/api/v2/status/system": {"platform": "Netgate 6100", "serial": "EXAMPLE123", "cpu_model": "Intel Atom C3558",
                              "cpu_count": 4, "cpu_usage": 12.5, "mem_usage": 93.1},
    "/api/v2/system/hostname": {"hostname": "fw-01", "domain": "example.com"},
    "/api/v2/system/version": {"version": "2.7.2-RELEASE", "base": "2.7"},
    "/api/v2/status/gateways": [
        {"name": "WAN_DHCP", "status": "online", "delay": "3.2ms", "loss": "0.0%"},
        {"name": "WAN2_FIBER", "status": "loss", "delay": 18.04, "loss": 12.0},
        {"name": "WAN3_LTE", "status": "down", "delay": "0ms", "loss": "100%"},
    ],
    "/api/v2/services/dhcp_servers": [
        {"id": "lan", "interface": "lan", "enable": True, "range_from": "192.0.2.10", "range_to": "192.0.2.19"},
        {"id": "opt1", "interface": "opt1", "enable": True, "range_from": "198.51.100.1", "range_to": "198.51.100.100"},
        {"id": "opt2", "interface": "opt2", "enable": False, "range_from": "203.0.113.1", "range_to": "203.0.113.9"},
    ],
    "/api/v2/status/dhcp_server/leases": (
        [{"ip": f"192.0.2.{n}", "mac": "02:00:00:00:00:01", "hostname": "laptop", "active_status": "active"}
         for n in range(10, 19)]
        + [{"ip": "192.0.2.19", "active_status": "expired"}, {"ip": "198.51.100.5", "active_status": "active"}]),
}

OPNSENSE = {
    "/api/diagnostics/system/system_information": {"name": "opn-01.example.com",
                                                   "versions": ["OPNsense 24.7.1-amd64", "FreeBSD 14.1"]},
    "/api/diagnostics/system/system_resources": {"memory": {"total": "8000000000", "used": "2000000000"}},
    "/api/routes/gateway/status": {"items": [{"name": "WAN_GW", "status": "none", "delay": "4.1 ms", "loss": "0.0 %"},
                                             {"name": "WAN2_GW", "status": "delay+loss", "delay": "250 ms",
                                              "loss": "5 %"}], "status": "ok"},
}


@pytest.fixture
def firewall(monkeypatch):
    calls = []

    def fake(self, method, url, **kw):
        path = url.removeprefix("https://fw.example.com")
        calls.append(path)
        if "X-API-Key" in self.headers:
            if self.headers["X-API-Key"] != "example-key":
                return Answer({"code": 401}, 401)
            return Answer(envelope(PFSENSE[path])) if path in PFSENSE else Answer({"code": 404}, 404)
        if self.auth != ("example-key", "example-secret"):
            return Answer({}, 401)
        return Answer(OPNSENSE[path]) if path in OPNSENSE else Answer({}, 404)

    monkeypatch.setattr(requests.Session, "request", fake)
    return calls


class Spec:
    id, name = "pfsense", "pfSense / OPNsense"


def pf(make, **extra):
    return make(url="https://fw.example.com", api_key="example-key", **extra)


def test_pfsense_health_wall(make, firewall):
    checks = {c["id"]: c for c in health.clean(Spec, pf(make).health_checks())}
    fw = checks["pfsense:firewall"]
    assert fw["kind"] == "firewall" and fw["name"] == "fw-01" and fw["status"] == "warn"   # memory 93%
    assert fw["summary"] == "pfSense 2.7.2-RELEASE"
    assert [(m["label"], m["value"]) for m in fw["metrics"]] == [("CPU", 12.5), ("Memory", 93.1)]
    assert checks["pfsense:gw-WAN_DHCP"]["status"] == "up"
    assert checks["pfsense:gw-WAN_DHCP"]["summary"] == "3.2 ms, 0% loss"
    assert checks["pfsense:gw-WAN2_FIBER"]["status"] == "warn" and checks["pfsense:gw-WAN2_FIBER"]["kind"] == "uplink"
    assert checks["pfsense:gw-WAN3_LTE"]["status"] == "down"


def test_pfsense_dhcp_pools(make, firewall):
    checks = {c["id"]: c for c in pf(make).health_checks()}
    lan = checks["dhcp-lan"]                 # 9 of 10 active: 90%, past the 80% warning
    assert lan["status"] == "warn" and lan["summary"] == "1 of 10 addresses free" and lan["kind"] == "dhcp"
    assert checks["dhcp-opt1"]["status"] == "up"
    assert "dhcp-opt2" not in checks         # turned off
    assert checks["dhcp-lan"]["metrics"][2]["value"] == "192.0.2.10 - 192.0.2.19"
    assert pf(make, pool_warn=95).health_checks()[-2]["status"] == "up"
    # nothing about a lease leaves: no MACs, addresses or host names
    assert "02:00:00" not in str(checks) and "laptop" not in str(checks)


def test_pfsense_inventory(make, firewall):
    items, skipped = inventory.clean_feed(pf(make).inventory())
    assert skipped == 0
    assert items == [{"name": "fw-01", "role": "firewall", "status": "active", "model": "Netgate 6100",
                      "serial": "EXAMPLE123", "platform": "pfsense", "os": "pfSense 2.7.2-RELEASE",
                      "cpu": "Intel Atom C3558", "cores": "4", "ref": "firewall"}]


def test_name_setting_and_ip_url(make, monkeypatch):
    def fake(self, method, url, **kw):
        return Answer(envelope(PFSENSE.get(url.removeprefix("https://192.0.2.1"), [])))
    monkeypatch.setattr(requests.Session, "request", fake)
    device, = make(url="https://192.0.2.1", api_key="example-key", name="fw-core-a").inventory()
    assert device["name"] == "fw-core-a" and device["mgmt_ip"] == "192.0.2.1"


def test_opnsense(make, firewall):
    plugin = make(platform="opnsense", url="https://fw.example.com", api_key="example-key", api_secret="example-secret")
    checks = {c["id"]: c for c in plugin.health_checks()}
    assert checks["firewall"]["name"] == "opn-01.example.com" and checks["firewall"]["status"] == "up"
    assert checks["firewall"]["metrics"] == [{"label": "Memory", "value": 25.0, "unit": "%", "tone": ""}]
    assert checks["gw-WAN_GW"]["status"] == "up" and checks["gw-WAN2_GW"]["status"] == "warn"
    assert not [c for c in checks if c.startswith("dhcp-")]
    assert plugin.inventory()[0]["os"] == "OPNsense 24.7.1-amd64"
    assert plugin.test() == "Connected to opn-01.example.com (OPNsense 24.7.1-amd64): 2 gateways, 0 DHCP pools."


def test_errors_say_what_to_fix(make, firewall):
    with pytest.raises(PluginError, match="URL and API key"):
        make().health_checks()
    with pytest.raises(PluginError, match="API secret"):
        make(platform="opnsense", url="https://fw.example.com", api_key="example-key").test()
    with pytest.raises(PluginError, match="refused the API key"):
        make(url="https://fw.example.com", api_key="wrong").test()


def test_without_the_rest_api_package(make, monkeypatch):
    monkeypatch.setattr(requests.Session, "request", lambda self, method, url, **kw: Answer("<html>", 404))
    with pytest.raises(PluginError, match="REST API package"):
        pf(make).test()
