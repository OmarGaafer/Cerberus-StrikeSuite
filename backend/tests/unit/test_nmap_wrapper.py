import pytest
from tools.wrappers.nmap_wrapper import NmapWrapper


@pytest.fixture
def wrapper():
    return NmapWrapper()


def test_run_basic(wrapper):
    r = wrapper.run("scanme.nmap.org", "-sn")
    assert r.success is True


def test_host_discovery(wrapper):
    r = wrapper.host_discovery("scanme.nmap.org")
    assert r.success is True


def test_scan_fast(wrapper):
    r = wrapper.scan_fast("scanme.nmap.org")
    assert r.success is True


def test_scan_specific_ports(wrapper):
    r = wrapper.scan_specific_ports("scanme.nmap.org", "22,80")
    assert r.success is True
