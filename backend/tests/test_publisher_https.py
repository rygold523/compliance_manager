import os
from unittest.mock import patch
import pytest
from app.services import publisher_https as https
from app.services import requirements_update_check as checks


def test_default_disabled_no_network(monkeypatch):
    monkeypatch.delenv(checks.ENABLE_LIVE_PUBLISHER_CHECKS, raising=False)
    monkeypatch.setattr(https.socket, 'getaddrinfo', lambda *a, **kw: pytest.fail('network used'))
    assert checks.check_framework('pci_dss', enabled=True)['status'] == 'manual_verification_required'


def test_opt_in_uses_transport(monkeypatch):
    monkeypatch.setenv(checks.ENABLE_LIVE_PUBLISHER_CHECKS, 'true')
    called = []
    monkeypatch.setattr(checks, 'fetch_publisher', lambda url, *, approved_sources: (
        called.append((url, approved_sources)) or {'status': 'reachable'}))
    result = checks.check_framework('pci_dss', enabled=True)
    assert result['status'] == 'publisher_reachable'
    assert result['requirements_current'] is None
    assert result['requirements_version_verified'] is False
    assert len(called) == 1


def test_disabled_skips_live_transport(monkeypatch):
    monkeypatch.setenv(checks.ENABLE_LIVE_PUBLISHER_CHECKS, 'true')
    monkeypatch.setattr(checks, 'fetch_publisher', lambda *a, **kw: pytest.fail('called'))
    assert checks.check_framework('pci_dss', enabled=False)['status'] == 'disabled'


@pytest.mark.parametrize('url', [
    'http://www.pcisecuritystandards.org/document_library/',
    'https://www.pcisecuritystandards.org.evil.com/document_library/',
    'https://www.pcisecuritystandards.org:444/document_library/',
    'https://www.pcisecuritystandards.org/document_library/?secret=1',
    'https://user@www.pcisecuritystandards.org/document_library/',
    'https://www.pcisecuritystandards.org/other',
])
def test_unapproved_url_rejected_before_dns(monkeypatch, url):
    monkeypatch.setattr(https.socket, 'getaddrinfo', lambda *a, **kw: pytest.fail('DNS called'))
    with pytest.raises(https.PublisherTransportError):
        https.fetch_publisher(url, approved_sources=checks._approved_sources())


@pytest.mark.parametrize('ip', ['127.0.0.1', '10.1.2.3', '169.254.169.254', '::1', '192.0.2.1'])
def test_private_and_non_global_addresses_rejected(monkeypatch, ip):
    monkeypatch.setattr(https.socket, 'getaddrinfo', lambda *a, **kw: [(None,None,None,None,(ip,443))])
    with pytest.raises(https.PublisherTransportError):
        https._resolve_public('example.org')


def test_mixed_public_private_addresses_rejected(monkeypatch):
    monkeypatch.setattr(https.socket, 'getaddrinfo', lambda *a, **kw: [
        (None,None,None,None,('8.8.8.8',443)), (None,None,None,None,('127.0.0.1',443))])
    with pytest.raises(https.PublisherTransportError):
        https._resolve_public('example.org')


class FakeResponse:
    def __init__(self, status=200, body=b'OK', content_type='text/html', declared=None):
        self.status, self.body, self.content_type, self.declared = status, body, content_type, declared
    def getheader(self, key, default=None):
        return {'Content-Type': self.content_type, 'Content-Length': self.declared}.get(key, default)
    def read(self, n):
        return self.body[:n]


class FakeConnection:
    def __init__(self, host, address):
        self.host, self.address = host, address
        self.response = FakeResponse()
        self.requests = []
    def request(self, method, path, headers):
        self.requests.append((method, path, headers))
    def getresponse(self):
        return self.response
    def close(self):
        pass


def test_exact_get_and_pinned_ip(monkeypatch):
    instances = []
    def factory(host, address):
        conn = FakeConnection(host, address)
        instances.append(conn)
        return conn
    monkeypatch.setattr(https, '_resolve_public', lambda host: ['8.8.8.8'])
    monkeypatch.setattr(https, '_PinnedHTTPSConnection', factory)
    url = 'https://www.pcisecuritystandards.org/document_library/'
    assert https.fetch_publisher(url, approved_sources=checks._approved_sources())['status'] == 'reachable'
    assert instances[0].address == '8.8.8.8'
    method, path, headers = instances[0].requests[0]
    assert (method, path) == ('GET', '/document_library/')
    assert 'Cookie' not in headers and 'Authorization' not in headers


@pytest.mark.parametrize('response', [
    FakeResponse(status=301), FakeResponse(status=302), FakeResponse(status=404),
    FakeResponse(body=b'x' * (https.MAX_RESPONSE_BYTES + 1)),
    FakeResponse(declared=str(https.MAX_RESPONSE_BYTES + 1)),
    FakeResponse(content_type='application/octet-stream'),
])
def test_bad_responses_fail_closed(monkeypatch, response):
    monkeypatch.setattr(https, '_resolve_public', lambda host: ['8.8.8.8'])
    def factory(host, address):
        conn = FakeConnection(host, address)
        conn.response = response
        return conn
    monkeypatch.setattr(https, '_PinnedHTTPSConnection', factory)
    with pytest.raises(https.PublisherTransportError):
        https.fetch_publisher('https://www.pcisecuritystandards.org/document_library/',
                              approved_sources=checks._approved_sources())


def test_network_error_no_version_claim(monkeypatch):
    monkeypatch.setenv(checks.ENABLE_LIVE_PUBLISHER_CHECKS, 'true')
    monkeypatch.setattr(checks, 'fetch_publisher', lambda *a, **kw: (_ for _ in ()).throw(https.PublisherTransportError('failed')))
    result = checks.check_framework('pci_dss', enabled=True)
    assert result['status'] == 'check_failed'
    assert result['requirements_current'] is None


def test_header_budget_rejects_oversized_line():
    import io
    stream = https._HeaderBudgetFile(io.BytesIO(b'A' * (https.MAX_HEADER_BYTES + 1)))
    with pytest.raises(https.PublisherTransportError):
        stream.readline()


def test_header_budget_rejects_excessive_header_count():
    import io
    stream = https._HeaderBudgetFile(io.BytesIO(b'X: a\r\n' * (https.MAX_HEADER_FIELDS + 3)))
    with pytest.raises(https.PublisherTransportError):
        for _ in range(https.MAX_HEADER_FIELDS + 3):
            stream.readline()


def test_header_budget_accepts_normal_headers():
    import io
    stream = https._HeaderBudgetFile(io.BytesIO(b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n'))
    assert stream.readline() == b'HTTP/1.1 200 OK\r\n'
    assert stream.readline() == b'Content-Type: text/html\r\n'
    assert stream.readline() == b'\r\n'


def test_https_deadline_expired_before_connect(monkeypatch):
    connection = https._PinnedHTTPSConnection('example.org', '8.8.8.8')
    connection._deadline = https.time.monotonic() - 1
    monkeypatch.setattr(https.socket, 'create_connection', lambda *a, **kw: pytest.fail('socket opened'))
    with pytest.raises(https.PublisherTransportError, match='deadline'):
        connection.connect()


def test_tls_io_deadline_expired_without_read():
    from types import SimpleNamespace

    sock = SimpleNamespace(
        _publisher_deadline=https.time.monotonic() - 1
    )
    with pytest.raises(https.PublisherTransportError, match='deadline'):
        https._DeadlineSSLSocket._limit_timeout(sock)


def test_malformed_port_fails_closed_before_dns(monkeypatch):
    monkeypatch.setattr(https.socket, 'getaddrinfo', lambda *a, **kw: pytest.fail('DNS called'))
    with pytest.raises(https.PublisherTransportError):
        https.fetch_publisher('https://www.pcisecuritystandards.org:bad/document_library/',
                              approved_sources=checks._approved_sources())
