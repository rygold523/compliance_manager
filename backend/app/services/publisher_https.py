"""Pinned, direct, HTTPS-only GET for fixed official publisher landing pages.

No redirects, proxies, cookies, credentials, request bodies, or persistence.
DNS resolution is isolated in a killable process with a strict caller deadline.
"""
import http.client
import ipaddress
import multiprocessing
import socket
import ssl
import time
from urllib.parse import urlsplit

MAX_RESPONSE_BYTES = 256 * 1024
DNS_TIMEOUT_SECONDS = 3
CONNECT_TIMEOUT_SECONDS = 3
READ_TIMEOUT_SECONDS = 8
HTTPS_IO_DEADLINE_SECONDS = 12  # Starts after DNS; OS resolver timeout is independent.
MAX_HEADER_BYTES = 16 * 1024
MAX_HEADER_FIELDS = 40


class PublisherTransportError(Exception):
    pass


def _resolve_worker(host, send_connection):
    """Resolve in a child process so a stuck OS resolver can be terminated."""
    try:
        records = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        addresses = sorted({record[4][0] for record in records})
        send_connection.send(("ok", addresses))
    except BaseException:
        # Do not serialize exception objects or expose resolver details.
        try:
            send_connection.send(("error", []))
        except (BrokenPipeError, EOFError, OSError):
            pass
    finally:
        send_connection.close()


def _stop_resolver(process):
    """Terminate a resolver worker and ensure it is reaped within a bounded wait."""
    if process.is_alive():
        process.terminate()
    process.join(timeout=0.2)
    if process.is_alive():
        # Process.kill is available on supported Python 3.7+ runtimes.
        process.kill()
        process.join(timeout=0.2)


def _resolve_public(host):
    """Resolve host within DNS_TIMEOUT_SECONDS and accept only globally routable IPs."""
    receive_connection = None
    send_connection = None
    process = None
    try:
        # Linux production containers support fork. It lets this isolated worker
        # use the same libc/NSS resolver configuration without shelling out.
        context = multiprocessing.get_context("fork")
        receive_connection, send_connection = context.Pipe(duplex=False)
        process = context.Process(
            target=_resolve_worker,
            args=(host, send_connection),
            daemon=True,
        )
        process.start()
        send_connection.close()
        send_connection = None

        if not receive_connection.poll(DNS_TIMEOUT_SECONDS):
            _stop_resolver(process)
            raise PublisherTransportError("Publisher DNS resolution timed out")

        try:
            status, addresses = receive_connection.recv()
        except (EOFError, OSError) as exc:
            raise PublisherTransportError("Publisher DNS resolution failed") from exc

        process.join(timeout=0.2)
        if process.is_alive():
            _stop_resolver(process)

        if status != "ok":
            raise PublisherTransportError("Publisher DNS resolution failed")
        if not addresses:
            raise PublisherTransportError("Publisher DNS resolution failed")

        try:
            parsed_addresses = [ipaddress.ip_address(address) for address in addresses]
        except ValueError as exc:
            raise PublisherTransportError("Publisher DNS returned an invalid address") from exc

        if any(not address.is_global for address in parsed_addresses):
            raise PublisherTransportError("Publisher DNS is not exclusively public")

        # Return the original normalized address strings for socket.create_connection.
        return sorted({str(address) for address in parsed_addresses})
    except PublisherTransportError:
        raise
    except (OSError, ValueError, RuntimeError) as exc:
        raise PublisherTransportError("Publisher DNS resolution failed") from exc
    finally:
        if send_connection is not None:
            send_connection.close()
        if receive_connection is not None:
            receive_connection.close()
        if process is not None:
            if process.is_alive():
                _stop_resolver(process)
            else:
                process.join(timeout=0)


class _HeaderBudgetFile:
    """Limit status line and header bytes before stdlib header parsing allocates them."""

    def __init__(self, stream):
        self.stream = stream
        self.remaining = MAX_HEADER_BYTES
        self.lines = 0

    def readline(self, limit=-1):
        if self.remaining <= 0:
            raise PublisherTransportError("Publisher response headers too large")
        # A capped read prevents allocation beyond the remaining header budget.
        cap = self.remaining + 1
        line = self.stream.readline(cap if limit < 0 else min(cap, limit))
        self.remaining -= len(line)
        self.lines += 1
        if self.remaining < 0 or self.lines > MAX_HEADER_FIELDS + 2:
            raise PublisherTransportError("Publisher response headers too large")
        return line


class _BoundedHTTPResponse(http.client.HTTPResponse):
    def begin(self):
        original = self.fp
        self.fp = _HeaderBudgetFile(original)
        try:
            super().begin()
        finally:
            self.fp = original


class _DeadlineSSLSocket(ssl.SSLSocket):
    """Refresh socket timeout against an absolute HTTPS I/O deadline per read/write."""

    def _limit_timeout(self):
        remaining = self._publisher_deadline - time.monotonic()
        if remaining <= 0:
            raise PublisherTransportError("Publisher HTTPS deadline exceeded")
        self.settimeout(min(READ_TIMEOUT_SECONDS, remaining))

    def read(self, *args, **kwargs):
        self._limit_timeout()
        return super().read(*args, **kwargs)

    def send(self, *args, **kwargs):
        self._limit_timeout()
        return super().send(*args, **kwargs)

    def sendall(self, *args, **kwargs):
        self._limit_timeout()
        return super().sendall(*args, **kwargs)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, address):
        context = ssl.create_default_context()
        context.sslsocket_class = _DeadlineSSLSocket
        super().__init__(host=host, port=443, timeout=CONNECT_TIMEOUT_SECONDS,
                         context=context)
        self.response_class = _BoundedHTTPResponse
        self._address = address
        self._deadline = time.monotonic() + HTTPS_IO_DEADLINE_SECONDS

    def connect(self):
        # Connect only to the prevalidated address; no second DNS lookup.
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise PublisherTransportError("Publisher HTTPS deadline exceeded")
        raw = socket.create_connection((self._address, 443), min(self.timeout, remaining))
        try:
            remaining = self._deadline - time.monotonic()
            if remaining <= 0:
                raise PublisherTransportError("Publisher HTTPS deadline exceeded")
            raw.settimeout(min(READ_TIMEOUT_SECONDS, remaining))
            # Default context verifies certificate chain and hostname via SNI.
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
            self.sock._publisher_deadline = self._deadline
        except BaseException:
            raw.close()
            raise


def fetch_publisher(url, *, approved_sources):
    """Return reachability metadata only; never return/store page content.

    approved_sources must contain exact (hostname, path) pairs. Only port 443.
    """
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise PublisherTransportError("Malformed publisher URL") from exc
    if (parsed.scheme != "https" or parsed.username is not None or
            parsed.password is not None or port not in (None, 443) or
            parsed.query or parsed.fragment or
            (parsed.hostname, parsed.path) not in approved_sources or
            parsed.netloc != parsed.hostname):
        raise PublisherTransportError("Publisher URL is not approved")
    host = parsed.hostname
    addresses = _resolve_public(host)
    # Use the first validated public address; no fallback to an unverified target.
    connection = _PinnedHTTPSConnection(host, addresses[0])
    try:
        connection.request("GET", parsed.path, headers={
            "Accept": "text/html,application/xhtml+xml",
            "User-Agent": "ComplianceDashboard-PublisherDiscovery/1.0",
            "Connection": "close",
        })
        response = connection.getresponse()
        # Reject redirects, non-200 responses, and oversized payloads.
        if response.status != 200:
            raise PublisherTransportError("Publisher did not return HTTP 200")
        declared = response.getheader("Content-Length")
        if declared is not None:
            try:
                size = int(declared)
            except ValueError as exc:
                raise PublisherTransportError("Invalid response length") from exc
            if size < 0 or size > MAX_RESPONSE_BYTES:
                raise PublisherTransportError("Publisher response exceeds size limit")
        content_type = response.getheader("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type not in ("text/html", "application/xhtml+xml"):
            raise PublisherTransportError("Unexpected publisher content type")
        body = response.read(MAX_RESPONSE_BYTES + 1)
        if len(body) > MAX_RESPONSE_BYTES:
            raise PublisherTransportError("Publisher response exceeds size limit")
        return {"status": "reachable", "http_status": 200}
    except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
        raise PublisherTransportError("Publisher HTTPS retrieval failed") from exc
    finally:
        connection.close()
