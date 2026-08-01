#!/usr/bin/env python3
"""cert — SSL certificate expiry checker for domains.

Check the expiry date of SSL/TLS certificates for one or more domains.
Shows days remaining and warns when a certificate is expired or close to expiry.
Zero external dependencies — uses only Python stdlib.
"""

import argparse
import datetime
import socket
import ssl
import sys

__version__ = "1.0.0"
__author__ = "Bobby Hansen"

# Default warn threshold in days
DEFAULT_WARN_DAYS = 30
# Default connect timeout in seconds
DEFAULT_TIMEOUT = 10
# Default port
DEFAULT_PORT = 443


class CertError(Exception):
    """Base exception for cert tool errors."""


class CertResult:
    """Result of a certificate check for a single domain."""

    def __init__(self, domain: str, port: int = DEFAULT_PORT):
        self.domain = domain
        self.port = port
        self.not_after: datetime.datetime | None = None
        self.issuer: str | None = None
        self.subject: str | None = None
        self.serial: str | None = None
        self.error: str | None = None

    @property
    def days_remaining(self) -> int | None:
        if self.not_after is None:
            return None
        delta = self.not_after - datetime.datetime.now(datetime.timezone.utc)
        return delta.days

    @property
    def expired(self) -> bool:
        if self.days_remaining is None:
            return False
        return self.days_remaining < 0

    @property
    def status(self) -> str:
        if self.error:
            return "ERROR"
        if self.expired:
            return "EXPIRED"
        if self.days_remaining is not None and self.days_remaining <= DEFAULT_WARN_DAYS:
            return "WARN"
        return "OK"


def check_domain(domain: str, port: int = DEFAULT_PORT, timeout: int = DEFAULT_TIMEOUT) -> CertResult:
    """Check the SSL certificate for a given domain and port.

    Args:
        domain: Domain name to check.
        port: TCP port (default 443).
        timeout: Connection timeout in seconds.

    Returns:
        CertResult with certificate details.

    Raises:
        CertError: On connection or certificate retrieval failure.
    """
    result = CertResult(domain, port)

    try:
        context = ssl.create_default_context()
        # We don't verify hostname here — we just want the cert info
        context.check_hostname = False
        # CERT_REQUIRED ensures the server sends its certificate
        context.verify_mode = ssl.CERT_REQUIRED

        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        if not cert:
            result.error = f"No certificate returned for {domain}:{port}"
            return result

        # Parse notAfter
        not_after_str = cert.get("notAfter")
        if not not_after_str:
            result.error = f"Certificate has no expiry date for {domain}:{port}"
            return result

        # Parse the date — format is 'MMM DD HH:MM:SS YYYY GMT'
        result.not_after = datetime.datetime.strptime(
            not_after_str, "%b %d %H:%M:%S %Y %Z"
        ).replace(tzinfo=datetime.timezone.utc)

        # Extract issuer
        issuer_parts = cert.get("issuer", [])
        if issuer_parts:
            result.issuer = dict(issuer_parts[0]).get("organizationName", str(issuer_parts[0]))

        # Extract subject
        subject_parts = cert.get("subject", [])
        if subject_parts:
            result.subject = dict(subject_parts[0]).get("commonName", str(subject_parts[0]))

        # Extract serial number
        result.serial = cert.get("serialNumber")

    except socket.gaierror as e:
        raise CertError(f"DNS resolution failed for '{domain}': {e}") from e
    except socket.timeout as e:
        raise CertError(f"Connection timed out for '{domain}:{port}': {e}") from e
    except ConnectionRefusedError as e:
        raise CertError(f"Connection refused for '{domain}:{port}': {e}") from e
    except OSError as e:
        raise CertError(f"Connection failed for '{domain}:{port}': {e}") from e
    except ssl.SSLError as e:
        raise CertError(f"SSL error for '{domain}:{port}': {e}") from e

    return result


def format_result(result: CertResult, verbose: bool = False) -> str:
    """Format a single CertResult for display."""
    if result.error:
        return f"  {result.domain}:{result.port}  ERROR  ({result.error})"

    days = result.days_remaining
    status = result.status

    if result.expired:
        label = f"EXPIRED {abs(days)} days ago"
    elif days == 0:
        label = "EXPIRES TODAY"
    elif days == 1:
        label = "1 day remaining"
    else:
        label = f"{days} days remaining"

    line = f"  {result.domain}:{result.port}  {status:7s}  {label}"

    if verbose:
        line += f"\n    Issuer: {result.issuer or 'N/A'}"
        line += f"\n    Subject: {result.subject or 'N/A'}"
        line += f"\n    Expires: {result.not_after.strftime('%Y-%m-%d %H:%M UTC') if result.not_after else 'N/A'}"

    return line


def main(argv: list[str] | None = None) -> int:
    """Main entry point. Returns exit code."""
    parser = argparse.ArgumentParser(
        prog="cert",
        description="Check SSL/TLS certificate expiry dates for domains.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  cert example.com\n"
            "  cert example.com google.com github.com\n"
            "  cert example.com --port 8443\n"
            "  cert example.com --warn 14\n"
            "  cert example.com --verbose\n"
            "  cert example.com --timeout 5\n"
        ),
    )
    parser.add_argument(
        "domains",
        nargs="+",
        metavar="DOMAIN",
        help="One or more domain names to check",
    )
    parser.add_argument(
        "-p", "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"TCP port to connect to (default: {DEFAULT_PORT})",
    )
    parser.add_argument(
        "-w", "--warn",
        type=int,
        default=DEFAULT_WARN_DAYS,
        help=f"Warn when days remaining is below this threshold (default: {DEFAULT_WARN_DAYS})",
    )
    parser.add_argument(
        "-t", "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"Connection timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed certificate info (issuer, subject, exact expiry)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"cert {__version__}",
    )

    args = parser.parse_args(argv)

    exit_code = 0
    results: list[CertResult] = []

    for domain in args.domains:
        try:
            result = check_domain(domain, args.port, args.timeout)
            results.append(result)
        except CertError as e:
            print(f"cert: error: {e}", file=sys.stderr)
            exit_code = 1
            continue

    # Print results
    for result in results:
        print(format_result(result, args.verbose))

    # Determine exit code based on results
    if exit_code == 0:
        for result in results:
            if result.error:
                exit_code = 1
            elif result.expired:
                exit_code = 2
            elif result.days_remaining is not None and result.days_remaining <= args.warn:
                exit_code = 3

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
