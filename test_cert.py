"""Tests for cert — SSL certificate expiry checker."""

import datetime
import sys
from unittest.mock import patch, MagicMock

import pytest

# Add parent to path so we can import cert
sys.path.insert(0, ".")
from cert import (
    CertResult,
    CertError,
    check_domain,
    format_result,
    main,
    __version__,
)


class TestCertResult:
    """Tests for the CertResult data class."""

    def test_days_remaining_none_when_no_expiry(self):
        result = CertResult("example.com")
        assert result.days_remaining is None

    def test_days_remaining_positive(self):
        result = CertResult("example.com")
        future = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30)
        result.not_after = future
        # days_remaining uses timedelta.days which truncates toward zero
        assert result.days_remaining in (29, 30)

    def test_expired_true_when_past(self):
        result = CertResult("example.com")
        past = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
        result.not_after = past
        assert result.expired is True

    def test_expired_false_when_future(self):
        result = CertResult("example.com")
        future = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
        result.not_after = future
        assert result.expired is False

    def test_status_ok(self):
        result = CertResult("example.com")
        future = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
        result.not_after = future
        assert result.status == "OK"

    def test_status_warn(self):
        result = CertResult("example.com")
        future = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=15)
        result.not_after = future
        assert result.status == "WARN"

    def test_status_expired(self):
        result = CertResult("example.com")
        past = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
        result.not_after = past
        assert result.status == "EXPIRED"

    def test_status_error(self):
        result = CertResult("example.com")
        result.error = "Something went wrong"
        assert result.status == "ERROR"


class TestFormatResult:
    """Tests for the format_result function."""

    def test_error_format(self):
        result = CertResult("example.com")
        result.error = "Connection failed"
        output = format_result(result)
        assert "ERROR" in output
        assert "Connection failed" in output

    def test_ok_format(self):
        result = CertResult("example.com")
        future = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=100)
        result.not_after = future
        output = format_result(result)
        assert "OK" in output
        assert "days remaining" in output

    def test_expired_format(self):
        result = CertResult("example.com")
        past = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=5)
        result.not_after = past
        output = format_result(result)
        assert "EXPIRED" in output
        assert "days ago" in output

    def test_verbose_format(self):
        result = CertResult("example.com")
        future = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=100)
        result.not_after = future
        result.issuer = "Test Issuer"
        result.subject = "example.com"
        output = format_result(result, verbose=True)
        assert "Issuer:" in output
        assert "Test Issuer" in output
        assert "Subject:" in output
        assert "example.com" in output


class TestCheckDomain:
    """Tests for the check_domain function."""

    @patch("cert.socket.create_connection")
    @patch("cert.ssl.create_default_context")
    def test_successful_check(self, mock_ssl_context, mock_create_connection):
        """Test a successful certificate check."""
        # Mock the SSL context and wrapped socket
        mock_context = MagicMock()
        mock_ssl_context.return_value = mock_context

        mock_ssock = MagicMock()
        mock_context.wrap_socket.return_value.__enter__.return_value = mock_ssock

        # Mock the certificate
        mock_ssock.getpeercert.return_value = {
            "notAfter": "Jan 15 12:00:00 2030 GMT",
            "issuer": [[("organizationName", "Test CA")]],
            "subject": [[("commonName", "example.com")]],
            "serialNumber": "ABCDEF",
        }

        result = check_domain("example.com")

        assert result.domain == "example.com"
        assert result.port == 443
        assert result.not_after is not None
        assert result.issuer == "Test CA"
        assert result.subject == "example.com"
        assert result.serial == "ABCDEF"
        assert result.error is None

    @patch("cert.socket.create_connection")
    @patch("cert.ssl.create_default_context")
    def test_no_cert_returned(self, mock_ssl_context, mock_create_connection):
        """Test when no certificate is returned."""
        mock_context = MagicMock()
        mock_ssl_context.return_value = mock_context

        mock_ssock = MagicMock()
        mock_context.wrap_socket.return_value.__enter__.return_value = mock_ssock
        mock_ssock.getpeercert.return_value = None

        result = check_domain("example.com")
        assert result.error is not None
        assert "No certificate" in result.error

    @patch("cert.socket.create_connection")
    @patch("cert.ssl.create_default_context")
    def test_no_expiry_date(self, mock_ssl_context, mock_create_connection):
        """Test when certificate has no notAfter field."""
        mock_context = MagicMock()
        mock_ssl_context.return_value = mock_context

        mock_ssock = MagicMock()
        mock_context.wrap_socket.return_value.__enter__.return_value = mock_ssock
        mock_ssock.getpeercert.return_value = {"subject": [[("commonName", "example.com")]]}

        result = check_domain("example.com")
        assert result.error is not None
        assert "no expiry date" in result.error

    @patch("cert.socket.create_connection")
    def test_dns_failure(self, mock_create_connection):
        """Test DNS resolution failure."""
        import socket as real_socket
        mock_create_connection.side_effect = real_socket.gaierror("Name or service not known")

        with pytest.raises(CertError) as excinfo:
            check_domain("nonexistent.example.com")
        assert "DNS resolution failed" in str(excinfo.value)

    @patch("cert.socket.create_connection")
    def test_connection_timeout(self, mock_create_connection):
        """Test connection timeout."""
        import socket as real_socket
        mock_create_connection.side_effect = real_socket.timeout("timed out")

        with pytest.raises(CertError) as excinfo:
            check_domain("example.com")
        assert "timed out" in str(excinfo.value)

    @patch("cert.socket.create_connection")
    def test_connection_refused(self, mock_create_connection):
        """Test connection refused."""
        mock_create_connection.side_effect = ConnectionRefusedError("Connection refused")

        with pytest.raises(CertError) as excinfo:
            check_domain("example.com")
        assert "Connection refused" in str(excinfo.value)


class TestMain:
    """Tests for the main entry point."""

    def test_version(self):
        """Test --version flag."""
        with pytest.raises(SystemExit) as excinfo:
            main(["--version"])
        assert excinfo.value.code == 0

    def test_help(self):
        """Test --help flag."""
        with pytest.raises(SystemExit) as excinfo:
            main(["--help"])
        assert excinfo.value.code == 0

    def test_no_domains(self):
        """Test that no domains produces an error."""
        with pytest.raises(SystemExit):
            main([])

    @patch("cert.check_domain")
    def test_single_domain_ok(self, mock_check):
        """Test a single domain that returns OK."""
        result = CertResult("example.com")
        result.not_after = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=100)
        mock_check.return_value = result

        exit_code = main(["example.com"])
        assert exit_code == 0

    @patch("cert.check_domain")
    def test_single_domain_expired(self, mock_check):
        """Test a single domain that is expired."""
        result = CertResult("example.com")
        result.not_after = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
        mock_check.return_value = result

        exit_code = main(["example.com"])
        assert exit_code == 2

    @patch("cert.check_domain")
    def test_single_domain_warn(self, mock_check):
        """Test a single domain that is close to expiry."""
        result = CertResult("example.com")
        result.not_after = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=15)
        mock_check.return_value = result

        exit_code = main(["example.com"])
        assert exit_code == 3

    @patch("cert.check_domain")
    def test_multiple_domains(self, mock_check):
        """Test multiple domains."""
        result1 = CertResult("example.com")
        result1.not_after = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=100)

        result2 = CertResult("example.org")
        result2.not_after = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=200)

        mock_check.side_effect = [result1, result2]

        exit_code = main(["example.com", "example.org"])
        assert exit_code == 0

    @patch("cert.check_domain")
    def test_custom_port(self, mock_check):
        """Test custom port flag."""
        result = CertResult("example.com", port=8443)
        result.not_after = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=100)
        mock_check.return_value = result

        exit_code = main(["--port", "8443", "example.com"])
        assert exit_code == 0
        # Verify check_domain was called with port=8443
        _, kwargs = mock_check.call_args
        # check_domain is called with positional args from main
        assert mock_check.call_args[0][1] == 8443

    @patch("cert.check_domain")
    def test_custom_warn_threshold(self, mock_check):
        """Test custom warn threshold."""
        result = CertResult("example.com")
        result.not_after = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=5)
        mock_check.return_value = result

        # With default warn=30, this would be exit code 3
        # With warn=3, this should be exit code 0
        exit_code = main(["--warn", "3", "example.com"])
        assert exit_code == 0

    @patch("cert.check_domain")
    def test_verbose_flag(self, mock_check):
        """Test verbose flag doesn't crash."""
        result = CertResult("example.com")
        result.not_after = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=100)
        result.issuer = "Test"
        result.subject = "example.com"
        mock_check.return_value = result

        exit_code = main(["--verbose", "example.com"])
        assert exit_code == 0

    @patch("cert.check_domain")
    def test_domain_with_error(self, mock_check):
        """Test a domain that raises CertError."""
        mock_check.side_effect = CertError("DNS resolution failed for 'bad.example.com'")

        exit_code = main(["bad.example.com"])
        assert exit_code == 1


class TestVersion:
    """Tests for version constant."""

    def test_version_string(self):
        assert __version__ == "1.0.0"
