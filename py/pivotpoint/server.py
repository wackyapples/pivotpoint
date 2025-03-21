import http.server
import socket
import socketserver
import ssl
import threading
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import slog


@dataclass
class RedirectRule:
    """Configuration for a single redirect rule."""

    target_url: str
    redirect_type: int = 301  # Default to permanent redirect
    preserve_path: bool = True  # Default to preserving path
    https_first: bool = False  # Default to not redirecting to HTTPS first

    @lru_cache(maxsize=128)
    def get_redirect_url(self, original_path: str) -> str:
        """Get the final redirect URL based on the configuration."""
        if self.preserve_path:
            parsed_url = urlparse(self.target_url)
            return f"{parsed_url.scheme}://{parsed_url.netloc}{original_path}"
        return self.target_url

    def __hash__(self):
        return hash((self.target_url, self.preserve_path, self.https_first))


class RedirectRules:
    """Container for redirect rules with optimized matching."""

    def __init__(self):
        self.exact_rules: dict[str, RedirectRule] = {}
        self.wildcard_rules: dict[str, RedirectRule] = {}
        self.default_rule: RedirectRule | None = None

    def add_rule(self, pattern: str, rule: RedirectRule):
        """Add a rule to the appropriate collection based on pattern type."""
        if pattern == "default":
            self.default_rule = rule
        elif pattern.startswith("*."):
            self.wildcard_rules[pattern[2:]] = rule  # Store without the "*." prefix
        else:
            self.exact_rules[pattern] = rule

    @lru_cache(maxsize=128)
    def get_rule(self, host: str) -> RedirectRule | None:
        """Get the matching rule for a host using optimized matching."""
        # Try exact match first
        if rule := self.exact_rules.get(host):
            return rule

        # Try wildcard match using domain parts
        domain_parts = host.split(".")
        for i in range(len(domain_parts) - 1):
            suffix = ".".join(domain_parts[i:])
            if rule := self.wildcard_rules.get(suffix):
                return rule

        # Fall back to default rule
        return self.default_rule

    @lru_cache(maxsize=128)
    def __getitem__(self, host: str) -> RedirectRule | None:
        return self.get_rule(host)


class RedirectHandler(http.server.BaseHTTPRequestHandler):
    """Handler for HTTP requests that performs redirects based on the Host header."""

    server: "SNITCPServer"
    redirection_rules: RedirectRules
    server_config: dict[str, Any]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.redirection_rules = None
        self.server_name = None
        self.is_ssl_connection = False
        self.server_config = {}

    def do_GET(self):
        self.handle_request()

    def do_HEAD(self):
        self.handle_request()

    def do_POST(self):
        self.handle_request()

    def setup(self):
        super().setup()
        self.redirection_rules = load_redirection_rules(
            self.server.redirect_config_file
        )
        self.server_config = self.server.server_config
        self.protocol_version = "HTTP/1.1"
        self.is_ssl_connection = self.server.is_ssl_enabled and hasattr(
            self.connection, "context"
        )

    def handle_request(self):
        """Process the request and perform redirection based on Host header."""
        host = self.headers.get("Host", "").split(":")[0]  # Remove port if present

        self.perform_redirect(host)

    def redirect_to_https(self):
        """Redirect HTTP request to HTTPS on the same host."""
        https_port = self.server_config.get("https_port", 443)
        host = self.server.server_address[0]

        https_url = f"https://{host}:{https_port}{self.path}"

        self.send_response(301)  # Always permanent redirect
        self.send_header("Location", https_url)
        self.send_header("Content-Length", "0")
        self.end_headers()

        logger.info(
            f"Redirected HTTP request for {host}{self.path} to HTTPS {https_url}"
        )

    def perform_redirect(self, host: str):
        """Perform redirection based on host header to the configured destination."""
        rule = self.redirection_rules.get_rule(host)
        if rule:
            self._apply_redirect(rule, host)
            return

        logger.warning(f"No destination found for host: {host}")
        self.send_response(404)
        self.end_headers()

    def _apply_redirect(self, rule: RedirectRule, host: str):
        """Apply the redirect rule to the current request."""
        if rule.https_first and not self.is_ssl_connection:
            self.redirect_to_https()
            return

        full_url = (
            rule.get_redirect_url(self.path)
            if rule.preserve_path
            else rule.get_redirect_url()  # Take advantage of the cache
        )

        self.send_response(rule.redirect_type)
        self.send_header("Location", full_url)
        self.send_header("Content-Length", "0")
        self.end_headers()

        logger.info(
            f"Redirected {host}{self.path} to {full_url} (type: {rule.redirect_type})"
        )

    # Override to suppress request logging to stderr
    def log_message(self, format, *args):
        pass


class SNITCPServer(socketserver.ThreadingTCPServer):
    """
    TCP Server with SNI support to serve multiple TLS certificates based on hostname.
    """

    def __init__(
        self,
        server_address: tuple[str, int],
        RequestHandlerClass: http.server.BaseHTTPRequestHandler,
        redirect_config_file: str | Path,
        cert_mappings: dict[str, ssl.SSLContext],
        server_config: dict[str, Any],
        default_context: ssl.SSLContext,
    ):
        """
        Initialize server with certificate mappings.

        Args:
            server_address: (host, port) tuple
            RequestHandlerClass: Handler class for requests
            cert_mappings: Dictionary mapping hostnames to SSL contexts
            default_context: Default SSL context to use when hostname not in mappings
        """
        self.cert_mappings = cert_mappings
        self.redirect_config_file = redirect_config_file
        self.default_context = default_context
        self.is_ssl_enabled = default_context is not None
        self.server_config = server_config

        # Set up SNI callback for the default context
        if self.is_ssl_enabled:
            self.default_context.sni_callback = self.sni_callback
            self.sni_server_name = None

        socketserver.ThreadingTCPServer.__init__(
            self, server_address, RequestHandlerClass
        )

        # Create a standard socket
        self.socket = socket.socket(self.address_family, self.socket_type)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_bind()
        self.server_activate()

    def sni_callback(
        self, ssl_socket: ssl.SSLSocket, server_name: str, ssl_context: ssl.SSLContext
    ):
        """
        Callback function for SNI (Server Name Indication).
        This is called during the TLS handshake when the client specifies a hostname.

        Args:
            ssl_socket: The SSL socket
            server_name: The server name indicated by the client
            ssl_context: The SSL context
        """
        self.sni_server_name = server_name
        slog.info("SNI callback received hostname", server_name=server_name)

        # If we have a specific context for this hostname, use it
        if server_name and server_name in self.cert_mappings:
            # Update the socket's context to use the correct certificate
            ssl_socket.context = self.cert_mappings[server_name]

    def get_request(self):
        """
        Get request from client, but wrap socket with correct certificate based on SNI.
        """
        newsocket, fromaddr = self.socket.accept()

        if not self.is_ssl_enabled:
            return newsocket, fromaddr

        # Reset the SNI server name for this new connection
        self.sni_server_name = None

        # Create a wrapped TLS socket that will perform the handshake
        ssl_socket = self.default_context.wrap_socket(
            newsocket, server_side=True, do_handshake_on_connect=False
        )

        # Begin the TLS handshake
        try:
            # Start handshake to get client hello with SNI
            while True:
                try:
                    ssl_socket.do_handshake()
                    break
                except ssl.SSLWantReadError:
                    continue

        except ssl.SSLError as e:
            slog.error("TLS handshake error", error=str(e))
            newsocket.close()
            raise

        server_name = self.sni_server_name

        if server_name:
            slog.info("Using certificate for SNI hostname", server_name=server_name)

        return ssl_socket, fromaddr


def parse_config_line(line: str) -> tuple[str, str, list[str]]:
    """Parse a line of the configuration file and return a tuple of host, target_url, and options."""
    parts = line.split()
    if len(parts) < 2:
        slog.warn("Invalid line in config", line=line)
        return None, None, []
    return parts[0], parts[1], parts[2:]


def load_redirection_rules(config_file: str | Path) -> RedirectRules:
    """
    Parse the configuration file and return a RedirectRules object.
    Format: source_domain target_url [options...]
    """
    if not isinstance(config_file, Path):
        config_file = Path(config_file)

    if not config_file.exists():
        slog.warn("Configuration file not found", file=str(config_file))
        return RedirectRules()

    rules = RedirectRules()
    with config_file.open("r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Split into source, target, and options
            host, target_url, options = parse_config_line(line)
            if host is None:
                continue

            # Parse options
            redirect_type = 301
            preserve_path = True
            https_first = False

            for option in options:
                if option.startswith("type="):
                    try:
                        redirect_type = int(option.split("=")[1])
                        if redirect_type not in (301, 302):
                            slog.warn(
                                "Invalid redirect type", host=host, type=redirect_type
                            )
                            continue
                    except ValueError:
                        slog.warn(
                            "Invalid redirect type format", host=host, option=option
                        )
                        continue

                elif option.startswith("preserve_path="):
                    value = option.split("=")[1].lower()
                    preserve_path = value == "yes"

                elif option.startswith("https_first="):
                    value = option.split("=")[1].lower()
                    https_first = value == "yes"

            rule = RedirectRule(
                target_url=target_url,
                redirect_type=redirect_type,
                preserve_path=preserve_path,
                https_first=https_first,
            )
            rules.add_rule(host, rule)

    return rules


def load_cert_context(cert_file: str | Path, key_file: str | Path) -> ssl.SSLContext:
    """
    Create and configure an SSL context with certificate and key.

    Args:
        cert_file: Path to certificate file
        key_file: Path to key file

    Returns:
        An SSL context configured with the certificate and key
    """
    if not isinstance(cert_file, Path):
        cert_file = Path(cert_file)

    if not isinstance(key_file, Path):
        key_file = Path(key_file)

    if not cert_file.exists() or not key_file.exists():
        slog.error(
            "Certificate or key file not found",
            cert_file=str(cert_file),
            key_file=str(key_file),
        )
        raise FileNotFoundError(f"Certificate or key file not found")

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.options |= ssl.OP_CIPHER_SERVER_PREFERENCE
    context.load_cert_chain(certfile=cert_file, keyfile=key_file)

    return context


@lru_cache(maxsize=1)
def load_cert_mappings(
    config_file: str | Path,
) -> tuple[dict[str, ssl.SSLContext], ssl.SSLContext | None]:
    """
    Load certificate mappings from configuration file.

    Returns:
        tuple: (cert_mappings, default_context)
        cert_mappings is a dictionary mapping hostnames to SSL contexts
        default_context is the default SSL context
    """
    if not isinstance(config_file, Path):
        config_file = Path(config_file)

    if not config_file.exists():
        slog.warn("Certificate configuration file not found", file=str(config_file))
        return {}, None

    cert_mappings: dict[str, ssl.SSLContext] = {}
    default_context = None

    with config_file.open("r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            host, cert_info = line.split(" ", 1)
            cert_file, key_file = cert_info.split(" ", 1)

            if host == "default":
                default_context = load_cert_context(cert_file, key_file)
                continue

            try:
                context = load_cert_context(cert_file, key_file)
                cert_mappings[host] = context
                slog.info("Loaded certificate", host=host, cert_file=cert_file)
            except Exception as e:
                slog.error("Error loading certificate", host=host, error=str(e))

    return cert_mappings, default_context


def load_server_config(config_file: str | Path) -> dict[str, Any]:
    """
    Load server configuration from a file.
    """
    if not isinstance(config_file, Path):
        config_file = Path(config_file)

    if not config_file.exists():
        slog.warn("Server configuration file not found", file=str(config_file))
        return {}

    server_config = {}

    with config_file.open("r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            key, value = line.split(" ", 1)
            server_config[key] = value

    return server_config


def run_server(server_config: dict[str, Any]):
    """
    Run the server with the given configuration.
    """
    try:
        cert_mappings, default_context = load_cert_mappings(server_config["certs_file"])

        redirects = load_redirection_rules(server_config["redirects_file"])

        handler = RedirectHandler
        https_server = SNITCPServer(
            (server_config["host"], server_config["https_port"]),
            handler,
            redirects,
            cert_mappings,
            server_config,
            default_context,
        )

        http_server = SNITCPServer(
            (server_config["host"], server_config["http_port"]),
            handler,
            redirects,
            {},
            server_config,
            None,
        )

        http_thread = threading.Thread(target=http_server.serve_forever, daemon=True)
        http_thread.start()

        slog.info(
            "Starting HTTP redirect server",
            host=server_config["host"],
            port=server_config["http_port"],
        )
        slog.info(
            "Starting secure redirect server with SNI support",
            host=server_config["host"],
            port=server_config["https_port"],
        )
        slog.info(
            "Loaded certificates",
            count=len(cert_mappings),
            has_default=bool(default_context),
        )
        slog.info("Press Ctrl+C to stop the server")

        https_server.serve_forever()

    except KeyboardInterrupt:
        slog.info("Server stopped by user")
    except Exception as e:
        slog.error("Error starting server", error=str(e))
    finally:
        if https_server:
            slog.info("Shutting down HTTPS server...")
            https_server.shutdown()
            https_server.server_close()
            slog.info("HTTPS server closed")

        if http_server:
            slog.info("Shutting down HTTP server...")
            http_server.shutdown()
            http_server.server_close()
            slog.info("HTTP server closed")

        slog.info("All servers closed")
