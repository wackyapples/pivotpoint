#!/usr/bin/env python3

import argparse
import http.server
import logging
import socket
import socketserver
import ssl
import threading
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("redirect_server")


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


class RedirectHandler(http.server.BaseHTTPRequestHandler):
    """Handler for HTTP requests that performs redirects based on the Host header."""

    server: "SNITCPServer"
    redirection_rules: dict[str, RedirectRule]
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
        rule = self.redirection_rules.get(host, self.redirection_rules.get("default"))
        if not rule:
            logger.warning(f"No destination found for host: {host}")
            self.send_response(404)
            self.end_headers()
            return

        if rule.https_first and not self.is_ssl_connection:
            self.redirect_to_https()
            return
        else:
            logger.info(f"{rule.https_first = } {self.is_ssl_connection = }")

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

    def version_string(self):
        return f"PivotPoint/0.1 {self.sys_version}"


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
        logger.info(f"SNI callback received hostname: {server_name}")

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
            logger.error(f"TLS handshake error: {e}")
            newsocket.close()
            raise

        server_name = self.sni_server_name

        if server_name:
            logger.info(f"Using certificate for SNI hostname: {server_name}")

        return ssl_socket, fromaddr


def parse_config_line(line: str) -> tuple[str, str, list[str]]:
    """Parse a line of the configuration file and return a tuple of host, target_url, and options."""
    parts = line.split()
    if len(parts) < 2:
        logger.warning(f"Invalid line in config: {line}")
        return None, None, []
    return parts[0], parts[1], parts[2:]


@lru_cache(maxsize=1)
def load_redirection_rules(config_file: str | Path) -> dict[str, RedirectRule]:
    """
    Parse the configuration file and return a dictionary of host to RedirectRule.
    Format: source_domain target_url [options...]
    """
    if not isinstance(config_file, Path):
        config_file = Path(config_file)

    if not config_file.exists():
        logger.warning(f"Configuration file not found: {config_file}")
        return {}

    rules = {}
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
                            logger.warning(
                                f"Invalid redirect type for {host}: {redirect_type}"
                            )
                            continue
                    except ValueError:
                        logger.warning(
                            f"Invalid redirect type format for {host}: {option}"
                        )
                        continue

                elif option.startswith("preserve_path="):
                    value = option.split("=")[1].lower()
                    preserve_path = value == "yes"

                elif option.startswith("https_first="):
                    value = option.split("=")[1].lower()
                    https_first = value == "yes"

            rules[host] = RedirectRule(
                target_url=target_url,
                redirect_type=redirect_type,
                preserve_path=preserve_path,
                https_first=https_first,
            )

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
        logger.error(f"Certificate ({cert_file}) or key ({key_file}) file not found")
        raise FileNotFoundError(f"Certificate or key file not found")

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)

    # Configure with modern ciphers and protocols
    # Disable older, insecure protocols
    context.minimum_version = ssl.TLSVersion.TLSv1_1

    # Use server's preferred cipher suites
    context.options |= ssl.OP_CIPHER_SERVER_PREFERENCE

    # Load certificate and private key
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
        logger.warning(f"Certificate configuration file not found: {config_file}")
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
                logger.info(f"Loaded certificate for {host}: {cert_file}")
            except Exception as e:
                logger.error(f"Error loading certificate for {host}: {e}")

    return cert_mappings, default_context


def get_args():
    parser = argparse.ArgumentParser(description="PivotPoint server")
    parser.add_argument(
        "--redirects",
        "-r",
        type=str,
        required=True,
        help="Redirects configuration file",
    )
    parser.add_argument(
        "--certs",
        "-c",
        type=str,
        required=True,
        help="Certificates configuration file",
    )
    parser.add_argument(
        "--http-port",
        "-p",
        type=int,
        default=8080,
        help="HTTP port to listen on",
    )
    parser.add_argument(
        "--https-port",
        "-s",
        type=int,
        default=8443,
        help="HTTPS port to listen on",
    )
    parser.add_argument(
        "--host",
        "-H",
        type=str,
        default="",
        help="Host to listen on",
    )
    return parser.parse_args()


def main():
    """Main function to start the redirection server with SNI support."""
    # Server configuration
    args = get_args()
    https_port = args.https_port
    http_port = args.http_port
    https_server = None
    http_server = None
    http_thread = None
    server_config = {
        "https_port": https_port,
        "http_port": http_port,
    }

    try:
        # Load certificate mappings and default context
        cert_mappings, default_context = load_cert_mappings(args.certs)

        # Create the HTTPS server with SNI support
        handler = RedirectHandler
        https_server = SNITCPServer(
            (args.host, https_port),
            handler,
            args.redirects,
            cert_mappings,
            server_config,
            default_context,
        )

        # Create an HTTP server that will redirect to HTTPS
        http_server = SNITCPServer(
            (args.host, http_port), handler, args.redirects, {}, server_config, None
        )

        # Start HTTP server in a separate thread
        http_thread = threading.Thread(target=http_server.serve_forever, daemon=True)
        http_thread.start()

        logger.info(f"Starting HTTP redirect server on port {http_port}")
        logger.info(
            f"Starting secure redirect server with SNI support on port {https_port}"
        )
        logger.info(
            f"Loaded certificates for {len(cert_mappings)} hostnames plus default"
        )
        logger.info("Press Ctrl+C to stop the server")

        # Start the HTTPS server in the main thread
        https_server.serve_forever()

    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Error starting server: {e}")
    finally:

        if https_server:
            logger.info("Shutting down HTTPS server...")
            https_server.shutdown()
            https_server.server_close()
            logger.info("HTTPS server closed")

        if http_server:
            logger.info("Shutting down HTTP server...")
            http_server.shutdown()
            http_server.server_close()
            logger.info("HTTP server closed")

        logger.info("All servers closed")


if __name__ == "__main__":
    main()
