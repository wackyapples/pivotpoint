import argparse

import slog
from server import run_server
from config import parse_config

def get_args():
    parser = argparse.ArgumentParser(description="PivotPoint server")
    parser.add_argument(
        "--config",
        "-c",
        type=str,
        required=True,
        help="Configuration file",
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
    parser.add_argument(
        "--log-level",
        "-l",
        type=str,
        default="info",
        choices=["debug", "info", "warn", "error"],
        help="Log level",
    )
    parser.add_argument(
        "--log-format",
        "-f",
        type=str,
        default="text",
        choices=["text", "json"],
        help="Log format (text or json)",
    )
    return parser.parse_args()


def main():
    """Main function to start the redirection server with SNI support."""
    args = get_args()
    server_config = {
        "https_port": args.https_port,
        "http_port": args.http_port,
        "host": args.host,
    }

    # Configure logging
    level = slog.Level.from_string(args.log_level)
    handler = (
        slog.JSONHandler(level=level)
        if args.log_format == "json"
        else slog.TextHandler(level=level)
    )
    slog.set_default(slog.Logger(handler))
    
    redirects, certs, server_config = parse_config(args.config)

    run_server(redirects, certs, server_config)
