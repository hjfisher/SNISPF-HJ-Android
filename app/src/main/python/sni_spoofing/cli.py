"""
SNISPF - Cross-platform SNI spoofing and DPI bypass tool.

Works on Windows, macOS, and Linux without requiring kernel drivers.
On Linux with root, enables raw packet injection for the seq_id trick.

Usage:
    snispf --config config.json
    snispf --listen 0.0.0.0:40443 --connect 104.18.38.202:443 --sni cdnjs.cloudflare.com
    snispf --check-domains domains.txt --output verified.txt
"""

import argparse
import asyncio
import json
import logging
import os
import platform
import signal
import sys
from pathlib import Path

# Add parent to path for direct script execution
if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).parent.parent))

from sni_spoofing import __version__
from sni_spoofing.bypass import (
    BypassStrategy,
    CombinedBypass,
    DirectBypass,
    FakeSNIBypass,
    FragmentBypass,
    RawInjector,
    is_raw_available,
)
from sni_spoofing.forwarder import start_server
from sni_spoofing.shaping import TrafficShaper
from sni_spoofing.pool import build_connection_manager
from sni_spoofing.ip_discovery import build_ip_discovery
from sni_spoofing.sni_discovery import build_sni_discovery
from sni_spoofing.utils import (
    check_platform_capabilities,
    get_default_interface_ipv4,
    is_valid_ip,
    is_valid_port,
    resolve_host,
)

# ─── Banner ──────────────────────────────────────────────────────────────────

def _build_banner() -> str:
    """Render the startup banner with the current package version.

    The version is read from ``sni_spoofing.__version__`` so the banner always
    matches the installed package (fixes the long-standing "source still says
    v1.7.0" reports from users who clone the repo at a newer release).
    """
    version_line = f"SNI Spoofing + TLS Fragmentation  v{__version__}"
    # Inside-the-box content is 63 chars wide (between '│  ' and the trailing '│').
    return (
        "\n"
        " ███████╗███╗   ██╗██╗███████╗██████╗ ███████╗\n"
        " ██╔════╝████╗  ██║██║██╔════╝██╔══██╗██╔════╝\n"
        " ███████╗██╔██╗ ██║██║███████╗██████╔╝█████╗\n"
        " ╚════██║██║╚██╗██║██║╚════██║██╔═══╝ ██╔══╝\n"
        " ███████║██║ ╚████║██║███████║██║     ██║\n"
        " ╚══════╝╚═╝  ╚═══╝╚═╝╚══════╝╚═╝     ╚═╝\n"
        "\n"
        "     ┌──────────────────────────────────────────────────────────────────┐\n"
        "     │  SNISPF - Cross-Platform DPI Bypass Tool                        │\n"
        f"     │  {version_line:<63}│\n"
        "     │  Works on Windows / macOS / Linux                               │\n"
        "     │  https://github.com/Rainman69/SNISPF                            │\n"
        "     └──────────────────────────────────────────────────────────────────┘\n"
    )


BANNER = _build_banner()

# ─── Logging ─────────────────────────────────────────────────────────────────

def setup_logging(verbose: bool = False, quiet: bool = False):
    """Configure logging with deduplication guard."""
    if quiet:
        level = logging.WARNING
    elif verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO

    formatter = logging.Formatter(
        "%(asctime)s │ %(levelname)-7s │ %(message)s",
        datefmt="%H:%M:%S",
    )

    logger = logging.getLogger("snispf")
    # Prevent handler accumulation on repeated calls
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    logger.setLevel(level)

    return logger


# ─── Config ──────────────────────────────────────────────────────────────────

DEFAULT_CONFIG = {
    "LISTEN_HOST": "0.0.0.0",
    "LISTEN_PORT": 40443,
    "CONNECT_IP": "104.18.38.202",
    "CONNECT_PORT": 443,
    "FAKE_SNI": "cdnjs.cloudflare.com",
    "BYPASS_METHOD": "fragment",
    "FRAGMENT_STRATEGY": "sni_split",
    "FRAGMENT_DELAY": 0.1,
    "USE_TTL_TRICK": False,
    "FAKE_SNI_METHOD": "prefix_fake",
}


def load_config(config_path: str) -> dict:
    """Load configuration from JSON file."""
    try:
        with open(config_path, "r") as f:
            user_config = json.load(f)

        # Merge with defaults
        config = DEFAULT_CONFIG.copy()
        config.update(user_config)
        return config
    except FileNotFoundError:
        print(f"Error: Config file not found: {config_path}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in config file: {e}")
        sys.exit(1)


def generate_config(output_path: str):
    """Generate a default configuration file."""
    config = {
        "LISTEN_HOST": "0.0.0.0",
        "LISTEN_PORT": 40443,
        "CONNECT_IP": "104.18.38.202",
        "CONNECT_PORT": 443,
        "FAKE_SNI": "cdnjs.cloudflare.com",
        "BYPASS_METHOD": "fragment",
        "FRAGMENT_STRATEGY": "sni_split",
        "FRAGMENT_DELAY": 0.1,
        "USE_TTL_TRICK": False,
        "FAKE_SNI_METHOD": "prefix_fake",
    }

    with open(output_path, "w") as f:
        json.dump(config, f, indent=2)

    print(f"Generated default config: {output_path}")
    print(json.dumps(config, indent=2))


# ─── Strategy Builder ────────────────────────────────────────────────────────

def build_strategy(config: dict, raw_injector=None) -> BypassStrategy:
    """Build the appropriate bypass strategy from config.

    Available methods:
    - "direct": No SNI spoofing at all — forward the client's real
      ClientHello unmodified. Use when the upstream itself already
      handles censorship circumvention (e.g. VLESS+Reality, Trojan) and
      SNISPF-HJ is only being used for its multi-IP connection pool.
    - "fragment": Fragment TLS ClientHello at SNI boundary
    - "fake_sni": Send fake ClientHello with spoofed SNI (needs raw sockets
      for the seq_id trick; falls back to fragmentation without them)
    - "combined": Both fragmentation and fake SNI (recommended)
    """
    method = config.get("BYPASS_METHOD", "fragment").lower()

    if method == "direct":
        return DirectBypass()
    elif method == "fragment":
        return FragmentBypass(
            strategy=config.get("FRAGMENT_STRATEGY", "sni_split"),
            fragment_delay=config.get("FRAGMENT_DELAY", 0.1),
        )
    elif method == "fake_sni":
        return FakeSNIBypass(
            method=config.get("FAKE_SNI_METHOD", "prefix_fake"),
            raw_injector=raw_injector,
            use_ttl_trick=config.get("USE_TTL_TRICK", False),
            # When a raw injector is active, also fragment the real
            # ClientHello at the SNI boundary so that DPI which
            # reassembles the TCP stream cannot match the SNI on the
            # real handshake. Required for some xhttp / ws configs
            # (e.g. multi-value ALPN like h3,h2,http/1.1).
            fragment_real=config.get("FAKE_SNI_FRAGMENT_REAL", True),
            fragment_strategy=config.get("FRAGMENT_STRATEGY", "sni_split"),
        )
    elif method == "combined":
        return CombinedBypass(
            fragment_strategy=config.get("FRAGMENT_STRATEGY", "sni_split"),
            use_ttl_trick=config.get("USE_TTL_TRICK", False),
            fragment_delay=config.get("FRAGMENT_DELAY", 0.1),
            raw_injector=raw_injector,
        )
    else:
        print(f"Warning: Unknown bypass method '{method}', using 'fragment'")
        return FragmentBypass()


# ─── CLI ─────────────────────────────────────────────────────────────────────

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        prog="snispf",
        description=(
            "SNISPF - Cross-platform DPI bypass tool.\n\n"
            "This tool forwards TCP connections while applying DPI bypass\n"
            "techniques (SNI spoofing, TLS fragmentation) to circumvent\n"
            "internet censorship."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s --config config.json\n"
            "  %(prog)s -l 0.0.0.0:40443 -c 104.18.38.202:443 -s cdnjs.cloudflare.com\n"
            "  %(prog)s -l :40443 -c 104.18.38.202:443 -s www.speedtest.net -m combined\n"
            "  %(prog)s --generate-config my_config.json\n"
            "\nBypass Methods:\n"
            "  direct     - No SNI spoofing; forward client's real SNI as-is\n"
            "               (use when upstream already handles censorship\n"
            "               circumvention itself, e.g. VLESS+Reality/Trojan)\n"
            "  fragment   - Fragment TLS ClientHello at SNI boundary (default)\n"
            "  fake_sni   - Inject fake ClientHello (needs root for seq_id trick)\n"
            "  combined   - Both fragmentation and fake SNI (most effective)\n"
            "\nDomain Checker:\n"
            "  %(prog)s --check-domains domains.txt\n"
            "  %(prog)s --check-domains domains.txt --output verified.txt\n"
            "  %(prog)s --check-domains domains.txt --check-http\n"
            "\nhttps://github.com/Rainman69/SNISPF"
        ),
    )

    # Config file
    parser.add_argument(
        "--config", "-C",
        help="Path to JSON config file",
    )
    parser.add_argument(
        "--generate-config",
        metavar="PATH",
        help="Generate a default config file and exit",
    )

    # Connection settings
    parser.add_argument(
        "--listen", "-l",
        metavar="HOST:PORT",
        help="Listen address (default: 0.0.0.0:40443)",
    )
    parser.add_argument(
        "--connect", "-c",
        metavar="IP:PORT",
        help="Target server address (default: 104.18.38.202:443)",
    )
    parser.add_argument(
        "--sni", "-s",
        metavar="HOSTNAME",
        help="Fake SNI hostname (default: cdnjs.cloudflare.com)",
    )

    # Bypass settings
    parser.add_argument(
        "--method", "-m",
        choices=["direct", "fragment", "fake_sni", "combined"],
        help="Bypass method (default: fragment)",
    )
    parser.add_argument(
        "--fragment-strategy",
        choices=["sni_split", "half", "multi", "tls_record_frag"],
        help="Fragment strategy (default: sni_split)",
    )
    parser.add_argument(
        "--fragment-delay",
        type=float,
        metavar="SECONDS",
        help="Delay between fragments in seconds (default: 0.1)",
    )
    parser.add_argument(
        "--ttl-trick",
        action="store_true",
        help="Use IP TTL trick for fake packets (may need privileges)",
    )
    parser.add_argument(
        "--no-raw",
        action="store_true",
        help="Disable raw socket injection even if available",
    )

    # ─── Domain checker ──────────────────────────────────────────────
    domain_group = parser.add_argument_group("Domain Checker Options")
    domain_group.add_argument(
        "--check-domains",
        metavar="FILE",
        help="Check domains from a file to find Cloudflare-backed ones",
    )
    domain_group.add_argument(
        "--check-workers",
        type=int,
        default=50,
        metavar="N",
        help="Parallel workers for domain checking (default: 50)",
    )
    domain_group.add_argument(
        "--check-timeout",
        type=float,
        default=3.0,
        metavar="SECONDS",
        help="Per-domain timeout for checking (default: 3.0)",
    )
    domain_group.add_argument(
        "--output",
        metavar="FILE",
        help="Export verified Cloudflare domains to a file",
    )
    domain_group.add_argument(
        "--check-http",
        action="store_true",
        help="Also verify HTTP connectivity during domain check",
    )

    # Output settings
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output (debug logging)",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Quiet output (warnings only)",
    )
    parser.add_argument(
        "--version", "-V",
        action="version",
        version=f"SNISPF {__version__}",
    )
    parser.add_argument(
        "--info",
        action="store_true",
        help="Show platform capabilities and exit",
    )

    return parser.parse_args()


def parse_host_port(addr: str, default_host: str = "0.0.0.0", default_port: int = 443) -> tuple:
    """Parse HOST:PORT string.  Returns (host, port)."""
    if not addr:
        return default_host, default_port

    if addr.startswith(":"):
        try:
            return default_host, int(addr[1:])
        except ValueError:
            print(f"Error: Invalid port in '{addr}'")
            sys.exit(1)

    parts = addr.rsplit(":", 1)
    if len(parts) == 2:
        host = parts[0] or default_host
        try:
            port = int(parts[1])
        except ValueError:
            print(f"Error: Invalid port in '{addr}'")
            sys.exit(1)
        return host, port
    else:
        return parts[0], default_port


def show_platform_info():
    """Display platform capability information."""
    caps = check_platform_capabilities()

    # Also check raw injection availability
    caps["raw_injection"] = is_raw_available()

    print("\n╔══════════════════════════════════════════╗")
    print("║       Platform Capabilities              ║")
    print("╠══════════════════════════════════════════╣")
    for key, value in caps.items():
        status = "✓" if value is True else ("✗" if value is False else str(value))
        print(f"║  {key:<28} {status:>8}  ║")
    print("╚══════════════════════════════════════════╝")

    print("\nRecommended bypass methods for your platform:")
    if caps["raw_injection"]:
        print("  ✓ Raw packet injection available (running as root)")
        print("  ★ Recommended: combined (uses seq_id trick + fragmentation)")
        print("  ★ Also good:   fake_sni (uses seq_id trick)")
    elif caps["raw_socket"]:
        print("  ✓ All methods available (running with sufficient privileges)")
        print("  ★ Recommended: combined --ttl-trick")
    else:
        print("  ✓ fragment    - TLS ClientHello fragmentation")
        print("  ✓ fake_sni    - TTL trick + fragmentation (auto-enabled)")
        print("  ✓ combined    - TTL trick + fragmentation (recommended)")
        print("  ★ Recommended: combined (auto-uses TTL trick)")
        if platform.system() != "Windows":
            print("  ℹ  Run with sudo/root for raw injection (seq_id trick)")
        print("  ℹ  TTL trick is auto-enabled when raw sockets are unavailable")

    print("\nDomain Checker:")
    print("  ✓ Bulk Cloudflare-backed domain verifier (no privileges needed)")
    print("  ★ Use --check-domains FILE to validate SNI candidates")


# ─── Domain Checker Command ──────────────────────────────────────────────────

def run_domain_check(args, logger):
    """Execute a bulk domain check and print results."""
    from sni_spoofing.scanner import DomainChecker

    checker = DomainChecker(
        concurrency=args.check_workers,
        timeout=args.check_timeout,
        verify_tls=True,
        verify_http=getattr(args, "check_http", False),
    )

    # Load domains from file
    try:
        domains = checker.load_domains_from_file(args.check_domains)
    except FileNotFoundError:
        print(f"Error: File not found: {args.check_domains}")
        return
    except Exception as e:
        print(f"Error reading file: {e}")
        return

    if not domains:
        print("No domains found in file.")
        return

    print(f"\n  Checking {len(domains)} domains...\n")

    # Progress display
    def progress(done, total):
        pct = done * 100 // total
        bar = "█" * (pct // 5) + "░" * (20 - pct // 5)
        print(f"\r  Checking: [{bar}] {done}/{total} ({pct}%)", end="", flush=True)

    results = checker.check_domains(domains, progress_cb=progress)
    print()  # newline after progress bar

    # Display results
    cf_results = [r for r in results if r.is_cloudflare]
    usable = [r for r in results if r.usable_as_sni]

    print(f"\n{'═' * 90}")
    print(f"  Domain Check Results")
    print(f"{'═' * 90}")
    print(f"  Total domains:    {len(results)}")
    print(f"  Behind Cloudflare: {len(cf_results)}")
    print(f"  Usable as SNI:    {len(usable)}")
    print(f"{'═' * 90}\n")

    # Show Cloudflare-backed domains
    print(checker.results_table(results, cloudflare_only=True))

    # Export if requested
    if args.output:
        count = checker.export_sni_list(results, args.output)
        print(f"\n  Exported {count} verified domains to {args.output}")

    # Also show summary for non-CF domains
    non_cf = [r for r in results if not r.is_cloudflare and r.ip]
    if non_cf:
        print(f"\n  Note: {len(non_cf)} domains are NOT behind Cloudflare")
        print(f"  (these will not work for SNI spoofing through Cloudflare IPs)")
    print()


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    """Main entry point."""
    args = parse_args()

    # Handle special commands
    if args.generate_config:
        generate_config(args.generate_config)
        return

    if args.info:
        print(BANNER)
        show_platform_info()
        return

    # Print banner
    print(BANNER)

    # Setup logging
    logger = setup_logging(verbose=args.verbose, quiet=args.quiet)

    # Load configuration
    if args.config:
        config = load_config(args.config)
    else:
        config = DEFAULT_CONFIG.copy()

    # Override with CLI arguments
    if args.listen:
        host, port = parse_host_port(args.listen, "0.0.0.0", 40443)
        config["LISTEN_HOST"] = host
        config["LISTEN_PORT"] = port

    if args.connect:
        host, port = parse_host_port(args.connect, "104.18.38.202", 443)
        config["CONNECT_IP"] = host
        config["CONNECT_PORT"] = port

    if args.sni:
        config["FAKE_SNI"] = args.sni

    if args.method:
        config["BYPASS_METHOD"] = args.method

    if args.fragment_strategy:
        config["FRAGMENT_STRATEGY"] = args.fragment_strategy

    if args.fragment_delay is not None:
        config["FRAGMENT_DELAY"] = args.fragment_delay

    if args.ttl_trick:
        config["USE_TTL_TRICK"] = True

    # ── Domain checker mode ───────────────────────────────────────────
    if args.check_domains:
        run_domain_check(args, logger)
        return

    # ── Auto-load config.json if present and no --config given ──────
    if not args.config:
        for candidate in ["config.json", "snispf.json"]:
            if os.path.isfile(candidate):
                logger.info("Auto-loading config from %s", candidate)
                user_config = load_config(candidate)
                # Only apply file values for keys that were NOT
                # explicitly overridden by CLI arguments.
                cli_overridden = set()
                if args.listen:
                    cli_overridden.update(["LISTEN_HOST", "LISTEN_PORT"])
                if args.connect:
                    cli_overridden.update(["CONNECT_IP", "CONNECT_PORT"])
                if args.sni:
                    cli_overridden.add("FAKE_SNI")
                if args.method:
                    cli_overridden.add("BYPASS_METHOD")
                if args.fragment_strategy:
                    cli_overridden.add("FRAGMENT_STRATEGY")
                if args.fragment_delay is not None:
                    cli_overridden.add("FRAGMENT_DELAY")
                if args.ttl_trick:
                    cli_overridden.add("USE_TTL_TRICK")

                for key, val in user_config.items():
                    if key not in cli_overridden:
                        config[key] = val
                break

    # ── Validate config ───────────────────────────────────────────────
    if not is_valid_port(config["LISTEN_PORT"]):
        print(f"Error: Invalid listen port: {config['LISTEN_PORT']}")
        sys.exit(1)

    if not is_valid_port(config["CONNECT_PORT"]):
        print(f"Error: Invalid connect port: {config['CONNECT_PORT']}")
        sys.exit(1)

    # Resolve target host if needed
    config["CONNECT_IP"] = resolve_host(config["CONNECT_IP"])

    # ── Build connection pool (multi-IP / multi-SNI) ──────────────────
    # build_connection_manager returns None when only a single IP+SNI is
    # configured, in which case the server falls back to the original
    # single-target code path.  When a pool IS available, the "primary"
    # CONNECT_IP and FAKE_SNI values are set to the first list entries so
    # that the raw injector (which still needs a single remote IP) still
    # works for the most common upstream.
    conn_manager = build_connection_manager(config)
    if conn_manager is not None:
        # Derive a representative IP for interface detection and raw injector.
        first_ip = list(conn_manager.explorer.stats.keys())[0][0]
        config.setdefault("CONNECT_IP", first_ip)
        config.setdefault("FAKE_SNI", list(conn_manager.explorer.stats.keys())[0][1])

    # Detect interface IP
    interface_ip = get_default_interface_ipv4(config["CONNECT_IP"])
    logger.info(f"Default interface: {interface_ip or 'auto'}")

    # ── Raw injector setup ────────────────────────────────────────────
    raw_injector = None
    use_raw = not getattr(args, 'no_raw', False)
    method = config.get("BYPASS_METHOD", "fragment").lower()

    if use_raw and method in ("fake_sni", "combined") and interface_ip:
        if is_raw_available():
            from sni_spoofing.bypass.raw_injector import RawInjector
            raw_injector = RawInjector(
                local_ip=interface_ip,
                remote_ip=config["CONNECT_IP"],
                remote_port=config["CONNECT_PORT"],
                fake_sni_builder=None,
            )
            if not raw_injector.start():
                logger.warning(
                    "Raw injector failed to start. "
                    "Enabling TTL trick as fallback."
                )
                raw_injector = None
                config["USE_TTL_TRICK"] = True
        else:
            # No raw sockets (macOS, Android/Termux, unprivileged Linux).
            # Auto-enable the TTL trick: sends a fake ClientHello with a
            # low IP TTL that reaches the nearby DPI middlebox but expires
            # before the real server.  Works on any platform that supports
            # setsockopt(IP_TTL).
            config["USE_TTL_TRICK"] = True
            if method == "fake_sni":
                logger.info(
                    "Raw sockets not available (need root/CAP_NET_RAW). "
                    "fake_sni will use TTL trick + fragmentation."
                )
            elif method == "combined":
                logger.info(
                    "Raw sockets not available. "
                    "Using TTL trick + fragmentation bypass."
                )

    # Build bypass strategy
    strategy = build_strategy(config, raw_injector=raw_injector)

    # Show configuration summary
    logger.info(f"Platform: {platform.system()} {platform.machine()}")
    logger.info(f"Python: {platform.python_version()}")

    # ── Start pool health loop in background daemon thread ────────────
    if conn_manager is not None:
        conn_manager.start_health_loop()
        logger.info(
            "Connection pool active — %d pair(s), %d active slot(s)",
            len(conn_manager.explorer.stats),
            conn_manager.pool.slots,
        )

        # ── Start dynamic IP discovery (optional) ──────────────────────
        discovery = build_ip_discovery(conn_manager, config)
        if discovery is not None:
            discovery.start()
            logger.info(
                "Dynamic IP discovery active — batch=%d  interval=%ds",
                discovery.scan_batch, int(discovery.scan_interval),
            )
        else:
            logger.info(
                "Dynamic IP discovery: disabled "
                "(set DYNAMIC_IP_DISCOVERY=true in config to enable)"
            )

        # ── Start dynamic SNI discovery (optional) ─────────────────────
        sni_discovery = build_sni_discovery(conn_manager, config)
        if sni_discovery is not None:
            sni_discovery.start()
            logger.info(
                "Dynamic SNI discovery active — batch=%d  interval=%ds  "
                "source_refresh=%ds",
                sni_discovery.scan_batch, int(sni_discovery.scan_interval),
                int(sni_discovery.source_refresh_interval),
            )
        else:
            logger.info(
                "Dynamic SNI discovery: disabled "
                "(set DYNAMIC_SNI_DISCOVERY=true in config to enable)"
            )

    # Setup signal handlers for graceful shutdown
    def signal_handler(sig, frame):
        print("\n\nShutting down...")
        if raw_injector:
            raw_injector.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, signal_handler)

    # Run the server
    shaper = TrafficShaper.from_config(config)
    try:
        asyncio.run(
            start_server(
                listen_host=config["LISTEN_HOST"],
                listen_port=config["LISTEN_PORT"],
                connect_ip=config["CONNECT_IP"],
                connect_port=config["CONNECT_PORT"],
                fake_sni=config["FAKE_SNI"],
                bypass_strategy=strategy,
                interface_ip=interface_ip,
                raw_injector=raw_injector,
                conn_manager=conn_manager,
                shaper=shaper,
            )
        )
    except KeyboardInterrupt:
        print("\nShutting down...")
    except PermissionError:
        print(f"\nError: Permission denied on port {config['LISTEN_PORT']}.")
        if config["LISTEN_PORT"] < 1024:
            print("Ports below 1024 require root/administrator privileges.")
            print(f"Try: sudo {sys.argv[0]} ... or use a port >= 1024")
        sys.exit(1)
    except OSError as e:
        if "address already in use" in str(e).lower():
            print(f"\nError: Port {config['LISTEN_PORT']} is already in use.")
            print("Use --listen :PORT to specify a different port.")
        else:
            print(f"\nError: {e}")
        sys.exit(1)
    finally:
        if raw_injector:
            raw_injector.stop()


if __name__ == "__main__":
    main()
