"""Domain utilities: bulk Cloudflare-domain checker.

This module previously hosted a Cloudflare clean-IP scanner together with
an SNI rotator and a background re-scan engine.  The scanner was never
finished and frequently produced misleading results (rate-limit false
negatives, stale caches, mis-ordered latency rankings), so the entire
``--scan`` / ``--auto`` / ``--rescan`` feature surface has been removed.

What stays is the lightweight bulk **domain checker**: given a text file
of hostnames it tells you which ones are actually fronted by Cloudflare
and therefore usable as a fake SNI value.  It is fully synchronous, has
no background threads, and is safe to invoke from the CLI.
"""

from .domain_checker import DomainChecker, DomainResult, is_cloudflare_ip

__all__ = [
    "DomainChecker",
    "DomainResult",
    "is_cloudflare_ip",
]
