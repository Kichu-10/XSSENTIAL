"""Loopback-only network safeguards shared by XSSential's HTTP and browser code."""

from __future__ import annotations

import ipaddress
from urllib.parse import urljoin, urlsplit


class UnsafeTargetError(ValueError):
    """Raised when a URL is not confined to the configured local origin."""


def _origin(url: str) -> tuple[str, str, int]:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise UnsafeTargetError("Only absolute HTTP(S) URLs are allowed.")
    try:
        port = parsed.port
    except ValueError as error:
        raise UnsafeTargetError("The URL has an invalid port.") from error
    return parsed.scheme.lower(), parsed.hostname.lower(), port or (
        443 if parsed.scheme.lower() == "https" else 80
    )


def validate_loopback_url(url: str, allowed_origin: tuple[str, str, int] | None = None) -> str:
    """Validate a literal loopback address or localhost URL and return it unchanged."""
    try:
        parsed = urlsplit(url)
        origin = _origin(url)
    except (TypeError, ValueError) as error:
        if isinstance(error, UnsafeTargetError):
            raise
        raise UnsafeTargetError("Invalid target URL.") from error

    if parsed.username is not None or parsed.password is not None:
        raise UnsafeTargetError("URLs containing credentials are not allowed.")

    hostname = origin[1]
    if hostname != "localhost":
        try:
            address = ipaddress.ip_address(hostname)
        except ValueError as error:
            raise UnsafeTargetError(
                "Only localhost or a loopback IP address is allowed."
            ) from error
        if not address.is_loopback:
            raise UnsafeTargetError(
                "Only localhost or a loopback IP address is allowed."
            )

    if allowed_origin is not None and origin != allowed_origin:
        raise UnsafeTargetError(
            "The URL is outside the configured local origin."
        )
    return url


def loopback_origin(url: str) -> tuple[str, str, int]:
    """Return the origin tuple after enforcing the loopback restriction."""
    validate_loopback_url(url)
    return _origin(url)


def safe_request(
    session,
    method: str,
    url: str,
    *,
    allowed_origin: tuple[str, str, int],
    max_redirects: int = 5,
    **kwargs,
):
    """Send an HTTP request while validating every redirect before following it."""
    current_url = url
    current_method = method.upper()
    request_kwargs = dict(kwargs)

    for redirect_count in range(max_redirects + 1):
        validate_loopback_url(current_url, allowed_origin)
        response = session.request(
            current_method,
            current_url,
            allow_redirects=False,
            **request_kwargs,
        )
        if response.status_code not in {301, 302, 303, 307, 308}:
            return response

        location = response.headers.get("Location")
        if not location:
            return response

        next_url = urljoin(response.url or current_url, location)
        try:
            validate_loopback_url(next_url, allowed_origin)
        except UnsafeTargetError:
            response.close()
            raise

        if redirect_count == max_redirects:
            response.close()
            raise UnsafeTargetError("Too many redirects from the local target.")

        if response.status_code == 303 or (
            response.status_code in {301, 302}
            and current_method not in {"GET", "HEAD"}
        ):
            current_method = "GET"
            for key in ("data", "json", "files"):
                request_kwargs.pop(key, None)
        request_kwargs.pop("params", None)
        response.close()
        current_url = next_url

    raise UnsafeTargetError("Too many redirects from the local target.")
