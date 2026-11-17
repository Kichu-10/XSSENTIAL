#!/usr/bin/env python3

import json
import uuid
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from playwright.sync_api import sync_playwright

if __package__:
    from .scope import UnsafeTargetError, loopback_origin, validate_loopback_url
else:
    from scope import UnsafeTargetError, loopback_origin, validate_loopback_url


class DOMAuditor:
    def __init__(self, target: str):
        validate_loopback_url(target)
        parsed = urlsplit(target)
        self.origin = loopback_origin(target)
        self.target = urlunsplit(
            (parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, "")
        )
        self.marker = "xsx_" + uuid.uuid4().hex[:12]
        self.token = uuid.uuid4().hex
        self.results: list[dict] = []
        self.blocked_urls: set[str] = set()
        self.instrumentation = Path(__file__).resolve().parent / "js" / "instrumentation.js"

    def build_payload(self) -> str:
        return (
            f"<svg onload=\"window.__xssentinel_exec('{self.token}')\"></svg>"
        )

    def build_test_url(self) -> str:
        parsed = urlsplit(self.target)
        params = parse_qsl(parsed.query, keep_blank_values=True)
        params.append(("xssentinel", self.marker + self.build_payload()))
        return urlunsplit(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                urlencode(params, doseq=True),
                parsed.fragment,
            )
        )

    def _guard_route(self, route):
        request_url = route.request.url
        if request_url.startswith(("about:", "data:", "blob:")):
            route.continue_()
            return
        try:
            validate_loopback_url(request_url, self.origin)
        except UnsafeTargetError:
            self.blocked_urls.add(request_url)
            route.abort()
            return
        route.continue_()

    def run(self) -> list[dict]:
        if not self.instrumentation.is_file():
            raise FileNotFoundError(
                f"DOM instrumentation file not found: {self.instrumentation}"
            )

        test_url = self.build_test_url()
        validate_loopback_url(test_url, self.origin)

        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                headless=True,
                args=[
                    "--disable-background-networking",
                    "--disable-component-update",
                    "--disable-dns-prefetch",
                    "--no-first-run",
                ],
            )
            try:
                context = browser.new_context(service_workers="block")
                context.route("**/*", self._guard_route)
                page = context.new_page()
                page.add_init_script(path=str(self.instrumentation))
                page.add_init_script(
                    """
                    (() => {
                      const NativeWebSocket = window.WebSocket;
                      function LocalOnlyWebSocket(url, protocols) {
                        const destination = new URL(url, window.location.href);
                        if (destination.origin !== window.location.origin) {
                          throw new DOMException(
                            "XSSentinel blocks cross-origin WebSockets",
                            "SecurityError"
                          );
                        }
                        return protocols === undefined
                          ? new NativeWebSocket(url)
                          : new NativeWebSocket(url, protocols);
                      }
                      LocalOnlyWebSocket.prototype = NativeWebSocket.prototype;
                      Object.setPrototypeOf(LocalOnlyWebSocket, NativeWebSocket);
                      window.WebSocket = LocalOnlyWebSocket;
                      const blockDirectNetwork = () => {
                        throw new DOMException(
                          "XSSentinel blocks direct peer connections",
                          "SecurityError"
                        );
                      };
                      if ("RTCPeerConnection" in window) {
                        window.RTCPeerConnection = blockDirectNetwork;
                      }
                      if ("webkitRTCPeerConnection" in window) {
                        window.webkitRTCPeerConnection = blockDirectNetwork;
                      }
                      if ("WebTransport" in window) {
                        window.WebTransport = blockDirectNetwork;
                      }
                    })();
                    """
                )
                page.goto(
                    test_url,
                    wait_until="domcontentloaded",
                    timeout=20_000,
                )
                page.evaluate(
                    "marker => window.__xssentinel_set_marker(marker)",
                    self.marker,
                )
                page.wait_for_timeout(500)
                report = page.evaluate(
                    """
                    () => ({
                      sources: window.__xssentinel?.sources || [],
                      sinks: window.__xssentinel?.sinks || [],
                      executions: window.__xssentinel?.executions || []
                    })
                    """
                )
                execution_verified = any(
                    item.get("token") == self.token
                    for item in report["executions"]
                )
                source_sink_observed = bool(report["sources"] and report["sinks"])
                self.results.append(
                    {
                        "url": test_url,
                        "type": "DOM-XSS",
                        "marker": self.marker,
                        "sources": report["sources"],
                        "sinks": report["sinks"],
                        "executions": report["executions"],
                        "execution_verified": execution_verified,
                        "source_sink_observed": source_sink_observed,
                        "confidence": (
                            "high"
                            if execution_verified
                            else "medium"
                            if source_sink_observed
                            else "informational"
                        ),
                    }
                )
            finally:
                browser.close()

        for blocked_url in sorted(self.blocked_urls):
            print(f"[LOCAL-ONLY] Blocked cross-origin browser request: {blocked_url}")
        return self.results

    def save(self) -> Path:
        output_dir = Path(__file__).resolve().parent / "reports"
        output_dir.mkdir(parents=True, exist_ok=True)
        output_path = output_dir / "dom-report.json"
        output_path.write_text(
            json.dumps(self.results, indent=2),
            encoding="utf-8",
        )
        return output_path


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="Run XSSentinel's localhost-only DOM audit."
    )
    parser.add_argument(
        "--url",
        required=True,
        help="Local app URL (localhost or loopback IP only)",
    )
    args = parser.parse_args(argv)

    try:
        auditor = DOMAuditor(args.url)
    except UnsafeTargetError as error:
        parser.error(str(error))
    findings = auditor.run()
    output_path = auditor.save()
    print(f"DOM report saved: {output_path}")
    print(json.dumps(findings, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
