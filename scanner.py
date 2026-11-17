#!/usr/bin/env python3

import argparse
import json
import uuid
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style, init

if __package__:
    from .scope import (
        UnsafeTargetError,
        loopback_origin,
        safe_request,
        validate_loopback_url,
    )
else:
    from scope import (
        UnsafeTargetError,
        loopback_origin,
        safe_request,
        validate_loopback_url,
    )


TIMEOUT = 12
MAX_PAGES = 40
REPORT_DIR = Path(__file__).resolve().parent / "reports"

init(autoreset=True)


class XSSentinel:
    def __init__(self, target: str):
        validate_loopback_url(target)
        parsed = urlsplit(target)
        self.origin = loopback_origin(target)
        self.target = urlunsplit(
            (parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, "")
        )
        self.session = requests.Session()
        self.session.headers.update(
            {"User-Agent": "XSSentinel/1.0 Local Security Scanner"}
        )
        self.visited: set[str] = set()
        self.findings: list[dict[str, str]] = []
        self.dom_findings: list[dict] = []

    def in_scope(self, url: str) -> bool:
        try:
            validate_loopback_url(url, self.origin)
        except UnsafeTargetError:
            return False
        return True

    def _request(self, method: str, url: str, **kwargs):
        return safe_request(
            self.session,
            method,
            url,
            allowed_origin=self.origin,
            timeout=TIMEOUT,
            **kwargs,
        )

    def record(self, category: str, url: str, evidence: str, confidence: str):
        self.findings.append(
            {
                "type": category,
                "url": url,
                "evidence": evidence,
                "confidence": confidence,
            }
        )
        print(f"{Fore.RED}[{category}]{Style.RESET_ALL} {url}")
        print(f"Evidence: {evidence}")

    def crawl(self) -> list[str]:
        queue = [self.target]
        queued = {self.target}

        while queue and len(self.visited) < MAX_PAGES:
            url = queue.pop(0)
            if url in self.visited or not self.in_scope(url):
                continue
            self.visited.add(url)

            try:
                response = self._request("GET", url)
            except (requests.RequestException, UnsafeTargetError) as error:
                print(f"{Fore.YELLOW}[CRAWL ERROR]{Style.RESET_ALL} {url}: {error}")
                continue

            try:
                if "text/html" not in response.headers.get("Content-Type", "").lower():
                    continue
                soup = BeautifulSoup(response.text, "html.parser")
                page_url = response.url
                print(f"{Fore.CYAN}[CRAWL]{Style.RESET_ALL} {page_url}")

                for link in soup.find_all("a", href=True):
                    next_url = urljoin(page_url, link["href"])
                    if (
                        self.in_scope(next_url)
                        and next_url not in self.visited
                        and next_url not in queued
                    ):
                        queue.append(next_url)
                        queued.add(next_url)
            finally:
                response.close()

        return list(self.visited)

    def reflected_xss(self, url: str):
        parsed = urlsplit(url)
        query = parse_qsl(parsed.query, keep_blank_values=True)
        if not query:
            return

        for index in range(len(query)):
            parameter = query[index][0]
            marker = "XSX" + uuid.uuid4().hex[:12]
            test_query = list(query)
            test_query[index] = (parameter, marker)
            test_url = urlunsplit(
                (
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    urlencode(test_query, doseq=True),
                    parsed.fragment,
                )
            )

            try:
                response = self._request("GET", test_url)
            except (requests.RequestException, UnsafeTargetError) as error:
                print(
                    f"{Fore.YELLOW}[REFLECTION ERROR]{Style.RESET_ALL} "
                    f"{test_url}: {error}"
                )
                continue

            try:
                if marker not in response.text:
                    continue
                soup = BeautifulSoup(response.text, "html.parser")
                contexts = {
                    element.parent.name
                    for element in soup.find_all(string=lambda text: text and marker in text)
                    if element.parent is not None
                }
                context_text = ", ".join(sorted(contexts)) or "response body"
                self.record(
                    "REFLECTED-INPUT",
                    test_url,
                    f"Harmless marker reflected in {context_text}; this alone does not confirm XSS.",
                    "Informational",
                )
            finally:
                response.close()

    def stored_xss(self, url: str):
        try:
            response = self._request("GET", url)
        except (requests.RequestException, UnsafeTargetError) as error:
            print(f"{Fore.YELLOW}[FORM ERROR]{Style.RESET_ALL} {url}: {error}")
            return

        try:
            page_url = response.url
            soup = BeautifulSoup(response.text, "html.parser")
            forms = soup.find_all("form")
        finally:
            response.close()

        for form in forms:
            action = urljoin(page_url, form.get("action") or page_url)
            if not self.in_scope(action):
                continue

            method = form.get("method", "get").lower()
            if method not in {"get", "post"}:
                continue

            fields: dict[str, str] = {}
            marker = "XSX" + uuid.uuid4().hex[:12]
            marker_added = False
            for field in form.select("input[name], textarea[name]"):
                name = field.get("name")
                if not name:
                    continue
                if field.name == "textarea":
                    fields[name] = marker
                    marker_added = True
                    continue

                field_type = field.get("type", "text").lower()
                if field_type == "hidden":
                    fields[name] = field.get("value", "")
                elif field_type in {"text", "search", "email", "url", "tel"}:
                    fields[name] = marker
                    marker_added = True

            if not marker_added:
                continue

            try:
                result = self._request(
                    method.upper(),
                    action,
                    **({"data": fields} if method == "post" else {"params": fields}),
                )
                result.close()
                check = self._request("GET", page_url)
            except (requests.RequestException, UnsafeTargetError) as error:
                print(f"{Fore.YELLOW}[FORM ERROR]{Style.RESET_ALL} {action}: {error}")
                continue

            try:
                if marker in check.text:
                    self.record(
                        "STORED-MARKER",
                        page_url,
                        "A harmless submitted marker appeared when the form page was revisited.",
                        "Informational",
                    )
            finally:
                check.close()

    def run_dom_audit(self):
        if __package__:
            from .dom_audit import DOMAuditor
        else:
            from dom_audit import DOMAuditor

        auditor = DOMAuditor(self.target)
        self.dom_findings = auditor.run()
        output_path = auditor.save()
        print(f"{Fore.CYAN}[DOM REPORT]{Style.RESET_ALL} {output_path}")
        for finding in self.dom_findings:
            if finding["execution_verified"]:
                label = "LOCAL DOM EXECUTION VERIFIED"
                color = Fore.RED
            elif finding["source_sink_observed"]:
                label = "LOCAL DOM SOURCE/SINK OBSERVED"
                color = Fore.YELLOW
            else:
                label = "NO LOCAL DOM FLOW CONFIRMED"
                color = Fore.GREEN
            print(f"{color}[{label}]{Style.RESET_ALL} {finding['url']}")
        return self.dom_findings

    def save_report(self) -> Path:
        REPORT_DIR.mkdir(parents=True, exist_ok=True)
        output_path = REPORT_DIR / "reports.json"
        report = {
            "target": self.target,
            "pages_scanned": len(self.visited),
            "findings_count": len(self.findings),
            "findings": self.findings,
            "dom_findings": self.dom_findings,
        }
        output_path.write_text(
            json.dumps(report, indent=2),
            encoding="utf-8",
        )
        print(f"{Fore.GREEN}Report saved: {output_path}{Style.RESET_ALL}")
        return output_path

    def run(self, test_stored: bool = False, test_dom: bool = False):
        print(f"{Fore.GREEN}XSSentinel - localhost-only scanner{Style.RESET_ALL}")
        pages = self.crawl()
        for url in pages:
            self.reflected_xss(url)
            if test_stored:
                self.stored_xss(url)
        if test_dom:
            self.run_dom_audit()
        return self.save_report()

    def close(self):
        self.session.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="XSSentinel: marker-based checks for an intentionally vulnerable local app."
    )
    parser.add_argument("--url", required=True, help="Local app URL (localhost or loopback IP only)")
    parser.add_argument(
        "--stored",
        action="store_true",
        help="Submit harmless markers to same-origin text fields and textareas",
    )
    parser.add_argument(
        "--dom",
        action="store_true",
        help="Run the browser-based DOM source/sink check (requires Playwright Chromium)",
    )
    args = parser.parse_args(argv)

    try:
        scanner = XSSentinel(args.url)
    except UnsafeTargetError as error:
        parser.error(str(error))

    try:
        scanner.run(test_stored=args.stored, test_dom=args.dom)
    finally:
        scanner.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
