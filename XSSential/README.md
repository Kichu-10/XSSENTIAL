# XSSENTINEL

XSSentinel performs marker-based checks against a **local test application only**.
It accepts `localhost` and literal loopback IP addresses (`127.0.0.1`, `::1`).
Other hostnames and IP addresses are rejected. HTTP redirects and browser requests
are also restricted to the configured local origin.

Use only with an intentionally vulnerable application that you control. The
optional `--stored` mode submits harmless markers to local form fields and may
change data in the test application; use disposable test data.

## Install

Run these commands from the XSSential project directory (the repository root
when cloned from GitHub):

```powershell
python -m pip install -r requirements.txt
python -m playwright install chromium
```

## Run

```powershell
python scanner.py --url http://127.0.0.1:8000
python scanner.py --url http://localhost:8000 --stored --dom
```

The scanner saves HTTP findings to `reports\reports.json`. The DOM audit saves
its results to `reports\dom-report.json`. The `--dom`
option uses Playwright Chromium and blocks cross-origin requests.
