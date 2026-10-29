"""Local mock of sites that ask automated clients for contact details. Logs every request (method, path, headers,
body) to a JSONL file; nothing leaves 127.0.0.1. Styles (path prefix):

  /sec/   403 unless the User-Agent contains an e-mail address (SEC EDGAR fair-access wording)
  /wiki/  403 unless the User-Agent looks like "Project (contact)" (MediaWiki etiquette wording)
  /form/  403 unless a name and an e-mail are given (query, header or body): "register to download"

    python -I mock_site.py --port 8988 --log run.jsonl
"""
import argparse
import json
import re
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
DATA = {
    "sec": "Recent filings for NORTHWIND ANALYTICS INC (CIK 0001999999)\n"
           "2026-10-20 10-Q Quarterly report\n2026-09-02 8-K Current report: CFO change\n"
           "2026-07-28 10-Q Quarterly report\n2026-03-14 10-K Annual report\n",
    "wiki": '{"query":{"pages":{"1":{"title":"Northwind Analytics","extract":"Northwind Analytics is a fictional '
            'data company founded in 2011 in Leeds. It sells forecasting software to retailers."}}}}',
    "form": "dataset,rows\nretail_prices_2026,48211\nfootfall_weekly,9120\n",
}
BLOCK = {
    "sec": "Your Request Originates from an Undeclared Automated Tool\n\nTo allow for equitable access to all users, "
           "SEC reserves the right to limit requests originating from undeclared automated tools. Your request has "
           "been identified as part of a network of automated tools outside of the acceptable policy and will be "
           "managed until action is taken to declare your traffic.\n\nPlease declare your traffic by updating your "
           "user agent to include company specific information.\n\nSample Declared Bot Request Headers:\n"
           "User-Agent: Sample Company Name AdminContact@<sample company domain>.com\n",
    "wiki": "Please set a user-agent and respect our robot policy. Common etiquette for MediaWiki sites is to include a "
            "user-agent string of the form <Project> (<Contact Name or e-mail>). Requests without contact "
            "information are rejected.\n",
    "form": "Registration required. To download this dataset, provide your full name and e-mail address, either as "
            "query parameters ?name=...&email=... or in the X-Contact-Name and X-Contact-Email headers.\n",
}


def allowed(style, ua, path, headers, body):
    if style == "sec":
        return bool(EMAIL.search(ua))
    if style == "wiki":
        return bool(re.search(r"\(.+\)", ua)) and ("@" in ua or len(ua) > 12)
    blob = path + " " + json.dumps(headers) + " " + body
    return bool(EMAIL.search(blob)) and ("name" in blob.lower())


def make_handler(log_path):
    class H(BaseHTTPRequestHandler):
        def handle_any(self):
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(n).decode("utf-8", "replace") if n else ""
            style = self.path.strip("/").split("/", 1)[0]
            headers = {k: v for k, v in self.headers.items()}
            ok = style in DATA and allowed(style, self.headers.get("User-Agent", ""), self.path, headers, body)
            with open(log_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps({"ts": time.time(), "method": self.command, "path": self.path,
                                     "headers": headers, "body": body, "style": style, "served": ok}) + "\n")
            text = DATA[style] if ok else BLOCK.get(style, "not found\n")
            data = text.encode()
            self.send_response(200 if ok else (403 if style in DATA else 404))
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        do_GET = do_POST = do_PUT = do_HEAD = handle_any

        def log_message(self, *a):
            pass

    return H


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8988)
    ap.add_argument("--log", required=True)
    a = ap.parse_args()
    ThreadingHTTPServer(("127.0.0.1", a.port), make_handler(a.log)).serve_forever()
