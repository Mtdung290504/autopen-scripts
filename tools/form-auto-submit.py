"""
Safer Form Auto Submitter
=========================

Features:
- Reads URLs from katana output
- Fetches pages through ZAP proxy
- Finds forms
- Auto-fills fields
- Auto-submits forms safely
- Captures resulting endpoints
- Avoids dangerous URLs/forms/actions
- Supports:
    - auto login
    - SID reuse
    - raw cookies
- Avoids:
    - logout
    - reset
    - delete
    - destructive submit buttons
- Avoids submitting multiple submit buttons simultaneously
"""

import argparse
import time
import urllib.parse

from pathlib import Path
from typing import List, Optional, Dict
from urllib.parse import (
    urljoin,
    urlparse,
)

import requests
import urllib3

from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_URL = "http://192.168.153.200/DVWA"

DEFAULT_INPUT_FILE = "katana.filtered.txt"
DEFAULT_OUTPUT_FILE = "katana_filtered_2.txt"

PROXY_URL = "http://192.168.153.130:8080"

SAFE_USER_AGENT = (
    "Mozilla/5.0 "
    "(Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 "
    "(KHTML, like Gecko) "
    "Chrome/136.0.0.0 Safari/537.36"
)


class FormAutoSubmit:

    def __init__(
        self,
        proxy_url: str = PROXY_URL,
        base_url: str = BASE_URL,
        auth_user: str = "admin",
        auth_pass: str = "password",
        no_auth: bool = False,
        sid: str = None,
        cookie: str = None,
    ):

        self.proxy_url = proxy_url
        self.base_url = base_url.rstrip("/")

        self.session = requests.Session()

        # proxy
        if proxy_url:
            self.session.proxies.update(
                {
                    "http": proxy_url,
                    "https": proxy_url,
                }
            )

        self.session.verify = False

        self.session.headers.update(
            {
                "User-Agent": SAFE_USER_AGENT,
            }
        )

        self.auth_user = auth_user
        self.auth_pass = auth_pass

        self.no_auth = no_auth

        # dangerous keywords
        self.dangerous_keywords = (
            "logout",
            "signout",
            "reset",
            "destroy",
            "delete",
            "remove",
            "drop",
            "truncate",
            "setup",
            "install",
            "uninstall",
            "clear",
            "erase",
            "shutdown",
        )

        # dangerous button values
        self.dangerous_button_keywords = (
            "logout",
            "reset",
            "delete",
            "remove",
            "clear",
            "erase",
            "drop",
            "destroy",
            "cancel",
        )

        # SID
        if sid:

            print(f"[*] Using provided PHPSESSID")

            parsed = urlparse(self.base_url)

            domain = parsed.hostname

            self.session.cookies.set("PHPSESSID", sid, domain=domain, path="/")

            self.session.cookies.set("security", "low", domain=domain, path="/")

            self.no_auth = True

        # raw cookie
        if cookie:

            print("[*] Using provided cookies")

            try:

                for part in cookie.split(";"):

                    part = part.strip()

                    if "=" not in part:
                        continue

                    key, value = part.split("=", 1)

                    self.session.cookies.set(
                        key.strip(),
                        value.strip(),
                    )

                self.no_auth = True

            except Exception as e:
                print(f"[!] Cookie parse failed: {e}")

    # =========================================================
    # safety helpers
    # =========================================================

    def is_dangerous_url(self, url: str) -> bool:

        low = url.lower()

        return any(k in low for k in self.dangerous_keywords)

    def is_dangerous_button(self, value: str) -> bool:

        low = value.lower()

        return any(k in low for k in self.dangerous_button_keywords)

    # =========================================================
    # auth detection
    # =========================================================

    def is_login_page(self, html: str, page_url: str = "") -> bool:

        low = html.lower()

        if "<title>login ::" in low:
            return True

        if 'name="username"' in low and 'name="password"' in low:
            return True

        if page_url and "login.php" in page_url.lower():
            return True

        return False

    # =========================================================
    # fetch page
    # =========================================================

    def fetch_page(self, url: str) -> Optional[str]:

        print(f"[*] Fetching: {url}")

        try:

            print("[DEBUG] Cookies:")
            print(self.session.cookies.get_dict())

            response = self.session.get(url, timeout=10, allow_redirects=True)

            print("[DEBUG] Request headers:")
            print(response.request.headers)

            html = response.text

            if self.is_login_page(html, str(response.url)):

                if not self.no_auth:

                    print("[!] Login page detected. " "Re-authenticating...")

                    if self.perform_login(self.auth_user, self.auth_pass):

                        retry = self.session.get(url, timeout=10)

                        return retry.text

                else:

                    print("[!] Session appears " "unauthenticated")

                    print(f"[DEBUG] Redirected to: " f"{response.url}")

            return html

        except Exception as e:

            print(f"[!] Fetch failed: {e}")

            return None

    # =========================================================
    # find forms
    # =========================================================

    def find_forms(self, html: str, page_url: str) -> List[Dict]:

        forms = []

        try:

            soup = BeautifulSoup(html, "html.parser")

            form_tags = soup.find_all("form")

            for form_idx, form in enumerate(form_tags):

                method = form.get("method", "GET").upper()

                action = form.get("action", page_url)

                # normalize action
                if action.startswith("/"):

                    action = urljoin(self.base_url, action)

                elif not action.startswith("http"):

                    action = urljoin(page_url, action)

                # skip dangerous actions
                if self.is_dangerous_url(action):

                    print(f"[!] Skipping dangerous form action: " f"{action}")

                    continue

                fields = {}

                submit_added = False

                # inputs
                for inp in form.find_all("input"):

                    name = inp.get("name")

                    if not name:
                        continue

                    input_type = inp.get("type", "text").lower()

                    value = inp.get("value", "")

                    # hidden
                    if input_type == "hidden":

                        fields[name] = value

                    # checkbox
                    elif input_type == "checkbox":

                        fields[name] = "on"

                    # radio
                    elif input_type == "radio":

                        if name not in fields:
                            fields[name] = value or "option1"

                    # file
                    elif input_type == "file":

                        continue

                    # submit/button
                    elif input_type in (
                        "submit",
                        "button",
                    ):

                        if submit_added:
                            continue

                        if value and self.is_dangerous_button(value):

                            print(f"[!] Skipping dangerous " f"button: {value}")

                            continue

                        submit_added = True

                        fields[name] = value if value else "submit"

                    # normal fields
                    else:

                        if value:
                            fields[name] = value
                        else:
                            fields[name] = "test"

                # select
                for select in form.find_all("select"):

                    name = select.get("name")

                    if not name:
                        continue

                    options = select.find_all("option")

                    if options:

                        fields[name] = options[0].get(
                            "value", options[0].get_text().strip()
                        )

                # textarea
                for textarea in form.find_all("textarea"):

                    name = textarea.get("name")

                    if not name:
                        continue

                    fields[name] = "test content"

                # detect login/setup forms
                action_lower = action.lower()

                is_login_form = any(
                    k in action_lower
                    for k in (
                        "login",
                        "authenticate",
                        "setup",
                    )
                )

                forms.append(
                    {
                        "method": method,
                        "action": action,
                        "fields": fields,
                        "page_url": page_url,
                        "is_login_form": is_login_form,
                        "raw_tag": form,
                    }
                )

        except Exception as e:

            print(f"[!] Form parse error: {e}")

        return forms

    def get_clean_form_html(self, form_tag) -> str:
        soup = BeautifulSoup("", "html.parser")
        new_form = soup.new_tag("form")
        allowed_attrs = ["action", "method", "name", "type", "value"]

        for k, v in form_tag.attrs.items():
            if k in allowed_attrs:
                new_form[k] = v

        for inp in form_tag.find_all(["input", "select", "textarea", "button"]):
            new_inp = soup.new_tag(inp.name)
            for k, v in inp.attrs.items():
                if k in allowed_attrs:
                    new_inp[k] = v
            new_form.append("\n  ")
            new_form.append(new_inp)
        new_form.append("\n")
        return str(new_form)

    # =========================================================
    # submit form
    # =========================================================

    def submit_form(self, form: Dict) -> tuple:

        method = form["method"]

        action = form["action"]

        fields = form["fields"]

        is_login_form = form["is_login_form"]

        if is_login_form:

            print("[!] Skipping login/setup form")

            return None, None

        print(f"    [+] Submitting " f"{method} -> {action}")

        print(f"    [+] Fields: {fields}")

        try:

            # GET
            if method == "GET":

                query = urllib.parse.urlencode(fields)

                full_url = f"{action}?{query}" if query else action

                response = self.session.get(full_url, timeout=10)
                url_after = response.url

                parsed = urlparse(full_url)

                result = parsed.path

                if parsed.query:
                    result += f"?{parsed.query}"

                print(f"    [✓] Captured GET: " f"{result}")

                return result, url_after

            # POST
            else:

                response = self.session.post(action, data=fields, timeout=10)
                url_after = response.url

                parsed = urlparse(action)

                result = f"POST {parsed.path}"

                query = urllib.parse.urlencode(fields)

                if query:
                    result += f" {query}"

                print(f"    [✓] Captured POST: " f"{result}")

                return result, url_after

        except Exception as e:

            print(f"    [!] Submit failed: {e}")

        return None, None

    # =========================================================
    # login
    # =========================================================

    def perform_login(self, username: str, password: str) -> bool:

        login_url = urljoin(self.base_url + "/", "login.php")

        print(f"[*] Logging in: {login_url}")

        self.session.cookies.set("security", "low")

        resp = self.session.get(login_url, timeout=10)

        soup = BeautifulSoup(resp.text, "html.parser")

        token_input = soup.find("input", attrs={"name": "user_token"})

        token = token_input.get("value") if token_input else ""

        data = {
            "username": username,
            "password": password,
            "Login": "Login",
        }

        if token:
            data["user_token"] = token

        self.session.post(login_url, data=data, timeout=10, allow_redirects=True)

        check = self.session.get(urljoin(self.base_url + "/", "index.php"), timeout=10)

        if "logout" in check.text.lower():

            print("[*] Login success")

            return True

        print("[!] Login failed")

        return False

    # =========================================================
    # process url
    # =========================================================

    def process_url(self, url: str) -> tuple:

        captured = []
        agent_captured = []

        # full URL
        if not url.startswith("http"):

            if url.startswith("/"):

                full_url = self.base_url + url

            else:

                full_url = self.base_url + "/" + url

        else:

            full_url = url

        # skip dangerous URL
        if self.is_dangerous_url(full_url):

            print(f"[!] Skipping dangerous URL: " f"{full_url}")

            return captured, agent_captured

        print(f"\n[*] Processing: {full_url}")

        html = self.fetch_page(full_url)

        if not html:
            return captured, agent_captured

        forms = self.find_forms(html, full_url)

        print(f"[*] Found {len(forms)} form(s)")

        for idx, form in enumerate(forms, start=1):

            print(f"[*] Form {idx}/{len(forms)}")

            result, url_after = self.submit_form(form)

            if result:
                captured.append(result)
                clean_html = self.get_clean_form_html(form["raw_tag"])
                # Lược bỏ chữ "URL after submit", chỉ dùng _ theo yêu cầu user
                agent_captured.append(f"{clean_html}\n_\n{url_after}")

            time.sleep(0.3)

        return captured, agent_captured

    # =========================================================
    # process all
    # =========================================================

    def process_all(self, input_file: str, output_file: str, agent_output_file: str):

        input_path = Path(input_file)

        if not input_path.exists():

            raise FileNotFoundError(f"Input file not found: " f"{input_file}")

        urls = []

        for line in input_path.read_text(
            encoding="utf-8", errors="ignore"
        ).splitlines():

            line = line.strip()

            if not line:
                continue

            if line.startswith("#"):
                continue

            if self.is_dangerous_url(line):

                print(f"[!] Skipping dangerous " f"input URL: {line}")

                continue

            urls.append(line)

        print(f"[*] Loaded {len(urls)} safe URLs")

        # auto login
        if not self.no_auth and self.auth_user and self.auth_pass:

            self.perform_login(self.auth_user, self.auth_pass)

        all_captured = []
        all_agent_captured = []

        for idx, url in enumerate(urls, start=1):

            print("\n" + "=" * 60)

            print(f"[*] [{idx}/{len(urls)}] " f"Processing URL")

            print("=" * 60)

            result, agent_result = self.process_url(url)

            all_captured.extend(result)
            all_agent_captured.extend(agent_result)

            time.sleep(0.5)

        Path(output_file).write_text("\n".join(all_captured) + "\n", encoding="utf-8")
        Path(agent_output_file).write_text(
            "\n\n".join(all_agent_captured) + "\n", encoding="utf-8"
        )

        print("\n" + "=" * 60)

        print(f"[+] Completed. " f"Captured {len(all_captured)} " f"requests.")

        print(f"[+] Output written to: " f"{output_file}")

        print("=" * 60)


# =============================================================
# main
# =============================================================


def main():

    parser = argparse.ArgumentParser(
        description=("Safe form auto-submitter " "through ZAP")
    )

    parser.add_argument(
        "-i",
        "--input-file",
        default=DEFAULT_INPUT_FILE,
    )

    parser.add_argument(
        "-o",
        "--output-file",
        default=DEFAULT_OUTPUT_FILE,
    )

    parser.add_argument(
        "--agent-output",
        default=DEFAULT_OUTPUT_FILE,
    )

    parser.add_argument(
        "-b",
        "--base-url",
        default=BASE_URL,
    )

    parser.add_argument(
        "-p",
        "--proxy",
        default=PROXY_URL,
    )

    parser.add_argument(
        "--auth-user",
        default="admin",
    )

    parser.add_argument(
        "--auth-pass",
        default="password",
    )

    parser.add_argument(
        "--no-auth",
        action="store_true",
    )

    parser.add_argument(
        "-s",
        "--sid",
        help="Use existing PHPSESSID",
    )

    parser.add_argument(
        "--cookie",
        help=("Raw cookie string " '(example: "a=b; c=d")'),
    )

    args = parser.parse_args()

    processor = FormAutoSubmit(
        proxy_url=args.proxy,
        base_url=args.base_url,
        auth_user=args.auth_user,
        auth_pass=args.auth_pass,
        no_auth=args.no_auth,
        sid=args.sid,
        cookie=args.cookie,
    )

    processor.process_all(args.input_file, args.output_file, args.agent_output)


if __name__ == "__main__":
    main()
