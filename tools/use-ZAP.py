import argparse
import json
import time
import os
import requests
import urllib3
from pathlib import Path
from zapv2 import ZAPv2
from datetime import datetime, timedelta


def parse_session(file_path: str) -> dict:
    """Đọc session file (format: key=val; key=val) → dict cookies. Chỉ đọc dòng đầu tiên."""
    cookies = {}
    if not file_path or not os.path.exists(file_path):
        return cookies
    try:
        content = ""
        for line in Path(file_path).read_text(encoding="utf-8").splitlines():
            if line.strip() and not line.startswith("#"):
                content = line.strip()
                break

        for item in content.split(";"):
            if "=" in item:
                k, v = item.split("=", 1)
                cookies[k.strip()] = v.strip()
    except Exception as e:
        print(f"[!] Lỗi đọc session file: {e}")
    return cookies


# ==========================================
# 1. TRIỆT TIÊU PROXY LOOP TRONG SCRIPT
# ==========================================
# Lệnh này chỉ ảnh hưởng đến tiến trình hiện tại, không làm hỏng máy ngoài.
os.environ["no_proxy"] = "127.0.0.1,localhost,zap"
for key in list(os.environ.keys()):
    if "proxy" in key.lower():
        os.environ.pop(key)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class FastZapScanner:
    def __init__(
        self,
        proxy_host="127.0.0.1",
        proxy_port="8080",
        api_key="",
        cookies: dict = None,
        fast_mode=False,
    ):
        self.proxy_url = f"http://{proxy_host}:{proxy_port}"
        self.cookies = cookies or {}
        self.fast_mode = fast_mode

        # Cấu hình để thư viện ZAPv2 biết server ZAP đang nằm ở đâu (máy ảo Kali)
        # Nếu chạy từ ngoài vào, proxies này trỏ tới địa chỉ IP của máy ảo.
        self.zap = ZAPv2(
            apikey=api_key, proxies={"http": self.proxy_url, "https": self.proxy_url}
        )

        # Loại bỏ HTTPS ngay khi khởi tạo
        # self._disable_https_scanning()

        # Rule IDs tốn thời gian: SQLi Timing, DOM XSS, v.v.
        # 40026: DOM XSS
        self.slow_rules = (
            "40019,40020,40021,40022,40023,40024,40026,90037,90033,40027,90011"
        )

        if self.cookies:
            self._setup_auth()
        if self.fast_mode:
            self._optimize_policy()

    def _log(self, msg):
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")

    def _disable_https_scanning(self):
        """Loại biên hoàn toàn HTTPS khỏi ZAP để tránh quét thừa"""
        try:
            # Loại khỏi Proxy, Scanner và Context
            # self.zap.core.exclude_from_proxy("^https://.*")
            # self.zap.ascan.exclude_from_scan("^https://.*")
            # self.zap.context.exclude_from_context("Default Context", "^https://.*")
            # self._log("[*] Đã cấu hình ZAP loại bỏ hoàn toàn các mục tiêu HTTPS.")
            pass
        except Exception as e:
            self._log(f"[!] Lỗi khi loại biên HTTPS: {e}")

    def _setup_auth(self):
        try:
            try:
                self.zap.replacer.remove_rule("auth-session")
            except:
                pass
            cookie_header = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
            self.zap.replacer.add_rule(
                description="auth-session",
                enabled="true",
                matchtype="REQ_HEADER",
                matchregex="false",
                matchstring="Cookie",
                replacement=cookie_header,
                initiators="",
            )
            self._log(f"[+] Đã nạp xác thực session: {cookie_header}")
        except Exception as e:
            self._log(f"[!] Lỗi Replacer: {e}")

    def _optimize_policy(self):
        policy_name = "Sequence"
        self._log(f"[*] Đang tinh chỉnh Policy: {policy_name}...")
        try:
            # 1. Disable các rule chậm CHỈ dành riêng cho Policy "Pen Test"
            # Thư viện zapv2 cho phép truyền scanpolicyname vào disable_scanners
            self.zap.ascan.disable_scanners(
                ids=self.slow_rules, scanpolicyname=policy_name
            )

            # 2. Giới hạn thời gian mỗi rule trên Policy này (ví dụ 2 phút)
            # Lưu ý: Một số bản ZAP cũ set_option ảnh hưởng global, nhưng hãy cứ gọi để chắc chắn
            self.zap.ascan.set_option_max_rule_duration_in_mins(15)

            self._log(f"[+] Đã loại bỏ rule Time-based trên Policy '{policy_name}'.")
        except Exception as e:
            self._log(f"[!] Lỗi khi tinh chỉnh Policy: {e}")

    def get_findings(self, url, base_url):
        results = []
        try:
            # Strip query string trước khi dùng làm baseurl:
            # ZAP inject payload vào query param → alert URL sẽ có query KHÁC
            # với URL gốc. Nếu dùng full URL (có query string) làm baseurl,
            # alerts với param đã bị thay đổi sẽ không match và bị bỏ sót.
            # VD: scan "fi/?page=include.php" → alert ở "fi/?page=../../etc/passwd"
            # → không match → Path Traversal bị miss hoàn toàn.
            alerts_baseurl = url.split("?")[0]
            raw_alerts = self.zap.core.alerts(baseurl=alerts_baseurl)
            for alert in raw_alerts:
                msg_id = alert.get("messageId")
                raw_req, raw_res = "", ""
                if msg_id:
                    try:
                        msg = self.zap.core.message(msg_id)
                        raw_req = msg.get("requestHeader", "") + msg.get(
                            "requestBody", ""
                        )
                        raw_res = msg.get("responseHeader", "") + msg.get(
                            "responseBody", ""
                        )
                    except:
                        pass

                results.append(
                    {
                        "endpoint": alert.get("url", "").replace(base_url, ""),
                        "method": alert.get("method", "GET"),
                        "inputVector": alert.get("inputVector", ""),
                        "param": alert.get("param", ""),
                        "finding_type": alert.get("name", ""),
                        "severity": alert.get("risk", ""),
                        "confidence": alert.get("confidence", ""),
                        "evidence": alert.get("evidence", ""),
                        "payload": alert.get("attack", ""),
                        "raw_request": raw_req,
                        "raw_response": raw_res,
                    }
                )
        except Exception as e:
            self._log(f"[!] Lỗi trích xuất alert cho {url}: {e}")
        return results

    def run_scan(self, url, base_url):
        # try:
        #     self.zap.ascan.remove_all_scans()
        #     self._log("[*] Đã clear scan cũ")
        # except:
        #     pass

        self._log(f"[*] Đang xử lý: {url}")
        with requests.Session() as s:
            s.trust_env = False
            s.proxies = {"http": self.proxy_url, "https": self.proxy_url}
            try:
                s.get(url, verify=False, timeout=10)
            except:
                pass

        try:
            scan_id = self.zap.ascan.scan(
                url=url,
                recurse=(url != "/" and True or False),
                # recurse=(False),
                scanpolicyname="Sequence",
            )
            if not str(scan_id).isdigit():
                self._log(f"    [!] ZAP Reject: {scan_id}")
                return []

            while int(self.zap.ascan.status(scan_id)) < 100:
                print(
                    f"    [SCAN] {self.zap.ascan.status(scan_id)}% hoàn thành...",
                    end="\r",
                )
                time.sleep(5)

            self._log(f"\n    [+] Hoàn tất Scan: {url}")
            return self.get_findings(url, base_url)
        except Exception as e:
            self._log(f"\n    [!] Lỗi trong quá trình Scan {url}: {e}")
            return []


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ZAP Authenticated Targeted Scanner")
    parser.add_argument("-i", "--input-file", required=True)
    parser.add_argument("-b", "--base-url", required=True)
    parser.add_argument(
        "-s",
        "--session",
        required=True,
        help="Path đến session file (vd: target_info/session.txt)",
    )
    parser.add_argument("--fast-scan", action="store_true")
    parser.add_argument("-a", "--api-key", default="ksggc5u2lduvgiha5t9ues878a")
    parser.add_argument("-o", "--output", default="zap_results.json")

    # Thêm tham số Proxy Host và Port
    parser.add_argument(
        "--proxy-host",
        default="127.0.0.1",
        help="Địa chỉ IP của máy chạy ZAP (máy ảo Kali)",
    )
    parser.add_argument("--proxy-port", default="8080", help="Cổng của ZAP Proxy")

    args = parser.parse_args()

    total_start_time = time.time()

    cookies = parse_session(args.session)
    if not cookies:
        print(f"[!] Không đọc được session từ: {args.session}")
        exit()

    base = args.base_url.rstrip("/") + "/"
    path = Path(args.input_file)
    if not path.exists():
        print(f"[!] File không tìm thấy: {args.input_file}")
        exit()

    # Lọc bỏ ngay từ bước nạp targets nếu list có HTTPS
    targets = [
        (
            l.strip()
            if l.startswith("http")
            else f"{base.rstrip('/')}/{l.strip().lstrip('/')}"
        )
        for l in path.read_text().splitlines()
        if l.strip()
    ]

    print(
        f"\n{'='*50}\n[*] BẮT ĐẦU QUY TRÌNH QUÉT ({len(targets)} TARGETS)\n[*] PROXY: {args.proxy_host}:{args.proxy_port}\n{'='*50}"
    )

    scanner = FastZapScanner(
        proxy_host=args.proxy_host,
        proxy_port=args.proxy_port,
        cookies=cookies,
        api_key=args.api_key,
        fast_mode=args.fast_scan,
    )

    all_results = []
    for t in targets:
        findings = scanner.run_scan(t, base)
        all_results.extend(findings)

    final_data = {"base": args.base_url, "results": all_results}

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(final_data, f, indent=4, ensure_ascii=False)

    total_end_time = time.time()
    duration = str(timedelta(seconds=round(total_end_time - total_start_time)))

    print(f"\n{'='*50}")
    print(f"[+] HOÀN TẤT: Đã ghi {len(all_results)} findings vào {args.output}")
    print(f"[+] TỔNG THỜI GIAN THỰC THI: {duration}")
    print(f"{'='*50}\n")
