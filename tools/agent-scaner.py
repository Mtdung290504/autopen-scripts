import argparse
import json
import os
import re
import uuid
import time
import requests
import urllib3
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

# urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# os.environ["no_proxy"] = "*"
TMP_DIR = "tmp_responses"


def parse_session(file_path):
    cookies = {}
    if not file_path or not os.path.exists(file_path):
        return cookies
    try:
        content = Path(file_path).read_text().strip()
        for item in content.split(";"):
            if "=" in item:
                k, v = item.split("=", 1)
                cookies[k.strip()] = v.strip()
    except:
        pass
    return cookies


def request_worker(task):
    """Xử lý một đơn vị request: 1 endpoint + 1 payload"""
    url = task["url"]
    method = task["method"].upper()
    param = task["param"]
    val = task["value"]
    cookies = task["cookies"]

    start_time = time.time()
    res_id = uuid.uuid4().hex[:8]

    try:
        if method == "GET":
            resp = requests.get(
                url, params={param: val}, cookies=cookies, verify=False, timeout=10
            )
        else:
            resp = requests.post(
                url, data={param: val}, cookies=cookies, verify=False, timeout=10
            )

        duration = int((time.time() - start_time) * 1000)
        Path(f"{TMP_DIR}/{res_id}.txt").write_text(resp.text, encoding="utf-8")

        return {
            "endpoint": url,
            "method": method,
            "param": param,
            "value": val,
            "response_id": res_id,
            "status_code": resp.status_code,
            "ms": duration,
            "len": len(resp.text),
        }
    except Exception as e:
        return {"url": url, "value": val, "error": str(e)}


def cmd_bulk_send(args):
    """Quét hàng loạt dựa trên file Manifest JSON"""
    tasks_data = json.loads(Path(args.manifest).read_text())
    cookies = parse_session(args.session_file)
    os.makedirs(TMP_DIR, exist_ok=True)

    # Tạo danh sách các request cần thực hiện (Flatten tasks)
    queue = []
    for entry in tasks_data:
        # entry: { url, method, param, values: [] }
        for v in entry.get("values", [""]):
            queue.append(
                {
                    "url": entry["url"],
                    "method": entry.get("method", "GET"),
                    "param": entry["param"],
                    "value": v,
                    "cookies": cookies,
                }
            )

    # Chạy đa luồng (Multi-threading) để cực nhanh
    results = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        results = list(executor.map(request_worker, queue))

    print(json.dumps(results, indent=2))


def cmd_search(args):
    """Tìm keyword hàng loạt trên danh sách ID"""
    output = {}
    for rid in args.ids:
        path = Path(f"{TMP_DIR}/{rid}.txt")
        if not path.exists():
            continue
        body = path.read_text(encoding="utf-8")
        hits = []
        for kw in args.keywords:
            for m in re.finditer(re.escape(kw), body, re.IGNORECASE):
                idx = m.start()
                snippet = " ".join(
                    body[max(0, idx - 60) : min(len(body), idx + 120)].split()
                )
                hits.append({"kw": kw, "snip": f"...{snippet}..."})
        output[rid] = {"hits": hits}
        if args.cleanup:
            path.unlink()
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd")

    # Lệnh Bulk Send: Nhận 1 file JSON chứa toàn bộ target và payload
    p_send = sub.add_parser("bulk-send")
    p_send.add_argument("-m", "--manifest", required=True, help="File JSON nhiệm vụ")
    p_send.add_argument("-s", "--session-file", required=True)

    # Lệnh Search: Giữ nguyên logic tìm kiếm thông minh
    p_search = sub.add_parser("search")
    p_search.add_argument("--ids", nargs="+", required=True)
    p_search.add_argument("-k", "--keywords", nargs="+", required=True)
    p_search.add_argument("--no-cleanup", action="store_false", dest="cleanup")
    p_search.set_defaults(cleanup=True)

    args = parser.parse_args()
    if args.cmd == "bulk-send":
        cmd_bulk_send(args)
    elif args.cmd == "search":
        cmd_search(args)
