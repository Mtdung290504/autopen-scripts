from __future__ import annotations

"""
Phase 2 reducer for agent-facing triage.

======================================================================
CƠ CHẾ HOẠT ĐỘNG (MECHANISM):
Script này hoạt động như một bộ lọc và tối ưu hóa dữ liệu (reducer) 
từ kết quả quét của ZAP, chuẩn bị dữ liệu tinh gọn để cấp cho AI Agent:
1. Gom nhóm (Clustering): Nhóm các lỗ hổng dựa trên URL path (bỏ query string), 
   HTTP method, input vector và parameter. Điều này giúp gộp các payload 
   khác nhau tấn công vào cùng một điểm mục tiêu thành một cluster duy nhất.
2. Rút gọn dữ liệu (Reduction): Thay vì ném toàn bộ HTTP Response khổng lồ 
   cho AI, script chỉ trích xuất những phần quan trọng: Status line, 
   các headers cốt lõi, ZAP Evidence, ngữ cảnh và Reflection snippet.
3. Loại bỏ trùng lặp (Deduplication): Loại bỏ các finding và payload trùng lặp.
4. Sắp xếp (Sorting): Ưu tiên đẩy các cluster có mức độ nghiêm trọng cao lên đầu.
======================================================================

Schema Output:

{
  "base": "http://host/app/",
  "items": [
    {
      "target": {
        "endpoint": "vulnerabilities/xss_s/",
        "method": "POST",
        "inputVector": "form",
        "param": "txtName"
      },
      "findings": [
        "Cross Site Scripting (Reflected) [High/Medium]"
      ],
      "payloads": [
        "</div><script>alert(1)</script><div>"
      ],
      "response": "HTTP/1.1 200 OK\nContent-Type: text/html;charset=utf-8\n\n[ZAP Evidence] ...",
      "repeat": 5
    }
  ]
}

Giải thích các trường (Field notes):
- `target` — Bề mặt tấn công (input surface). Đây là điểm mà Agent cần tập trung phân tích xem có thực sự lọt lỗ hổng hay không.
- `findings` và `payloads` — Danh sách các lỗi và payload tương ứng (đã được dedupe). Nếu 1 lỗi không có payload, nó sẽ là chuỗi rỗng.
- `response` — Chuỗi mô phỏng HTTP Response nhưng đã bị rút gọn tới mức tối đa, chỉ giữ lại các manh mối quan trọng cho Agent ([ZAP Evidence], [Context], [Reflection]).
- `repeat` — Tín hiệu độ tin cậy (Confidence Signal). Nó thể hiện CÓ BAO NHIÊU kết quả của ZAP đã bị gom chung vào cluster này. 
    * Ví dụ: Nếu "repeat": 5, nghĩa là ZAP đã bắn 5 payload khác nhau vào cùng 1 parameter này và đều báo lỗi. 
    * Đối với AI Agent, chỉ số này càng cao thì khả năng đây là Lỗi Thật (True Positive) càng lớn. Trường này CHỈ xuất hiện khi có từ 2 kết quả trùng lặp trở lên.
"""

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path
from urllib.parse import unquote_plus, urlparse

SEVERITY_RANK = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "informational": 4,
    "info": 4,
}

# Headers có giá trị thực sự cho Agent
KEEP_HEADERS = {
    "content-type",
    "location",
    "set-cookie",
    "content-security-policy",
}

# Finding types cần check reflection trong body
REFLECTION_FINDING_KEYWORDS = {
    "xss",
    "inject",
    "ssti",
    "template",
    "traversal",
    "inclusion",
}


# ──────────────────────────────────────────────────────────────
# TEXT UTILITIES
# ──────────────────────────────────────────────────────────────


def normalize_text(value: object) -> str:
    return str(value or "").strip()


def normalize_space(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def dedupe_strings(items: list[str]) -> list[str]:
    return list(dict.fromkeys(item for item in items if item))


# ──────────────────────────────────────────────────────────────
# HTTP PARSING
# ──────────────────────────────────────────────────────────────


def split_raw_response(raw_response: str) -> tuple[str, dict[str, str], str]:
    if "\r\n\r\n" in raw_response:
        head, body = raw_response.split("\r\n\r\n", 1)
    elif "\n\n" in raw_response:
        head, body = raw_response.split("\n\n", 1)
    else:
        head, body = raw_response, ""

    lines = [line for line in head.splitlines() if line.strip()]
    status_line = lines[0].strip() if lines else ""
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        key = name.strip().lower()
        clean_value = value.strip()
        if key == "set-cookie" and key in headers:
            headers[key] = f"{headers[key]} || {clean_value}"
        else:
            headers[key] = clean_value
    return status_line, headers, body


# ──────────────────────────────────────────────────────────────
# CLUSTER KEY (Chỉ dùng nội bộ để gom nhóm)
# ──────────────────────────────────────────────────────────────


def build_cluster_key(item: dict) -> str:
    endpoint = normalize_text(item.get("endpoint"))
    # Strip query string khỏi endpoint để cluster đúng
    path_only = urlparse(endpoint).path.strip("/")
    return "|".join(
        [
            normalize_text(item.get("method")).upper(),
            path_only,
            normalize_text(item.get("inputVector")),
            normalize_text(item.get("param")),
        ]
    )


# ──────────────────────────────────────────────────────────────
# RESPONSE REDUCER
# ──────────────────────────────────────────────────────────────


def build_reduced_response(items: list[dict]) -> str:
    raw_response = normalize_text(items[0].get("raw_response"))
    status_line, headers, body = split_raw_response(raw_response)
    lines: list[str] = []

    # 1. Status line
    if status_line:
        lines.append(status_line)

    # 2. Headers
    for name in KEEP_HEADERS:
        if name in headers:
            lines.append(f"{name.title()}: {headers[name]}")

    # 3. ZAP Evidence
    zap_evidences = dedupe_strings(
        [
            normalize_text(item.get("evidence"))
            for item in items
            if normalize_text(item.get("evidence"))
        ]
    )

    if zap_evidences:
        lines.append("")
        for ev in zap_evidences:
            lines.append(f"[ZAP Evidence] {ev[:300]}")

    # 4. Context window
    for ev in zap_evidences:
        if len(ev) < 120 and ev in body:
            idx = body.index(ev)
            window = normalize_space(body[max(0, idx - 80) : idx + len(ev) + 150])
            if window and window != ev:
                lines.append(f"[Context] {window[:400]}")
            break

    # 5. Reflection snippet
    for item in items:
        payload = normalize_text(item.get("payload"))
        finding = normalize_text(item.get("finding_type")).lower()
        if not payload:
            continue
        if not any(kw in finding for kw in REFLECTION_FINDING_KEYWORDS):
            continue
        decoded_payload = unquote_plus(payload)
        for candidate in [payload, decoded_payload]:
            if candidate in body:
                idx = body.index(candidate)
                snippet = normalize_space(
                    body[max(0, idx - 60) : idx + len(candidate) + 80]
                )
                lines.append(f"[Reflection] {snippet[:300]}")
                break
        break

    return "\n".join(lines).strip()


# ──────────────────────────────────────────────────────────────
# FINDING + PAYLOAD LISTS
# ──────────────────────────────────────────────────────────────


def format_finding(item: dict) -> str:
    finding_type = normalize_text(item.get("finding_type"))
    severity = normalize_text(item.get("severity"))
    confidence = normalize_text(item.get("confidence"))
    return f"{finding_type} [{severity}/{confidence}]"


def build_finding_payload_lists(items: list[dict]) -> tuple[list[str], list[str]]:
    seen: set[tuple[str, str]] = set()
    findings: list[str] = []
    payloads: list[str] = []
    for item in items:
        finding = format_finding(item)
        payload = normalize_text(item.get("payload"))
        pair = (finding, payload)
        if pair in seen:
            continue
        seen.add(pair)
        findings.append(finding)
        payloads.append(payload)
    return findings, payloads


# ──────────────────────────────────────────────────────────────
# CLUSTER → ITEM
# ──────────────────────────────────────────────────────────────


def build_item(cluster_key: str, items: list[dict]) -> dict:
    first = items[0]
    findings, payloads = build_finding_payload_lists(items)

    target = {
        "endpoint": normalize_text(first.get("endpoint")),
        "method": normalize_text(first.get("method")).upper(),
        "inputVector": normalize_text(first.get("inputVector")),
        "param": normalize_text(first.get("param")),
    }

    # Bỏ trường clusterKey ở đây
    reduced: dict = {
        "target": target,
        "findings": findings,
        "payloads": payloads,
        "response": build_reduced_response(items),
    }

    if len(items) > 1:
        reduced["repeat"] = len(items)

    return reduced


# ──────────────────────────────────────────────────────────────
# SORT — HIGH severity trước
# ──────────────────────────────────────────────────────────────


def sort_items(items: list[dict]) -> list[dict]:
    def rank(entry: dict) -> tuple:
        highest = 99
        for finding in entry.get("findings", []):
            match = re.search(r"\[([^\]/]+)/", str(finding))
            severity = match.group(1).lower() if match else ""
            highest = min(highest, SEVERITY_RANK.get(severity, 99))
        target = entry.get("target", {})
        return (
            highest,
            str(target.get("endpoint", "")),
            str(target.get("param", "")),
        )

    return sorted(items, key=rank)


# ──────────────────────────────────────────────────────────────
# MAIN REDUCE
# ──────────────────────────────────────────────────────────────


def reduce_phase2(data: dict) -> dict:
    base = normalize_text(data.get("base"))
    results = data.get("results", [])
    if not isinstance(results, list):
        raise ValueError("Input JSON không có list `results` hợp lệ.")
    results = [item for item in results if isinstance(item, dict)]

    clusters: dict[str, list[dict]] = defaultdict(list)
    for item in results:
        # Cluster key vẫn được dùng nội bộ tại đây
        clusters[build_cluster_key(item)].append(item)

    reduced_items = [build_item(ck, citems) for ck, citems in clusters.items()]
    return {"base": base, "items": sort_items(reduced_items)}


# ──────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Phase 2 reducer — agent-facing ZAP triage"
    )
    parser.add_argument(
        "--input", "-i", required=True, help="Input JSON file (ZAP filtered results)"
    )
    parser.add_argument(
        "--output", "-o", default="output/phase2_reduced.json", help="Output JSON file"
    )
    args = parser.parse_args(argv)

    input_path = Path(args.input).expanduser().resolve()
    output_path = Path(args.output).expanduser().resolve()

    data = json.loads(input_path.read_text(encoding="utf-8", errors="replace"))
    reduced = reduce_phase2(data)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(reduced, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    print(f"Input  : {len(data.get('results', []))} results")
    print(f"Clusters: {len(reduced['items'])}")
    print(f"Output : {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
