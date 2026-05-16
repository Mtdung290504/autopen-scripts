"""
filter_findings.py — Rule-based filter cho ZAP findings

CHIẾN THUẬT LỌC:
  Câu hỏi cốt lõi: "Agent có thể làm gì thêm với finding này không?"
  Nếu không có injection point → Agent không can thiệp được → bỏ.

  Chia finding thành 3 loại:
    KEEP  — Injection finding: ZAP inject payload vào param, có evidence thật.
            Agent đọc được, custom payload thêm được.
    DROP  — Configuration finding: ZAP đọc header/response rồi báo thiếu cái gì đó.
            Không có injection point, Agent không làm gì thêm được.
    LOCAL — Observation finding: ZAP thấy pattern đáng ngờ nhưng không confirm.
            Không rõ ràng đủ để DROP, không chắc đủ để KEEP → để local model xử lý.

LUỒNG:
  zap_output.json
    → [Script này] → zap_filtered.json  (KEEP + LOCAL)
                   → zap_dropped.json   (DROP, debug)
    → [Local AI]   → zap_for_agent.json (đã triage)
    → [Gemini Agent]

RULE THỨ TỰ ƯU TIÊN:
  1. Dedup        — cùng endpoint+finding_type+param+method → bỏ phần tử sau
  2. False Positive — ZAP tự đánh nhãn → bỏ
  3. Configuration  — không có injection point → bỏ
  4. Informational  — chỉ giữ nếu là injection finding quan trọng
  5. Low severity   — bỏ nếu không có payload/evidence thật/user input vector
  6. Còn lại        → giữ (local model xử lý tiếp)
"""

import json
import argparse
import socket
import time
import urllib.error
import urllib.request
from pathlib import Path

# Todo: Change Model API URL
DEFAULT_FILTER_API_URL = (
    "https://campbell-ones-manufacture-fish.trycloudflare.com/filter"
)

# ──────────────────────────────────────────────────────────────
# RULE 3 — Configuration findings
# ZAP đọc header/response rồi báo — không có injection point
# Bỏ hết, không phụ thuộc severity hay endpoint
# ──────────────────────────────────────────────────────────────
CONFIGURATION_FINDING_TYPES = {
    # Cookie flags
    "Cookie No HttpOnly Flag",
    "Cookie Without Secure Flag",
    "Cookie No SameSite Attribute",
    "Cookie without SameSite Attribute",
    "Session Management Response Identified",
    # Missing security headers
    "Missing Anti-clickjacking Header",
    "Content-Type Header Missing",
    "X-Content-Type-Options Header Missing",
    "Strict-Transport-Security Header Not Set",
    "Content Security Policy (CSP) Header Not Set",
    "Permissions Policy Header Not Set",
    "Cross-Domain Misconfiguration",
    "HTTP Only Site",  # site chạy HTTP không HTTPS — configuration, không có injection point
    # ZAP scan noise
    "Retrieved from Cache",
    "Modern Web Application",
    "Timestamp Disclosure - Unix",
    "Private IP Disclosure",
    "Absence of Anti-CSRF Tokens",
    "Information Disclosure - Suspicious Comments",
    "User Controllable HTML Element Attribute (Potential XSS)",
    "User Controllable JavaScript Event (XSS)",
    "Server Leaks Version Information via Server HTTP Response Header Field",
    "Information Disclosure - Debug Error Messages",
}

# ──────────────────────────────────────────────────────────────
# RULE 4 — Informational passthrough
# Những finding_type này vẫn giữ dù severity=Informational
# ──────────────────────────────────────────────────────────────
INFORMATIONAL_PASSTHROUGH_TYPES = {
    "Path Traversal",
    "SQL Injection",
    "SQL Injection - MySQL",
    "SQL Injection - SQLite",
    "Blind SQL Injection",
    "Remote OS Command Injection",
    "Server Side Include",
    "Remote File Inclusion",
    "XSLT Injection",
    "XXE",
    "SSRF",
    "SSTI",
    "Server Side Template Injection",
    "Cross Site Scripting (Reflected)",
    "Cross Site Scripting (Persistent)",
    "Cross Site Scripting (DOM Based)",
}

# ──────────────────────────────────────────────────────────────
# RULE 5 — Evidence không có giá trị thật
# Chỉ là tên header/cookie, không phải data bị leak
# ──────────────────────────────────────────────────────────────
BORING_EVIDENCE = {
    "phpsessid",
    "session",
    "set-cookie: phpsessid",
    "set-cookie: security",
    "set-cookie: session",
    "x-frame-options",
    "content-type",
    "x-content-type-options",
    "strict-transport-security",
}

API_TIMEOUT_SECONDS = 180
API_FIELDS_TO_REMOVE = {"raw_request", "raw_response"}


def is_useless(finding: dict) -> tuple[bool, str]:
    """
    Trả về (True, lý do) nếu finding chắc chắn vô dụng.
    Trả về (False, "") nếu nên giữ lại.
    """
    finding_type = finding.get("finding_type", "")
    severity = finding.get("severity", "").upper()
    confidence = finding.get("confidence", "").strip()
    evidence = finding.get("evidence", "").strip()
    payload = finding.get("payload", "").strip()
    input_vector = finding.get("inputVector", "").strip().lower()

    # Rule 2 — ZAP tự đánh False Positive
    if confidence == "False Positive":
        return True, "ZAP tự đánh confidence=False Positive"

    # Rule 3 — Configuration finding (exact match)
    if finding_type in CONFIGURATION_FINDING_TYPES:
        return (
            True,
            f"Configuration finding '{finding_type}' — không có injection point",
        )

    # Rule 3b — Fuzzy match: ZAP hay đổi format tên finding giữa các version
    # Dùng keyword thay vì exact string để tránh lỗi mismatch
    finding_type_lower = finding_type.lower()
    FUZZY_DROP_KEYWORDS = [
        "server leaks",  # "Server Leaks Version Information via \"Server\" ..."
        "timestamp disclosure",
        "private ip disclosure",
        "information disclosure - suspicious",
        "user controllable html",
        "user controllable javascript",
        "clickjacking",
    ]
    for keyword in FUZZY_DROP_KEYWORDS:
        if keyword in finding_type_lower:
            return (
                True,
                f"Configuration finding (fuzzy match on '{keyword}') — không có injection point",
            )

    # Rule 3c — Application Error Disclosure: chỉ bỏ khi là directory listing
    # Giữ lại nếu evidence là stack trace / PHP error / SQL error — Agent có thể khai thác
    if finding_type == "Application Error Disclosure":
        DIRECTORY_LISTING_EVIDENCE = {
            "parent directory",
            "index of /",
            "directory listing",
            "[to parent directory]",
        }
        if evidence.lower().strip() in DIRECTORY_LISTING_EVIDENCE:
            return (
                True,
                "Application Error Disclosure do directory listing — không có injection point",
            )
        # Evidence khác (stack trace, PHP error...) → giữ lại

    # Rule 4 — Informational + không phải injection finding
    if severity in ("INFO", "INFORMATIONAL"):
        if finding_type not in INFORMATIONAL_PASSTHROUGH_TYPES:
            return (
                True,
                f"severity=Informational và '{finding_type}' không phải injection finding",
            )

    # Rule 5 — Low severity + không có injection signal nào
    if severity == "LOW":
        has_real_payload = bool(payload)
        has_real_evidence = bool(evidence) and evidence.lower() not in BORING_EVIDENCE
        # inputVector là header/cookie → không phải user-controlled
        has_user_input = bool(input_vector) and input_vector not in (
            "",
            "header",
            "cookie",
            "responseheader",
        )

        if not has_real_payload and not has_real_evidence and not has_user_input:
            return True, (
                "severity=LOW, không có payload/evidence thật/user input vector — "
                "ZAP không có basis inject, Agent không làm thêm được"
            )

    return False, ""


def build_api_payload(findings: list[dict]) -> list[dict]:
    sanitized: list[dict] = []
    for finding in findings:
        if isinstance(finding, dict):
            sanitized.append(
                {
                    key: value
                    for key, value in finding.items()
                    if key not in API_FIELDS_TO_REMOVE
                }
            )
        else:
            sanitized.append(finding)
    return sanitized


def validate_api_response(payload: dict, item_count: int) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("API response phai la JSON object")

    if set(payload.keys()) != {"keep", "drop"}:
        raise ValueError("API response phai chi co 2 key: keep va drop")

    validated: dict[str, list[int]] = {}
    all_indexes: set[int] = set()

    for key in ("keep", "drop"):
        value = payload.get(key)
        if not isinstance(value, list):
            raise ValueError(f"API response field '{key}' phai la list")

        cleaned: list[int] = []
        for item in value:
            if not isinstance(item, int):
                raise ValueError(f"API response field '{key}' phai chua integer")
            if item < 0 or item >= item_count:
                raise ValueError(f"Index {item} trong '{key}' bi out of range")
            if item in all_indexes:
                raise ValueError(f"Index {item} bi lap giua keep/drop")
            cleaned.append(item)
            all_indexes.add(item)

        validated[key] = cleaned

    expected_indexes = set(range(item_count))
    if all_indexes != expected_indexes:
        raise ValueError("API response khong cover day du tat ca index")

    return validated


def call_filter_api(
    findings: list[dict], api_url: str, timeout_seconds: int, log
) -> dict | None:
    if not findings:
        log("[+] Khong co finding nao de gui API")
        return None

    payload = build_api_payload(findings)
    request_body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(
        url=api_url,
        data=request_body,
        method="POST",
        headers={"Content-Type": "application/json"},
    )

    started = time.perf_counter()
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            response_text = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as error:
        response_text = error.read().decode("utf-8", errors="replace")
        log(
            f"[!] API HTTP error {error.code} {error.reason} -> bo qua API, dung ket qua local"
        )
        log(f"[!] API response: {response_text}")
        return None
    except (urllib.error.URLError, TimeoutError, socket.timeout) as error:
        log(
            f"[!] API/network timeout or error -> bo qua API, dung ket qua local: {error}"
        )
        return None
    except Exception as error:  # noqa: BLE001
        log(f"[!] Loi goi API -> bo qua API, dung ket qua local: {error}")
        return None

    elapsed = time.perf_counter() - started

    try:
        parsed_response = json.loads(response_text)
        validated_response = validate_api_response(parsed_response, len(findings))
    except (json.JSONDecodeError, ValueError) as error:
        log(f"[!] API tra ve sai dinh dang -> bo qua API, dung ket qua local: {error}")
        return None

    log(
        f"[+] API OK sau {elapsed:.2f}s | keep={len(validated_response['keep'])} | "
        f"drop={len(validated_response['drop'])}"
    )
    return validated_response


def apply_api_drop(filtered: dict, api_result: dict) -> None:
    current_results = filtered.get("results", [])
    drop_set = set(api_result["drop"])
    api_dropped: list[dict] = []
    final_results: list[dict] = []

    for index, finding in enumerate(current_results):
        if index in drop_set:
            api_dropped.append({**finding, "_drop_reason": "api_drop"})
        else:
            final_results.append(finding)

    filtered["results"] = final_results

    dropped_bucket = filtered.setdefault("_dropped", [])
    dropped_bucket.extend(api_dropped)

    stats = filtered.get("_filter_stats", {})
    original_count = stats.get(
        "original_count", len(final_results) + len(dropped_bucket)
    )
    kept_count = len(final_results)
    dropped_count = len(dropped_bucket)
    reduction_pct = round(
        (dropped_count / original_count * 100) if original_count else 0, 1
    )

    filtered["_filter_stats"] = {
        "original_count": original_count,
        "kept_count": kept_count,
        "dropped_count": dropped_count,
        "reduction_pct": reduction_pct,
    }


def filter_findings(data: dict) -> dict:
    results = data.get("results", [])
    base = data.get("base", "")

    kept: list[dict] = []
    dropped: list[dict] = []
    seen: set[tuple] = set()

    for finding in results:

        # Rule 1 — Dedup
        sig = (
            finding.get("endpoint", ""),
            finding.get("finding_type", ""),
            finding.get("param", ""),
            finding.get("method", ""),
        )
        if sig in seen:
            dropped.append({**finding, "_drop_reason": "duplicate"})
            continue
        seen.add(sig)

        useless, reason = is_useless(finding)
        if useless:
            dropped.append({**finding, "_drop_reason": reason})
        else:
            kept.append(finding)

    return {
        "base": base,
        "results": kept,
        "_filter_stats": {
            "original_count": len(results),
            "kept_count": len(kept),
            "dropped_count": len(dropped),
            "reduction_pct": round(
                (len(dropped) / len(results) * 100) if results else 0, 1
            ),
        },
        "_dropped": dropped,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Filter ZAP findings - local rule first, API triage second"
    )
    parser.add_argument("-i", "--input", required=True, help="File JSON tu ZAP")
    parser.add_argument(
        "-o", "--output", default="zap_filtered.json", help="File JSON dau ra"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Log chi tiet (human debug)"
    )
    parser.add_argument(
        "--drop-file", default="", help="Ghi findings bi drop ra file rieng (debug)"
    )
    parser.add_argument(
        "--keep-dropped",
        action="store_true",
        help="Giu _dropped trong output chinh (debug)",
    )
    parser.add_argument("--pretty", action="store_true", help="Indent JSON output")
    parser.add_argument(
        "--api-url",
        default=DEFAULT_FILTER_API_URL,
        help=f"API URL bo sung. Default: {DEFAULT_FILTER_API_URL}",
    )
    parser.add_argument(
        "--api-timeout",
        type=int,
        default=API_TIMEOUT_SECONDS,
        help=f"Timeout goi API theo giay. Default: {API_TIMEOUT_SECONDS}",
    )
    args = parser.parse_args()

    log = print if args.verbose else lambda *a, **k: None

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"[!] Khong tim thay file: {input_path}")
        return

    data = json.loads(input_path.read_text(encoding="utf-8"))
    filtered = filter_findings(data)
    local_stats = filtered["_filter_stats"]

    log(f"[+] Original  : {local_stats['original_count']} findings")
    log(f"[+] Kept local: {local_stats['kept_count']} findings")
    log(
        f"[+] Drop local: {local_stats['dropped_count']} findings ({local_stats['reduction_pct']}% reduction)"
    )

    api_result = call_filter_api(
        filtered.get("results", []),
        api_url=args.api_url,
        timeout_seconds=args.api_timeout,
        log=log,
    )
    if api_result is not None:
        apply_api_drop(filtered, api_result)
        stats = filtered["_filter_stats"]
        log(f"[+] Kept final: {stats['kept_count']} findings")
        log(
            f"[+] Drop final: {stats['dropped_count']} findings ({stats['reduction_pct']}% reduction)"
        )
    else:
        stats = filtered["_filter_stats"]
        log("[+] API bi bo qua, ghi ket qua local hien tai")

    indent = 2 if args.pretty else None
    separators = None if args.pretty else (",", ":")

    if args.drop_file:
        Path(args.drop_file).write_text(
            json.dumps(
                {"base": filtered["base"], "dropped": filtered["_dropped"]},
                ensure_ascii=False,
                indent=indent,
                separators=separators,
            ),
            encoding="utf-8",
        )
        log(f"[+] Dropped -> {args.drop_file}")

    if not args.keep_dropped:
        filtered.pop("_dropped", None)

    output_path = Path(args.output)
    output_path.write_text(
        json.dumps(filtered, ensure_ascii=False, indent=indent, separators=separators),
        encoding="utf-8",
    )
    log(f"[+] Filtered -> {output_path}")

    if args.verbose:
        input_size = input_path.stat().st_size
        output_size = output_path.stat().st_size
        size_saved = (1 - output_size / input_size) * 100 if input_size else 0
        log(f"\n[+] Input  : {input_size:,} bytes")
        log(f"[+] Output : {output_size:,} bytes  ({size_saved:.1f}% smaller)")
        log(f"\n{'='*55}")
        log("KEPT FINDINGS:")
        for f in filtered["results"]:
            log(
                f"  [{f.get('severity','?'):13}] "
                f"{f.get('finding_type','?'):45} | "
                f"{f.get('endpoint','?'):35} | "
                f"param={f.get('param','')}"
            )


if __name__ == "__main__":
    main()
