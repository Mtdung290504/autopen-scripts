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
from pathlib import Path

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
        description="Filter ZAP findings — drop thứ chắc chắn vô dụng, giữ lại cho local model"
    )
    parser.add_argument("-i", "--input", required=True, help="File JSON từ ZAP")
    parser.add_argument(
        "-o", "--output", default="zap_filtered.json", help="File JSON đầu ra"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Log chi tiết (human debug)"
    )
    parser.add_argument(
        "--drop-file", default="", help="Ghi findings bị drop ra file riêng (debug)"
    )
    parser.add_argument(
        "--keep-dropped",
        action="store_true",
        help="Giữ _dropped trong output chính (debug)",
    )
    parser.add_argument("--pretty", action="store_true", help="Indent JSON output")
    args = parser.parse_args()

    log = print if args.verbose else lambda *a, **k: None

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"[!] Không tìm thấy file: {input_path}")
        return

    data = json.loads(input_path.read_text(encoding="utf-8"))
    filtered = filter_findings(data)
    stats = filtered["_filter_stats"]

    log(f"[+] Original : {stats['original_count']} findings")
    log(f"[+] Kept     : {stats['kept_count']} findings  → local model / Agent")
    log(
        f"[+] Dropped  : {stats['dropped_count']} findings ({stats['reduction_pct']}% reduction)"
    )

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
        log(f"[+] Dropped  → {args.drop_file}")

    if not args.keep_dropped:
        filtered.pop("_dropped", None)

    output_path = Path(args.output)
    output_path.write_text(
        json.dumps(filtered, ensure_ascii=False, indent=indent, separators=separators),
        encoding="utf-8",
    )
    log(f"[+] Filtered → {output_path}")

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
