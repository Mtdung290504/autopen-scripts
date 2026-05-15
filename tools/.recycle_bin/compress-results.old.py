"""
Rule-based filter cho ZAP findings.
Chỉ loại bỏ những finding CHẮC CHẮN vô dụng.
Những cái nhập nhằng giữ lại — để local model xử lý tiếp.
"""

import json
import argparse
from pathlib import Path

# ──────────────────────────────────────────
# RULE 1 — Finding type vô dụng hoàn toàn
# Không phụ thuộc severity, không phụ thuộc endpoint
# ──────────────────────────────────────────
USELESS_FINDING_TYPES = {
    "Cookie No HttpOnly Flag",
    "Cookie Without Secure Flag",
    "Cookie No SameSite Attribute",
    "Missing Anti-clickjacking Header",  # x-frame-options
    "Content-Type Header Missing",
    "X-Content-Type-Options Header Missing",
    "Strict-Transport-Security Header Not Set",
    "Content Security Policy (CSP) Header Not Set",
    "Permissions Policy Header Not Set",
    "Server Leaks Version Information via Server HTTP Response Header Field",
    "Retrieved from Cache",
    "Modern Web Application",
    "Timestamp Disclosure - Unix",
    "Information Disclosure - Debug Error Messages",
    "Absence of Anti-CSRF Tokens",  # ZAP báo sai rất nhiều
}

# ──────────────────────────────────────────
# RULE 2 — Confidence "False Positive"
# ZAP tự đánh nhãn này → bỏ luôn
# ──────────────────────────────────────────
USELESS_CONFIDENCE = {"False Positive"}

# ──────────────────────────────────────────
# RULE 3 — Severity INFO + Confidence Low/Medium
# + finding_type không quan trọng
# ──────────────────────────────────────────
INFO_PASSTHROUGH_TYPES = {
    # Những finding_type INFO nào vẫn cần giữ dù severity thấp
    "Path Traversal",
    "SQL Injection",
    "Remote OS Command Injection",
    "Server Side Include",
    "Remote File Inclusion",
    "XSLT Injection",
    "XXE",
    "SSRF",
    "SSTI",
}


def is_useless(finding: dict) -> tuple[bool, str]:
    """
    Trả về (True, lý do) nếu finding chắc chắn vô dụng.
    Trả về (False, "") nếu nên giữ lại.
    """
    finding_type = finding.get("finding_type", "")
    severity = finding.get("severity", "").upper()
    confidence = finding.get("confidence", "")
    endpoint = finding.get("endpoint", "")
    param = finding.get("param", "")
    evidence = finding.get("evidence", "")

    # Rule 1 — finding type vô dụng hoàn toàn
    if finding_type in USELESS_FINDING_TYPES:
        return (
            True,
            f"finding_type '{finding_type}' là misconfiguration header, không actionable",
        )

    # Rule 2 — ZAP tự đánh False Positive
    if confidence in USELESS_CONFIDENCE:
        return True, "ZAP tự đánh confidence=False Positive"

    # Rule 3 — INFO severity + không phải finding quan trọng
    if severity == "INFO" and finding_type not in INFO_PASSTHROUGH_TYPES:
        return True, f"severity=INFO và finding_type '{finding_type}' không quan trọng"

    # Rule 4 — Không có param, không có evidence, không có payload
    # + severity thấp → ZAP scan mù, không có gì để test
    has_param = bool(param and param.strip())
    has_evidence = bool(evidence and evidence.strip())
    has_payload = bool(finding.get("payload", "").strip())

    if severity == "LOW" and not has_param and not has_evidence and not has_payload:
        return (
            True,
            "severity=LOW, không có param/evidence/payload — ZAP không có basis để báo",
        )

    # Rule 5 — Duplicate: cùng endpoint + cùng finding_type + cùng param
    # (xử lý ở ngoài hàm này, cần context toàn list)

    return False, ""


def filter_findings(data: dict) -> dict:
    results = data.get("results", [])
    base = data.get("base", "")

    kept = []
    dropped = []
    seen_signatures = set()  # dedup

    for finding in results:
        # Rule 5 — Dedup
        sig = (
            finding.get("endpoint", ""),
            finding.get("finding_type", ""),
            finding.get("param", ""),
            finding.get("method", ""),
        )
        if sig in seen_signatures:
            dropped.append(
                {
                    **finding,
                    "_drop_reason": "duplicate: cùng endpoint+finding_type+param+method",
                }
            )
            continue
        seen_signatures.add(sig)

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
        "_dropped": dropped,  # giữ lại để debug, có thể bỏ nếu không cần
    }


def main():
    parser = argparse.ArgumentParser(
        description="Filter ZAP findings — chỉ loại bỏ thứ chắc chắn vô dụng"
    )

    parser.add_argument(
        "-i",
        "--input",
        required=True,
        help="File JSON từ ZAP (zap_output.json)",
    )

    parser.add_argument(
        "-o",
        "--output",
        default="zap_filtered.json",
        help="File JSON đầu ra",
    )

    parser.add_argument(
        "--drop-file",
        default="",
        help="Ghi findings bị drop ra file riêng",
    )

    parser.add_argument(
        "--keep-dropped",
        action="store_true",
        help="Giữ _dropped trong output chính (debug)",
    )

    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON (debug/human readable)",
    )

    args = parser.parse_args()

    input_path = Path(args.input)

    if not input_path.exists():
        print(f"[!] Không tìm thấy file: {input_path}")
        return

    data = json.loads(input_path.read_text(encoding="utf-8"))

    filtered = filter_findings(data)

    stats = filtered["_filter_stats"]

    print(f"[+] Original : {stats['original_count']} findings")
    print(f"[+] Kept     : {stats['kept_count']} findings")
    print(
        f"[+] Dropped  : {stats['dropped_count']} findings "
        f"({stats['reduction_pct']}% reduction)"
    )

    # ─────────────────────────────────────
    # Ghi dropped ra file riêng nếu yêu cầu
    # ─────────────────────────────────────
    if args.drop_file:
        dropped_data = {
            "base": filtered["base"],
            "dropped": filtered["_dropped"],
        }

        drop_json = json.dumps(
            dropped_data,
            ensure_ascii=False,
            indent=2 if args.pretty else None,
            separators=None if args.pretty else (",", ":"),
        )

        Path(args.drop_file).write_text(
            drop_json,
            encoding="utf-8",
        )

        print(f"[+] Dropped findings → {args.drop_file}")

    # ─────────────────────────────────────
    # Default: KHÔNG giữ _dropped
    # ─────────────────────────────────────
    if not args.keep_dropped:
        filtered.pop("_dropped", None)

    # ─────────────────────────────────────
    # Compact JSON mặc định
    # ─────────────────────────────────────
    output_json = json.dumps(
        filtered,
        ensure_ascii=False,
        indent=2 if args.pretty else None,
        separators=None if args.pretty else (",", ":"),
    )

    output_path = Path(args.output)

    output_path.write_text(
        output_json,
        encoding="utf-8",
    )

    print(f"[+] Filtered findings → {output_path}")

    # ─────────────────────────────────────
    # Size stats
    # ─────────────────────────────────────
    input_size = input_path.stat().st_size
    output_size = output_path.stat().st_size

    reduction = (1 - (output_size / input_size)) * 100 if input_size > 0 else 0

    print("\n" + "=" * 50)
    print(f"[+] Input size : {input_size:,} bytes")
    print(f"[+] Output size: {output_size:,} bytes")
    print(f"[+] Size saved : {reduction:.1f}%")

    # ─────────────────────────────────────
    # Preview
    # ─────────────────────────────────────
    print(f"\n{'='*50}")
    print("KEPT FINDINGS:")

    for f in filtered["results"]:
        print(
            f"  [{f.get('severity','?')}] "
            f"{f.get('finding_type','?')} | "
            f"{f.get('endpoint','?')} | "
            f"param={f.get('param','')}"
        )


# Run: ```py .\zip.py -i <input_file> -o <output_file> --pretty```
if __name__ == "__main__":
    main()
