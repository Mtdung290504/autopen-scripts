from __future__ import annotations

"""
Phase 2 reducer for agent-facing triage.

Schema:

{
  "base": "http://host/app/",
  "items": [
    {
      "clusterKey": "POST|vulnerabilities/xss_s/|form|txtName",
      "target": {
        "endpoint": "vulnerabilities/xss_s/",
        "method": "POST",
        "inputVector": "form",
        "param": "txtName"
      },
      "findings": [
        "Cross Site Scripting (Reflected) [High/Medium]",
        "Parameter Tampering [Medium/Low]"
      ],
      "payloads": [
        "</div><script>alert(1)</script><div>",
        ""
      ],
      "response": "HTTP/1.1 200 OK\nContent-Type: text/html;charset=utf-8\n\n<form ...>...</form>\n\n<div id=\"guestbook_comments\">Name: </div><script>alert(1)</script><div>...</div>",
      "confirmReflection": true,
      "repeat": 2
    }
  ]
}

Field notes:
- `clusterKey` is kept intentionally. It is the stable dedupe key and the join key for phase 3.
- `target` contains the input surface the agent should reason about.
- `findings` and `payloads` are aligned by index. If a finding has no payload, the payload at that same index is "".
- `response` is a single reduced HTTP-like string: status line + relevant headers + only useful body snippets.
- `confirmReflection` is intentionally broad: any controllable query/body input is marked true for phase 3.
- `repeat` appears only when a cluster contains more than one source result.
"""

import argparse
import html
import json
import re
from collections import defaultdict
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import parse_qsl, unquote_plus, urlparse


FORM_BLOCK_PATTERN = re.compile(r"<form\b[^>]*>.*?</form>", re.IGNORECASE | re.DOTALL)
HTML_HINT_PATTERN = re.compile(r"<!doctype|<html|<body|<form|<input|<textarea|<select|<script", re.IGNORECASE)
LEAK_PATTERNS = [
    re.compile(r"root:.*:0:0", re.IGNORECASE),
    re.compile(r"/etc/passwd", re.IGNORECASE),
    re.compile(r"php warning|stack trace|uncaught .*exception", re.IGNORECASE),
    re.compile(r"sql syntax|sqlstate|mysqli_sql_exception|postgresql.*error|oracle.*error|odbc.*error", re.IGNORECASE),
    re.compile(r"uid=\d+", re.IGNORECASE),
]
VOID_TAGS = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4, "info": 4}
BODY_INPUT_VECTORS = {"form", "post", "postdata", "body", "json", "xml", "multipart"}
HEADER_NAMES_TO_KEEP = {
    "content-type",
    "location",
    "set-cookie",
    "x-frame-options",
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
}
MAX_BODY_SEGMENTS = 8
MAX_BODY_SEGMENT_LENGTH = 2200
MAX_EVIDENCE_WINDOWS = 5


def normalize_text(value: object) -> str:
    return str(value or "").strip()


def normalize_space(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def dedupe_strings(items: list[str]) -> list[str]:
    return list(dict.fromkeys(item for item in items if item))


def compress_segments(segments: list[str]) -> list[str]:
    reduced: list[str] = []
    normalized_seen: list[str] = []

    for segment in segments:
        cleaned = segment.strip()
        if not cleaned:
            continue
        normalized = normalize_space(cleaned)

        if any(normalized in existing for existing in normalized_seen):
            continue

        next_reduced: list[str] = []
        next_seen: list[str] = []
        for existing_raw, existing_norm in zip(reduced, normalized_seen):
            if existing_norm in normalized:
                continue
            next_reduced.append(existing_raw)
            next_seen.append(existing_norm)

        next_reduced.append(cleaned)
        next_seen.append(normalized)
        reduced = next_reduced
        normalized_seen = next_seen

    return reduced


def looks_like_html(text: str) -> bool:
    return bool(HTML_HINT_PATTERN.search(text))


def split_raw_request(raw_request: str) -> tuple[str, dict[str, str], str]:
    if "\r\n\r\n" in raw_request:
        head, body = raw_request.split("\r\n\r\n", 1)
    elif "\n\n" in raw_request:
        head, body = raw_request.split("\n\n", 1)
    else:
        head, body = raw_request, ""

    lines = [line for line in head.splitlines() if line.strip()]
    request_line = lines[0].strip() if lines else ""
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers[name.strip().lower()] = value.strip()
    return request_line, headers, body


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


def extract_request_target(request_line: str) -> str:
    parts = request_line.split()
    return parts[1].strip() if len(parts) >= 2 else ""


def parse_request_params(raw_request: str) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    request_line, _, body = split_raw_request(raw_request)
    request_target = extract_request_target(request_line)
    query_pairs = [(key.strip(), value) for key, value in parse_qsl(urlparse(request_target).query, keep_blank_values=True) if key.strip()]
    body_pairs = [(key.strip(), value) for key, value in parse_qsl(body, keep_blank_values=True) if key.strip()]
    return query_pairs, body_pairs


def build_cluster_key(item: dict[str, object]) -> str:
    return "|".join(
        [
            normalize_text(item.get("method")).upper(),
            normalize_text(item.get("endpoint")),
            normalize_text(item.get("inputVector")),
            normalize_text(item.get("param")),
        ]
    )


def format_finding(item: dict[str, object]) -> str:
    finding_type = normalize_text(item.get("finding_type"))
    severity = normalize_text(item.get("severity"))
    confidence = normalize_text(item.get("confidence"))
    return f"{finding_type} [{severity}/{confidence}]"


def build_finding_payload_lists(items: list[dict[str, object]]) -> tuple[list[str], list[str]]:
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


def extract_forms(html_text: str) -> list[str]:
    return compress_segments([match.group(0).strip() for match in FORM_BLOCK_PATTERN.finditer(html_text) if match.group(0).strip()])


class ElementParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.elements: list[dict[str, object]] = []
        self.stack: list[dict[str, object]] = []

    def handle_starttag(self, tag: str, attrs_list: list[tuple[str, str | None]]) -> None:
        attrs = {key: value or "" for key, value in attrs_list}
        self.stack.append({"tag": tag, "attrs": attrs, "start_html": self.get_starttag_text() or f"<{tag}>", "text_parts": []})

    def handle_startendtag(self, tag: str, attrs_list: list[tuple[str, str | None]]) -> None:
        attrs = {key: value or "" for key, value in attrs_list}
        self.elements.append({"tag": tag, "attrs": attrs, "html": self.get_starttag_text() or f"<{tag} />", "text": ""})

    def handle_data(self, data: str) -> None:
        if not self.stack:
            return
        text = normalize_space(data)
        if text:
            self.stack[-1]["text_parts"].append(text)

    def handle_endtag(self, tag: str) -> None:
        if not self.stack:
            return
        node = self.stack.pop()
        text_value = normalize_space(" ".join(node["text_parts"]))[:1200]
        start_html = str(node["start_html"])
        if node["tag"] in VOID_TAGS:
            element_html = start_html
        elif text_value:
            element_html = f"{start_html}{text_value}</{node['tag']}>"
        else:
            element_html = f"{start_html}</{node['tag']}>"
        self.elements.append({"tag": node["tag"], "attrs": node["attrs"], "html": element_html, "text": text_value})


def parse_elements(html_text: str) -> list[dict[str, object]]:
    parser = ElementParser()
    parser.feed(html_text)
    return parser.elements


def tokenize_html_snippet(value: str) -> list[str]:
    text_only = normalize_space(re.sub(r"<[^>]+>", " ", value))
    tokens = [token for token in re.split(r"[^A-Za-z0-9_:/\\.%?-]+", text_only) if token]
    return [token for token in tokens if token]


def is_strong_token(token: str) -> bool:
    cleaned = token.strip()
    if not cleaned:
        return False
    if len(cleaned) >= 8:
        return True
    if any(char in cleaned for char in "<>\"'=/\\:%?&;(){}[]"):
        return True
    return False


def collect_reflection_tokens(items: list[dict[str, object]]) -> list[str]:
    tokens: list[str] = []
    for item in items:
        payload = normalize_text(item.get("payload"))
        evidence = normalize_text(item.get("evidence"))
        raw_request = normalize_text(item.get("raw_request"))
        param = normalize_text(item.get("param"))

        if payload:
            tokens.append(unquote_plus(payload))
        if evidence:
            if "<" in evidence and ">" in evidence:
                tokens.extend(tokenize_html_snippet(evidence))
            else:
                tokens.append(unquote_plus(evidence))

        query_pairs, body_pairs = parse_request_params(raw_request)
        if param:
            for key, value in query_pairs + body_pairs:
                if key == param and value:
                    tokens.append(unquote_plus(value))

    return [token for token in dedupe_strings(tokens) if is_strong_token(token)]


def build_token_variants(token: str) -> list[str]:
    return dedupe_strings(
        [
            token,
            html.escape(token, quote=False),
            html.escape(token, quote=True),
            token.replace("'", "&#39;"),
            token.replace("'", "&#x27;"),
        ]
    )


def extract_reflected_segments(body: str, tokens: list[str]) -> list[str]:
    if not body or not tokens or not looks_like_html(body):
        return []

    segments: list[str] = []
    for element in parse_elements(body):
        element_html = normalize_text(element.get("html"))
        if not element_html:
            continue
        text_value = normalize_text(element.get("text"))
        attrs = element.get("attrs", {})
        matched = False

        for token in tokens:
            variants = build_token_variants(token)
            if any(variant in text_value for variant in variants):
                matched = True
            if isinstance(attrs, dict):
                for attr_name, attr_value in attrs.items():
                    if any(variant in str(attr_name) or variant in str(attr_value) for variant in variants):
                        matched = True
                        break
            if matched:
                break

        if matched:
            segments.append(element_html[:MAX_BODY_SEGMENT_LENGTH])
        if len(segments) >= MAX_BODY_SEGMENTS:
            break

    return compress_segments(segments)


def extract_evidence_windows(body: str, items: list[dict[str, object]]) -> list[str]:
    windows: list[str] = []
    search_terms: list[str] = []

    for item in items:
        evidence = normalize_text(item.get("evidence"))
        payload = normalize_text(item.get("payload"))
        if evidence:
            if "<" in evidence and ">" in evidence:
                search_terms.extend(tokenize_html_snippet(evidence))
            else:
                search_terms.append(unquote_plus(evidence))
        if payload:
            search_terms.append(unquote_plus(payload))

    for term in dedupe_strings(search_terms):
        if len(term) < 4:
            continue
        start = body.find(term)
        if start == -1:
            continue
        left = max(0, start - 120)
        right = min(len(body), start + len(term) + 120)
        windows.append(normalize_space(body[left:right]))
        if len(windows) >= MAX_EVIDENCE_WINDOWS:
            return compress_segments(windows)

    for pattern in LEAK_PATTERNS:
        match = pattern.search(body)
        if not match:
            continue
        left = max(0, match.start() - 120)
        right = min(len(body), match.end() + 120)
        windows.append(normalize_space(body[left:right]))
        if len(windows) >= MAX_EVIDENCE_WINDOWS:
            break

    return compress_segments(windows)[:MAX_EVIDENCE_WINDOWS]


def select_response_headers(headers: dict[str, str], items: list[dict[str, object]]) -> list[str]:
    lines: list[str] = []
    mentioned_params = {normalize_text(item.get("param")).lower() for item in items if normalize_text(item.get("param"))}
    finding_text = " ".join(normalize_text(item.get("finding_type")).lower() for item in items)

    for name in HEADER_NAMES_TO_KEEP:
        if name in headers:
            lines.append(f"{name.title()}: {headers[name]}")

    if ("cookie" in finding_text or "session" in finding_text) and "set-cookie" in headers:
        candidate = f"Set-Cookie: {headers['set-cookie']}"
        if candidate not in lines:
            lines.append(candidate)

    for param in mentioned_params:
        if param in headers:
            candidate = f"{param.title()}: {headers[param]}"
            if candidate not in lines:
                lines.append(candidate)

    return dedupe_strings(lines)


def build_reduced_response(items: list[dict[str, object]]) -> str:
    raw_response = normalize_text(items[0].get("raw_response"))
    status_line, headers, body = split_raw_response(raw_response)
    lines: list[str] = []

    if status_line:
        lines.append(status_line)
    for header_line in select_response_headers(headers, items):
        lines.append(header_line)

    tokens = collect_reflection_tokens(items)
    forms = extract_forms(body) if looks_like_html(body) else []
    reflected_segments = extract_reflected_segments(body, tokens)
    evidence_windows = extract_evidence_windows(body, items)
    body_segments = compress_segments(reflected_segments + forms + evidence_windows)[:MAX_BODY_SEGMENTS]

    if body_segments:
        lines.append("")
        lines.extend(segment[:MAX_BODY_SEGMENT_LENGTH] for segment in body_segments)

    return "\n".join(lines).strip()


def should_confirm_reflection(items: list[dict[str, object]]) -> bool:
    for item in items:
        input_vector = normalize_text(item.get("inputVector")).lower().replace(" ", "")
        raw_request = normalize_text(item.get("raw_request"))
        query_pairs, body_pairs = parse_request_params(raw_request)

        if query_pairs or body_pairs:
            return True
        if input_vector in BODY_INPUT_VECTORS or input_vector == "querystring":
            return True

    return False


def build_item(cluster_key: str, items: list[dict[str, object]]) -> dict[str, object]:
    first = items[0]
    findings, payloads = build_finding_payload_lists(items)

    target = {
        "endpoint": normalize_text(first.get("endpoint")),
        "method": normalize_text(first.get("method")).upper(),
        "inputVector": normalize_text(first.get("inputVector")),
        "param": normalize_text(first.get("param")),
    }

    reduced = {
        "clusterKey": cluster_key,
        "target": target,
        "findings": findings,
        "payloads": payloads,
        "response": build_reduced_response(items),
    }

    if should_confirm_reflection(items):
        reduced["confirmReflection"] = True

    if len(items) > 1:
        reduced["repeat"] = len(items)

    return reduced


def sort_items(items: list[dict[str, object]]) -> list[dict[str, object]]:
    def item_rank(entry: dict[str, object]) -> tuple[object, ...]:
        highest = 99
        for finding in entry.get("findings", []):
            match = re.search(r"\[([^\]/]+)/", str(finding))
            severity = match.group(1).lower() if match else ""
            highest = min(highest, SEVERITY_RANK.get(severity, 99))
        target = entry.get("target", {})
        return (
            entry.get("confirmReflection") is False,
            highest,
            str(target.get("endpoint", "")),
            str(target.get("param", "")),
        )

    return sorted(items, key=item_rank)


def load_results(data: dict[str, object]) -> list[dict[str, object]]:
    results = data.get("results")
    if not isinstance(results, list):
        raise ValueError("Input JSON khong co list `results` hop le.")
    return [item for item in results if isinstance(item, dict)]


def reduce_phase2(data: dict[str, object]) -> dict[str, object]:
    base = normalize_text(data.get("base"))
    results = load_results(data)

    clusters = defaultdict(list)
    for item in results:
        clusters[build_cluster_key(item)].append(item)

    reduced_items = [build_item(cluster_key, cluster_items) for cluster_key, cluster_items in clusters.items()]
    return {"base": base, "items": sort_items(reduced_items)}


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Phase 2 reducer for agent-facing ZAP triage.")
    parser.add_argument("--input", "-i", required=True, help="Path to input JSON file")
    parser.add_argument("--output", "-o", default="output/phase2_reduced.json", help="Path to output JSON file")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    input_path = Path(args.input).expanduser().resolve()
    output_path = Path(args.output).expanduser().resolve()

    data = json.loads(input_path.read_text(encoding="utf-8", errors="replace"))
    reduced = reduce_phase2(data)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(reduced, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"Input results: {len(load_results(data))}")
    print(f"Clusters: {len(reduced['items'])}")
    print(f"Confirm reflection: {sum(1 for item in reduced['items'] if item.get('confirmReflection'))}")
    print(f"Output: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
