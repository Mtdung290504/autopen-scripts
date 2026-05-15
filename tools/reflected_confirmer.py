from __future__ import annotations

"""
Phase 3 confirmer for phase-2 items with `confirmReflection=true`.

Schema:

{
  "base": "http://host/app/",
  "items": [
    {
      "clusterKey": "GET|vulnerabilities/xss_r/?name=test|querystring|name",
      "target": {
        "endpoint": "vulnerabilities/xss_r/?name=test",
        "method": "GET",
        "inputVector": "querystring",
        "param": "name"
      },
      "reflectionConfirmed": true,
      "reason": "both_canaries_reflected",
      "responseA": "HTTP/1.1 200 OK\nContent-Type: text/html;charset=utf-8\n\n<form ...>...</form>\n\n<pre>Hello qk8X2mP4rT1a</pre>",
      "responseB": "HTTP/1.1 200 OK\nContent-Type: text/html;charset=utf-8\n\n<form ...>...</form>\n\n<pre>Hello qk8X2mP4rT1b</pre>"
    }
  ]
}

Notes:
- This script uses phase 2 output plus the original source JSON.
- Only items with `confirmReflection=true` are replayed.
- Replay uses two benign canaries and compares reduced responses.
- `responseA` and `responseB` are reduced HTTP-like strings, not raw full responses.
"""

import argparse
import html
import json
import re
from collections import defaultdict
from html.parser import HTMLParser
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse
from urllib.request import Request, urlopen


FORM_BLOCK_PATTERN = re.compile(r"<form\b[^>]*>.*?</form>", re.IGNORECASE | re.DOTALL)
HTML_HINT_PATTERN = re.compile(r"<!doctype|<html|<body|<form|<input|<textarea|<select|<script", re.IGNORECASE)
VOID_TAGS = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}
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
MAX_BODY_SEGMENTS = 6
MAX_BODY_SEGMENT_LENGTH = 2200
CANARY_A = "qk8X2mP4rT1a"
CANARY_B = "qk8X2mP4rT1b"


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


def build_cluster_key(item: dict[str, object]) -> str:
    return "|".join(
        [
            normalize_text(item.get("method")).upper(),
            normalize_text(item.get("endpoint")),
            normalize_text(item.get("inputVector")),
            normalize_text(item.get("param")),
        ]
    )


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


def extract_reflected_segments(body: str, token: str) -> list[str]:
    if not body or not token or not looks_like_html(body):
        return []

    variants = build_token_variants(token)
    segments: list[str] = []
    for element in parse_elements(body):
        element_html = normalize_text(element.get("html"))
        if not element_html:
            continue

        text_value = normalize_text(element.get("text"))
        attrs = element.get("attrs", {})
        matched = any(variant in text_value for variant in variants)

        if not matched and isinstance(attrs, dict):
            for attr_name, attr_value in attrs.items():
                if any(variant in str(attr_name) or variant in str(attr_value) for variant in variants):
                    matched = True
                    break

        if matched:
            segments.append(element_html[:MAX_BODY_SEGMENT_LENGTH])
        if len(segments) >= MAX_BODY_SEGMENTS:
            break

    return compress_segments(segments)


def select_response_headers(headers: dict[str, str]) -> list[str]:
    lines = []
    for name in HEADER_NAMES_TO_KEEP:
        if name in headers:
            lines.append(f"{name.title()}: {headers[name]}")
    return dedupe_strings(lines)


def build_reduced_response_from_parts(status_line: str, headers: dict[str, str], body: str, token: str) -> str:
    lines: list[str] = []
    if status_line:
        lines.append(status_line)
    lines.extend(select_response_headers(headers))

    reflected_segments = extract_reflected_segments(body, token)
    forms = extract_forms(body) if looks_like_html(body) else []
    body_segments = compress_segments(reflected_segments + forms)[:MAX_BODY_SEGMENTS]

    if body_segments:
        lines.append("")
        lines.extend(body_segments)

    return "\n".join(lines).strip()


def build_target_url(request_line: str, base: str) -> str:
    request_target = extract_request_target(request_line)
    parsed = urlparse(request_target)
    if parsed.scheme and parsed.netloc:
        return request_target
    return urljoin(base, request_target)


def mutate_query(url: str, param: str, marker: str) -> str:
    parsed = urlparse(url)
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    mutated = False
    rewritten: list[tuple[str, str]] = []
    for key, value in query_pairs:
        if key == param:
            rewritten.append((key, marker))
            mutated = True
        else:
            rewritten.append((key, value))
    if not mutated and param:
        rewritten.append((param, marker))
    return urlunparse(parsed._replace(query=urlencode(rewritten, doseq=True)))


def mutate_body(body: str, param: str, marker: str) -> str:
    body_pairs = parse_qsl(body, keep_blank_values=True)
    mutated = False
    rewritten: list[tuple[str, str]] = []
    for key, value in body_pairs:
        if key == param:
            rewritten.append((key, marker))
            mutated = True
        else:
            rewritten.append((key, value))
    if not mutated and param:
        rewritten.append((param, marker))
    return urlencode(rewritten, doseq=True)


def build_replay_request(raw_request: str, base: str, input_vector: str, param: str, marker: str) -> tuple[str, str, dict[str, str], bytes | None]:
    request_line, headers, body = split_raw_request(raw_request)
    method = request_line.split()[0].upper() if request_line else "GET"
    url = build_target_url(request_line, base)
    headers = dict(headers)
    headers.pop("host", None)
    headers.pop("content-length", None)

    input_vector = input_vector.lower().replace(" ", "")
    url_has_query = bool(urlparse(url).query)
    body_has_params = bool(parse_qsl(body, keep_blank_values=True))

    new_url = url
    new_body = body
    if param:
        if url_has_query:
            new_url = mutate_query(url, param, marker)
        elif body_has_params or input_vector in BODY_INPUT_VECTORS or method in {"POST", "PUT", "PATCH"}:
            new_body = mutate_body(body, param, marker)
        else:
            new_url = mutate_query(url, param, marker)

    data = None
    if method in {"POST", "PUT", "PATCH"} or new_body:
        data = new_body.encode("utf-8")
        headers.setdefault("content-type", "application/x-www-form-urlencoded")

    return method, new_url, headers, data


def fetch_reduced_response(raw_request: str, base: str, input_vector: str, param: str, marker: str, timeout: int) -> str:
    method, url, headers, data = build_replay_request(raw_request, base, input_vector, param, marker)
    request = Request(url=url, data=data, headers=headers, method=method)

    try:
        with urlopen(request, timeout=timeout) as response:
            body_bytes = response.read()
            body = body_bytes.decode("utf-8", errors="replace")
            status_line = f"HTTP/1.1 {response.status} {response.reason}"
            response_headers = {key.lower(): value for key, value in response.headers.items()}
            return build_reduced_response_from_parts(status_line, response_headers, body, marker)
    except HTTPError as error:
        body = error.read().decode("utf-8", errors="replace")
        status_line = f"HTTP/1.1 {error.code} {error.reason}"
        response_headers = {key.lower(): value for key, value in error.headers.items()}
        return build_reduced_response_from_parts(status_line, response_headers, body, marker)
    except URLError as error:
        raise RuntimeError(f"Network error: {error.reason}") from error


def marker_present(text: str, marker: str) -> bool:
    return marker in text


def resolve_phase2_target(phase2_item: dict[str, object]) -> dict[str, str]:
    raw_target = phase2_item.get("target")
    target = raw_target if isinstance(raw_target, dict) else {}

    return {
        "endpoint": normalize_text(target.get("endpoint") or phase2_item.get("endpoint")),
        "method": normalize_text(target.get("method") or phase2_item.get("method")).upper(),
        "inputVector": normalize_text(target.get("inputVector") or phase2_item.get("inputVector")),
        "param": normalize_text(target.get("param") or phase2_item.get("param")),
    }


def resolve_replay_request(phase2_item: dict[str, object], source_item: dict[str, object]) -> str:
    candidates = [
        source_item.get("raw_request"),
        source_item.get("request"),
        phase2_item.get("raw_request"),
        phase2_item.get("request"),
    ]
    for candidate in candidates:
        request_text = normalize_text(candidate)
        if request_text:
            return request_text
    return ""


def confirm_item(base: str, phase2_item: dict[str, object], source_item: dict[str, object], timeout: int) -> dict[str, object]:
    target = resolve_phase2_target(phase2_item)
    raw_request = resolve_replay_request(phase2_item, source_item)
    input_vector = normalize_text(target.get("inputVector"))
    param = normalize_text(target.get("param"))

    if not raw_request:
        raise ValueError("Replay request khong ton tai trong source hoac phase2 item.")

    response_a = fetch_reduced_response(raw_request, base, input_vector, param, CANARY_A, timeout)
    response_b = fetch_reduced_response(raw_request, base, input_vector, param, CANARY_B, timeout)

    has_a = marker_present(response_a, CANARY_A)
    has_b = marker_present(response_b, CANARY_B)

    if has_a and has_b:
        confirmed = True
        reason = "both_canaries_reflected"
    elif has_a or has_b:
        confirmed = False
        reason = "one_way_reflection_or_inconsistent_response"
    elif response_a != response_b:
        confirmed = False
        reason = "responses_differ_but_canaries_not_visible"
    else:
        confirmed = False
        reason = "no_visible_reflection"

    return {
        "clusterKey": normalize_text(phase2_item.get("clusterKey")),
        "target": target,
        "reflectionConfirmed": confirmed,
        "reason": reason,
        "responseA": response_a,
        "responseB": response_b,
    }


def load_phase2(path: Path) -> dict[str, object]:
    data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    if not isinstance(data.get("items"), list):
        raise ValueError("Phase 2 file khong co `items` hop le.")
    return data


def load_source_results(path: Path) -> dict[str, list[dict[str, object]]]:
    data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    results = data.get("results")
    if not isinstance(results, list):
        raise ValueError("Source file khong co `results` hop le.")

    clusters: dict[str, list[dict[str, object]]] = {}
    grouped = defaultdict(list)
    for item in results:
        if isinstance(item, dict):
            grouped[build_cluster_key(item)].append(item)
    clusters.update(grouped)
    return clusters


def run_phase3(phase2_data: dict[str, object], source_clusters: dict[str, list[dict[str, object]]], timeout: int) -> dict[str, object]:
    base = normalize_text(phase2_data.get("base"))
    items = phase2_data.get("items", [])
    confirmed_items: list[dict[str, object]] = []

    for item in items:
        if not isinstance(item, dict):
            continue
        if not item.get("confirmReflection"):
            continue

        cluster_key = normalize_text(item.get("clusterKey"))
        source_cluster = source_clusters.get(cluster_key, [])
        if not source_cluster and not normalize_text(item.get("request")) and not normalize_text(item.get("raw_request")):
            confirmed_items.append(
                {
                    "clusterKey": cluster_key,
                    "target": resolve_phase2_target(item),
                    "reflectionConfirmed": False,
                    "reason": "source_cluster_not_found",
                    "responseA": "",
                    "responseB": "",
                }
            )
            continue

        try:
            confirmed_items.append(confirm_item(base, item, source_cluster[0] if source_cluster else {}, timeout))
        except Exception as exc:
            confirmed_items.append(
                {
                    "clusterKey": cluster_key,
                    "target": resolve_phase2_target(item),
                    "reflectionConfirmed": False,
                    "reason": "request_error",
                    "responseA": "",
                    "responseB": "",
                    "error": str(exc),
                }
            )

    return {"base": base, "items": confirmed_items}


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Phase 3 confirmer for phase-2 confirmReflection items.")
    parser.add_argument("--phase2", required=True, help="Path to phase2 reduced JSON file")
    parser.add_argument("--source", required=True, help="Path to original source JSON file")
    parser.add_argument("--output", default="output/phase3_confirmed.json", help="Path to output JSON file")
    parser.add_argument("--timeout", type=int, default=15, help="HTTP timeout in seconds")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    phase2_path = Path(args.phase2).expanduser().resolve()
    source_path = Path(args.source).expanduser().resolve()
    output_path = Path(args.output).expanduser().resolve()

    phase2_data = load_phase2(phase2_path)
    source_clusters = load_source_results(source_path)
    reduced = run_phase3(phase2_data, source_clusters, args.timeout)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(reduced, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"Phase2 items with confirmReflection: {sum(1 for item in phase2_data['items'] if item.get('confirmReflection'))}")
    print(f"Phase3 outputs: {len(reduced['items'])}")
    print(f"Confirmed reflection: {sum(1 for item in reduced['items'] if item.get('reflectionConfirmed'))}")
    print(f"Output: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
