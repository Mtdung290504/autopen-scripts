# Kick-off Message

Paste cái này vào tin nhắn đầu tiên khi bắt đầu session với Agent.
Không cần paste nội dung file — Agent tự đọc.

---

## ---- COPY TỪ ĐÂY ----

Môi trường: workspace tại `c:\VS_Code_Workplace\ATW&CSDL\`

ZAP proxy: `192.168.153.130:8080`

Tất cả pre-conditions đã hoàn tất (recon xong, `site-endpoints.txt` và `site-forms.txt` đã có). Bắt đầu pipeline từ Step 0.

## ---- ĐẾN ĐÂY ----

---

# Hướng Dẫn Theo Platform

## Antigravity (khuyên dùng)

1. Copy `agent-system-prompt.md` → paste vào ô **System Instructions** của conversation.
2. Paste kick-off message trên vào tin nhắn đầu tiên → gửi.
3. Agent tự đọc file, chạy tool, viết report.

Antigravity có sẵn `view_file` (đọc file) và `run_command` (chạy shell) — không cần setup thêm.

## Nếu hết rate / đổi model — Claude API hoặc OpenAI

Cần model hỗ trợ **tool use / function calling** với 2 tool:

| Tool        | Mô tả                                 | Param                |
| ----------- | ------------------------------------- | -------------------- |
| `read_file` | Đọc file theo path                    | `path: str`          |
| `run_shell` | Chạy shell command, trả stdout+stderr | `cmd: str, cwd: str` |

Cách nhanh nhất: dùng Python agent nhỏ với Claude API:

```python
import anthropic, subprocess
from pathlib import Path

client = anthropic.Anthropic()

tools = [
    {
        "name": "read_file",
        "description": "Read a file from the workspace",
        "input_schema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"]
        }
    },
    {
        "name": "run_shell",
        "description": "Run a shell command in the project root",
        "input_schema": {
            "type": "object",
            "properties": {
                "cmd": {"type": "string"},
                "cwd": {"type": "string", "default": "."}
            },
            "required": ["cmd"]
        }
    }
]

SYSTEM = Path("agent-system-prompt.md").read_text()
PROJECT_ROOT = r"c:\VS_Code_Workplace\ATW&CSDL"

def handle_tool(name, inputs):
    if name == "read_file":
        return Path(PROJECT_ROOT, inputs["path"]).read_text(encoding="utf-8", errors="replace")
    if name == "run_shell":
        result = subprocess.run(
            inputs["cmd"], shell=True,
            cwd=inputs.get("cwd", PROJECT_ROOT),
            capture_output=True, text=True, timeout=1800
        )
        return result.stdout + result.stderr

messages = [{"role": "user", "content": "Bắt đầu. ZAP proxy: 192.168.153.130:8080."}]

while True:
    resp = client.messages.create(
        model="claude-opus-4-5",
        max_tokens=8096,
        system=SYSTEM,
        tools=tools,
        messages=messages
    )
    messages.append({"role": "assistant", "content": resp.content})

    if resp.stop_reason == "end_turn":
        print(resp.content[-1].text)
        break

    tool_results = []
    for block in resp.content:
        if block.type == "tool_use":
            output = handle_tool(block.name, block.input)
            tool_results.append({
                "type": "tool_result",
                "tool_use_id": block.id,
                "content": str(output)[:50000]  # hard cap để không overflow context
            })

    messages.append({"role": "user", "content": tool_results})
```

## Claude.ai Project (không có terminal)

Không thể chạy CLI → agent chỉ có thể:

- Đọc file đã upload.
- Generate command cho bạn chạy tay → bạn paste output lại.

Phù hợp nếu bạn muốn **kiểm tra logic agent** mà không cần automation thật.

Setup:

1. Upload toàn bộ `target_info/*`, `zap_reduced.json`, `tools/.tools-descriptions-for-agent.md` vào Project.
2. Paste `agent-system-prompt.md` vào Project Instructions — **bỏ phần Phase 1, 2, 3** (các bước chạy shell), giữ từ Phase 4 trở đi.
3. Gửi: _"Bắt đầu từ Phase 4. zap_reduced.json đã upload."_
