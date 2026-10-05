"""
Fair local-model Mode-B test: call Ollama CORRECTLY (raised num_ctx, top-level
system, format=json) on the small vulnerable fixture and measure whether a 7B
CPU model can produce a well-structured finding in reasonable time.

This bypasses vulnhuntr's broken Ollama client to isolate the real question:
can the local model do the reasoning, if the integration is correct?
"""
import json
import time
import urllib.request

MODEL = "qwen2.5-coder:7b"
URL = "http://127.0.0.1:11434/api/generate"

with open(r"D:\Ramansh\proof-modeB\vuln_app\app.py", "r", encoding="utf-8") as fh:
    code = fh.read()

system = (
    "You are a security code auditor. Analyze the given Python file for "
    "remotely exploitable vulnerabilities. Respond ONLY with JSON matching: "
    '{"findings":[{"vuln_class":str,"function":str,"line_hint":str,'
    '"severity":"low|medium|high|critical","why":str,'
    '"poc_request":str}]}. If none, return {"findings":[]}.'
)
prompt = f"Audit this file:\n\n```python\n{code}\n```"

payload = {
    "model": MODEL,
    "prompt": prompt,
    "system": system,            # top-level, as Ollama expects
    "format": "json",            # native JSON mode
    "stream": False,
    "options": {
        "temperature": 0.1,
        "num_ctx": 8192,         # fits the whole file + instructions
    },
}

req = urllib.request.Request(
    URL, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}
)

t0 = time.time()
with urllib.request.urlopen(req, timeout=1800) as resp:
    data = json.loads(resp.read())
elapsed = time.time() - t0

raw = data.get("response", "")
in_tok = data.get("prompt_eval_count")
out_tok = data.get("eval_count")
out_ns = data.get("eval_duration") or 1

print(f"=== TIMING ===")
print(f"wall_seconds: {elapsed:.1f}")
print(f"input_tokens: {in_tok}  output_tokens: {out_tok}")
print(f"gen_tokens_per_sec: {out_tok / (out_ns/1e9):.2f}" if out_tok else "n/a")
print(f"\n=== JSON VALID? ===")
try:
    parsed = json.loads(raw)
    print("YES - parsed cleanly")
    print(f"findings_count: {len(parsed.get('findings', []))}")
    classes = [f.get("vuln_class", "?") for f in parsed.get("findings", [])]
    print(f"vuln_classes: {classes}")
    print(f"\n=== FINDINGS ===")
    print(json.dumps(parsed, indent=2)[:3000])
except Exception as e:
    print(f"NO - {e}")
    print(f"\n=== RAW (first 2000 chars) ===")
    print(raw[:2000])
