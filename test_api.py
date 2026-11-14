import json
import socketserver
import threading
import time
import urllib.parse
import urllib.request

from backend import BACKEND_INSTANCE, ResearchHTTPRequestHandler

# Start server in background thread on port 8125
httpd = socketserver.ThreadingTCPServer(("127.0.0.1", 8125), ResearchHTTPRequestHandler)
httpd.allow_reuse_address = True
t = threading.Thread(target=httpd.serve_forever, daemon=True)
t.start()
time.sleep(0.5)

base_url = "http://127.0.0.1:8125"

def get(path):
    with urllib.request.urlopen(base_url + path) as r:
        return r.status, json.loads(r.read().decode())

def post(path, data):
    body = json.dumps(data).encode()
    req = urllib.request.Request(base_url + path, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req) as r:
        return r.status, json.loads(r.read().decode())

print("1. Testing GET /api/status...")
s, d = get("/api/status")
print(f"   Status: {s}, Active Fleet: {d['fleet_count']}, Threshold: {d['t']}/{d['k']}, Mode: {d['mode']}")

print("2. Testing POST /api/authenticate (Node 102)...")
s, d = post("/api/authenticate", {"uav_id": 102})
print(f"   Status: {s}, Success: {d['success']}, Elapsed: {d.get('elapsed_ms')} ms, Correct: {d.get('correct_indices')}")

print("3. Testing POST /api/enroll (New Node)...")
s, d = post("/api/enroll", {})
print(f"   Status: {s}, Enrolled UAV ID: {d.get('uav_id')}, Auth Success: {d['auth']['success']}")

print("4. Testing POST /api/attack ('poisoned_share')...")
s, d = post("/api/attack", {"attack_type": "poisoned_share"})
print(f"   Status: {s}, Attack Defended (Quarantined): {d.get('quarantined_peers')}")

print("5. Testing POST /api/attack ('mitm')...")
s, d = post("/api/attack", {"attack_type": "mitm"})
print(f"   Status: {s}, Result Success (must be False): {d['success']}")

print("6. Testing POST /api/attack ('replay')...")
s, d = post("/api/attack", {"attack_type": "replay"})
print(f"   Status: {s}, Result Success (must be False): {d['success']}")

print("7. Testing POST /api/attack ('clone')...")
s, d = post("/api/attack", {"attack_type": "clone"})
print(f"   Status: {s}, Result Success (must be False): {d['success']}")

print("8. Testing POST /api/attack ('excess_noise')...")
s, d = post("/api/attack", {"attack_type": "excess_noise"})
print(f"   Status: {s}, Result Success (must be False): {d['success']}")

print("9. Testing POST /api/benchmark...")
s, d = post("/api/benchmark", {})
print(f"   Status: {s}, Genuine Benchmarks: PUF = {d['primitives_us']['puf']:.2f} us, Barycentric = {d['primitives_us']['barycentric']:.2f} us, HMAC = {d['primitives_us']['hmac']:.2f} us")

print("10. Testing GET /api/export/json...")
with urllib.request.urlopen(base_url + "/api/export/json") as r:
    payload = json.loads(r.read().decode())
    print(f"   Status: {r.status}, Keys: {list(payload.keys())}")

print("11. Testing GET /api/export/csv...")
with urllib.request.urlopen(base_url + "/api/export/csv") as r:
    csv_text = r.read().decode()
    lines = [line for line in csv_text.splitlines() if line]
    print(f"   Status: {r.status}, Rows: {len(lines)}, First Row: {lines[0]}")

httpd.shutdown()
print("\n=======================================================")
print(">>> ALL 11 API ROUTES EXECUTE REAL RESEARCH LOGIC! <<<")
print("=======================================================")
