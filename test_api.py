import urllib.request
import json

url = "http://localhost:8000/api/analyze"
data = {"url": "https://music.youtube.com"}

req = urllib.request.Request(
    url, 
    data=json.dumps(data).encode("utf-8"), 
    headers={"Content-Type": "application/json"},
    method="POST"
)

try:
    with urllib.request.urlopen(req) as response:
        resp_data = response.read().decode("utf-8")
        print(json.dumps(json.loads(resp_data), indent=2))
except Exception as e:
    print(f"Error: {e}")
