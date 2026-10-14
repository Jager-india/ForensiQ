import http.server
import json


class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        content_len = int(self.headers.get("Content-Length", 0))
        self.rfile.read(content_len)

        payload = {
            "text": "Hello, let us review the vendor procurement status. We verified the 25,000 deposit yesterday. Make sure the kickback is arranged before Friday. Keep this conversation completely off the record. Please confirm the payment clearance once completed.",
            "segments": [
                {
                    "start": 15.0,
                    "end": 28.0,
                    "text": "Speaker 1: Hello, let us review the vendor procurement status.",
                },
                {
                    "start": 75.0,
                    "end": 88.0,
                    "text": "Speaker 2: We verified the 25,000 deposit yesterday.",
                },
                {
                    "start": 210.0,
                    "end": 222.0,
                    "text": "Speaker 1: Make sure the kickback is arranged before Friday.",
                },
                {
                    "start": 229.0,
                    "end": 242.0,
                    "text": "Speaker 2: Keep this conversation completely off the record.",
                },
                {
                    "start": 285.0,
                    "end": 298.0,
                    "text": "Speaker 1: Please confirm the payment clearance once completed.",
                },
            ],
        }

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode("utf-8"))


http.server.HTTPServer(("127.0.0.1", 8434), Handler).serve_forever()
