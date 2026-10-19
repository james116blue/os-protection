#!/usr/bin/env python3
"""
Учебное веб-приложение с намеренной уязвимостью command injection.
Только для лаборатории по защите ОС. Не использовать в продакшене.

Эндпоинт /ping принимает параметр host и подставляет его в системную
команду ping без какой-либо проверки — классическая OS command injection.

Запуск напрямую (без Docker):
    python3 vulnerable_app.py

Порт по умолчанию: 8080
"""

import subprocess
import socket
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

PORT = 8080

PAGE = """<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Network Tool</title></head>
<body>
<h2>Простой сетевой инструмент</h2>
<form action="/ping" method="get">
  Host: <input type="text" name="host" value="127.0.0.1">
  <input type="submit" value="Ping">
</form>
<p>Hostname сервера: {hostname}</p>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    def _send(self, body: bytes, status: int = 200, content_type: str = "text/html; charset=utf-8"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == "/":
            body = PAGE.format(hostname=socket.gethostname()).encode("utf-8")
            self._send(body)
            return

        if parsed.path == "/ping":
            qs = parse_qs(parsed.query)
            host = qs.get("host", ["127.0.0.1"])[0]

            # НАМЕРЕННАЯ УЯЗВИМОСТЬ:
            # shell=True + неэкранированная подстановка пользовательского
            # ввода в строку команды. Позволяет инъекцию через ; | && $() и т.д.
            cmd = f"ping -c 1 -W 2 {host}"
            try:
                result = subprocess.run(
                    cmd, shell=True, capture_output=True, text=True, timeout=10
                )
                output = result.stdout + result.stderr
            except Exception as e:
                output = f"Ошибка выполнения: {e}"

            body = f"<pre>{output}</pre><p><a href='/'>Назад</a></p>".encode("utf-8")
            self._send(body)
            return

        self._send(b"Not Found", status=404)

    def log_message(self, format, *args):
        # компактный лог в stdout, чтобы было видно запросы при демонстрации
        print(f"[{self.client_address[0]}] {format % args}")


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", PORT), Handler)
    print(f"Vulnerable app listening on 0.0.0.0:{PORT}")
    server.serve_forever()
