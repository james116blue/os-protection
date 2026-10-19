#!/usr/bin/env python3
"""
Учебная "забытая" debug-служба для лабораторной работы по защите хоста
от сетевых атак.

Имитирует типичную ошибку конфигурации: внутренний диагностический
сервис, который должен быть доступен только с localhost, по ошибке
слушает на всех интерфейсах (0.0.0.0) без какой-либо аутентификации.
Любой, кто может достать до порта, получает служебную информацию.

Порт: 9000
"""

import socketserver

# HOST определяет, на каких сетевых интерфейсах слушает служба:
#   "0.0.0.0"   — на всех интерфейсах (доступно откуда угодно, где есть
#                 маршрут до хоста) — учебная УЯЗВИМАЯ настройка по умолчанию
#   "127.0.0.1" — только на loopback (доступно только процессам на этой
#                 же машине) — целевое состояние после задания 2
HOST = "0.0.0.0"
PORT = 9000
FLAG_PATH = "/root/flags/flag2.txt"


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            with open(FLAG_PATH) as f:
                flag = f.read().strip()
        except Exception:
            flag = "FLAG_NOT_FOUND"

        banner = (
            b"DEBUG STATUS SERVICE v0.1\n"
            b"status: ok\n"
            b"uptime: 1337s\n"
            b"internal-flag: " + flag.encode() + b"\n"
        )
        self.request.sendall(banner)


if __name__ == "__main__":
    with socketserver.TCPServer((HOST, PORT), Handler) as server:
        server.allow_reuse_address = True
        print(f"Debug status service listening on {HOST}:{PORT}")
        server.serve_forever()
