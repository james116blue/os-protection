#!/bin/bash
#
# lab_network_protection_setup.sh
# Готовит Debian 13 как намеренно уязвимый стенд для лабораторной работы
# «Защита хостинговой системы от сетевых атак» (SSH / сеть / Docker).
#
# Использование:
#   sudo ./lab_network_protection_setup.sh "Ivanov_I_I"
#
# Запускать ТОЛЬКО на чистой учебной VM, изолированной от боевых систем.

set -euo pipefail

if [ "$EUID" -ne 0 ]; then
    echo "Запустите с sudo/от root." >&2
    exit 1
fi

STUDENT_ID="${1:-unknown_student}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== [0/6] Генерация метки лабораторной работы (анти-плагиат) ==="

RANDOM_PART=$(openssl rand -hex 4)
RAW="${STUDENT_ID}|$(hostname)|$(date +%s)|${RANDOM_PART}"
LAB_TOKEN=$(echo -n "$RAW" | sha256sum | cut -c1-16)

echo "$LAB_TOKEN" > /etc/lab-token
chmod 644 /etc/lab-token

cat > /etc/profile.d/99-lab-token.sh <<EOF
# Метка лабораторной работы — встраивается в приглашение терминала
export LAB_TOKEN="$LAB_TOKEN"
if [ -n "\${PS1:-}" ]; then
    PS1="[LAB:\$LAB_TOKEN] \$PS1"
fi
EOF
chmod 644 /etc/profile.d/99-lab-token.sh

if ! grep -q "LAB_TOKEN" /etc/motd 2>/dev/null; then
    { echo ""; echo "Метка лабораторной работы: [LAB:$LAB_TOKEN]"; echo "Студент: $STUDENT_ID"; } >> /etc/motd
fi

echo "LAB_TOKEN = $LAB_TOKEN"
echo "Откройте новый терминал (или выполните: exec bash -l), чтобы метка появилась в приглашении."

echo "=== [1/6] Флаги ==="

mkdir -p /root/flags
chmod 700 /root/flags

for i in 1 2 3 4; do
    f="/root/flags/flag${i}.txt"
    if [ ! -f "$f" ]; then
        echo "FLAG{net_lab_${i}_$(openssl rand -hex 6)}" > "$f"
    fi
    chmod 600 "$f"
done
chown -R root:root /root/flags

echo "=== [2/6] Пользователь hacker ==="

if ! id -u hacker >/dev/null 2>&1; then
    useradd -m -s /bin/bash hacker
fi
echo "hacker:hacker" | chpasswd

echo "=== [3/6] Небезопасная настройка SSH ==="

SSHD_CONFIG="/etc/ssh/sshd_config"
cp -n "$SSHD_CONFIG" "${SSHD_CONFIG}.orig.bak" || true

sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' "$SSHD_CONFIG"
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' "$SSHD_CONFIG"
sed -i 's/^#\?MaxAuthTries.*/MaxAuthTries 100/' "$SSHD_CONFIG"
grep -q '^PermitRootLogin' "$SSHD_CONFIG" || echo "PermitRootLogin yes" >> "$SSHD_CONFIG"
grep -q '^PasswordAuthentication' "$SSHD_CONFIG" || echo "PasswordAuthentication yes" >> "$SSHD_CONFIG"
grep -q '^MaxAuthTries' "$SSHD_CONFIG" || echo "MaxAuthTries 100" >> "$SSHD_CONFIG"

echo "root:toor123" | chpasswd
systemctl restart sshd
echo "SSH: root/toor123, PermitRootLogin yes, PasswordAuthentication yes"

echo "=== [4/6] Забытая debug-служба (порт 9000, слушает на всех интерфейсах) ==="

mkdir -p /opt/lab-net
cp "$SCRIPT_DIR/../app/debug_status_service.py" /opt/lab-net/ 2>/dev/null || \
    echo "ВНИМАНИЕ: не найден app/debug_status_service.py рядом со скриптом." >&2

cat > /etc/systemd/system/lab-debug.service <<'EOF'
[Unit]
Description=Lab debug status service (INTENTIONALLY insecure)
After=network.target

[Service]
ExecStart=/usr/bin/python3 /opt/lab-net/debug_status_service.py
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now lab-debug.service
echo "Debug-служба поднята на 0.0.0.0:9000"

echo "=== [5/6] Установка Docker и уязвимого приложения ==="

if ! command -v docker >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -y -qq docker.io
    systemctl enable --now docker
fi

APP_DIR="/opt/vulnerable_app"
mkdir -p "$APP_DIR"
cp "$SCRIPT_DIR/../app/vulnerable_app.py" "$APP_DIR/" 2>/dev/null || \
    echo "ВНИМАНИЕ: не найден app/vulnerable_app.py рядом со скриптом." >&2

docker rm -f vuln_app >/dev/null 2>&1 || true

# НАМЕРЕННО ПЛОХАЯ КОНФИГУРАЦИЯ (цель задания 3):
#   --privileged   — контейнер получает почти все возможности хоста
#   -v /:/hostfs   — весь хост примонтирован внутрь контейнера
docker run -d \
    --name vuln_app \
    --privileged \
    -v /:/hostfs \
    -p 8080:8080 \
    -v "$APP_DIR":/app \
    -w /app \
    python:3-slim \
    python3 vulnerable_app.py

echo "Уязвимое приложение поднято на порту 8080 (контейнер privileged, /hostfs = корень хоста)"

echo "=== [6/6] Стандартные сетевые инструменты (nmap, hydra, netcat) ==="

apt-get update -qq
apt-get install -y -qq nmap hydra netcat-traditional curl

# Небольшой учебный словарь для hydra — toor123 внутри намеренно
WORDLIST=/home/hacker/wordlist.txt
cat > "$WORDLIST" <<'WORDS'
123456
password
toor
toor123
root
qwerty
admin
letmein
WORDS
chown hacker:hacker "$WORDLIST"

echo
echo "=================================================================="
echo " Готово. LAB_TOKEN: $LAB_TOKEN"
echo " Студент: $STUDENT_ID"
echo "=================================================================="
echo " Уязвимое исходное состояние:"
echo "  - SSH: root/toor123, вход по паролю разрешён, без лимита попыток"
echo "  - Debug-служба на 0.0.0.0:9000 отдаёт flag2 без авторизации"
echo "  - Docker-контейнер privileged + /hostfs = корень хоста, в нём"
echo "    веб-приложение с command injection (flag3 через host mount)"
echo "  - Пользователь hacker:hacker создан, словарь в ~/wordlist.txt"
echo "=================================================================="
