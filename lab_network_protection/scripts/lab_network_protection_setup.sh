#!/bin/bash
#
# lab_network_protection_setup.sh
# Готовит Debian 13 как намеренно уязвимый стенд для лабораторной работы
# «Защита хостинговой системы от сетевых атак» (SSH / fail2ban / Docker / nftables).
#
# Использование:
#   sudo ./lab_network_protection_setup.sh "Ivanov_I_I" <задание>
#
#   <задание> — одно из:
#     ssh       — задание 1: слабый sshd, root/toor123, flag1, hydra
#     fail2ban  — задание 2: снова включает вход по паролю (fail2ban ставится вручную)
#     docker    — задание 3: docker.io + уязвимый контейнер, flag3
#     firewall  — задание 4: debug-служба на 0.0.0.0:9000, flag2 (Docker НЕ ставится)
#     all       — всё сразу (значение по умолчанию)
#
# Запускать ТОЛЬКО на чистой учебной VM, изолированной от боевых систем.

set -euo pipefail

if [ "$EUID" -ne 0 ]; then
    echo "Запустите с sudo/от root." >&2
    exit 1
fi

STUDENT_ID="${1:-unknown_student}"
TASK="${2:-all}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_SRC="$SCRIPT_DIR/../app"

case "$TASK" in
    ssh|fail2ban|docker|firewall|all) ;;
    *)
        echo "Неизвестное задание: '$TASK'." >&2
        echo "Допустимо: ssh | fail2ban | docker | firewall | all" >&2
        exit 1
        ;;
esac

echo "=== [0] Генерация метки лабораторной работы (анти-плагиат) ==="

RANDOM_PART=$(openssl rand -hex 4)
RAW="${STUDENT_ID}|$(hostname)|$(date +%s)|${RANDOM_PART}"
LAB_TOKEN=$(echo -n "$RAW" | sha256sum | cut -c1-16)

# Метка не перегенерируется при повторном запуске скрипта под другое задание:
# у студента должна быть одна и та же метка на все задания.
if [ -s /etc/lab-token ]; then
    LAB_TOKEN=$(cat /etc/lab-token)
    echo "Используется существующая метка из /etc/lab-token."
else
    echo "$LAB_TOKEN" > /etc/lab-token
fi
chmod 644 /etc/lab-token

cat > /etc/profile.d/99-lab-token.sh <<EOF
# Метка лабораторной работы — встраивается в приглашение терминала
export LAB_TOKEN="$LAB_TOKEN"
if [ -n "\${PS1:-}" ]; then
    PS1="[LAB:\$LAB_TOKEN] \$PS1"
fi
EOF
chmod 644 /etc/profile.d/99-lab-token.sh

if ! grep -q "Метка лабораторной работы" /etc/motd 2>/dev/null; then
    { echo ""; echo "Метка лабораторной работы: [LAB:$LAB_TOKEN]"; echo "Студент: $STUDENT_ID"; } >> /etc/motd
fi

echo "LAB_TOKEN = $LAB_TOKEN"
echo "Откройте новый терминал (или выполните: exec bash -l), чтобы метка появилась в приглашении."

echo "=== [1] Базовый стенд: флаги, пользователь hacker, словарь ==="

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

if ! id -u hacker >/dev/null 2>&1; then
    useradd -m -s /bin/bash hacker
fi
echo "hacker:hacker" | chpasswd

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

apt-get update -qq
apt-get install -y -qq curl wget >/dev/null

# --- Общая функция: привести sshd в уязвимое состояние ---------------------
configure_vulnerable_sshd() {
    local sshd_config="/etc/ssh/sshd_config"
    cp -n "$sshd_config" "${sshd_config}.orig.bak" || true

    sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' "$sshd_config"
    sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' "$sshd_config"
    sed -i 's/^#\?MaxAuthTries.*/MaxAuthTries 100/' "$sshd_config"
    grep -q '^PermitRootLogin' "$sshd_config" || echo "PermitRootLogin yes" >> "$sshd_config"
    grep -q '^PasswordAuthentication' "$sshd_config" || echo "PasswordAuthentication yes" >> "$sshd_config"
    grep -q '^MaxAuthTries' "$sshd_config" || echo "MaxAuthTries 100" >> "$sshd_config"

    echo "root:toor123" | chpasswd
    systemctl restart sshd
}

# --- Задание 1: SSH --------------------------------------------------------
setup_ssh() {
    echo "=== [2] Задание 1 (SSH): слабая конфигурация sshd ==="
    configure_vulnerable_sshd
    apt-get install -y -qq hydra nmap >/dev/null
    echo "SSH: root/toor123, PermitRootLogin yes, PasswordAuthentication yes, MaxAuthTries 100"
    echo "Готово для задания 1. Docker и debug-служба на 9000 не устанавливались."
}

# --- Задание 2: fail2ban ---------------------------------------------------
setup_fail2ban() {
    echo "=== [2] Задание 2 (fail2ban): сценарий «пароль отключить нельзя» ==="
    local sshd_config="/etc/ssh/sshd_config"
    cp -n "$sshd_config" "${sshd_config}.orig.bak" || true

    sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' "$sshd_config"
    sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' "$sshd_config"
    grep -q '^PermitRootLogin' "$sshd_config" || echo "PermitRootLogin yes" >> "$sshd_config"
    grep -q '^PasswordAuthentication' "$sshd_config" || echo "PasswordAuthentication yes" >> "$sshd_config"

    echo "root:toor123" | chpasswd
    systemctl restart sshd
    apt-get install -y -qq hydra nmap >/dev/null

    echo "Вход по паролю и вход root по SSH включены, root:toor123."
    echo "MaxAuthTries намеренно НЕ меняется: даже при малом значении hydra продолжает"
    echo "перебор, переподключаясь заново, — это и есть разница с fail2ban."
    echo "Сам fail2ban студент устанавливает вручную в шаге 2 задания."
}

# --- Задание 3: Docker -----------------------------------------------------
setup_docker() {
    echo "=== [2] Задание 3 (Docker): уязвимый контейнер ==="
    if ! command -v docker >/dev/null 2>&1; then
        apt-get install -y -qq docker.io >/dev/null
        systemctl enable --now docker
    fi

    local app_dir="/opt/vulnerable_app"
    mkdir -p "$app_dir"
    if [ -f "$APP_SRC/vulnerable_app.py" ]; then
        cp "$APP_SRC/vulnerable_app.py" "$app_dir/"
    else
        echo "ВНИМАНИЕ: не найден app/vulnerable_app.py рядом со скриптом." >&2
    fi

    docker rm -f vuln_app >/dev/null 2>&1 || true

    # НАМЕРЕННО ПЛОХАЯ КОНФИГУРАЦИЯ (цель задания 3):
    #   --privileged   — контейнер получает почти все возможности хоста
    #   -v /:/hostfs   — весь хост примонтирован внутрь контейнера
    docker run -d \
        --name vuln_app \
        --privileged \
        -v /:/hostfs \
        -p 8080:8080 \
        -v "$app_dir":/app \
        -w /app \
        python:3-slim \
        python3 vulnerable_app.py

    echo "Уязвимое приложение поднято на порту 8080 (контейнер privileged, /hostfs = корень хоста)"
    echo "Готово для задания 3. Debug-служба на 9000 не устанавливалась."
}

# --- Задание 4: firewall / debug-служба ------------------------------------
setup_firewall() {
    echo "=== [2] Задание 4 (firewall): забытая debug-служба на 0.0.0.0:9000 ==="
    mkdir -p /opt/lab-net
    if [ -f "$APP_SRC/debug_status_service.py" ]; then
        cp "$APP_SRC/debug_status_service.py" /opt/lab-net/
    else
        echo "ВНИМАНИЕ: не найден app/debug_status_service.py рядом со скриптом." >&2
    fi

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
    apt-get install -y -qq nmap netcat-traditional >/dev/null

    echo "Debug-служба поднята на 0.0.0.0:9000"
    echo "Готово для задания 4. Docker НЕ устанавливался — для этого задания он не нужен."
}

case "$TASK" in
    ssh)      setup_ssh ;;
    fail2ban) setup_fail2ban ;;
    docker)   setup_docker ;;
    firewall) setup_firewall ;;
    all)
        setup_ssh
        setup_fail2ban
        setup_docker
        setup_firewall
        ;;
esac

echo
echo "=================================================================="
echo " Готово. Задание: $TASK"
echo " LAB_TOKEN: $LAB_TOKEN"
echo " Студент: $STUDENT_ID"
echo "=================================================================="
case "$TASK" in
    ssh)
        echo " Уязвимое состояние: SSH root/toor123, вход по паролю, MaxAuthTries 100"
        echo " Пользователь hacker:hacker, словарь в ~/wordlist.txt"
        ;;
    fail2ban)
        echo " Сценарий: вход по паролю включён (PasswordAuthentication yes)"
        echo " fail2ban ставится и настраивается вручную в шаге 2 задания 2"
        ;;
    docker)
        echo " Docker-контейнер vuln_app: privileged + /hostfs = корень хоста,"
        echo " веб-приложение с command injection (flag3 через host mount)"
        ;;
    firewall)
        echo " Debug-служба на 0.0.0.0:9000 отдаёт flag2 без авторизации"
        echo " Docker не установлен"
        ;;
    all)
        echo " Полный стенд: SSH root/toor123 · debug-служба 0.0.0.0:9000 ·"
        echo " Docker-контейнер privileged + /hostfs · пользователь hacker:hacker"
        ;;
esac
echo "=================================================================="
