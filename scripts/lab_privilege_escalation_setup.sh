#!/usr/bin/env bash
#
# lab_privilege_escalation_setup.sh — развёртывание учебного окружения для лабораторной работы
# по эскалации привилегий и защите Linux (SUID, PATH, sudoers, cron,
# symlink-атаки, systemd).
#
# ВНИМАНИЕ: скрипт НАМЕРЕННО создаёт небезопасные конфигурации.
# Запускать только на чистой, только что установленной ВМ Debian 13,
# не содержащей важных данных и, желательно, изолированной от сети.
#
# Использование:
#   sudo ./lab_privilege_escalation_setup.sh <student_id>
#
# <student_id> — любой идентификатор студента (ФИО, логин, номер группы).
# Используется только для генерации уникальной метки LAB_TOKEN,
# которая должна быть видна на каждом скриншоте в отчёте.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Запустите скрипт от имени root: sudo $0 <student_id>" >&2
  exit 1
fi

STUDENT_ID="${1:-}"
if [[ -z "$STUDENT_ID" ]]; then
  echo "Использование: sudo $0 <student_id>" >&2
  exit 1
fi

MARKER=/etc/lab-provisioned
if [[ -f "$MARKER" ]]; then
  echo "Окружение уже развёрнуто (найден $MARKER)."
  echo "Чтобы пересоздать его с нуля — удалите $MARKER и запустите скрипт заново"
  echo "(часть заданий к этому моменту может быть уже 'исправлена', поэтому"
  echo "чистое пересоздание имеет смысл только на свежей ВМ)."
  exit 0
fi

echo "[*] Предварительные проверки..."
if id -u hacker >/dev/null 2>&1; then
  cat >&2 <<'EOF'
ОШИБКА: пользователь 'hacker' уже существует в системе.

Этот скрипт рассчитан на чистую, только что установленную ВМ Debian 13,
где учётной записи 'hacker' ещё нет. Повторное использование уже
существующей записи небезопасно для лабораторной работы:

  - её пароль не будет приведён к ожидаемому ('hacker'), поэтому шаги
    лабораторной работы (su - hacker) могут не сработать;
  - её shell/домашний каталог могут не соответствовать ожиданиям скрипта
    (например, nologin вместо bash, отсутствующий $HOME);
  - её текущие членства в группах (например, sudo) исказят задание 3
    (hacker получит заведомо более широкие права, чем задумано).

Варианты:
  1) Запустить скрипт на чистой ВМ (рекомендуется).
  2) Если вы точно знаете, что эта запись создана предыдущим прогоном
     этого же скрипта и её можно удалить:
       userdel -r hacker
     и запустить скрипт заново.
EOF
  exit 1
fi

echo "[*] Обновление пакетов и установка зависимостей..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq build-essential sudo cron python3 coreutils util-linux >/dev/null

echo "[*] Создание учебного пользователя 'hacker' (роль «нарушителя»)..."
useradd -m -s /bin/bash hacker
echo "hacker:hacker" | chpasswd
echo "    Создан пользователь hacker / пароль hacker. Рекомендуется сменить пароль."

echo "[*] Генерация уникальной метки лабораторной работы (анти-плагиат)..."
TOKEN=$(printf '%s' "${STUDENT_ID}-$(hostname)-$(date +%s%N)-${RANDOM}${RANDOM}" | sha256sum | cut -c1-16)
echo "$TOKEN" > /etc/lab-token
chmod 644 /etc/lab-token

cat > /etc/profile.d/99-lab-token.sh <<EOF
export LAB_TOKEN="$TOKEN"
export LAB_STUDENT="$STUDENT_ID"
if [ -n "\${PS1:-}" ]; then
  PS1="[LAB:$TOKEN]\$PS1"
fi
EOF
chmod 644 /etc/profile.d/99-lab-token.sh

cat >> /etc/motd <<EOF

====================================================================
 Учебная лаборатория «Защита ОС». Студент: $STUDENT_ID
 Метка лабораторной работы (LAB_TOKEN): $TOKEN
 Эта метка должна быть видна на КАЖДОМ скриншоте в отчёте.
====================================================================
EOF

echo "[*] Создание контрольных флагов для каждого задания..."
mkdir -p /root/flags
for i in 1 2 3 4 5 6; do
  echo "FLAG-${i}: $TOKEN" > /root/flags/flag${i}.txt
done
chmod 600 /root/flags/*.txt
chown root:root /root/flags/*.txt

# ---------------------------------------------------------------------
# Задание 1: опасный SUID-бит на интерпретаторе python3
# ---------------------------------------------------------------------
echo "[*] [1/6] Установка SUID на python3..."
PYTHON_BIN=$(readlink -f "$(command -v python3)")
chmod u+s "$PYTHON_BIN"

# ---------------------------------------------------------------------
# Задание 2: SUID-бинарь, вызывающий команду без полного пути ($PATH)
# ---------------------------------------------------------------------
echo "[*] [2/6] Сборка уязвимого SUID-бинаря sysinfo (PATH hijacking)..."
mkdir -p /opt/lab-suid-path
cat > /opt/lab-suid-path/sysinfo.c <<'EOF'
#include <stdlib.h>
#include <stdio.h>

int main(void) {
    printf("Сбор информации о системе...\n");
    /* УЯЗВИМОСТЬ: команда вызывается без полного пути, поиск идёт по $PATH */
    system("id");
    return 0;
}
EOF
gcc -o /usr/local/bin/sysinfo /opt/lab-suid-path/sysinfo.c
chown root:root /usr/local/bin/sysinfo
chmod 4755 /usr/local/bin/sysinfo

# ---------------------------------------------------------------------
# Задание 3: опасная запись в sudoers
# ---------------------------------------------------------------------
echo "[*] [3/6] Добавление опасной записи в sudoers..."
cat > /etc/sudoers.d/90-lab <<'EOF'
hacker ALL=(root) NOPASSWD: /usr/bin/less
EOF
chmod 440 /etc/sudoers.d/90-lab
visudo -c -f /etc/sudoers.d/90-lab >/dev/null

# ---------------------------------------------------------------------
# Задание 4: root-cron, запускающий скрипт из каталога с правами записи
#            для непривилегированного пользователя
# ---------------------------------------------------------------------
echo "[*] [4/6] Настройка root-cron с каталогом, доступным для записи всем..."
mkdir -p /opt/lab-cron
cat > /opt/lab-cron/healthcheck.sh <<'EOF'
#!/bin/bash
# Учебный скрипт "проверки состояния системы", запускается от root по cron.
date >> /var/log/lab-healthcheck.log
EOF
chown root:root /opt/lab-cron/healthcheck.sh
chmod 755 /opt/lab-cron/healthcheck.sh
chmod 777 /opt/lab-cron   # преднамеренная ошибка конфигурации
touch /var/log/lab-healthcheck.log
chmod 666 /var/log/lab-healthcheck.log
echo "* * * * * root /opt/lab-cron/healthcheck.sh" > /etc/cron.d/lab-healthcheck
chmod 644 /etc/cron.d/lab-healthcheck

# ---------------------------------------------------------------------
# Задание 5: привилегированный "читатель" файлов, не проверяющий symlink
# ---------------------------------------------------------------------
echo "[*] [5/6] Настройка привилегированного обработчика заявок (symlink)..."
mkdir -p /var/lab/intake /var/lab/public
chown hacker:hacker /var/lab/intake
chmod 755 /var/lab/intake
chmod 755 /var/lab/public
echo "тестовая заявка" > /var/lab/intake/submission.txt
chown hacker:hacker /var/lab/intake/submission.txt

cat > /opt/lab-cron/collector.sh <<'EOF'
#!/bin/bash
# Учебный скрипт "обработки заявок", запускается от root по cron.
# УЯЗВИМОСТЬ: не проверяет, что submission.txt - обычный файл, а не symlink.
SRC="/var/lab/intake/submission.txt"
OUT="/var/lab/public/last_report.txt"
cat "$SRC" > "$OUT"
chmod 644 "$OUT"
EOF
chown root:root /opt/lab-cron/collector.sh
chmod 755 /opt/lab-cron/collector.sh
touch /var/log/lab-collector-errors.log
chmod 666 /var/log/lab-collector-errors.log
echo "* * * * * root /opt/lab-cron/collector.sh" > /etc/cron.d/lab-collector
chmod 644 /etc/cron.d/lab-collector

# ---------------------------------------------------------------------
# Задание 6: systemd-сервис со слабыми правами на исполняемый файл
# ---------------------------------------------------------------------
echo "[*] [6/6] Настройка systemd-сервиса со слабыми правами..."
mkdir -p /opt/lab-systemd
cat > /opt/lab-systemd/worker.sh <<'EOF'
#!/bin/bash
# Учебный "фоновый обработчик", запускается от root через systemd.
date >> /var/log/lab-worker.log
EOF
chown root:root /opt/lab-systemd/worker.sh
chmod 777 /opt/lab-systemd/worker.sh   # преднамеренная ошибка конфигурации
touch /var/log/lab-worker.log
chmod 666 /var/log/lab-worker.log

cat > /etc/systemd/system/lab-worker.service <<'EOF'
[Unit]
Description=Lab worker service (учебный, НАМЕРЕННО НЕБЕЗОПАСНЫЙ)

[Service]
Type=oneshot
ExecStart=/opt/lab-systemd/worker.sh
EOF

cat > /etc/systemd/system/lab-worker.timer <<'EOF'
[Unit]
Description=Запускает lab-worker.service каждую минуту

[Timer]
OnBootSec=30
OnUnitActiveSec=60

[Install]
WantedBy=timers.target
EOF
chmod 644 /etc/systemd/system/lab-worker.service /etc/systemd/system/lab-worker.timer

systemctl daemon-reload
systemctl enable --now cron >/dev/null
systemctl enable --now lab-worker.timer >/dev/null

touch "$MARKER"

echo
echo "====================================================================="
echo " Учебное окружение развёрнуто."
echo " Метка лабораторной работы (LAB_TOKEN): $TOKEN"
echo " Учебный пользователь-«нарушитель»: hacker / hacker"
echo
echo " Откройте новый терминал (или выполните: exec bash -l), чтобы"
echo " увидеть метку [LAB:$TOKEN] в приглашении — она должна быть видна"
echo " на каждом скриншоте в отчёте."
echo "====================================================================="
