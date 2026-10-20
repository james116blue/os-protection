# Материалы лабораторной «Защита хоста от сетевых атак»

Каталог содержит скрипт подготовки учебного стенда и файлы уязвимых приложений
для лабораторной работы занятия 3.

```
scripts/lab_network_protection_setup.sh — разворачивает стенд под выбранное задание и выдаёт метку LAB_TOKEN
app/vulnerable_app.py                   — уязвимое приложение (command injection), задание 3
app/debug_status_service.py             — «забытая» debug-служба на порту 9000, задание 4
```

Само задание: [лабораторная_3.md](../занятие%203%20защита%20сети%2020.10.2026/лабораторная/лабораторная_3.md).

Скрипты скачиваются на виртуальную машину командами из раздела 0.2 задания:

```bash
BASE=https://raw.githubusercontent.com/james116blue/os-protection/2026_fall/lab_network_protection
wget -O scripts/lab_network_protection_setup.sh "$BASE/scripts/lab_network_protection_setup.sh"
wget -O app/vulnerable_app.py                   "$BASE/app/vulnerable_app.py"
wget -O app/debug_status_service.py             "$BASE/app/debug_status_service.py"
```

Запуск — с указанием задания, под которое готовится стенд:

```bash
chmod +x scripts/lab_network_protection_setup.sh

sudo ./scripts/lab_network_protection_setup.sh "Ivanov_I_I" ssh       # задание 1: SSH
sudo ./scripts/lab_network_protection_setup.sh "Ivanov_I_I" fail2ban  # задание 2: fail2ban
sudo ./scripts/lab_network_protection_setup.sh "Ivanov_I_I" docker    # задание 3: Docker
sudo ./scripts/lab_network_protection_setup.sh "Ivanov_I_I" firewall  # задание 4: nftables
sudo ./scripts/lab_network_protection_setup.sh "Ivanov_I_I" all       # полный стенд
```

Скрипт устанавливает только то, что нужно выбранному заданию: вариант `firewall`
не ставит Docker, вариант `docker` не поднимает debug-службу на 9000. Повторный
запуск с другим заданием доустанавливает недостающее, метка `LAB_TOKEN` при этом
не меняется.
