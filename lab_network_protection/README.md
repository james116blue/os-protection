# Материалы лабораторной «Защита хоста от сетевых атак»

Каталог содержит скрипт подготовки учебного стенда и файлы уязвимых приложений
для лабораторной работы занятия 3.

```
scripts/lab_network_protection_setup.sh — разворачивает стенд и выдаёт метку LAB_TOKEN
app/vulnerable_app.py                   — уязвимое приложение (command injection), задание 3
app/debug_status_service.py             — «забытая» debug-служба на порту 9000, задание 2
```

Само задание: [лабораторная_3.md](../занятие%203%20защита%20сети%2020.10.2026/лабораторная/лабораторная_3.md).

Скрипты скачиваются на виртуальную машину командами из раздела 0.1 задания:

```bash
BASE=https://raw.githubusercontent.com/james116blue/os-protection/2026_fall/lab_network_protection
wget -O scripts/lab_network_protection_setup.sh "$BASE/scripts/lab_network_protection_setup.sh"
wget -O app/vulnerable_app.py                   "$BASE/app/vulnerable_app.py"
wget -O app/debug_status_service.py             "$BASE/app/debug_status_service.py"
```
