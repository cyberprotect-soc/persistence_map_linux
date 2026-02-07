#!/bin/bash

# Linux Forensic Investigation Tool
# Автономная версия

# Конфигурация
source_dir="/tmp/forensic_$(date +%Y%m%d_%H%M%S)"
output_arc="$source_dir.zip"
filter="" # Опциональный фильтр для grep

# Пароль для архива - задается вручную
ARCHIVE_PASSWORD="PASSWORD"

# Период для journalctl (последние 7 дней)
days_back=7
since_date=$(date -d "$days_back days ago" +"%Y-%m-%d 00:00:00")
until_date=$(date +"%Y-%m-%d 23:59:59")

# Создание файла с информацией об инциденте
create_incident_info() {
    local incident_file="$source_dir/incident_info.txt"
    
    echo "=== ИНФОРМАЦИЯ ОБ ИНЦИДЕНТЕ ===" > "$incident_file"
    echo "Дата и время инцидента: $(date '+%Y-%m-%d %H:%M:%S')" >> "$incident_file"
    echo "Получен с: SIEM-OFFICE" >> "$incident_file"
    echo "Система: $(hostname)" >> "$incident_file"
    echo "Период сбора данных: $since_date - $until_date" >> "$incident_file"
    echo "Пользователь, выполнивший сбор: $(whoami)" >> "$incident_file"
    echo "IP адрес системы: $(hostname -I 2>/dev/null || ip addr show | grep -oP 'inet \K[\d.]+' | grep -v '127.0.0.1' | head -1)" >> "$incident_file"
    echo "Пароль для архива: $ARCHIVE_PASSWORD" >> "$incident_file"
    echo "" >> "$incident_file"
    echo "=== СВОДКА СИСТЕМЫ ===" >> "$incident_file"
    echo "ОС: $(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '\"')" >> "$incident_file"
    echo "Ядро: $(uname -r)" >> "$incident_file"
    echo "Время работы: $(uptime -p 2>/dev/null || uptime)" >> "$incident_file"
    echo "Количество пользователей: $(who | wc -l)" >> "$incident_file"
}

# Создание директорий
create_directories() {
    local dirs=(
        "$source_dir/cron"
        "$source_dir/authorization_logs"
        "$source_dir/bash_hist"
        "$source_dir/user_info"
        "$source_dir/packets_installed_info/dpkg"
        "$source_dir/packets_installed_info/apt"
        "$source_dir/general_logs/messages_logs"
        "$source_dir/general_logs/syslog_logs"
        "$source_dir/general_logs/audit"
        "$source_dir/network/ssh_configs"
        "$source_dir/network/firewall_logs"
        "$source_dir/network/xrdp_logs"
        "$source_dir/SystemInfo"
        "$source_dir/Persistence Linux"
    )
    
    for dir in "${dirs[@]}"; do
        mkdir -p "$dir"
    done
}

# Создание карты персистентности
create_persistence_map() {
    echo "Создание карты персистентности..."
    
    local map_file="$source_dir/Карта персистентности Linux/persistence_map.txt"
    
    cat > "$map_file" << 'EOF'
# Linux Persistence Map v0.2

## Pepe Berba | pberba.github.io

| systemd-generators    |
|---|
| Executes the following:    |
| /etc/systemd/system-generators/*    |
| /usr/local/lib/systemd/system-generators/*    |
| /lib/systemd/system-generators/*    |
| Generates services files from:    |
| /etc/init.d/*    |
| /etc/rc.local    |
| _MITRE: T1037, T1547, T1037.004_

---

### Atsirishhicron (Cron Scheduler)

**Defined in**:  
/lib/systemd/system/cron.service  

**Searches for cron jobs in**:  
/etc/crontab  
/var/spool/cron/crontabs/*  
/etc/cron.d  

**NetCrerenda runs jobs for anacron**:  
/etc/cron.hourly/*  
/etc/cron.daily/*  
/etc/cron.weekly/*  
/etc/cron.monthly/*  

**MITRE: T1053.003**

---

### modi

**/etc/update-motd.d/***

**MITRE: T1037**

---

### labinfinit [PID 1] (System systemd)**

**/etc/systemd/system.conf**

All paths in "systemd-analyze unit-paths":  
/lib/systemd/system/*  
/etc/systemd/system/*  

---

### systemd timers  
**MITRE: T1053.006**

---

### systemd services  
**MITRE: T1545.002**

---

### Atsirishinisshd (SSH Daemon)

**Defined in**:  
/lib/systemd/system/ssh.service  

**Configured in**:  
/etc/ssh/sshd_config  

**Runs**:  
~/.ssh/rc, /etc/ssh/sshrc  

---

### User Accounts

**Use rinfo**:  
/etc/gshadow /etc/sudoers  
/etc/passwd /etc/sudoers.d/  
/etc/groups  

**Authentication info**:  
/etc/shadow  
~/.ssh/authorized.keys  

**MITRE: T1156.001, T1078, T1098.004, T1098**

---

### web server (web shells)

**/var/www/html/{bad.php}**  
/etc/bginx/  
/etc/apachez/  

**MITRE: T1505.003**

---

### systemd-user (User systemd)

**/etc/systemd/user.conf**

All paths in "systemd-analyze unit-paths --user":  
/lib/systemd/user/*  
/etc/systemd/user/*  

---

### user systemd-generators

**Executes the following:**  
/etc/systemd/user-generators/*  
/usr/local/lib/systemd/user-generators/*  
/usr/lib/systemd/user-generators/*  

**MITRE: T1037**

---

### rootkits

**User Mode Rootkits**:  
/etc/ld.so.preload  

**Kernel Mode Rootkits**:  
/lib/modules/  

**Look for usage of:**  
modprobe, insmod, lsmod, rmmod  

**MITRE: T1547.006, T1574.006**

---

### infected client software

**OS and User Binaries**:  
/bin, /sbin, /usr/bin/, /lib, ...  

**Example Python and unattended-upgrades**:  
/usr/lib/python3*  
/usr/lib/python3*/dist-packages  
/usr/share/unattended-upgrades/  
unattended-upgrade-shutdown  

**MITRE: T1554**

---

### hinhhash (Login Shell)

**/etc/hash.bashrc**  
~/.bashrc  

**/etc/profile /etc/profile.d/***  
~/.profile  
~/.bash_profile  
~/.bash_login  

**/etc/hash.hash_logout**  
~/.bash_logout  

**MITRE: T1546.004**

---

**Note: Strictly, the plan, sysfend module is what hundreds user systemd and registers the session to sysfend-loginal but this interaction is not captured by this map to make it less messy.**
EOF

    # Копирование карты персистентности в виде изображения (если есть)
    local image_sources=(
        "/tmp/persistence_map.png"
        "/home/*/persistence_map.png"
        "/root/persistence_map.png"
        "./persistence_map.png"
    )
    
    for img_source in "${image_sources[@]}"; do
        if ls $img_source 1> /dev/null 2>&1; then
            cp $img_source "$source_dir/Карта персистентности Linux/" 2>/dev/null && break
        fi
    done
}

# Сбор логов для карты персистентности
collect_persistence_logs() {
    echo "Сбор логов для карты персистентности..."
    
    local persistence_dir="$source_dir/Persistence Linux"
    
    # systemd generators
    echo "=== SYSTEMD GENERATORS ===" > "$persistence_dir/systemd_generators.txt"
    find /etc/systemd/system-generators /usr/local/lib/systemd/system-generators /lib/systemd/system-generators -type f 2>/dev/null >> "$persistence_dir/systemd_generators.txt"
    
    # Cron jobs
    echo "=== CRON JOBS ===" > "$persistence_dir/cron_jobs.txt"
    find /etc/cron* /var/spool/cron -type f 2>/dev/null >> "$persistence_dir/cron_jobs.txt"
    [ -f "/etc/crontab" ] && cat "/etc/crontab" >> "$persistence_dir/cron_jobs.txt"
    
    # SSH authorized keys
    echo "=== SSH AUTHORIZED KEYS ===" > "$persistence_dir/ssh_authorized_keys.txt"
    for home_dir in /home/* /root; do
        if [ -d "$home_dir" ] && [ -f "$home_dir/.ssh/authorized_keys" ]; then
            user=$(basename "$home_dir")
            echo "=== User: $user ===" >> "$persistence_dir/ssh_authorized_keys.txt"
            cat "$home_dir/.ssh/authorized_keys" >> "$persistence_dir/ssh_authorized_keys.txt" 2>/dev/null
            echo "" >> "$persistence_dir/ssh_authorized_keys.txt"
        fi
    done
    
    # Bash profiles
    echo "=== BASH PROFILES ===" > "$persistence_dir/bash_profiles.txt"
    [ -f "/etc/bash.bashrc" ] && echo "=== /etc/bash.bashrc ===" >> "$persistence_dir/bash_profiles.txt" && cat "/etc/bash.bashrc" >> "$persistence_dir/bash_profiles.txt"
    [ -f "/etc/profile" ] && echo "=== /etc/profile ===" >> "$persistence_dir/bash_profiles.txt" && cat "/etc/profile" >> "$persistence_dir/bash_profiles.txt"
    
    # Web directories
    echo "=== WEB DIRECTORIES ===" > "$persistence_dir/web_directories.txt"
    [ -d "/var/www/html" ] && find /var/www/html -type f -name "*.php" -o -name "*.jsp" -o -name "*.asp" 2>/dev/null >> "$persistence_dir/web_directories.txt"
    
    # Kernel modules
    echo "=== KERNEL MODULES ===" > "$persistence_dir/kernel_modules.txt"
    lsmod 2>/dev/null >> "$persistence_dir/kernel_modules.txt"
    
    # LD_PRELOAD
    echo "=== LD_PRELOAD ===" > "$persistence_dir/ld_preload.txt"
    [ -f "/etc/ld.so.preload" ] && cat "/etc/ld.so.preload" >> "$persistence_dir/ld_preload.txt"
    
    # Systemd services
    echo "=== SYSTEMD SERVICES ===" > "$persistence_dir/systemd_services.txt"
    systemctl list-unit-files --type=service 2>/dev/null >> "$persistence_dir/systemd_services.txt"
    
    # Systemd timers
    echo "=== SYSTEMD TIMERS ===" > "$persistence_dir/systemd_timers.txt"
    systemctl list-timers --all 2>/dev/null >> "$persistence_dir/systemd_timers.txt"
}

# Логирование ошибок
setup_logging() {
    exec 2> "$source_dir/errors.log"
    echo "Forensic collection started: $(date)" > "$source_dir/collection_info.txt"
    echo "Period: $since_date - $until_date" >> "$source_dir/collection_info.txt"
    echo "Hostname: $(hostname)" >> "$source_dir/collection_info.txt"
}

# Сбор информации о пакетах
collect_package_info() {
    echo "Сбор информации о пакетах..."
    
    # Dpkg логи
    if [ -f "/var/log/dpkg.log" ]; then
        if [ -n "$filter" ]; then
            grep "$filter" "/var/log/dpkg.log" > "$source_dir/packets_installed_info/dpkg/dpkg_filtered.log"
        else
            cp "/var/log/dpkg.log" "$source_dir/packets_installed_info/dpkg/"
            find "/var/log/" -type f -name "dpkg.log*" -exec cp {} "$source_dir/packets_installed_info/dpkg/" \;
        fi
    fi
    
    # APT логи
    if [ -f "/var/log/apt/history.log" ]; then
        if [ -n "$filter" ]; then
            grep "$filter" "/var/log/apt/history.log" > "$source_dir/packets_installed_info/apt/apt_history_filtered.log"
        else
            find "/var/log/apt/" -type f -name "history.log*" -exec cp {} "$source_dir/packets_installed_info/apt/" \;
        fi
    fi
    
    # Список установленных пакетов
    dpkg -l > "$source_dir/packets_installed_info/installed_packages.txt" 2>/dev/null || true
    snap list > "$source_dir/packets_installed_info/snap_packages.txt" 2>/dev/null || true
    which rpm >/dev/null 2>&1 && rpm -qa > "$source_dir/packets_installed_info/rpm_packages.txt" 2>/dev/null || true
}

# Сбор системных логов
collect_system_logs() {
    echo "Сбор системных логов..."
    
    # Syslog
    if [ -f "/var/log/syslog" ]; then
        if [ -n "$filter" ]; then
            grep "$filter" "/var/log/syslog" > "$source_dir/general_logs/syslog_logs/syslog_filtered.log"
        else
            find "/var/log/" -type f -name "syslog*" -exec cp {} "$source_dir/general_logs/syslog_logs/" \;
        fi
    fi
    
    # Messages
    if [ -f "/var/log/messages" ]; then
        if [ -n "$filter" ]; then
            grep "$filter" "/var/log/messages" > "$source_dir/general_logs/messages_logs/messages_filtered.log"
        else
            find "/var/log/" -type f -name "messages*" -exec cp {} "$source_dir/general_logs/messages_logs/" \;
        fi
    fi
    
    # Journalctl
    if [ -n "$filter" ]; then
        journalctl -S "$since_date" -U "$until_date" -o short-iso | grep "$filter" > "$source_dir/general_logs/systemd_journal_filtered.log" 2>/dev/null || true
    else
        journalctl -S "$since_date" -U "$until_date" -o short-iso > "$source_dir/general_logs/systemd_journal.log" 2>/dev/null || true
    fi
    
    # Audit logs
    if [ -d "/var/log/audit" ]; then
        if [ -n "$filter" ]; then
            find "/var/log/audit" -type f -name "*audit*" -exec grep -l "$filter" {} \; | head -10 > "$source_dir/general_logs/audit/audit_files_with_matches.txt"
            find "/var/log/audit" -type f -name "*audit*" -exec grep "$filter" {} \; > "$source_dir/general_logs/audit/filtered_audit.log" 2>/dev/null || true
        else
            find "/var/log/audit" -type f -name "*audit*" -exec cp {} "$source_dir/general_logs/audit/" \; 2>/dev/null || true
        fi
    fi
}

# Сбор логов аутентификации
collect_auth_logs() {
    echo "Сбор логов аутентификации..."
    
    # Auth.log
    if [ -f "/var/log/auth.log" ]; then
        if [ -n "$filter" ]; then
            grep "$filter" "/var/log/auth.log" > "$source_dir/authorization_logs/auth_filtered.log"
        else
            cp "/var/log/auth.log" "$source_dir/authorization_logs/" 2>/dev/null || true
            find "/var/log/" -type f -name "auth.log*" -exec cp {} "$source_dir/authorization_logs/" \; 2>/dev/null || true
        fi
    fi
    
    # Secure log (для RHEL-based систем)
    if [ -f "/var/log/secure" ]; then
        cp "/var/log/secure" "$source_dir/authorization_logs/" 2>/dev/null || true
    fi
    
    # Информация о входах
    w > "$source_dir/authorization_logs/current_users.txt" 2>/dev/null || true
    last > "$source_dir/authorization_logs/last_logins.txt" 2>/dev/null || true
    lastlog > "$source_dir/authorization_logs/lastlog.txt" 2>/dev/null || true
    
    # Бинарные логи (если доступны утилиты)
    which utmpdump >/dev/null 2>&1 && {
        [ -f "/var/log/wtmp" ] && utmpdump "/var/log/wtmp" > "$source_dir/authorization_logs/wtmp_parsed.txt" 2>/dev/null || true
        [ -f "/var/run/utmp" ] && utmpdump "/var/run/utmp" > "$source_dir/authorization_logs/utmp_parsed.txt" 2>/dev/null || true
        [ -f "/var/log/btmp" ] && utmpdump "/var/log/btmp" > "$source_dir/authorization_logs/btmp_parsed.txt" 2>/dev/null || true
    }
}

# Сбор информации о пользователях
collect_user_info() {
    echo "Сбор информации о пользователях..."
    
    cp "/etc/passwd" "$source_dir/user_info/" 2>/dev/null || true
    cp "/etc/group" "$source_dir/user_info/" 2>/dev/null || true
    cp "/etc/sudoers" "$source_dir/user_info/sudoers.txt" 2>/dev/null || true
    [ -f "/etc/shadow" ] && sudo cp "/etc/shadow" "$source_dir/user_info/shadow.txt" 2>/dev/null || true
    
    # Информация о домашних директориях
    ls -la "/home/" > "$source_dir/user_info/home_directory_listing.txt" 2>/dev/null || true
    
    # Детальная информация о пользователях
    local output_users="$source_dir/user_info/users_detailed.txt"
    
    for username in $(cut -d: -f1 /etc/passwd 2>/dev/null); do
        echo "=== User: $username ===" >> "$output_users"
        echo "UID: $(id -u "$username" 2>/dev/null)" >> "$output_users"
        echo "GID: $(id -g "$username" 2>/dev/null)" >> "$output_users"
        echo "Groups: $(groups "$username" 2>/dev/null)" >> "$output_users"
        echo "Home: $(getent passwd "$username" 2>/dev/null | cut -d: -f6)" >> "$output_users"
        echo "Shell: $(getent passwd "$username" 2>/dev/null | cut -d: -f7)" >> "$output_users"
        echo "Last login: $(lastlog -u "$username" 2>/dev/null | tail -1)" >> "$output_users"
        echo "Password info:" >> "$output_users"
        chage -l "$username" 2>/dev/null >> "$output_users" || echo "Cannot retrieve password info" >> "$output_users"
        echo -e "\n" >> "$output_users"
    done
}

# Сбор истории bash
collect_bash_history() {
    echo "Сбор истории команд..."
    
    # Функция конвертации времени
    convert_time() {
        date -d @"$1" +"%Y-%m-%d %H:%M:%S" 2>/dev/null || echo "Invalid timestamp: $1"
    }
    
    # История для домашних директорий
    for home_dir in /home/*; do
        if [ -d "$home_dir" ] && [ -f "$home_dir/.bash_history" ]; then
            local user=$(basename "$home_dir")
            local user_bash_file="$source_dir/bash_hist/${user}_bash_history.txt"
            
            echo "=== Bash history for user: $user ===" > "$user_bash_file"
            echo "Home directory: $home_dir" >> "$user_bash_file"
            echo "Collection time: $(date)" >> "$user_bash_file"
            echo "=====================================" >> "$user_bash_file"
            
            while IFS= read -r line; do
                if [[ "$line" == \#* ]]; then
                    timestamp=$(echo "$line" | cut -d'#' -f2)
                    echo "[$(convert_time "$timestamp")]" >> "$user_bash_file"
                else
                    echo "$line" >> "$user_bash_file"
                fi
            done < "$home_dir/.bash_history"
            echo -e "\n" >> "$user_bash_file"
        fi
    done
    
    # История root
    if [ -f "/root/.bash_history" ]; then
        local root_bash_file="$source_dir/bash_hist/root_bash_history.txt"
        echo "=== Bash history for root ===" > "$root_bash_file"
        echo "Collection time: $(date)" >> "$root_bash_file"
        echo "=============================" >> "$root_bash_file"
        
        while IFS= read -r line; do
            if [[ "$line" == \#* ]]; then
                timestamp=$(echo "$line" | cut -d'#' -f2)
                echo "[$(convert_time "$timestamp")]" >> "$root_bash_file"
            else
                echo "$line" >> "$root_bash_file"
            fi
        done < "/root/.bash_history"
    fi
    
    # Настройки bash
    [ -f "/etc/bash.bashrc" ] && cp "/etc/bash.bashrc" "$source_dir/bash_hist/" 2>/dev/null || true
    [ -f "/etc/profile" ] && cp "/etc/profile" "$source_dir/bash_hist/" 2>/dev/null || true
    
    # Сырая история (без обработки временных меток)
    for home_dir in /home/*; do
        if [ -d "$home_dir" ] && [ -f "$home_dir/.bash_history" ]; then
            local user=$(basename "$home_dir")
            cp "$home_dir/.bash_history" "$source_dir/bash_hist/${user}_bash_history_raw.txt" 2>/dev/null || true
        fi
    done
    [ -f "/root/.bash_history" ] && sudo cp "/root/.bash_history" "$source_dir/bash_hist/root_bash_history_raw.txt" 2>/dev/null || true
}

# Сбор сетевой информации
collect_network_info() {
    echo "Сбор сетевой информации..."
    
    # Конфигурация SSH
    [ -f "/etc/ssh/ssh_config" ] && cp "/etc/ssh/ssh_config" "$source_dir/network/ssh_configs/" 2>/dev/null || true
    [ -f "/etc/ssh/sshd_config" ] && cp "/etc/ssh/sshd_config" "$source_dir/network/ssh_configs/" 2>/dev/null || true
    
    # Сетевая статистика
    netstat -tuln > "$source_dir/network/netstat_listening.txt" 2>/dev/null || true
    netstat -ano > "$source_dir/network/netstat_all.txt" 2>/dev/null || true
    ss -tuln > "$source_dir/network/ss_listening.txt" 2>/dev/null || true
    ip addr > "$source_dir/network/ip_addr.txt" 2>/dev/null || true
    ip route > "$source_dir/network/ip_route.txt" 2>/dev/null || true
    
    # Firewall
    if which ufw >/dev/null 2>&1; then
        ufw status verbose > "$source_dir/network/ufw_status.txt" 2>/dev/null || true
        [ -f "/var/log/ufw.log" ] && cp "/var/log/ufw.log" "$source_dir/network/firewall_logs/" 2>/dev/null || true
    fi
    
    if which iptables >/dev/null 2>&1; then
        iptables -L -n -v > "$source_dir/network/iptables_rules.txt" 2>/dev/null || true
        iptables -t nat -L -n -v > "$source_dir/network/iptables_nat.txt" 2>/dev/null || true
    fi
    
    if which firewall-cmd >/dev/null 2>&1; then
        firewall-cmd --list-all > "$source_dir/network/firewalld_status.txt" 2>/dev/null || true
    fi
    
    # XRDP логи
    if [ -f "/var/log/xrdp.log" ]; then
        if [ -n "$filter" ]; then
            grep "$filter" "/var/log/xrdp.log" > "$source_dir/network/xrdp_logs/xrdp_filtered.log" 2>/dev/null || true
        else
            find "/var/log/" -type f -name "xrdp*" -exec cp {} "$source_dir/network/xrdp_logs/" \; 2>/dev/null || true
        fi
    fi
    
    # Сетевые соединения
    lsof -i > "$source_dir/network/network_connections.txt" 2>/dev/null || true
}

# Сбор информации о системе
collect_system_info() {
    echo "Сбор системной информации..."
    
    # Информация об ОС
    cat /etc/os-release > "$source_dir/SystemInfo/os_info.txt" 2>/dev/null || true
    uname -a > "$source_dir/SystemInfo/kernel_info.txt"
    hostnamectl > "$source_dir/SystemInfo/hostname_info.txt" 2>/dev/null || true
    
    # Аппаратная информация
    lscpu > "$source_dir/SystemInfo/cpu_info.txt" 2>/dev/null || true
    free -h > "$source_dir/SystemInfo/memory_info.txt" 2>/dev/null || true
    lsblk > "$source_dir/SystemInfo/disk_info.txt" 2>/dev/null || true
    df -h > "$source_dir/SystemInfo/disk_usage.txt" 2>/dev/null || true
    
    # Сервисы и процессы
    systemctl list-unit-files --type=service > "$source_dir/SystemInfo/services.txt" 2>/dev/null || true
    ps aux > "$source_dir/SystemInfo/processes.txt" 2>/dev/null || true
    pstree -aglpu > "$source_dir/SystemInfo/process_tree.txt" 2>/dev/null || true
    
    # Время работы системы
    uptime > "$source_dir/SystemInfo/uptime.txt" 2>/dev/null || true
    
    # Cron задачи
    cp "/etc/crontab" "$source_dir/cron/" 2>/dev/null || true
    [ -f "/etc/anacrontab" ] && cp "/etc/anacrontab" "$source_dir/cron/" 2>/dev/null || true
    crontab -l > "$source_dir/cron/current_user_crontab.txt" 2>/dev/null || true
    
    # Логи cron
    find "/var/log/" -type f -name "cron*" -exec cp {} "$source_dir/cron/" \; 2>/dev/null || true
    
    # Информация о загрузке
    who -b > "$source_dir/SystemInfo/system_boot_time.txt" 2>/dev/null || true
}

# Создание запароленного zip архива
create_encrypted_archive() {
    echo "Создание запароленного zip архива..."
    echo "Используется пароль: $ARCHIVE_PASSWORD"
    
    # Переход в директорию с данными
    cd "/tmp" || exit 1
    
    # Создание запароленного zip архива
    if which zip >/dev/null 2>&1; then
        zip -qr -P "$ARCHIVE_PASSWORD" "$output_arc" "$(basename "$source_dir")"
    else
        echo "ОШИБКА: zip не установлен. Установите его: apt-get install zip"
        exit 1
    fi
    
    echo "Запароленный архив создан: $output_arc"
    echo "Размер архива: $(du -sh "$output_arc" | cut -f1)" >> "$source_dir/collection_info.txt"
}

# Основная функция
main() {
    echo "=== Linux Forensic Collection Tool ==="
    echo "Начало сбора данных: $(date)"
    echo "Пароль архива: $ARCHIVE_PASSWORD"
    echo ""
    
    # Проверка наличия zip
    if ! which zip >/dev/null 2>&1; then
        echo "ОШИБКА: zip не установлен"
        echo "Установите его: sudo apt-get install zip"
        exit 1
    fi
    
    # Проверка прав
    if [ "$EUID" -ne 0 ]; then
        echo "ВНИМАНИЕ: Рекомендуется запускать с правами root для доступа ко всем логам"
        echo "Некоторые файлы могут быть недоступны для чтения"
    fi
    
    create_directories
    setup_logging
    create_incident_info
    create_persistence_map
    collect_persistence_logs
    
    # Сбор данных
    collect_package_info
    collect_system_logs
    collect_auth_logs
    collect_user_info
    collect_bash_history
    collect_network_info
    collect_system_info
    
    create_encrypted_archive
    
    echo "=== ОТЧЕТ О СОБРАННЫХ ДАННЫХ ==="
    echo "Основной файл с информацией: $source_dir/incident_info.txt"
    echo "Карта персистентности: $source_dir/Карта персистентности Linux/persistence_map.txt"
    echo "Запароленный архив: $output_arc"
    echo "Пароль архива: $ARCHIVE_PASSWORD"
    echo "Размер архива: $(du -sh "$output_arc" | cut -f1)"
    echo ""
    echo "Содержимое архива:"
    unzip -l "$output_arc" -P "$ARCHIVE_PASSWORD" | head -20
    echo "..."
    echo ""
    echo "Сбор данных завершен: $(date)"
    
    # Предупреждение о очистке
    echo ""
    echo "ВНИМАНИЕ: Временные файлы находятся в $source_dir"
    echo "Для очистки выполните: rm -rf $source_dir"
    echo ""
    echo "Архив $output_arc можно открыть в WinRAR или 7-Zip с паролем: $ARCHIVE_PASSWORD"

    # ЗАПУСК ДОПОЛНИТЕЛЬНОГО СКРИПТА s.sh ПОСЛЕ ВСЕХ ДЕЙСТВИЙ
    # ========== FORENSIC_MAIL ==========
    echo ""
    echo "=== FORENSIC EMAIL SENDER ==="
    
    # Автоматически используем созданный архив
    ARCHIVE_PATH="$output_arc"
    
    # Проверка telnet
    if ! which telnet >/dev/null 2>&1; then
        echo "❌ telnet не установлен, пропускаем отправку email"
        echo "Установите: sudo apt-get install telnet"
        exit 0
    fi
    
    # Проверка base64
    if ! which base64 >/dev/null 2>&1; then
        echo "⚠️  base64 не доступен, вложение не будет работать"
    fi
    
    # Проверка архива
    echo "Архив: $ARCHIVE_PATH"
    if file "$ARCHIVE_PATH" | grep -q "Zip archive"; then
        echo "✅ Формат: ZIP архив"
    else
        echo "⚠️  Внимание: Архив может быть поврежден"
    fi
    
    echo "Размер: $(du -sh "$ARCHIVE_PATH" | cut -f1)"
    echo "Пароль: $ARCHIVE_PASSWORD"
    echo ""
    
    # Автоматически отправляем email
    echo "Автоматическая отправка email..."
    
    # Функция кодирования архива в base64
    encode_archive() {
        if which base64 >/dev/null 2>&1; then
            base64 -w 76 "$ARCHIVE_PATH"
        else
            echo "❌ base64 не доступен"
            return 1
        fi
    }
    
    # Функция отправки email с вложением через telnet
    send_forensic_email() {
        echo ""
        echo "=== ОТПРАВКА FORENSIC ОТЧЕТА ==="
        echo "Архив: $(basename "$ARCHIVE_PATH")"
        echo "Размер: $(du -sh "$ARCHIVE_PATH" | cut -f1)"
        echo "SMTP сервер: $SMTP_SERVER:$SMTP_PORT"
        echo "От: $EMAIL_FROM"
        echo "Кому: $EMAIL_TO"
        echo ""
        
        # Создание временного файла с email
        local email_file="/tmp/email_attachment_$$.txt"
        
        # Формирование email с MIME вложением
        cat > "$email_file" << EOF
From: $EMAIL_FROM
To: $EMAIL_TO
Subject: Forensic Report - $(hostname) - $(date +%Y-%m-%d)
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUNDARY123"

--BOUNDARY123
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: base64

$(echo "🔍 ФОРЕНЗИК-ОТЧЕТ ДЛЯ ОТДЕЛА ИБ
====================================

🚨 ОБНАРУЖЕН ИНЦИДЕНТ БЕЗОПАСНОСТИ
Система: $(hostname)
Время сбора доказательств: $(date)
Период анализа: последние $days_back дней

📊 КЛЮЧЕВЫЕ ПОКАЗАТЕЛИ СИСТЕМЫ
• IP адрес: $(hostname -I 2>/dev/null | head -1)
• Время работы: $(uptime -p 2>/dev/null || uptime)
• Активные пользователи: $(who | wc -l)
• Запущенные процессы: $(ps aux | wc -l)
• Сетевые соединения: $(netstat -tun 2>/dev/null | grep ESTABLISHED | wc -l)

📁 ДЕТАЛИ АРХИВА С ДОКАЗАТЕЛЬСТВАМИ
• Архив: $(basename "$ARCHIVE_PATH")
• Размер: $(du -sh "$ARCHIVE_PATH" | cut -f1)


🕵️‍♂️ СОБРАННЫЕ КАТЕГОРИИ ДАННЫХ
─────────────────────────────────

🔐 SECURITY-ЛОГИ
  ✓ Логи аутентификации и авторизации
  ✓ Попытки входа (успешные/неудачные)
  ✓ SSH сессии и подключения
  ✓ Sudo команды и эскалация привилегий
  ✓ Auditd события (если включен)

💻 СИСТЕМНАЯ ИНФОРМАЦИЯ
  ✓ Системные логи (syslog, messages)
  ✓ Запущенные сервисы и демоны
  ✓ Cron задачи и автоматизация
  ✓ Информация о ядре и ОС
  ✓ Аппаратные характеристики

🌐 СЕТЕВАЯ АКТИВНОСТЬ
  ✓ Сетевые интерфейсы и конфигурация
  ✓ Активные соединения и порты
  ✓ Правила firewall и iptables
  ✓ DNS и routing таблицы
  ✓ SSH конфигурации

👥 ДАННЫЕ ПОЛЬЗОВАТЕЛЕЙ
  ✓ История команд ВСЕХ пользователей
  ✓ Учетные записи и группы
  ✓ Sudoers правила и привилегии
  ✓ Домашние директории
  ✓ Сессии и активность

🔗 МЕХАНИЗМЫ ПЕРСИСТЕНТНОСТИ
  ✓ Systemd сервисы и таймеры
  ✓ Автозагрузка (.bashrc, profile)
  ✓ SSH авторизованные ключи
  ✓ Kernel модули и драйверы
  ✓ Cron задачи пользователей

📦 ПРОГРАММНОЕ ОБЕСПЕЧЕНИЕ
  ✓ Установленные пакеты (dpkg/apt)
  ✓ История установки и обновлений
  ✓ Snap пакеты (если есть)
  ✓ Версии критического ПО

🎯 ПРИОРИТЕТНЫЕ ОБЛАСТИ ДЛЯ АНАЛИЗА
───────────────────────────────────

1. 🚨 ИСТОРИЯ КОМАНД (/bash_hist/)
   - Поиск подозрительных утилит
   - Скачивание и выполнение скриптов
   - Манипуляции с правами доступа

2. 🚨 ЛОГИ АУТЕНТИФИКАЦИИ (/authorization_logs/)
   - Неудачные попытки входа
   - Подозрительные IP адреса
   - Внеурочная активность

3. 🚨 АВТОЗАГРУЗКА (/Persistence Linux/)
   - Неизвестные сервисы systemd
   - Подозрительные cron задачи
   - Модификации .bashrc и profile

4. 🚨 СЕТЕВЫЕ СОЕДИНЕНИЯ (/network/)
   - Необычные исходящие соединения
   - Скрытые listening порты
   - Изменения firewall правил

⚠️  ИНСТРУКЦИИ ПО РАБОТЕ С АРХИВОМ
─────────────────────────────────

1. 📎 Архив прикреплен к письму
2. 🔓 Используйте пароль полученный ранее 
3. 🛠️ Откройте в WinRAR или 7-Zip
4. 📊 Начните анализ с папки /bash_hist/
5. ⏱️ Обратите внимание на временные метки

💡 РЕКОМЕНДАЦИИ ПО АНАЛИЗУ
• Сравните временные линии разных логов
• Проверьте команды, выполненные от root
• Ищите аномальную активность в нерабочее время
• Проверьте наличие известных IOC

📞 ДОПОЛНИТЕЛЬНАЯ ИНФОРМАЦИЯ
• Версия ядра: $(uname -r)

─────────────────────────────────────
Automated Forensic Collection Tool v2.0
Generated: $(date +%Y-%m-%d_%H:%M:%S)
======================================" | base64 -w 76)

--BOUNDARY123
Content-Type: application/zip; name="$(basename "$ARCHIVE_PATH")"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="$(basename "$ARCHIVE_PATH")"

EOF
        # Добавление архива в base64
        echo "Кодирование архива в base64..."
        if encode_archive >> "$email_file"; then
            echo "✅ Архив закодирован"
        else
            echo "❌ Ошибка кодирования архива"
            rm -f "$email_file"
            return 1
        fi

        # Завершение MIME
        echo "" >> "$email_file"
        echo "--BOUNDARY123--" >> "$email_file"

        echo "Отправка email с вложением..."
        local telnet_output="/tmp/email_send_$$.txt"
        
        # Отправка через telnet
        (
            sleep 2
            echo "HELO $(hostname)"
            sleep 1
            echo "MAIL FROM: <$EMAIL_FROM>"
            sleep 1
            echo "RCPT TO: <$EMAIL_TO>"
            sleep 1
            echo "DATA"
            sleep 1
            cat "$email_file"
            echo "."
            sleep 1
            echo "QUIT"
        ) | telnet "$SMTP_SERVER" "$SMTP_PORT" > "$telnet_output" 2>&1
        
        # Проверка результата
        if grep -q "250" "$telnet_output"; then
            echo "✅ Email с вложением успешно отправлен!"
            echo "Получатель: $EMAIL_TO"
            echo "Вложение: $(basename "$ARCHIVE_PATH")"
        else
            echo "❌ Ошибка отправки email"
            echo "Детали:"
            grep -E "5[0-9][0-9]|4[0-9][0-9]" "$telnet_output" | head -5
        fi
        
        # Очистка
        rm -f "$email_file" "$telnet_output"
    }
    
    # Настройки SMTP (добавьте свои значения)
    SMTP_SERVER=""
    SMTP_PORT="25"
    EMAIL_FROM=""
    EMAIL_TO=""
    
    # Если настройки SMTP заполнены, отправляем email
    if [ -n "$SMTP_SERVER" ] && [ -n "$EMAIL_FROM" ] && [ -n "$EMAIL_TO" ]; then
        send_forensic_email
    else
        echo "⚠️  Настройки SMTP не заполнены, пропускаем отправку email"
        echo "Заполните переменные SMTP_SERVER, EMAIL_FROM, EMAIL_TO в скрипте"
    fi


}

# Запуск скрипта
main "$@"

