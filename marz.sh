#!/bin/bash

# Get server name from the user
read -p "Enter the server name: " SERVER

# Update the root password and set DNS
echo 'root:sOn3lQ#bS@ls!7&m' | sudo chpasswd && \
  sed -i '16s/^/DNS=8.8.8.8\n/' /etc/systemd/resolved.conf && \
  service systemd-resolved restart && \
  apt update && \
  ufw disable && \
  wget https://github.com/sSsiRMoHaMMaD/backup/blob/main/cache.zip && \
  sudo sed -i 's/#SystemMaxUse=/SystemMaxUse=10M/' /etc/systemd/journald.conf && \
  sudo systemctl restart systemd-journald && \
  sudo echo '
  fs.file-max = 1048576
  fs.inotify.max_user_instances = 1048576
  net.core.rmem_max=16777216
  net.core.wmem_max=16777216
  net.core.netdev_max_backlog=2000
  net.ipv4.tcp_rmem = 8192 262144 536870912
  net.ipv4.tcp_wmem = 4096 16384 536870912
  net.ipv4.tcp_adv_win_scale = -2
  net.ipv4.tcp_collapse_max_bytes = 6291456
  # forward ipv4
  net.ipv4.ip_forward = 1
  net.ipv4.tcp_fastopen = 3
  net.ipv4.tcp_keepalive_time = 90
  net.ipv4.tcp_congestion_control=bbr
  net.core.default_qdisc=cake
  net.ipv6.conf.all.disable_ipv6=1
  net.ipv6.conf.default.disable_ipv6=1
  ' > /etc/sysctl.conf && \
  sudo mkdir /etc/systemd/system.conf.d && \
  sudo echo '[Manager]
  DefaultLimitNOFILE=infinity' > /etc/systemd/system.conf.d/99-unlimited.conf && \
  sudo echo 'session required pam_limits.so' >> /etc/pam.d/common-session && \
  sudo echo 'session required pam_limits.so' >> /etc/pam.d/common-session-noninteractive && \
  sudo echo '*       hard    nofile  unlimited
  *       soft    nofile  unlimited
  *       hard    nproc   unlimited
  *       soft    nproc   unlimited
  root       hard    nofile  unlimited
  root       soft    nofile  unlimited
  root       hard    nproc   unlimited
  root       soft    nproc   unlimited' > /etc/security/limits.conf && \
  sudo echo '*       hard    nofile  unlimited
  *       soft    nofile  unlimited
  *       hard    nproc   unlimited
  *       soft    nproc   unlimited
  root       hard    nofile  unlimited
  root       soft    nofile  unlimited
  root       hard    nproc   unlimited
  root       soft    nproc   unlimited' > /etc/security/limits.d/99-unlimited.conf && \
  wget https://github.com/sSsiRMoHaMMaD/backup/blob/main/marzban.zip && \
  apt install unzip -y && \
  unzip marzban.zip && \
  curl -fsSL https://get.docker.com | sh && \
  cd marzban && \
  sed -i 's/2083/8880/g' xray_config.json && \
  sed -i 's/8880/8888/g' env && \
  sed -i 's/SUDO_USERNAME = "soul"/SUDO_USERNAME = "dopaMine"/g' env && \
  sed -i 's/SUDO_PASSWORD = "M80b81M"/SUDO_PASSWORD = "80MinE84"/g' env && \
  docker compose up -d && \
  cd /var/lib/marzban/ && \
  rm -rf db.sqlite3 && \
  wget https://github.com/sSsiRMoHaMMaD/backup/blob/main/$SERVER/db.sqlite3 && \
  wget https://github.com/sSsiRMoHaMMaD/backup/blob/main/$SERVER/certs.zip && \
  unzip certs.zip && \
  cd && \
  cd marzban/ && \
  docker compose down && \
  rm -rf xray_config.json && \
  wget https://github.com/sSsiRMoHaMMaD/backup/blob/main/$SERVER/xray_config.json && \
  docker compose up -d && \
  reboot
