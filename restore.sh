#!/bin/bash

# Get server name from the user
read -p "Enter the server name: " SERVER

# Update the root password and set DNS
echo 'root:sOn3lQ#bS@ls!7&m' | sudo chpasswd && \
  ufw disable && \
  sed -i '16s/^/DNS=1.1.1.1 8.8.8.8\n/' /etc/systemd/resolved.conf && \
  echo 'nameserver 1.1.1.1
  nameserver 8.8.8.8' > /etc/resolv.conf
  service systemd-resolved restart && \
  apt update && \
  wget https://github.com/sSsiRMoHaMMaD/backup/archive/refs/heads/main.zip && \
  unzip main.zip && \
  mv /root/backup-main /root/backup && \
  sudo sed -i 's/#SystemMaxUse=/SystemMaxUse=10M/' /etc/systemd/journald.conf && \
  sudo systemctl restart systemd-journald && \
  sudo echo '
  fs.file-max = 51200
  fs.inotify.max_user_instances = 1048576
  net.core.rmem_max = 67108864
  net.core.wmem_max = 67108864
  net.core.netdev_max_backlog = 250000
  net.ipv4.tcp_adv_win_scale = -2
  net.ipv4.tcp_collapse_max_bytes = 6291456
  net.core.somaxconn = 4096
  net.ipv4.tcp_syncookies = 1
  net.ipv4.tcp_tw_reuse = 1
  net.ipv4.tcp_tw_recycle = 0
  net.ipv4.tcp_fin_timeout = 30
  net.ipv4.tcp_keepalive_time = 1200
  net.ipv4.ip_local_port_range = 10000 65000
  net.ipv4.tcp_max_syn_backlog = 8192
  net.ipv4.tcp_max_tw_buckets = 5000
  net.ipv4.tcp_fastopen = 3
  net.ipv4.tcp_mem = 25600 51200 102400
  net.ipv4.tcp_rmem = 4096 87380 67108864
  net.ipv4.tcp_wmem = 4096 65536 67108864
  net.ipv4.tcp_mtu_probing = 1
  net.ipv4.tcp_congestion_control=bbr
  net.core.default_qdisc=cake
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
  apt install unzip -y && \
  unzip /root/backup/marzban.zip -d /root/ && \
  curl -fsSL https://get.docker.com | sh && \
  cd marzban && \
  sed -i 's/2083/8880/g' xray_config.json && \
  sed -i 's/8880/8888/g' env && \
  sed -i 's/SUDO_USERNAME = "soul"/SUDO_USERNAME = "dopaMine"/g' env && \
  sed -i 's/SUDO_PASSWORD = "M80b81M"/SUDO_PASSWORD = "80MinE84"/g' env && \
  docker compose up -d && \
  cd /var/lib/marzban/ && \
  rm -rf db.sqlite3 && \
  mv /root/backup/$SERVER/db.sqlite3 /var/lib/marzban/db.sqlite3 && \
  unzip /root/backup/$SERVER/certs.zip -d /var/lib/marzban/ && \
  cd && \
  cd marzban/ && \
  docker compose down && \
  rm -rf xray_config.json && \
  mv /root/backup/$SERVER/xray_config.json /root/marzban/xray_config.json && \
  docker compose up -d && \
  cd && \

  wget https://github.com/wangyu-/udp2raw/releases/download/20230206.0/udp2raw_binaries.tar.gz && \
  tar -zxvf udp2raw_binaries.tar.gz && \
  mv udp2raw_amd64 /usr/local/bin/udp2raw && chmod +x /usr/local/bin/udp2raw && \
  echo '[Unit]
  Description=udp2raw service
  ConditionFileIsExecutable=/usr/local/bin/udp2raw
  ConditionPathExists=/etc/udp2raw.conf
  After=network.target
  [Service]
  Type=simple
  User=root
  Group=root
  #LimitNOFILE=32768
  PIDFile=/run/udp2raw.pid
  AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
  ExecStart=/usr/local/bin/udp2raw --conf-file /etc/udp2raw.conf
  Restart=on-failure
  [Install]
  WantedBy=multi-user.target' > /etc/systemd/system/udp2raw.service && \
  systemctl enable udp2raw.service && \
  systemctl start udp2raw.service && \

read -p "Enter the server name: " S_NAME
  sudo apt install wireguard-dkms wireguard-tools resolvconf -y
  unzip /root/backup/$S_NAME/wireguard.zip -d /etc/ && \
  mv /root/backup/udp2raw.sh /root/udp2raw.sh && \
  chmod +x /root/udp2raw.sh && \
  chmod 600 /etc/wireguard/privatekey && \
  sudo systemctl enable --now wg-quick@wg0 && \

# Get license key from the user
#read -p "Enter the license key: " LICENSE

# Install WireGuard and configure Warp
#wget https://github.com/ViRb3/wgcf/releases/download/v2.2.19/wgcf_2.2.19_linux_amd64 && \
 # mv wgcf_2.2.19_linux_amd64 /usr/bin/wgcf && \
  #chmod +x /usr/bin/wgcf && \
  #echo -e "wgcf register\n" | wgcf register && \
  #wgcf generate && \
  #sed -i '3s/.*/license_key = '$LICENSE'/' wgcf-account.toml && \
  #wgcf update && \
  #wgcf generate && \
  #sudo apt install wireguard-dkms wireguard-tools resolvconf -y && \
  #sed -i '7i\Table = off' wgcf-profile.conf && \
  #mv /root/wgcf-profile.conf /etc/wireguard/warp.conf && \
  #sudo systemctl enable --now wg-quick@warp && \
  #cd marzban/ && \
  #docker compose down && \
  #docker compose up -d && \
  #cd && \
  
  systemctl disable resolvconf.service && /
  systemctl disable resolvconf && /
  systemctl disable resolvconf-pull-resolved.path && /
  systemctl disable resolvconf-pull-resolved.service && /
  echo 'nameserver 8.8.8.8
  nameserver 1.1.1.1' > /etc/resolv.conf && /
  systemctl restart systemd-resolved && /

  unzip /root/backup/cache.zip -d /root/ && \
  chmod +x /root/cache.sh && \

  echo '#!/bin/bash

  # Open a new tmux session
  tmux new-session -d -s cache
  
  # Run the command in a tmux window
  tmux send-keys -t cache "bash /root/cache.sh > /dev/null 2>&1" Enter
  ' > /root/cache_run.sh && \
  chmod +x /root/cache_run.sh && \
  (crontab -l ; echo "@reboot /root/cache_run.sh") | crontab -
