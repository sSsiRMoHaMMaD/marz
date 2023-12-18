#!/bin/bash

# Update the root password and set DNS
echo 'root:sOn3lQ#bS@ls!7&m' | sudo chpasswd && \
  ufw disable && \
  sed -i '16s/^/DNS=1.1.1.1 8.8.8.8\n/' /etc/systemd/resolved.conf && \
  echo 'nameserver 1.1.1.1
  nameserver 8.8.8.8' > /etc/resolv.conf
  service systemd-resolved restart && \
  apt update && \
  apt install unzip -y && \
  wget https://github.com/sSsiRMoHaMMaD/backup/archive/refs/heads/main.zip && \
  unzip main.zip && \
  mv /root/backup-main /root/backup && \
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
  cd && \
  cd marzban/ && \
  docker compose down && \
  
  echo '{
    "log": {
      "loglevel": "info"
    },
    "inbounds": [
      {
        "tag": "VLESS TCP HTTP",
        "listen": "0.0.0.0",
        "port": $PORT_VTH,
        "protocol": "vless",
        "settings": {
          "clients": [],
          "decryption": "none"
        },
        "streamSettings": {
          "network": "tcp",
          "tcpSettings": {
            "header": {
              "type": "http",
              "request": {
                "method": "GET",
                "path": [
                  "/"
                ],
                "headers": {
                  "Host": [
                    ""
                  ]
                }
              },
              "response": {}
            }
          },
          "security": "none"
        },
        "sniffing": {
          "enabled": true,
          "destOverride": [
            "http",
            "tls"
          ]
        }
      },
      {
        "tag": "VLESS TCP",
        "listen": "0.0.0.0",
        "port": $PORT_VT,
        "protocol": "vless",
        "settings": {
          "clients": [],
          "decryption": "none"
        },
        "streamSettings": {
          "network": "tcp"
        },
        "sniffing": {
          "enabled": true,
          "destOverride": [
            "http",
            "tls"
          ]
        }
      },
      {
        "tag": "VLESS WS HTTP",
        "listen": "0.0.0.0",
        "port": $PORT_VWH,
        "protocol": "vless",
        "settings": {
          "clients": [],
          "decryption": "none"
        },
        "streamSettings": {
          "network": "ws",
          "security": "none",
          "wsSettings": {
            "path": "/",
            "headers": {
              "Host": ""
            }
          }
        },
        "sniffing": {
          "enabled": true,
          "destOverride": [
            "http",
            "tls"
          ]
        }
      },
      {
        "tag": "VLESS WS",
        "listen": "0.0.0.0",
        "port": 8880,
        "protocol": "vless",
        "settings": {
          "clients": [],
          "decryption": "none"
        },
        "streamSettings": {
          "network": "ws",
          "wsSettings": {
            "path": "/"
          }
        },
        "sniffing": {
          "enabled": true,
          "destOverride": [
            "http",
            "tls"
          ]
        }
      },
      {
        "tag": "SHADOWSOCKS",
        "listen": "0.0.0.0",
        "port": $PORT_SH,
        "protocol": "shadowsocks",
        "settings": {
          "clients": [],
          "network": "tcp,udp"
        }
      },
      {
        "tag": "VLESS TCP HTTP TLS",
        "listen": "0.0.0.0",
        "port": $PORT_VTHT,
        "protocol": "vless",
        "settings": {
          "clients": [],
          "decryption": "none"
        },
        "streamSettings": {
          "network": "tcp",
          "security": "tls",
          "tlsSettings": {
            "alpn": [
              "h2",
              "http/1.1"
            ],
            "certificates": [
              {
                "certificateFile": "/var/lib/marzban/certs/$DOMAIN.soulsharp.site.cer",
                "keyFile": "/var/lib/marzban/certs/$DOMAIN.soulsharp.site.cer.key"
              }
            ]
          },
          "tcpSettings": {
            "header": {
              "type": "http",
              "request": {
                "method": "GET",
                "path": [
                  "/"
                ],
                "headers": {
                  "Host": [
                    ""
                  ]
                }
              },
              "response": {}
            }
          }
        },
        "sniffing": {
          "enabled": true,
          "destOverride": [
            "http",
            "tls"
          ]
        }
      }
    ],
    "outbounds": [
      {
        "protocol": "freedom",
        "settings": {},
        "tag": "DIRECT"
      },
      {
        "protocol": "blackhole",
        "settings": {},
        "tag": "BLOCK"
      },
      {
        "tag": "warp",
        "protocol": "freedom",
        "streamSettings": {
          "sockopt": {
            "tcpFastOpen": true,
            "interface": "warp"
          }
        }
      }
    ],
    "routing": {
      "domainStrategy": "IPIfNonMatch",
      "rules": [
        {
          "outboundTag": "warp",
          "domain": [
            "geosite:google",
            "twitter.com",
            "instagram.com",
            "ipinfo.io",
            "x.com",
            "spotify.com",
            "tweetdeck.com",
            "twitter.co",
            "twttr.com",
            "twtrdns.net",
            "twitteroauth.com",
            "twitterstat.us",
            "twitterinc.com",
            "twitpic.com",
            "twimg.com",
            "t.co",
            "pscp.tv",
            "ads-twitter.com",
            "periscope.tv"
          ],
          "type": "field"
        },
        {
          "ip": [
            "geoip:private"
          ],
          "outboundTag": "BLOCK",
          "type": "field"
        },
        {
          "domain": [
            "localhost"
          ],
          "outboundTag": "BLOCK",
          "type": "field"
        }
      ]
    }
  }' > /root/marzban/xray_config.json && \

read -p "Enter the Domain: " DOMAIN
read -p "Enter the VTH: " PORT_VTH
read -p "Enter the VT: " PORT_VT
read -p "Enter the VWH: " PORT_VWH
read -p "Enter the SH: " PORT_SH
read -p "Enter the VTHT: " PORT_VTHT
read -p "Enter the SSL: " SSL
read -p "Enter the license key: " LICENSE

  sed -i "s/\$DOMAIN/$DOMAIN/g" /root/marzban/xray_config.json && \
  sed -i "s/\$PORT_VTH/$PORT_VTH/g" /root/marzban/xray_config.json && \
  sed -i "s/\$PORT_VT/$PORT_VT/g" /root/marzban/xray_config.json && \
  sed -i "s/\$PORT_VWH/$PORT_VWH/g" /root/marzban/xray_config.json && \
  sed -i "s/\$PORT_SH/$PORT_SH/g" /root/marzban/xray_config.json && \
  sed -i "s/\$PORT_VTHT/$PORT_VTHT/g" /root/marzban/xray_config.json && \

  apt install socat -y && \
  apt install cron -y && \
  curl https://get.acme.sh | sh -s email=wzme22@gmail.com && \
  export DOMAIN=$SSL.soulsharp.site && \
  mkdir -p /var/lib/marzban/certs && \
  ~/.acme.sh/acme.sh     --set-default-ca --server letsencrypt && \
  ~/.acme.sh/acme.sh \
    --issue --force --standalone -d "$SSL.soulsharp.site" \
    --fullchain-file "/var/lib/marzban/certs/$SSL.soulsharp.site.cer" \
    --key-file "/var/lib/marzban/certs/$SSL.soulsharp.site.cer.key" && \
  cd /root/marzban && \
  docker compose up -d && \
  cd && \

  wget https://github.com/ViRb3/wgcf/releases/download/v2.2.19/wgcf_2.2.19_linux_amd64 && \
  apt install wireguard -y && \
  mv wgcf_2.2.19_linux_amd64 /usr/bin/wgcf && \
  chmod +x /usr/bin/wgcf && \
  echo -e "wgcf register\n" | wgcf register && \
  wgcf generate && \
  sed -i '3s/.*/license_key = '$LICENSE'/' wgcf-account.toml && \
  wgcf update && \
  wgcf generate && \
  sudo apt install wireguard-dkms wireguard-tools resolvconf -y && \
  sed -i '7i\Table = off' wgcf-profile.conf && \
  mv /root/wgcf-profile.conf /etc/wireguard/warp.conf && \
  sudo systemctl enable --now wg-quick@warp && \
  cd marzban/ && \
  docker compose down && \
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

read -p "Enter the Local IP: " LOCAL_IP
  sed -i "s/\$LOCAL_IP/$LOCAL_IP/g" /etc/wireguard/wg0.conf && \
  
  ech '[Interface]
  Address = $LOCAL_IP/32
  MTU = 1342
  PostUp = bash /root/udp2raw.sh
  PostDown = killall udp2raw true
  PrivateKey = PRIVATEKEY

  [Peer]
  PublicKey = 6sNvmAZflqio1eyOL1LcQctVP/w5R8hmEbC60EaysEU=
  AllowedIPs = 192.168.1.2/32
  Endpoint = 127.0.0.1:51822
  PersistentKeepalive = 25

  [Peer]
  PublicKey = 6rcNbltBXH4rtfN2HHdJaH0dO0cEHD6EahEHzpxyJ3k=
  AllowedIPs = 192.168.1.3/32
  Endpoint = 127.0.0.1:51823
  PersistentKeepalive = 25

  [Peer]
  PublicKey = w+Z6jmS6myStCamphePS9HQYGf3Jx1XY8xIGGCM1lz4=
  AllowedIPs = 192.168.1.4/32
  Endpoint = 127.0.0.1:51824
  PersistentKeepalive = 25

  [Peer]
  PublicKey = 2qvW++9WtUkCALb9GDTjF/6cnI7AfCuXsgxIowuUXCI=
  AllowedIPs = 192.168.1.5/32
  Endpoint = 127.0.0.1:51825
  PersistentKeepalive = 25

  [Peer]
  PublicKey = x24595j8zufqTvkYNXu//vliWHnts7g/RVkFfWRsjVw=
  AllowedIPs = 192.168.1.6/32
  Endpoint = 127.0.0.1:51826
  PersistentKeepalive = 25' > /etc/wireguard/wg0.conf && \

  cd /etc/wireguard/ && \
  umask 077; wg genkey | tee privatekey | wg pubkey > publickey && \
  chmod 600 /etc/wireguard/privatekey && \

  sed -i "s/PrivateKey = PRIVATEKEY/PrivateKey = $(</etc/wireguard/privatekey)/g" /etc/wireguard/wg0.conf
  
  mv /root/backup/udp2raw.sh /root/udp2raw.sh && \
  chmod +x /root/udp2raw.sh && \
  sudo systemctl enable --now wg-quick@wg0 && \

  unzip /root/backup/cache.zip -d /root/ && \
  chmod +x /root/cache.sh && \

  echo '#!/bin/bash

  # Open a new tmux session
  tmux new-session -d -s cache
  
  # Run the command in a tmux window
  tmux send-keys -t cache "bash /root/cache.sh > /dev/null 2>&1" Enter
  ' > /root/cache_run.sh && \
  chmod +x /root/cache_run.sh && \
  (crontab -l ; echo "@reboot /root/cache_run.sh") | crontab - && \
  reboot
