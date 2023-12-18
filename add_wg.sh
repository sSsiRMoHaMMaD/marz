#!/bin/bash

read -p "Enter the PublicKey: " PUBKEY && \
read -p "Enter the Local IP: " LOCAL_IP && \

ech0 "[Peer]
PublicKey = $PUBKEY
AllowedIPs = $IP/32
PersistentKeepalive = 25" >> /etc/wireguard/wg0.conf && \

sed -i "s/\$PUBKEY/$PUBKEY/g" /etc/wireguard/wg0.conf && \
sed -i "s/\$LOCAL_IP/$LOCAL_IP/g" /etc/wireguard/wg0.conf && \

wg-quick down wg0 && \
wg-quick up wg0
