#!/bin/bash 

read -p "Enter the Ports: " PORTS && \
read -p "Enter the Local IP: " LOCAL_IP && \

sed '/#END_FILTER/i\-A FORWARD -d $LOCAL_IP/32 -p tcp -m multiport --dports $PORTS -j ACCEPT
-A FORWARD -d $LOCAL_IP/32 -p udp -m multiport --dports $PORTS -j ACCEPT' /etc/iptables/rules.v4

sed '/#END_NAT/i\-A PREROUTING -p tcp -m multiport --dports $PORTS -j DNAT --to-destination $LOCAL_IP
-A PREROUTING -p udp -m multiport --dports $PORTS -j DNAT --to-destination $LOCAL_IP
-A POSTROUTING -d $LOCAL_IP/32 -p tcp -m multiport --dports $PORTS -j MASQUERADE
-A POSTROUTING -d $LOCAL_IP/32 -p udp -m multiport --dports $PORTS -j MASQUERADE' /etc/iptables/rules.v4

systemctl restart iptables
