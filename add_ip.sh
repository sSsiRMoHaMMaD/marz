#!/bin/bash 

read -p "Enter the Ports: " PORTS && \
read -p "Enter the Local IP: " LOCAL_IP && \

sed -i '/#END_FILTER/i\-A FORWARD -d $LOCAL_IP\/32 -p tcp -m multiport --dports $PORTS -j ACCEPT\n-A FORWARD -d $LOCAL_IP\/32 -p udp -m multiport --dports $PORTS -j ACCEPT' /etc/iptables/rules.v4

sed -i '/#END_NAT/i\-A PREROUTING -p tcp -m multiport --dports $PORTS -j DNAT --to-destination $LOCAL_IP\n-A PREROUTING -p udp -m multiport --dports $PORTS -j DNAT --to-destination $LOCAL_IP\n-A POSTROUTING -d $LOCAL_IP/32 -p tcp -m multiport --dports $PORTS -j MASQUERADE\n-A POSTROUTING -d $LOCAL_IP/32 -p udp -m multiport --dports $PORTS -j MASQUERADE' /etc/iptables/rules.v4

systemctl restart iptables
