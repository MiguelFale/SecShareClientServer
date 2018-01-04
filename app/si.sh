#!/bin/sh

#http://www.thegeekstuff.com/scripts/iptables-rules

#CHANGE IPs TO YOUR LIKING
DC1="0.0.0.0"
DC2="0.0.0.0"
DC3="0.0.0.0"
DC4="0.0.0.0"
Storage="0.0.0.0"
WhatisThis1="0.0.0.0"
WhatisThis2="0.0.0.0"
WhattheBird="0.0.0.0"
Gateway="0.0.0.0"
Proxy="0.0.0.0"

# Permitir fazer pedidos DNS
sudo /sbin/iptables -A OUTPUT -p udp --dport 53 -j ACCEPT

# Responder a pings com origem na maquina WhattheBird
sudo /sbin/iptables -A OUTPUT -s $WhattheBird -p icmp -j ACCEPT

# Aceitar ligacoes de clientes vindos de qualquer origem
sudo /sbin/iptables -A INPUT -p tcp --dport 6666 -j ACCEPT

# Aceitar ligacoes ssh da rede local
sudo /sbin/iptables -A INPUT -d 10.101.148/22 -p tcp --dport 6666 -j ACCEPT 

# Nao filtrar o trafego do dispositivo de loopback
sudo /sbin/iptables -A INPUT -i lo -j ACCEPT
sudo /sbin/iptables -A OUTPUT -o lo -j ACCEPT

# Aceitar trafego relacionado com uma ligacao ja estabelecida
sudo /sbin/iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
sudo /sbin/iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Aceitar acessos essenciais
sudo /sbin/iptables -A OUTPUT -d $DC1 -j ACCEPT
sudo /sbin/iptables -A OUTPUT -d $DC2 -j ACCEPT
sudo /sbin/iptables -A OUTPUT -d $DC3 -j ACCEPT
sudo /sbin/iptables -A OUTPUT -d $DC4 -j ACCEPT
sudo /sbin/iptables -A OUTPUT -d $Storage -j ACCEPT
sudo /sbin/iptables -A OUTPUT -d $WhatisThis1 -j ACCEPT
sudo /sbin/iptables -A OUTPUT -d $WhatisThis2 -j ACCEPT
sudo /sbin/iptables -A OUTPUT -d $WhattheBird -j ACCEPT
sudo /sbin/iptables -A OUTPUT -d $Gateway -j ACCEPT
sudo /sbin/iptables -A OUTPUT -d $Proxy -j ACCEPT


sudo /sbin/iptables -A INPUT -s $DC1 -j ACCEPT
sudo /sbin/iptables -A INPUT -s $DC2 -j ACCEPT
sudo /sbin/iptables -A INPUT -s $DC3 -j ACCEPT
sudo /sbin/iptables -A INPUT -s $DC4 -j ACCEPT
sudo /sbin/iptables -A INPUT -s $Storage -j ACCEPT
sudo /sbin/iptables -A INPUT -s $WhatisThis1 -j ACCEPT
sudo /sbin/iptables -A INPUT -s $WhatisThis2 -j ACCEPT
sudo /sbin/iptables -A INPUT -s $WhattheBird -j ACCEPT
sudo /sbin/iptables -A INPUT -s $Gateway -j ACCEPT
sudo /sbin/iptables -A INPUT -s $Proxy -j ACCEPT

# Bloquear este computador (este é sempre o último)
sudo /sbin/iptables -P INPUT DROP

#corre ficheiro config de snort
sudo /usr/sbin/snort -c snort_si.config -A console

