#!/bin/bash

############################################################################
#  Criado por: Houston Santos     =    e-mail: houston_santos@hotmail.com  #
#  Fone: 81-81502739                                                       #
############################################################################

#### Declarando variaveis ####

# Interface WAN #
ifwan0="eth0"

# Interface LAN #
iflan1="eth1"

#### Funcao iniciar ####
iniciar(){
echo "====================================================================="
echo "=        ATIVANDO COMPARTILHAMENTO E POLITICAS DE SEGURANÇA         ="
echo "====================================================================="

# Abilitando forward & MASQUERADE #
modprobe iptable_nat
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -o $ifwan0 -j MASQUERADE
echo "Compartilhamento...............................................[ OK ]"

# Bloqueio do ICMP #
iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
echo "Bloqueio do ICMP...............................................[ OK ]"

# Protecao contra ataques #
echo 1 > /proc/sys/net/ipv4/conf/default/rp_filter
iptables -A INPUT -m state --state INVALID -j DROP
echo "Proteção contra ataques........................................[ OK ]"

# Pacotes rede interna #
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -i $iflan1 -j ACCEPT
#iptables -A INPUT -i $ifdmz -j ACCEPT
echo "Pacotes rede interna...........................................[ OK ]"

#iptables -t nat -A PREROUTING -s 192.168.1.0/24 -p tcp --dport 80 -j REDIRECT --to-port 2595
#iptables -t nat -A PREROUTING -s 192.168.1.0/24 -p tcp --dport 443 -j REDIRECT --to-port 2596

# Porta 2595 abrindo para rede Local/DMZ #
#iptables -A FORWARD -i $ILAN -p tcp --dport $squid -j ACCEPT

# Porta 2596 abrindo para rede Local/DMZ #
#iptables -A FORWARD -i $ILAN -p tcp --dport $squidssl -j ACCEPT

# Liberando portas #
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
echo "Liberando portas...............................................[ OK ]"

# Bloqueio conexcoes externas #
iptables -A INPUT -p tcp --syn -j DROP
echo "Bloqueio conexões externas.....................................[ OK ]"
}

#### Funcao parar ####
parar(){
echo "====================================================================="
echo "=         PARANDO COMPARILHAMENTO E POLITICAS DE SEGURANÇA          ="
echo "====================================================================="

# Lipando regras do Iptables #
iptables -F
iptables -t nat -F
}

case "$1" in
"start") iniciar ;;
"stop") parar ;;
"restart") parar; iniciar ;;
*) echo "Use os Parametros start ou stop"
esac
