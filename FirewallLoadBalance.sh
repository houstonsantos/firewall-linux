#!/bin/bash

############################################################################
#  Criado por: Houston Santos     =    e-mail: houston_santos@hotmail.com  #
#  Fone: 81-81502739                                                       #
############################################################################

#### Funcao iniciar ####
iniciar(){
echo "====================================================================="
echo "=                 ABILITANDO POLITICAS DO FIREWALL                  ="
echo "====================================================================="

### Limpando regras tabela filter e nat ###
iptables -F
iptables -t nat -F
echo "Limpando regras existentes.....................................[ OK ]"

### Aplicando regras default ###
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT
echo "Aplicando regras default.......................................[ OK ]"

#### Declarando variáveis ####
# Interface local #
ILAN=eth0

# Interface DMZ #
IDMZ=eth1

# Interfaces externas #
IWAN1=eth2
IWAN2=eth3

# Interface Loopback #
ILOCAL=lo

# Rede local #
LAN=192.168.254.0/255.255.255.0
DMZ=10.10.10.0/255.255.255.0

# Rede externa #
Internet=0.0.0.0/0.0.0.0

VESCNET_IP=201.76.97.10
VESCNET_NET=201.76.97.8/30
VESCNET_GW=201.76.97.9

HOTLINK_IP=189.1.16.194
HOTLINK_NET=189.1.16.192/29
HOTLINK_GW=189.1.16.193

#### Serviços ####
vpn=1723
vpn1=47
nob=1099
nob1=8080
nob2=8005
apl=8082
nfeba=8383
nfepe=8081
sweb1=8070
sweb2=8071
dvr=8090
############
rdp=3389
ftp=20:21
ftp1=20
ftp2=21
smtp=25
dns=53
dhcp1=67
dhcp2=68
http=80
pop=110
ntp=123
snmp=161:162
https=443
webmim=14044
Paltas=1024:65535
squid=2595
squidssl=2596
rip=520

############################################################################
#                      DEFININDO POLITICAS DE SEGURANCA                    #
############################################################################

# Proteção IP spoofing #
for spoofig in /proc/sys/net/ipv4/conf/*/rp_filter; do
echo "1" > $spoofig
done
echo "Protecao IP spoofing...........................................[ OK ]"

# Proteção de rotas #
echo 0 > /proc/sys/net/ipv4/conf/all/accept_redirects
echo "Protecao de rotas..............................................[ OK ]"

# Utilizado em diversos ataques, isso possibilita que o atacante determine o "caminho" que seu
# pacote vai percorrer (roteadores) ate seu destino. Junto com spoof, isso se torna muito perigoso.
echo 0 > /proc/sys/net/ipv4/conf/all/accept_source_route
echo "Protecao anti source route.....................................[ OK ]"

# Proteção responses bogus #
echo 1 > /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses
echo "Protecao responses bogus.......................................[ OK ]"

# Proteção Syn flood, DoS (inicio da conexão TCP) #
echo 1 > /proc/sys/net/ipv4/tcp_syncookies
echo "Protecao syn flood e DoS.......................................[ OK ]"

# Permitir ping entre as redes #
iptables -A INPUT -s 192.168.254.0/24 -p icmp -j ACCEPT
iptables -A INPUT -s 10.10.10.0/24 -p icmp -j ACCEPT
echo "Permitindo ping entre redes....................................[ OK ]"

# Proteção contra port scanners ocultos #
iptables -A INPUT -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s -j ACCEPT
iptables -A INPUT -s 0.0.0.0/0 -p icmp -j DROP
echo "Protecao port sanners..........................................[ OK ]"

# Proteção tracertroute #
iptables -A INPUT -p udp -s 0/0 -i $IWAN1 --dport 33435:33525 -j DROP
iptables -A INPUT -p udp -s 0/0 -i $IWAN2 --dport 33435:33525 -j DROP
echo "Protecao tracertroute..........................................[ OK ]"

# Proteção contra ataques #
iptables -A INPUT -m state --state INVALID -j DROP
iptables -A OUTPUT -p tcp ! --tcp-flags SYN,RST,ACK SYN -m state --state NEW -j DROP
echo "Protecao contra ataques........................................[ OK ]"

# Proteção ping da morte #
iptables -A FORWARD -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT
echo "Protecao ping da morte.........................................[ OK ]"

# Proteção syn floods #
iptables -A FORWARD -p tcp --syn -m limit --limit 1/s -j ACCEPT
echo "Protecao syn floods............................................[ OK ]"

############################################################################
#                      CARREGANDO MODULOS DO IPTABLES                      #
############################################################################
modprobe ip_tables
modprobe ip_nat_ftp
modprobe ip_conntrack_irc
modprobe ip_conntrack_ftp
modprobe ip_conntrack
modprobe ipt_state
modprobe ipt_LOG
modprobe ipt_MASQUERADE
modprobe iptable_filter
modprobe iptable_mangle
modprobe iptable_nat
modprobe sch_prio
echo "Carregando modulos do iptables ................................[ OK ]"

############################################################################
#                      DEFININDO POLITICAS DE ACESSO                       #
############################################################################

# Descartar pacotes fragmentados #
iptables -A INPUT -i $IWAN1 -f -j LOG --log-prefix "Pacote Fragmentado: "
iptables -A INPUT -i $IWAN1 -f -j DROP
iptables -A INPUT -i $IWAN2 -f -j LOG --log-prefix "Pacote Fragmentado: "
iptables -A INPUT -i $IWAN2 -f -j DROP
echo "Descartando pacotes fragmentados ..............................[ OK ]"

### Aqui vamos definir quem pode ou nao passar ###

# Abrindo para servidor Globalmedia #
iptables -t nat -I PREROUTING -p tcp --dport 25 -s 0/0 -d 208.43.42.120 -j ACCEPT
iptables -t nat -I PREROUTING -p tcp --dport 25 -s 208.43.42.120 -d 0/0 -j ACCEPT

# Abrindo e redirecionando DVR #
iptables -t nat -A PREROUTING -i $IWAN1 -p tcp -d 0/0 --dport 8090 -j DNAT --to 192.168.254.222:8090
iptables -t nat -A PREROUTING -i $IWAN1 -p tcp -d 0/0 --dport 37777 -j DNAT --to 192.168.254.222:37777
iptables -t nat -A PREROUTING -i $IWAN2 -p tcp -d 0/0 --dport 8090 -j DNAT --to 192.168.254.222:8090
iptables -t nat -A PREROUTING -i $IWAN2 -p tcp -d 0/0 --dport 37777 -j DNAT --to 192.168.254.222:37777

#iptables -t nat -A PREROUTING -i $IWAN1 -p tcp -d 0/0 --dport 8082 -j DNAT --to 10.10.10.2:8082
#iptables -t nat -A PREROUTING -i $IWAN2 -p tcp -d 0/0 --dport 8082 -j DNAT --to 10.10.10.2:8082

# Abrindo e redirecionando Storage #
iptables -t nat -A PREROUTING -i $IWAN1 -p tcp -d 0/0 --dport 8085 -j DNAT --to 192.168.254.38:80
iptables -t nat -A PREROUTING -i $IWAN2 -p tcp -d 0/0 --dport 8085 -j DNAT --to 192.168.254.38:80

# Abrindo e redirecionando Protheus #
iptables -t nat -A PREROUTING -i $IWAN1 -p tcp -d 0/0 --dport 1234 -j DNAT --to 10.10.10.2:1234
iptables -t nat -A PREROUTING -i $IWAN1 -p tcp -d 0/0 --dport 1271 -j DNAT --to 192.168.254.59:1271
iptables -t nat -A PREROUTING -i $IWAN1 -p tcp -d 0/0 --dport 1236 -j DNAT --to 10.10.10.2:1236
iptables -t nat -A PREROUTING -i $IWAN2 -p tcp -d 0/0 --dport 1234 -j DNAT --to 10.10.10.2:1234
iptables -t nat -A PREROUTING -i $IWAN2 -p tcp -d 0/0 --dport 1271 -j DNAT --to 192.168.254.59:1271
iptables -t nat -A PREROUTING -i $IWAN2 -p tcp -d 0/0 --dport 1236 -j DNAT --to 10.10.10.2:1236

# Liberando acesso a NFE Nota fiscal Eletronica #
iptables -t nat -I PREROUTING -p tcp --dport 443 -s 10.10.10.0/24 -d 200.238.83.69 -j ACCEPT
iptables -t nat -I PREROUTING -p tcp --dport 8081 -s 10.10.10.0/24 -d 200.238.83.69 -j ACCEPT
iptables -t nat -I PREROUTING -p tcp --dport 443 -s 200.238.83.69 -d 10.10.10.0/24 -j ACCEPT
iptables -t nat -I PREROUTING -p tcp --dport 8081 -s 200.238.83.69 -d 10.10.10.0/24 -j ACCEPT

iptables -t nat -I PREROUTING -p tcp --dport 8081 -s 10.10.10.0/24 -d 200.238.83.70 -j ACCEPT
iptables -t nat -I PREROUTING -p tcp --dport 443 -s 10.10.10.0/24 -d 200.238.83.70 -j ACCEPT
iptables -t nat -I PREROUTING -p tcp --dport 8081 -s 200.238.83.70 -d 10.10.10.0/24 -j ACCEPT
iptables -t nat -I PREROUTING -p tcp --dport 443 -s 200.238.83.70 -d 10.10.10.0/24 -j ACCEPT

iptables -t nat -I PREROUTING -p tcp --dport 443 -s 10.10.10.0/24 -d 200.223.31.78 -j ACCEPT
iptables -t nat -I PREROUTING -p tcp --dport 8081 -s 10.10.10.0/24 -d 200.223.31.78 -j ACCEPT
iptables -t nat -I PREROUTING -p tcp --dport 443 -s 200.223.31.78 -d 10.10.10.0/24 -j ACCEPT
iptables -t nat -I PREROUTING -p tcp --dport 8081 -s 200.223.31.78 -d 10.10.10.0/24 -j ACCEPT

iptables -t nat -A PREROUTING -p tcp -d 200.238.83.69 -j ACCEPT
iptables -t nat -A PREROUTING -p tcp -d 200.223.31.78 -j ACCEPT
iptables -t nat -A PREROUTING -p tcp -d 200.223.31.70 -j ACCEPT

iptables -A FORWARD -p tcp -d 200.238.83.69 -j ACCEPT
iptables -A FORWARD -p tcp -d 200.223.31.78 -j ACCEPT
iptables -A FORWARD -p tcp -d 200.223.31.70 -j ACCEPT

iptables -t nat -I PREROUTING -s 10.10.10.0/24 -p tcp --dport 8081 -j ACCEPT
iptables -t nat -I PREROUTING -s 10.10.10.0/24 -p tcp --dport 443 -j ACCEPT
iptables -t nat -I PREROUTING -s 10.10.10.0/24 -p tcp --dport 80 -j ACCEPT

# Liberando Conectividade Social #
iptables -t nat -I PREROUTING -p tcp --dport 80 -s 192.168.254.0/24 -d 200.201.173.68 -j ACCEPT
iptables -t nat -I PREROUTING -p tcp --dport 80 -s 200.201.173.68 -d 192.168.254.0/24 -j ACCEPT

iptables -t nat -I PREROUTING -p tcp --dport 80 -s 192.168.254.0/24 -d 200.201.174.207 -j ACCEPT
iptables -t nat -I PREROUTING -p tcp --dport 80 -s 200.201.174.207 -d 192.168.254.0/24 -j ACCEPT

iptables -t nat -I PREROUTING -p tcp --dport 80 -s 192.168.254.0/24 -d 64.4.44.82 -j ACCEPT
iptables -t nat -I PREROUTING -p tcp --dport 80 -s 64.4.44.82 -d 192.168.254.0/24 -j ACCEPT

iptables -t nat -A PREROUTING -p tcp -d 200.201.173.68 -j ACCEPT
iptables -t nat -A PREROUTING -p tcp -d 200.201.174.207 -j ACCEPT
iptables -t nat -A PREROUTING -p tcp -d 64.4.44.82 -j ACCEPT

iptables -A FORWARD -p tcp -d 200.201.173.68 -j ACCEPT
iptables -A FORWARD -p tcp -d 200.201.174.207 -j ACCEPT
iptables -A FORWARD -p tcp -d 64.4.44.82 -j ACCEPT

# Liberando Bradesco Net Empresas #
iptables -t nat -I PREROUTING -p tcp --dport 443 -s 192.168.254.0/24 -d 200.155.80.0/24 -j ACCEPT
iptables -t nat -I PREROUTING -p tcp --dport 443 -s 200.155.80.0/24 -d 192.168.254.0/24 -j ACCEPT
iptables -t nat -I PREROUTING -p tcp --dport 443 -s 192.168.254.0/24 -d 200.155.82.0/24 -j ACCEPT
iptables -t nat -I PREROUTING -p tcp --dport 443 -s 200.155.82.0/24 -d 192.168.254.0/24 -j ACCEPT
iptables -t nat -I PREROUTING -p tcp --dport 443 -s 192.168.254.0/24 -d 200.155.86.0/24 -j ACCEPT
iptables -t nat -I PREROUTING -p tcp --dport 443 -s 200.155.86.0/24 -d 192.168.254.0/24 -j ACCEPT
iptables -t nat -I PREROUTING -p tcp --dport 443 -s 192.168.254.0/24 -d 200.220.186.0/24 -j ACCEPT
iptables -t nat -I PREROUTING -p tcp --dport 443 -s 200.220.186.0/24 -d 192.168.254.0/24 -j ACCEPT
iptables -t nat -I PREROUTING -p tcp --dport 443 -s 192.168.254.0/24 -d 200.220.178.0/24 -j ACCEPT
iptables -t nat -I PREROUTING -p tcp --dport 443 -s 200.220.178.0/24 -d 192.168.254.0/24 -j ACCEPT
iptables -t nat -I PREROUTING -p tcp --dport 443 -s 192.168.254.0/24 -d 200.159.128.0/24 -j ACCEPT
iptables -t nat -I PREROUTING -p tcp --dport 443 -s 200.159.128.0/24 -d 192.168.254.0/24 -j ACCEPT

iptables -t nat -I PREROUTING -p tcp --dport 80 -s 192.168.254.0/24 -d 200.155.80.0/24 -j ACCEPT
iptables -t nat -I PREROUTING -p tcp --dport 80 -s 200.155.80.0/24 -d 192.168.254.0/24 -j ACCEPT
iptables -t nat -I PREROUTING -p tcp --dport 80 -s 192.168.254.0/24 -d 200.155.82.0/24 -j ACCEPT
iptables -t nat -I PREROUTING -p tcp --dport 80 -s 200.155.82.0/24 -d 192.168.254.0/24 -j ACCEPT
iptables -t nat -I PREROUTING -p tcp --dport 80 -s 192.168.254.0/24 -d 200.155.86.0/24 -j ACCEPT
iptables -t nat -I PREROUTING -p tcp --dport 80 -s 200.155.86.0/24 -d 192.168.254.0/24 -j ACCEPT
iptables -t nat -I PREROUTING -p tcp --dport 80 -s 192.168.254.0/24 -d 200.220.186.0/24 -j ACCEPT
iptables -t nat -I PREROUTING -p tcp --dport 80 -s 200.220.186.0/24 -d 192.168.254.0/24 -j ACCEPT
iptables -t nat -I PREROUTING -p tcp --dport 80 -s 192.168.254.0/24 -d 200.220.178.0/24 -j ACCEPT
iptables -t nat -I PREROUTING -p tcp --dport 80 -s 200.220.178.0/24 -d 192.168.254.0/24 -j ACCEPT
iptables -t nat -I PREROUTING -p tcp --dport 80 -s 192.168.254.0/24 -d 200.159.128.0/24 -j ACCEPT
iptables -t nat -I PREROUTING -p tcp --dport 80 -s 200.159.128.0/24 -d 192.168.254.0/24 -j ACCEPT
iptables -t nat -I PREROUTING -p tcp --dport 80 -s 192.168.254.0/24 -d 206.57.13.8 -j ACCEPT
iptables -t nat -I PREROUTING -p tcp --dport 80 -s 206.57.13.8 -d 192.168.254.0/24 -j ACCEPT

iptables -t nat -A PREROUTING -p tcp -d 200.155.80.0/24 -j ACCEPT
iptables -t nat -A PREROUTING -p tcp -d 200.155.82.0/24 -j ACCEPT
iptables -t nat -A PREROUTING -p tcp -d 200.155.86.0/24 -j ACCEPT
iptables -t nat -A PREROUTING -p tcp -d 200.220.186.0/24 -j ACCEPT
iptables -t nat -A PREROUTING -p tcp -d 200.220.178.0/24 -j ACCEPT
iptables -t nat -A PREROUTING -p tcp -d 200.159.128.0/24 -j ACCEPT
iptables -t nat -A PREROUTING -p tcp -d 206.57.13.8 -j ACCEPT

iptables -A FORWARD -p tcp -d 200.155.80.0/24 -j ACCEPT
iptables -A FORWARD -p tcp -d 200.155.82.0/24 -j ACCEPT
iptables -A FORWARD -p tcp -d 200.155.86.0/24 -j ACCEPT
iptables -A FORWARD -p tcp -d 200.220.186.0/24 -j ACCEPT
iptables -A FORWARD -p tcp -d 200.220.178.0/24 -j ACCEPT
iptables -A FORWARD -p tcp -d 200.159.128.0/24 -j ACCEPT
iptables -A FORWARD -p tcp -d 206.57.13.8 -j ACCEPT

# Liberando CobCaixa #
iptables -t nat -I PREROUTING -p tcp --dport 80 -s 192.168.254.0/24 -d 200.184.179.112 -j ACCEPT
iptables -t nat -I PREROUTING -p tcp --dport 443 -s 192.168.254.0/24 -d 200.184.179.112 -j ACCEPT
iptables -t nat -I PREROUTING -p tcp --dport 80 -s 200.184.179.112 -d 192.168.254.0/24 -j ACCEPT
iptables -t nat -I PREROUTING -p tcp --dport 443 -s 200.184.179.112 -d 192.168.254.0/24 -j ACCEPT

iptables -t nat -I PREROUTING -p tcp --dport 80 -s 192.168.254.0/24 -d 189.14.103.170 -j ACCEPT
iptables -t nat -I PREROUTING -p tcp --dport 443 -s 192.168.254.0/24 -d 189.14.103.170 -j ACCEPT
iptables -t nat -I PREROUTING -p tcp --dport 80 -s 189.14.103.170 -d 192.168.254.0/24 -j ACCEPT
iptables -t nat -I PREROUTING -p tcp --dport 443 -s 189.14.103.170 -d 192.168.254.0/24 -j ACCEPT

iptables -t nat -I PREROUTING -p tcp --dport 80 -s 192.168.254.0/24 -d 187.58.21.170 -j ACCEPT
iptables -t nat -I PREROUTING -p tcp --dport 443 -s 192.168.254.0/24 -d 187.58.21.170 -j ACCEPT
iptables -t nat -I PREROUTING -p tcp --dport 80 -s 187.58.21.170 -d 192.168.254.0/24 -j ACCEPT
iptables -t nat -I PREROUTING -p tcp --dport 443 -s 187.58.21.170 -d 192.168.254.0/24 -j ACCEPT

iptables -t nat -A PREROUTING -p tcp -d 200.184.179.112 -j ACCEPT
iptables -t nat -A PREROUTING -p tcp -d 189.14.103.170 -j ACCEPT
iptables -t nat -A PREROUTING -p tcp -d 187.58.21.170 -j ACCEPT

iptables -A FORWARD -p tcp -d 200.184.179.112 -j ACCEPT
iptables -A FORWARD -p tcp -d 189.14.103.170 -j ACCEPT
iptables -A FORWARD -p tcp -d 187.58.21.170 -j ACCEPT

# Abrindo e redirecionando Microsoft TS #
iptables -A INPUT -i $ILAN -p tcp --dport 3389 -j ACCEPT
iptables -A INPUT -i $IDMZ -p tcp --dport 3389 -j ACCEPT
iptables -A INPUT -i $IWAN1 -p tcp --dport 3389 -j ACCEPT
iptables -A INPUT -p udp -s 0/0 -i $IWAN1 --dport 3389 -j ACCEPT
iptables -A INPUT -p tcp -s 0/0 -i $IWAN1 --dport 3389 -j ACCEPT
iptables -A PREROUTING -t nat -m tcp -p tcp -i $IWAN2 --dport 3389 -j DNAT --to 10.10.10.2:3389
iptables -A INPUT -i $IWAN2 -p tcp --dport 3389 -j ACCEPT
iptables -A INPUT -p udp -s 0/0 -i $IWAN2 --dport 3389 -j ACCEPT
iptables -A INPUT -p tcp -s 0/0 -i $IWAN2 --dport 3389 -j ACCEPT
iptables -A PREROUTING -t nat -m tcp -p tcp -i $IWAN2 --dport 3389 -j DNAT --to 10.10.10.2:3389

# Abrindo e redirecionando Brande # 
iptables -A INPUT -i $IDMZ -p tcp --dport 8070 -j ACCEPT
iptables -A INPUT -i $IWAN1 -p tcp --dport 8070 -j ACCEPT
iptables -A INPUT -i $IWAN2 -p tcp --dport 8070 -j ACCEPT
iptables -A INPUT -p tcp -s 0/0 -i $IWAN1 --dport 8070 -j ACCEPT
iptables -A INPUT -p tcp -s 0/0 -i $IWAN2 --dport 8070 -j ACCEPT
#iptables -A PREROUTING -t nat -p tcp -d 0/0 --dport 8070 -j DNAT --to 10.10.10.2:8070
iptables -A PREROUTING -t nat -p tcp -d 0/0 --dport 8071 -j DNAT --to 10.10.10.15:8071

# Abrindo para VPN #
iptables -A INPUT -p TCP --dport 1723 -j ACCEPT
iptables -A OUTPUT -p TCP --dport 1723 -j ACCEPT
iptables -A INPUT -p 47 -j ACCEPT
iptables -A OUTPUT -p 47 -j ACCEPT
iptables -t nat -A PREROUTING -p tcp -d 0/0 --dport 1723 -j DNAT --to 10.10.10.4
iptables -t nat -A PREROUTING -p 47 -d 0/0 -j DNAT --to 10.10.10.4
iptables -A FORWARD -i $IWAN1 -p tcp -d 10.10.10.4 --dport 1723 -j ACCEPT
iptables -A FORWARD -o $IWAN1 -p tcp -s 10.10.10.4 --sport 1723 -j ACCEPT
iptables -A FORWARD -i $IWAN1 -p 47 -d 10.10.10.4 -j ACCEPT
iptables -A FORWARD -o $IWAN1 -p 47 -s 10.10.10.4 -j ACCEPT
iptables -A FORWARD -i $IWAN2 -p tcp -d 10.10.10.4 --dport 1723 -j ACCEPT
iptables -A FORWARD -o $IWAN2 -p tcp -s 10.10.10.4 --sport 1723 -j ACCEPT
iptables -A FORWARD -i $IWAN2 -p 47 -d 10.10.10.4 -j ACCEPT
iptables -A FORWARD -o $IWAN2 -p 47 -s 10.10.10.4 -j ACCEPT

# Localhost aceita todos pacotes #
iptables -A INPUT -i lo -j ACCEPT

# Porta 80 abrindo para rede Local\DMZ #
iptables -A INPUT -i $ILAN -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -i $IDMZ -p tcp --dport 80 -j ACCEPT

# Porta 443 abrindo para rede Local\DMZ #
iptables -A INPUT -i $ILAN -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -i $IDMZ -p tcp --dport 443 -j ACCEPT

# Porta 445 abrindo para Storage
iptables -A INPUT -p tcp --dport 445 -s 10.10.10.2 -d 192.168.254.38 -j ACCEPT 
iptables -A INPUT -p tcp --dport 445 -s 10.10.10.3 -d 192.168.254.38 -j ACCEPT

# Porta 3389 abrindo para rede Local\DMZ #
iptables -A INPUT -p tcp --dport 3389 -j ACCEPT
iptables -A INPUT -p udp --dport 3389 -j ACCEPT

# Porta 22 abrindo para rede Local #
iptables -A INPUT -i $ILAN -p tcp --dport 22 -j ACCEPT

# No iptables, temos de dizer quais sockets sao validos em uma conexao #
iptables -A INPUT -m state --state ESTABLISHED,RELATED,NEW -j ACCEPT
echo "Regras da chain INPUT .........................................[ OK ]"

### Aqui vamos definir quem pode ou nao passar pela chain FORWARD ###

# Primeiro, ativar o mascaramento (nat) #
iptables -t nat -F POSTROUTING

iptables -t nat -A POSTROUTING -o $IWAN1 -j MASQUERADE
echo "Ativando mascaramento WAN1 ....................................[ OK ]"

iptables -t nat -A POSTROUTING -o $IWAN2 -j MASQUERADE
echo "Ativando mascaramento WAN2 ....................................[ OK ]"

# Redireciona para Squid #
#iptables -t nat -A PREROUTING -i $ILAN -p tcp --dport 80 -j REDIRECT --to-port $squid
#iptables -t nat -A PREROUTING -i $ILAN -p tcp --dport 443 -j REDIRECT --to-port $squidssl
#iptables -t nat -A PREROUTING -i $IDMZ -p tcp --dport 80 -j REDIRECT --to-port $squid
#iptables -t nat -A PREROUTING -i $IDMZ -p tcp --dport 443 -j REDIRECT --to-port $squidssl

iptables -t nat -A PREROUTING -s 192.168.254.0/24 -p tcp --dport 80 -j REDIRECT --to-port $squid
iptables -t nat -A PREROUTING -s 192.168.254.0/24 -p tcp --dport 443 -j REDIRECT --to-port $squid
#iptables -t nat -A PREROUTING -s 192.168.254.0/24 -p tcp --dport 443 -j REDIRECT --to-port $squidssl
iptables -t nat -A PREROUTING -s 10.10.10.0/24 -p tcp --dport 80 -j REDIRECT --to-port $squid
iptables -t nat -A PREROUTING -s 10.10.10.0/24 -p tcp --dport 443 -j REDIRECT --to-port $squid
#iptables -t nat -A PREROUTING -s 10.10.10.0/24 -p tcp --dport 443 -j REDIRECT --to-port $squidssl

####################################################################################
# Agora dizemos quem e o que podem acessar externamente                            #
# no iptables, o controle do acesso a rede externa e feito na cadeia "FORWARD"     #
####################################################################################

# Abre para a interface de loopback #
iptables -A INPUT -p tcp --syn -s 127.0.0.1/255.0.0.0 -j ACCEPT

# Abre para uma faixa de enderecos da rede local #
iptables -A INPUT -p tcp --syn -s $LAN -j ACCEPT

# Cria rota para servidor TERMINAL SERVER App #
echo "1" > /proc/sys/net/ipv4/icmp_echo_ignore_all 

# Porta 14044 abrindo para rede Local/DMZ # 
iptables -A FORWARD -i $ILAN -p tcp --dport 14044 -j ACCEPT

# Porta 2595 abrindo para rede Local/DMZ #
iptables -A FORWARD -i $ILAN -p tcp --dport 2595 -j ACCEPT
iptables -A FORWARD -i $IDMZ -p tcp --dport 2595 -j ACCEPT

# Porta 2596 - ACEITA PARA A REDE LOCAL/DMZ #
#iptables -A FORWARD -i $ILAN -p tcp --dport $squidssl -j ACCEPT
#iptables -A FORWARD -i $IDMZ -p tcp --dport $squidssl -j ACCEPT

# Porta 53 abrindo para rede Local/DMZ #
iptables -A FORWARD -i $ILAN -p udp --dport 53 -j ACCEPT
iptables -A FORWARD -i $IDMZ -p udp --dport 53 -j ACCEPT
iptables -A FORWARD -i $ILAN -p tcp --dport 53 -j ACCEPT
iptables -A FORWARD -i $IDMZ -p tcp --dport 53 -j ACCEPT

# Porta 445 - Aceita para Storage #
iptables -A FORWARD -p tcp --dport 445 -s 10.10.10.2 -d 192.168.254.38 -j ACCEPT
iptables -A FORWARD -p tcp --dport 445 -s 10.10.10.3 -d 192.168.254.38 -j ACCEPT

# Porta 110 abrindo para rede Local #
iptables -A FORWARD -i $ILAN -p tcp --dport 110 -j ACCEPT

# Porta 25 abrindo para rede Local #
iptables -A FORWARD -i $ILAN -p tcp --dport 25 -j ACCEPT

# Porta 443 abrindo para rede Local/DMZ # 
iptables -A FORWARD -i $ILAN -p tcp --dport 443 -j ACCEPT
iptables -A FORWARD -i $IDMZ -p tcp --dport 443 -j ACCEPT

# Porta 21 abrindo para rede Local/DMZ #
iptables -A FORWARD -i $ILAN -p tcp --dport 21 -j ACCEPT
iptables -A FORWARD -i $IDMZ -p tcp --dport 21 -j ACCEPT

# Descarta pacotes invalidos para reenvio #
iptables -A FORWARD -m state --state INVALID -j DROP
echo "Descartando pacotes invalidos para reenvio ....................[ OK ]"

# Mantendo conexoes ativas #
#echo -n "Manutencao de conexoes ativas..."
#iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT  
  
# No iptables, temos de dizer quais sockets sao validos em uma conexao #
iptables -A FORWARD -m state --state ESTABLISHED,RELATED,NEW -j ACCEPT
echo "Regras da cahin FORWARD .......................................[ OK ]"

# Otimizando o roteamento #
iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
echo "Otimizando o roteamento .......................................[ OK ]"

####################################################################################
# Apesar do padrão do FORWARD ser bloquear tudo. Aqui as regras sao duplicada para # 
# gerar log ou seja, tudo o que e bloqueado por default no FORWARD e logado aqui   #
####################################################################################
iptables -A FORWARD -m limit --limit 2/m -j LOG --log-prefix "FORWARD: Bloqueio Padrao" --log-level 7
iptables -A FORWARD -j DROP

# Habilitando o trafego IP, entre as Interfaces de rede #
echo "1" > /proc/sys/net/ipv4/ip_forward
echo "Forwading abilitado............................................[ OK ]"

####################################################################################
# Ignora qualquer pacote de entrada, vindo de qualquer endereco, a menos que       # 
# especificado em regra, ao contrario bloqueia tudo                                #
####################################################################################
#iptables -A INPUT -p tcp --syn -j LOG --log-prefix "BLOQUEADO syn"
iptables -A INPUT -p tcp --syn -j DROP

# Marcando pacotes #
iptables -A PREROUTING -t mangle -p tcp --dport 443 -d 0.0.0.0/0.0.0.0 -j MARK --set-mark 2
iptables -A PREROUTING -t mangle -s 192.168.254.0/24 -d 0/0 -j MARK --set-mark 4
iptables -A PREROUTING -t mangle -s 10.10.10.0/24 -d 0/0 -j MARK --set-mark 4
echo "Marcando pacotes...............................................[ OK ]"

# Desabilitando o filtro de pacotes do martian source #
for eee in /proc/sys/net/ipv4/conf/*/rp_filter; do
echo 0 > $eee
done
echo "Desligando rp filter...........................................[ OK ]"
#cat /proc/sys/net/ipv4/conf/*/rp_filter

echo "STATUS FIREWALL................................................[ ON ]"

echo "====================================================================="
echo "=                     ABILITANDO BALANCIAMENTO                      ="
echo "====================================================================="

# Limpando tabelas #
ip route flush table VESCNET
ip route flush table HOTLINK
ip route flush table BALANCEAMENTO
echo "Limpando tabels ...............................................[ ON ]"

# Limpando regras #
ip rule del from 189.1.16.193 table HOTLINK
ip rule del from 201.76.97.9 table VESCNET
ip rule del fwmark 0x4 table BALANCEAMENTO
ip rule del fwmark 0x3 table HOTLINK
ip rule del fwmark 0x2 table VESCNET
ip route del default
echo "Limpando regras ...............................................[ ON ]"

# Configuracões tabela VESCNET #
ip route add 201.76.97.8/30 dev $IWAN2 src 201.76.97.10 table VESCNET
ip route add default via 201.76.97.9 table VESCNET
echo "Configurando tabela vescnet ...................................[ ON ]"

# Configuracões tabela HOTLINK #
ip route add 189.1.16.192/29 dev $IWAN1 src 189.1.16.194 table HOTLINK
ip route add default via 189.1.16.193 table HOTLINK
echo "Configurando tabela hotlink ...................................[ ON ]"

# Setando tabela principal de roteamento #
# OBS: caso os gateways estejam sendo informados no arquivo interface nao e nessesario essa tag #
#ip route add 189.1.16.192/29 dev $IWAN1 src 189.1.16.194
#ip route add 201.76.97.8/30 dev $IWAN2 src 201.76.97.10

# Trafico da eth2 sai pela tabela HOTLINK #
ip rule add from 189.1.16.194 table HOTLINK

# Trafico da eth3 sai pela tabela VESCNET #
ip rule add from 201.76.97.10 table VESCNET

####################################################################################
# Essa duas regra estou criando pois existe um redirect para para rede interna,    #
# e portanto preciso tratar a ida e a volta para que nao saia pelo balanceamento   #
# e sim pela interface de origem do redirect                                       #
####################################################################################

# Definindo regra para pacotes marcados sairem pela VESCNET #
ip rule add fwmark 2 table VESCNET
#ip rule add fwmark 2 lookup VESCNET prio 3

# Definindo regra para sacotes marcados sairem pela HOTLINK #
ip rule add fwmark 3 table HOTLINK
#ip rule add fwmark 3 lookup HOTLINK prio 3

# Definindo regra para marcacao de pacotes da intranet sairem pelo BALANCEAMENTO #
ip rule add fwmark 4 table BALANCEAMENTO
#ip rule add fwmark 4 lookup BALANCEAMENTO prio 3

# Criando balanceamento multilink para tabela BALANCEAMENTO #
ip route add default table BALANCEAMENTO nexthop via 201.76.97.9 dev $IWAN2 weight 1 nexthop via 189.1.16.193 dev $IWAN1 weight 1
echo "Configurando balanceamento ....................................[ ON ]"

# Definindo rota padrao #
ip route add default via 201.76.97.9
echo "Definindo rota padrao .........................................[ ON ]"

# Fazendo flush no cache de rotas que foram deletadas #
ip route flush cache
#sleep 3
}

#### Funcao parar ####
parar(){
echo "====================================================================="
echo "=                      DESSABILITANDO FIREWALL                      ="
echo "====================================================================="

### Lipnado regras ###
iptables -F
iptables -t nat -F
echo "Limpando regras existentes.....................................[ OK ]"
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD ACCEPT
echo "Aplicando regras default.......................................[ OK ]"

echo "STATUS FIREWALL...............................................[ OFF ]"
}

case "$1" in
"start") iniciar ;;
"stop") parar ;;
"restart") parar; iniciar ;;
*) echo "Use os parametro start e stop"
esac
