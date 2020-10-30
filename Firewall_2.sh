#!/bin/bash
firewall_start() {
echo "==============================================="
echo "| ::  SETANDO A CONFIGURACAO DO IPTABLES   :: |"
echo "==============================================="
ipt="/sbin/iptables"
### Passo 1: Limpando as regras ###
$ipt -F INPUT
$ipt -F OUTPUT
$ipt -F FORWARD
echo "Limpando todas as regras .................[ OK ]"
# Definindo a Politica Default das Cadeias
$ipt -P INPUT DROP 
$ipt -P FORWARD DROP
$ipt -P OUTPUT ACCEPT
echo "Setando as regras padrao .................[ OK ]"
# Portas e Servicos

#Porta de acesso e servico nobreaks
vpn=1723
vpn1=47
nob=1099
nob1=8080
nob2=8005
############
nfepe=8081
sweb=8070
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
rip=520
# Interfaces
IWAN1=eth2
IWAN2=eth3
ILAN=eth0
IDMZ=eth1
ILocal=lo
# Redes Internas
DMZ=10.10.10.0/255.255.255.0
LAN=192.168.254.0/255.255.255.0
#ADSL=$wan0

# Redes Externas
Internet=0.0.0.0/0.0.0.0

# Configurando a Protecao anti-spoofing
for spoofing in /proc/sys/net/ipv4/conf/*/rp_filter; do
echo "1" > $spoofing
done
echo "Setando a protecao anti-spoofing .........[ OK ]"

# Impedimos que um atacante possa maliciosamente alterar alguma rota
echo 0 > /proc/sys/net/ipv4/conf/all/accept_redirects
echo "Setando anti-redirecionamento ............[ OK ]"

# Utilizado em diversos ataques, isso possibilita que o atacante determine o "caminho" que seu
# pacote vai percorrer (roteadores) ate seu destino. Junto com spoof, isso se torna muito perigoso.
echo 0 > /proc/sys/net/ipv4/conf/all/accept_source_route
echo "Setando anti_source_route.................[ OK ]"

# Protecao contra responses bogus
echo 1 > /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses
echo "Setando anti-bogus_response ..............[ OK ]"

# Protecao contra ataques de syn flood (inicio da conexao TCP). Tenta conter ataques de DoS.
echo 1 > /proc/sys/net/ipv4/tcp_syncookies
echo "Setando protecao anti_synflood ...........[ OK ]"

##### permitir ping entre as redes
$ipt -A INPUT -s 192.168.254.0/24 -p icmp -j ACCEPT
$ipt -A INPUT -s 10.10.10.0/24 -p icmp -j ACCEPT


# Protecao contra port scanners ocultos
$ipt -A INPUT -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s -j ACCEPT
$ipt -A INPUT -s 0.0.0.0/0 -p icmp -j DROP


# Bloqueando tracertroute
$ipt -A INPUT -p udp -s 0/0 -i $IWAN1 --dport 33435:33525 -j DROP

#Protecoes contra ataques
$ipt -A INPUT -m state --state INVALID -j DROP
$ipt -A OUTPUT -p tcp ! --tcp-flags SYN,RST,ACK SYN -m state --state NEW -j DROP

#Ping da morte
$ipt -A FORWARD -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT

#Protecao contra Syn-floods
$ipt -A FORWARD -p tcp --syn -m limit --limit 1/s -j ACCEPT

### Passo 3: Carregando os modulos do iptables ###
modprobe ip_tables
modprobe iptable_filter
modprobe iptable_mangle
modprobe iptable_nat
modprobe ipt_MASQUERADE
modprobe ip_nat_ftp
modprobe ip_conntrack_ftp
modprobe ip_conntrack_irc
modprobe ipt_state
modprobe ipt_LOG
modprobe sch_prio
echo "Carregando modulos do iptables ...........[ OK ]"

# Descartar pacotes fragmentados:

echo -n "Bloqueando pacotes fragmentados..."
$ipt -A INPUT -i $IWAN2 -f -j LOG --log-prefix "Pacote fragmentado: "
$ipt -A INPUT -i $IWAN2 -f -j DROP
$ipt -A INPUT -i $IWAN1 -f -j LOG --log-prefix "Pacote Fragmentado: "
$ipt -A INPUT -i $IWAN1 -f -j DROP
echo "                           [OK]"

### Passo 4: Agora, vamos definir o que pode passar e o que nao ###
$ipt -t nat -A PREROUTING -i $IWAN1 -p tcp -d 0/0 --dport 8090 -j DNAT --to 192.168.254.222:8090
$ipt -t nat -A PREROUTING -i $IWAN1 -p tcp -d 0/0 --dport 37777 -j DNAT --to 192.168.254.222:37777
$ipt -t nat -A PREROUTING -i $IWAN2 -p tcp -d 0/0 --dport 8090 -j DNAT --to 192.168.254.222:8090
$ipt -t nat -A PREROUTING -i $IWAN2 -p tcp -d 0/0 --dport 37777 -j DNAT --to 192.168.254.222:37777
## Liberando acesso a NFE (Nota fiscal Eletronica)
$ipt -t nat -I PREROUTING -p tcp --dport 443 -s 10.10.10.0/24 -d 200.238.83.69 -j ACCEPT
$ipt -t nat -I PREROUTING -p tcp --dport 8081 -s 10.10.10.0/24 -d 200.238.83.69 -j ACCEPT
$ipt -t nat -I PREROUTING -p tcp --dport 443 -s 200.238.83.69 -d 10.10.10.0/24 -j ACCEPT
$ipt -t nat -I PREROUTING -p tcp --dport 8081 -s 200.238.83.69 -d 10.10.10.0/24 -j ACCEPT
$ipt -t nat -A PREROUTING -p tcp -d 200.238.83.69 -j ACCEPT
$ipt -A FORWARD -p tcp -d 200.238.83.69 -j ACCEPT
$ipt -t nat -A PREROUTING -p tcp -d 200.238.83.69 -j ACCEPT
$ipt -A FORWARD -p tcp -d 200.238.83.69 -j ACCEPT
$ipt -t nat -I PREROUTING -s 10.10.10.0/24 -p tcp --dport 8081 -j ACCEPT
$ipt -t nat -I PREROUTING -s 10.10.10.0/24 -p tcp --dport 443 -j ACCEPT
$ipt -t nat -I PREROUTING -s 10.10.10.0/24 -p tcp --dport 80 -j ACCEPT
## FIM NFE

$ipt -A INPUT -i eth1 -p tcp --dport 3389 -j ACCEPT
$ipt -A INPUT -i $IWAN1 -p tcp --dport 3389 -j ACCEPT
$ipt -A INPUT -p udp -s 0/0 -i $IWAN1 --dport 3389 -j ACCEPT
$ipt -A INPUT -p tcp -s 0/0 -i $IWAN1 --dport 3389 -j ACCEPT
$ipt -A INPUT -i $IWAN2 -p tcp --dport 3389 -j ACCEPT
$ipt -A INPUT -p udp -s 0/0 -i $IWAN2 --dport 3389 -j ACCEPT
$ipt -A INPUT -p tcp -s 0/0 -i $IWAN2 --dport 3389 -j ACCEPT
#$ipt -A PREROUTING -t nat -m tcp -p tcp -d 0/0 --dport 3389 -i $IWAN1 -j DNAT --to 10.10.10.2:3389
$ipt -A PREROUTING -t nat -m tcp -p tcp -i $IWAN1 --dport 3389 -j DNAT --to 10.10.10.2:3389
$ipt -A PREROUTING -t nat -m tcp -p tcp -i $IWAN2 --dport 3389 -j DNAT --to 10.10.10.2:3389

$ipt -A INPUT -i eth1 -p tcp --dport 8070 -j ACCEPT
$ipt -A INPUT -i $IWAN1 -p tcp --dport 8070 -j ACCEPT
$ipt -A INPUT -i $IWAN2 -p tcp --dport 8070 -j ACCEPT
$ipt -A INPUT -p tcp -s 0/0 -i $IWAN1 --dport 8070 -j ACCEPT
$ipt -A INPUT -p tcp -s 0/0 -i $IWAN2 --dport 8070 -j ACCEPT
$ipt -A PREROUTING -t nat -p tcp -d 0/0 --dport 8070 -j DNAT --to 10.10.10.2:8070

$ipt -A INPUT -p TCP --dport 1723 -j ACCEPT
$ipt -A OUTPUT -p TCP --dport 1723 -j ACCEPT
$ipt -A INPUT -p 47 -j ACCEPT
$ipt -A OUTPUT -p 47 -j ACCEPT
$ipt -t nat -A PREROUTING -p tcp -d 0/0 --dport 1723 -j DNAT --to 10.10.10.4
$ipt -t nat -A PREROUTING -p 47 -d 0/0 -j DNAT --to 10.10.10.4
$ipt -A FORWARD -i $IWAN1 -p tcp -d 10.10.10.4 --dport 1723 -j ACCEPT
$ipt -A FORWARD -o $IWAN1 -p tcp -s 10.10.10.4 --sport 1723 -j ACCEPT
$ipt -A FORWARD -i $IWAN1 -p 47 -d 10.10.10.4 -j ACCEPT
$ipt -A FORWARD -o $IWAN1 -p 47 -s 10.10.10.4 -j ACCEPT
$ipt -A FORWARD -i $IWAN2 -p tcp -d 10.10.10.4 --dport 1723 -j ACCEPT
$ipt -A FORWARD -o $IWAN2 -p tcp -s 10.10.10.4 --sport 1723 -j ACCEPT
$ipt -A FORWARD -i $IWAN2 -p 47 -d 10.10.10.4 -j ACCEPT
$ipt -A FORWARD -o $IWAN2 -p 47 -s 10.10.10.4 -j ACCEPT


# Cadeia de Entrada
# LOCALHOST - ACEITA TODOS OS PACOTES
$ipt -A INPUT -i lo -j ACCEPT

# PORTA $http - ACEITA PARA A REDE LOCAL\DMZ
$ipt -A INPUT -i $ILAN -p tcp --dport $http -j ACCEPT
$ipt -A INPUT -i $IDMZ -p tcp --dport $http -j ACCEPT

# PORTA 3389 - ACEITA PARA A REDE LOCAL\DMZ
$ipt -A INPUT -p tcp --dport $rdp -j ACCEPT
$ipt -A INPUT -p udp --dport $rdp -j ACCEPT

# PORTA 22 - ACEITA PARA A REDE LOCAL
$ipt -A INPUT -i $ILAN -p tcp --dport 22 -j ACCEPT

# No $ipt, temos de dizer quais sockets sao validos em uma conexao
$ipt -A INPUT -m state --state ESTABLISHED,RELATED,NEW -j ACCEPT
echo "Setando regras para INPUT ................[ OK ]"

################################
# Cadeia de Reenvio (FORWARD).
# Primeiro, ativar o mascaramento (nat).
$ipt -t nat -F POSTROUTING
$ipt -t nat -A POSTROUTING -o $IWAN1 -j MASQUERADE
$ipt -t nat -A POSTROUTING -o $IWAN2 -j MASQUERADE

echo "Ativando mascaramento de IP ..............[ OK ]"

## Redireciona para SQUID

$ipt -t nat -A PREROUTING -s 192.168.254.0/24 -p tcp --dport $http -j REDIRECT --to-port $squid
$ipt -t nat -A PREROUTING -s 192.168.254.0/24 -p tcp --dport $https -j REDIRECT --to-port $squid
$ipt -t nat -A PREROUTING -s 10.10.10.0/24 -p tcp --dport $http -j REDIRECT --to-port $squid
$ipt -t nat -A PREROUTING -s 10.10.10.0/24 -p tcp --dport $https -j REDIRECT --to-port $squid

# Agora dizemos quem e o que podem acessar externamente
# No $ipt, o controle do acesso a rede externa e feito na cadeia "FORWARD"
# Abre para a interface de loopback.
$ipt -A INPUT -p tcp --syn -s 127.0.0.1/255.0.0.0 -j ACCEPT
# Abre para uma faixa de enderecos da rede local

$ipt -A INPUT -p tcp --syn -s $LAN -j ACCEPT

#Cria rota para servidor TERMINAL SERVER App

echo "1" > /proc/sys/net/ipv4/icmp_echo_ignore_all 

# PORTA 14044 - ACEITA PARA A REDE LOCAL/DMZ 
$ipt -A FORWARD -i $ILAN -p tcp --dport $webmim -j ACCEPT

# PORTA 2595 - ACEITA PARA A REDE LOCAL/DMZ 
#$ipt -A FORWARD -i $ILAN -p tcp --dport $squid -j ACCEPT
#$ipt -A FORWARD -i $IDMZ -p tcp --dport $squid -j ACCEPT
$ipt -A FORWARD -i $ILAN -p tcp --dport $squid -j ACCEPT
$ipt -A FORWARD -i $IDMZ -p tcp --dport $squid -j ACCEPT

# PORTA 53 - ACEITA PARA A REDE LOCAL/DMZ

$ipt -A FORWARD -i $ILAN -p udp --dport $dns -j ACCEPT
$ipt -A FORWARD -i $IDMZ -p udp --dport $dns -j ACCEPT
$ipt -A FORWARD -i $ILAN -p tcp --dport $dns -j ACCEPT
$ipt -A FORWARD -i $IDMZ -p tcp --dport $dns -j ACCEPT

# PORTA 110 - ACEITA PARA A REDE LOCAL
$ipt -A FORWARD -i $ILAN -p tcp --dport $pop -j ACCEPT

# PORTA 25 - ACEITA PARA A REDE LOCAL
$ipt -A FORWARD -i $ILAN -p tcp --dport $smtp -j ACCEPT

# PORTA 443 - ACEITA PARA A REDE LOCAL/DMZ 
$ipt -A FORWARD -i $ILAN -p tcp --dport $https -j ACCEPT
$ipt -A FORWARD -i $IDMZ -p tcp --dport $https -j ACCEPT

# PORTA 21 - ACEITA PARA A REDE LOCAL/DMZ
$ipt -A FORWARD -i $ILAN -p tcp --dport $ftp -j ACCEPT
$ipt -A FORWARD -i $IDMZ -p tcp --dport $ftp -j ACCEPT
# Descarta pacotes invalidos:
#
echo -n "Descartando pacotes invalidos para reenvio..."
$ipt -A FORWARD -m state --state INVALID -j DROP
echo "                [OK]"
#
# No $ipt, temos de dizer quais sockets sao validos em uma conexao
$ipt -A FORWARD -m state --state ESTABLISHED,RELATED,NEW -j ACCEPT
#
echo -n "Otimizando o roteamento..."
$ipt -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
echo " [OK]"
echo "Setando regras para FORWARD ...............[ OK ]"
# Apesar do padrao do forward ser bloqueio. Aqui a regra eh duplicada para gerar log,
# ou seja, tudo o que eh bloqueado por default no forward eh logado aqui
$ipt -A FORWARD -m limit --limit 2/m -j LOG --log-prefix "FORWARD: Bloqueio Padrao" --log-level 7
$ipt -A FORWARD -j DROP

# Finalmente: Habilitando o trafego IP, entre as Interfaces de rede
echo "1" > /proc/sys/net/ipv4/ip_forward
echo "Setando ip_foward: ON ....................[ OK ]"
# Ignora qualquer pacote de entrada, vindo de qualquer endereco, a menos
# que especificado o contrario acima, Bloqueia tudo.
$ipt -A INPUT -p tcp --syn -j DROP
# Marcando pacotes
echo -n "Marcando pacotes..."
$ipt -A PREROUTING -t mangle -s 192.168.254.0/24 -d 0/0 -j MARK --set-mark 3
$ipt -A PREROUTING -t mangle -p tcp --dport 443 -d 0.0.0.0/0.0.0.0 -j MARK --set mark 4
echo "                                [OK]"
# Desabilitando o filtro de pacotes do martian source
echo -n "Desligando rp_filter..."
for eee in /proc/sys/net/ipv4/conf/*/rp_filter; do
echo 0 > $eee
done
cat /proc/sys/net/ipv4/conf/*/rp_filter
echo "                                [OK]"
#
#
# Definindo regras de balanceamento de Link:
	echo -n "Balanceando links wan0..."

	# wan0 #1
	ip route add 201.76.97.9/30 dev eth2 src 201.76.97.10 table wan1
	#ip route add 192.168.254.0/24 via 192.168.254.254 table wan1
	ip route add default via 201.76.97.9 table wan1

	# wan0 #2
	ip route add 172.16.4.9/30 dev eth3 src 172.16.4.10 table velox
	#ip route add 192.168.254.0/24 via 192.168.254.254 table velox
	ip route add default via 192.168.2.1 table velox

	# setando wan0 na tabela principal de roteamento
	ip route add 201.76.97.9/30 dev eth2 src 201.76.97.10
	ip route add 172.16.4.9/30 dev eth3 src 172.16.4.10

	# setando a rota preferencial
	ip route add default via 201.76.97.9
	# regras das tabelas
	ip rule add from 201.76.97.10 table wan1
	ip rule add from 172.16.4.10 table velox

# balanceamento de link
ip rule add fwmark 4 lookup wan1 prio 3 >> /dev/null
ip rule add fwmark 3 lookup wan0 prio 3
ip route add default table wan0 nexthop via 201.76.97.9 dev eth2 weight 3 nexthop via 172.16.4.9 dev eth3 weight 1
# flush no roteamento
ip route flush cache
echo "					[OK]"
sleep 3
#
#
echo "Firewall configurado com sucesso .........[ OK ]"
echo
}

firewall_restart() {
firewall_start
}
    
firewall_stop() {
    
echo "==========================================="
echo "| ::       DESLIGANDO FIREWALL          :: |"
echo "==========================================="
    
# Limpa as regras
ipt=/sbin/iptables

$ipt -F INPUT
$ipt -F OUTPUT
$ipt -F FORWARD
$ipt -P INPUT ACCEPT
$ipt -P OUTPUT ACCEPT
$ipt -P FORWARD ACCEPT
echo "Limpando e retaurando as regras .................[ OK ]"

    
}
    
case "$1" in
'start')
firewall_start
;;
'stop')
firewall_stop
;;
'restart')
firewall_restart
;;
*)
firewall_start
esac
