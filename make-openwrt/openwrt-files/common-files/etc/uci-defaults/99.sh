# Beware! myhome40  廖辉r5s AUTO  This script will be in /rom/etc/uci-defaults/ as part of the image.
# Uncomment lines to apply:

root_password="AAbbzxc123al~"

# log potential errors
exec >/tmp/setup.log 2>&1

if [ -n "$root_password" ]; then
  (echo "$root_password"; sleep 1; echo "$root_password") | passwd > /dev/null
fi

# /etc/config/dhcp
uci del dhcp.lan.ra_slaac
uci commit dhcp

# /etc/config/network
uci set network.lan.ipaddr='192.168.40.1/24'
uci set network.globals.ula_prefix='fd00:0:0::/48'
uci set network.globals.packet_steering='2'
uci set network.globals.steering_flows='128'
uci add_list network.lan.ip6class='wan6'
uci commit network

# /etc/config/firewall
uci set firewall.@defaults[0].flow_offloading='1'
uci set firewall.@defaults[0].synflood_protect='1'
uci set firewall.@defaults[0].flow_offloading_hw='1'
uci add firewall zone # =cfg0edc81
uci set firewall.@zone[-1].name='vpn'
uci set firewall.@zone[-1].input='ACCEPT'
uci set firewall.@zone[-1].output='ACCEPT'
uci set firewall.@zone[-1].forward='ACCEPT'
uci set firewall.@zone[-1].mtu_fix='1'
uci add_list firewall.cfg0edc81.network='vpn'
uci add firewall forwarding # =cfg0fad58
uci set firewall.@forwarding[-1].src='vpn'
uci set firewall.@forwarding[-1].dest='lan'
uci add firewall forwarding # =cfg10ad58
uci set firewall.@forwarding[-1].src='lan'
uci set firewall.@forwarding[-1].dest='vpn'
uci add firewall rule
uci set firewall.@rule[-1].name='web'
uci set firewall.@rule[-1].family='ipv6'
uci set firewall.@rule[-1].src='wan'
uci set firewall.@rule[-1].dest_port='22 7890 7891'
uci set firewall.@rule[-1].target='ACCEPT'
uci add firewall rule
uci set firewall.@rule[-1].name='ssh'
uci set firewall.@rule[-1].family='ipv6'
uci set firewall.@rule[-1].src='wan'
uci set firewall.@rule[-1].dest='*'
uci set firewall.@rule[-1].dest_port='22'
uci set firewall.@rule[-1].target='ACCEPT'
uci add firewall rule
uci set firewall.@rule[-1].name='wg-vpn'
uci set firewall.@rule[-1].family='ipv6'
uci add_list firewall.@rule[-1].proto='udp'
uci set firewall.@rule[-1].src='wan'
uci set firewall.@rule[-1].dest_port='51820'
uci set firewall.@rule[-1].target='ACCEPT'
uci commit firewall

# 设置系统时间
uci -q batch << EOI
set system.@system[0].hostname='liaohui_r5s'
set system.@system[0].zonename='Asia/Singapore'
set system.@system[0].timezone='<+08>-8'
set system.@system[0].log_proto='udp'
set system.@system[0].conloglevel='5'
set system.@system[0].cronloglevel='9'
#启用ntp
del system.ntp.enabled
del system.ntp.enable_serve
del system.ntp.server
add_list system.ntp.server='cn.ntp.org.cn'
add_list system.ntp.server='0.openwrt.pool.ntp.org'
commit system
EOI

# /etc/config/dropbear
uci set dropbear.@dropbear[0].GatewayPorts='on'
uci commit dropbear

# /etc/config/attendedsysupgrade
uci set attendedsysupgrade.client.advanced_mode='1'
uci commit attendedsysupgrade

# /etc/config/ddns
uci set ddns.myddns_ipv6.enabled='1'
uci set ddns.myddns_ipv6.service_name='dynv6.com'
uci set ddns.myddns_ipv6.lookup_host='myhome40.dynv6.net'
uci set ddns.myddns_ipv6.domain='myhome40.dynv6.net'
uci set ddns.myddns_ipv6.username='nono'
uci set ddns.myddns_ipv6.password='z2Qf7M7-_DQe-qB2y7JGy4enyL-yH9'
uci set ddns.myddns_ipv6.use_https='1'
uci set ddns.myddns_ipv6.cacert='/etc/ssl/certs'
uci set ddns.myddns_ipv6.ip_source='network'
uci set ddns.myddns_ipv6.ip_network='lan'
uci set ddns.myddns_ipv6.interface='lan'
uci set ddns.myddns_ipv6.use_syslog='2'
uci set ddns.myddns_ipv6.check_unit='minutes'
uci set ddns.myddns_ipv6.force_unit='minutes'
uci set ddns.myddns_ipv6.retry_unit='seconds'
uci del ddns.myddns_ipv4
uci del ddns.global.upd_privateip
uci set ddns.global.ddns_rundir='/var/run/ddns'
uci set ddns.global.ddns_logdir='/var/log/ddns'
uci commit ddns

# /etc/config/ddns
uci set ddns.dedyn_io=service
uci set ddns.dedyn_io.service_name='desec.io'
uci set ddns.dedyn_io.use_ipv6='1'
uci set ddns.dedyn_io.enabled='1'
uci set ddns.dedyn_io.lookup_host='liaohuir5s.ghf.dedyn.io'
uci set ddns.dedyn_io.domain='liaohuir5s.ghf.dedyn.io'
uci set ddns.dedyn_io.username='liaohuir5s.ghf.dedyn.io'
uci set ddns.dedyn_io.password='RbYmbown3uzy7g1XZ29za1ByGftb'
uci set ddns.dedyn_io.use_https='1'
uci set ddns.dedyn_io.cacert='/etc/ssl/certs'
uci set ddns.dedyn_io.ip_source='network'
uci set ddns.dedyn_io.ip_network='wan6'
uci set ddns.dedyn_io.interface='wan6'
uci set ddns.dedyn_io.use_syslog='2'
uci set ddns.dedyn_io.check_unit='minutes'
uci set ddns.dedyn_io.force_unit='minutes'
uci set ddns.dedyn_io.retry_unit='seconds'
uci commit ddns

# 添加lmz.dedyn.io
# /etc/config/ddns
uci set ddns.lmz_dedyn_io=service
uci set ddns.lmz_dedyn_io.service_name='desec.io'
uci set ddns.lmz_dedyn_io.use_ipv6='1'
uci set ddns.lmz_dedyn_io.enabled='1'
uci set ddns.lmz_dedyn_io.lookup_host='liaohuir5s.lmz.dedyn.io'
uci set ddns.lmz_dedyn_io.domain='liaohuir5s.lmz.dedyn.io'
uci set ddns.lmz_dedyn_io.username='liaohuir5s.lmz.dedyn.io'
uci set ddns.lmz_dedyn_io.password='gsUYXgFKptUcT9spnyEjMB9sLpgJ'
uci set ddns.lmz_dedyn_io.use_https='1'
uci set ddns.lmz_dedyn_io.cacert='/etc/ssl/certs'
uci set ddns.lmz_dedyn_io.ip_source='network'
uci set ddns.lmz_dedyn_io.ip_network='lan'
uci set ddns.lmz_dedyn_io.interface='lan'
uci set ddns.lmz_dedyn_io.use_syslog='2'
uci set ddns.lmz_dedyn_io.check_unit='minutes'
uci set ddns.lmz_dedyn_io.force_unit='minutes'
uci set ddns.lmz_dedyn_io.retry_unit='seconds'
uci commit ddns

#添加cloudflare ddns
uci set ddns.cloudflare_ipv6=service
uci set ddns.cloudflare_ipv6.service_name='cloudflare.com-v4'
uci set ddns.cloudflare_ipv6.use_ipv6='0'
uci set ddns.cloudflare_ipv6.enabled='1'
uci set ddns.cloudflare_ipv6.lookup_host='liaohuir5s.xys.cloudns.biz'
uci set ddns.cloudflare_ipv6.use_ipv6='1'
uci set ddns.cloudflare_ipv6.domain='liaohuir5s@xys.cloudns.biz'
uci set ddns.cloudflare_ipv6.username='liumingan@gmail.com'
uci set ddns.cloudflare_ipv6.password='924777fc86a52a5c3de2ed81e824a9f36e435'
uci set ddns.cloudflare_ipv6.use_https='1'
uci set ddns.cloudflare_ipv6.cacert='/etc/ssl/certs'
uci set ddns.cloudflare_ipv6.ip_source='network'
uci set ddns.cloudflare_ipv6.use_syslog='2'
uci set ddns.cloudflare_ipv6.check_unit='minutes'
uci set ddns.cloudflare_ipv6.force_unit='minutes'
uci set ddns.cloudflare_ipv6.retry_unit='seconds'
uci set ddns.cloudflare_ipv6.ip_network='wan6'
uci set ddns.cloudflare_ipv6.interface='wan6'
uci commit ddns

# 添加VPN通道
uci set network.vpn=interface
uci set network.vpn.proto='wireguard'
uci set network.vpn.private_key='2B+LLVt/MO46gAkRjZHwoKyOhMHmrAllSpgIwvynb18='
uci set network.vpn.listen_port='51820'
uci add_list network.vpn.addresses='192.168.100.40/24'
uci add_list network.vpn.addresses='fd00:0:0:2::40/64'
uci set network.vpn.mtu='1420'
uci set network.vpn.fwmark='0xca6a'
uci add_list network.vpn.dns='192.168.40.1'
uci commit network

# myhome20 融侨k2p
uci add network wireguard_vpn
uci set network.@wireguard_vpn[-1]=wireguard_vpn
uci set network.@wireguard_vpn[-1].description='rq'
uci set network.@wireguard_vpn[-1].public_key='FhvKtIkqWiEIl9HP1A6yQg6wEriVa+c1n/DZwmbnngI='
uci add_list network.@wireguard_vpn[-1].allowed_ips='192.168.100.2/32'
uci add_list network.@wireguard_vpn[-1].allowed_ips='192.168.20.0/24'
uci add_list network.@wireguard_vpn[-1].allowed_ips='fd00:0:0:2::2/128'
uci set network.@wireguard_vpn[-1].endpoint_host='rq.xys.dedyn.io'
uci set network.@wireguard_vpn[-1].endpoint_port='51820'
uci set network.@wireguard_vpn[-1].persistent_keepalive='25'
uci commit network

# (myhome10.dynv6.net) k3 主路由
uci add network wireguard_vpn
uci set network.@wireguard_vpn[-1]=wireguard_vpn
uci set network.@wireguard_vpn[-1].description='syk3'
uci set network.@wireguard_vpn[-1].public_key='vUeqshSRDnuFOgSRYJ1TRPXae6+hrpQLM9Aem87NHks='
uci add_list network.@wireguard_vpn[-1].allowed_ips='192.168.100.40/32'
uci add_list network.@wireguard_vpn[-1].allowed_ips='192.168.10.0/24'
uci add_list network.@wireguard_vpn[-1].allowed_ips='fd00:0:0:2::40/128'
uci set network.@wireguard_vpn[-1].endpoint_host='syk3.ghf.dedyn.io'
uci set network.@wireguard_vpn[-1].endpoint_port='51820'
uci set network.@wireguard_vpn[-1].persistent_keepalive='25'
uci commit network

# sj 手机
uci add network wireguard_vpn
uci set network.@wireguard_vpn[-1].description='sj'
uci set network.@wireguard_vpn[-1].public_key='L5sL64UGOMv9cQ0dQHFwZCs1Jl19pJBuBY47eISsp3A='
uci set network.@wireguard_vpn[-1].private_key='0NQ5ZOof3fVtB9WZHtK7sESvzWjq1TP20BqHgCUFRWc='
uci add_list network.@wireguard_vpn[-1].allowed_ips='192.168.100.8/29'
uci add_list network.@wireguard_vpn[-1].allowed_ips='fd00:0:0:2::8/126'
uci commit network

# 添加静态路由
uci add network route # =cfg0bc8b4
uci set network.@route[-1].interface='vpn'
uci set network.@route[-1].target='192.168.10.0/24'
uci add network route # =cfg0bc8b4
uci set network.@route[-1].interface='vpn'
uci set network.@route[-1].target='192.168.20.0/24'
uci commit network


#DHCP
uci set dhcp.lan.interface='lan'
uci set dhcp.lan.dhcpv4='server'
uci set dhcp.lan.dhcpv6='server'
uci set dhcp.lan.ra='server'
uci set dhcp.lan.start='100'
uci set dhcp.lan.limit='150'
uci set dhcp.lan.leasetime='12h'
uci add_list lan.ra_flags='managed-config'
uci add_list lan.ra_flags='other-config'
uci set dhcp.wan.interface='wan'
uci set dhcp.wan.ignore='1'
uci set dhcp.wan.start='100'
uci set dhcp.wan.limit='150'
uci set dhcp.wan.leasetime='12h'
uci set dhcp.odhcpd='odhcpd'
uci set dhcp.odhcpd.maindhcp='0'
uci set dhcp.odhcpd.leasefile='/tmp/hosts/odhcpd'
uci set dhcp.odhcpd.leasetrigger='/usr/sbin/odhcpd-update'
uci set dhcp.odhcpd.loglevel='4'
# 设置dnsmasq
uci del dhcp.cfg01411c.nonwildcard
uci del dhcp.cfg01411c.boguspriv
uci del dhcp.cfg01411c.filterwin2k
uci del dhcp.cfg01411c.filter_aaaa
uci del dhcp.cfg01411c.filter_a
uci del dhcp.cfg01411c.nonegcache
uci commit dhcp

# /etc/config/ttyd
uci set ttyd.@ttyd[-1].port='7681'
uci set ttyd.@ttyd[-1].ipv6='1'
uci set ttyd.@ttyd[-1].debug='3'
uci set ttyd.@ttyd[-1].command='/bin/login -f root'
uci commit ttyd

# /etc/config/fstab
uci set fstab.cfg054d78.target='/mnt/mmcblk1p3'
uci set fstab.cfg054d78.uuid='d5085710-62cf-4044-ba98-2ace20b187b2'
uci set fstab.cfg054d78.enabled='1'
uci set fstab.cfg064d78.target='/mnt/mmcblk1p4'
uci set fstab.cfg064d78.uuid='e06407fb-0f63-497d-82c1-2e2554cbaf80'
uci set fstab.cfg064d78.enabled='1'
uci commit fstab

echo 'net.ipv4.tcp_fastopen = 3
net.netfilter.nf_conntrack_max = 65535
vm.swappiness = 0
net.core.default_qdisc=fq_codel
net.ipv4.tcp_congestion_control=bbr' >> /etc/sysctl.conf

#重新加载配置
reload_config

#创建f.sh(下载install.sh)
cat << 'EOF' > /etc/f.sh
#!/bin/ash

MAX_RETRY=5  # 最大重试次数
RETRY_COUNT=0

while [ $RETRY_COUNT -lt $MAX_RETRY ]; do
    curl -o /tmp/install_yd_mihomo.sh 'https://gitlab.com/api/v4/projects/51320840/repository/files/install_yd_mihomo.sh/raw?ref=main&private_token=glpat-YyHNv-t28eVUy1Whvza5'

    if [ $? -eq 0 ]; then
        echo "Download successful";
        chmod a+x /tmp/install_yd_mihomo.sh
        exec /tmp/install_yd_mihomo.sh  # 使用 exec 运行下载的脚本，当前脚本会在此处退出
    else
        echo "Download failed. Retrying..."
        RETRY_COUNT=$((RETRY_COUNT+1))
        sleep 5  # 每次重试等待5秒
    fi
done

echo "Download failed after $MAX_RETRY attempts"
exit 1
EOF
# 赋予执行权限
chmod +x /etc/f.sh

#创建yd.sh(下载install_yd.sh)
cat << 'EOF' > /etc/yd.sh
#!/bin/ash

MAX_RETRY=3  # 最大重试次数
RETRY_COUNT=0

while [ $RETRY_COUNT -lt $MAX_RETRY ]; do
    HTTP_STATUS=$(curl -w "%{http_code}" -o /tmp/install_yd.sh 'https://gitlab.com/api/v4/projects/51320840/repository/files/install_yd.sh/raw?ref=main&private_token=glpat-YyHNv-t28eVUy1Whvza5')

    if [ $? -eq 0 ] && [ "$HTTP_STATUS" -eq 200 ]; then
        echo "Download successful"
        chmod +x /tmp/install_yd.sh
        exec /tmp/install_yd.sh  # 使用 exec 运行下载的脚本，当前脚本会在此处退出
    else
        echo "Download failed with status code $HTTP_STATUS. Retrying..."
        RETRY_COUNT=$((RETRY_COUNT+1))
        sleep 5  # 每次重试等待5秒
    fi
done

echo "Download failed after $MAX_RETRY attempts"
exit 1
EOF

# 赋予执行权限
chmod +x /etc/yd.sh

#创建detect_wan.sh(判断wan口)
cat << 'EOF' > /etc/detect_wan.sh
#!/bin/sh

# WAN接口名称（根据实际情况修改，通常是 eth0.2 或 eth1.2）
WAN_IF="eth0"

# 标志文件路径（由 mihomo 安装脚本创建）
FLAG_FILE="/usr/bin/mihomo"

# 检测WAN口是否有物理连接
check_wan_connection() {
    if ethtool "$WAN_IF" | grep -q "Link detected: yes"; then
        echo "WAN接口已连接"
        return 0
    else
        echo "WAN接口未连接"
        return 1
    fi
}

# 检测网络连通性
check_wan_ping_connection() {
    if ping -c 4 -W 3 114.114.114.114 > /dev/null 2>&1; then
        echo "WAN接口已连接且网络连通"
        return 0
    else
        echo "WAN接口未连接或网络不通"
        return 1
    fi
}

# 检测是否有DHCP分配的IP地址
check_dhcp() {
    if ifconfig "$WAN_IF" | grep -q "inet addr:"; then
        echo "检测到 DHCP 连接"
        return 0
    else
        return 1
    fi
}

# 使用任意的PPPoE用户名和密码进行拨号测试
try_pppoe() {
    uci set network.wan.proto='pppoe'
    uci set network.wan.username='071000906294'  # 假的PPPoE用户名
    uci set network.wan.password='123456'  # 假的PPPoE密码
    uci set network.wan.ipv6='0'
    uci set network.wan.mtu='1480'
    uci set network.wan6.device='@wan'
    uci set network.wan6.reqaddress='try'
    uci set network.wan6.reqprefix='auto'
    uci commit network
    /etc/init.d/network restart

    sleep 10  # 等待拨号完成
    if logread | grep -q "pppoe"; then
        echo "检测到PPPoE信号"
        return 0
    else
        return 1
    fi
}

# 检查 mihomo 是否已经安装
check_mihomo() {
    if [ -f "$FLAG_FILE" ]; then
        echo "标志文件存在，mihomo 已安装"
        return 0
    else
        return 1
    fi
}

# 主函数逻辑：检测并配置网络连接方式
detect_connection_and_run_script() {
    if check_dhcp; then
        echo "已检测到 DHCP 连接"
    else
        echo "未检测到 DHCP 连接，尝试PPPoE拨号"
        if try_pppoe; then
            echo "PPPoE 信号检测成功，配置wan口为pppoe成功"
        else
            echo "未检测到 DHCP 或 PPPoE 信号，无法确定网络连接方式"
        fi
    fi
}

# 主逻辑部分：优先检查网络连通性，再安装 mihomo
while true; do
    if check_wan_connection; then
        if check_wan_ping_connection; then
            echo "网络通畅，继续执行"

            # 检查 mihomo 是否已经安装
            if ! check_mihomo; then
                # 如果 mihomo 未安装，则运行 mihomo 安装脚本
                echo "开始安装 mihomo"
                cd /etc && bash ./f.sh
                sleep 180
                cd /etc && ./yd.sh
            else
                echo "mihomo 已经安装，跳过安装步骤"
            fi

            break  # 网络正常并安装完毕，退出循环
        else
            # 如果网络不通，开始检测网络模式并配置
            echo "网络不通，开始检测网络模式..."
            detect_connection_and_run_script
        fi
    else
        echo "等待WAN接口连接..."
        sleep 5  # 等待5秒后再次检测
    fi
done
EOF

# 赋予执行权限
chmod +x /etc/detect_wan.sh

# 添加启动项
cat << 'EOF' > /etc/rc.local
# Put your custom commands here that should be executed once
# the system init finished. By default this file does nothing.
/etc/detect_wan.sh &
sleep 600
/etc/init.d/ddns restart
exit 0
EOF
chmod +x /etc/rc.local  # 保证 /etc/rc.local 的权限

#校正时间
/etc/init.d/sysntpd enable
/etc/init.d/sysntpd start
#
sysctl -p /etc/sysctl.d/*
sysctl -p /etc/sysctl.conf

exit 0
