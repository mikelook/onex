#!/bin/bash
echo -e "\033[46;33m---------------系统配置---------------------------------\033[0m"
apt update --allow-releaseinfo-change
apt upgrade -y
apt-get update -y 
apt-get upgrade -y
apt-get install rsyslog -y
systemctl start rsyslog
systemctl enable rsyslog
apt-get install vim -y
apt-get install touch -y
apt-get install cron -y 
apt-get install iptables -y 
apt-get install fail2ban -y 
apt-get install sudo -y 
apt-get install curl -y 
apt-get install update -y 
systemctl start fail2ban
systemctl enable fail2ban
#apt install selinux-basics selinux-policy-default -y
# 读取用户名作为变量
read -p "请输入用户名: " username

# 添加用户
useradd -m "$username"
if [ $? -ne 0 ]; then
    echo "用户添加失败"
    exit 1
fi

# 更改用户密码
passwd "$username"
if [ $? -ne 0 ]; then
    echo "更改密码失败"
    exit 1
fi

# 切换到新用户
su - "$username" -c "
    # 生成密钥对
    ssh-keygen -t rsa -b 4096 -f /home/$username/.ssh/id_rsa -N ''
    
    # 安装公钥（VPS）
    cd /home/$username/.ssh
    cat id_rsa.pub >> authorized_keys
    cat id_rsa
    
    # 设置权限
    chmod 600 /home/$username/.ssh/authorized_keys
    chmod -R 700 /home/$username/.ssh
    rm -f id_rsa
    
    exit
"

# 切换到 root 用户
su - <<EOF
    # 修改 sudoers 文件
    chmod +w /etc/sudoers
    echo "$username  ALL=(ALL:ALL) ALL" >> /etc/sudoers
    echo "$username ALL=NOPASSWD: ALL" >> /etc/sudoers
    chmod -w /etc/sudoers
EOF



echo -e "\033[46;33m--------------------------修改sshg---------------------------------\033[0m"
cp /etc/ssh/sshd_config /etc/ssh/sshd_config_123backup #没测试
# 提示用户输入新的 SSH 端口号
read -p "请输入新的SSH端口号: " newport
export newport

# 使用 sed 命令修改 sshd_config 中的 Port 参数

# 使用 sed 命令插入新行
sed -i '/^PermitRootLogin yes/d' /etc/ssh/sshd_config
sed -i "2iPort $newport" /etc/ssh/sshd_config
sed -i '3iPubkeyAuthentication yes' /etc/ssh/sshd_config
sed -i '4iPasswordAuthentication no' /etc/ssh/sshd_config
sed -i '5iPermitRootLogin no' /etc/ssh/sshd_config
service ssh restart
echo "修改完成，请查看 vim /etc/ssh/sshd_config"
echo -e "\033[46;33m---------------xray配置---------------------------------\033[0m"
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u root
cd /usr/local/etc/xray
xray uuid > uuid
xray x25519 > key

# 设置 xray key 文件路径
# 输出抓取到的内容
echo -e "\033[46;33m---------------服务配置---------------------------------\033[0m"
mkdir -p /usr/local/etc/xray
key_file="/usr/local/etc/xray/key"

touch xtls.json
read -p "请输入uuid: " uuid
echo "输入的uuid是: $uuid"
read -p "请输入域名带443: " domain
read -p "请输入服务器名1: " domain1
read -p "请输入服务器名2: " domain2
read -p "请输入服务器名3: " domain3
read -p "请输入服务器名4: " domain4
read -p "请输入privatekey: " key
# 判断 key 文件是否存在
if [ -f "$key_file" ]; then
  # 使用 grep 抓取第一行包含 "private key:" 后的内容
  key=$(head -n 1 "$key_file" | awk -F ': ' '{print $2}')
echo "抓取到的内容为: $s"
else
  echo "Key 文件不存在：$key_file"
fi

uuid=$(cat /usr/local/etc/xray/uuid)
config='{
  "log": {
    "loglevel": "info",
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log"
  },
  "api": {
    "tag": "api",
    "services": [
      "HandlerService",
      "LoggerService",
      "StatsService"
    ]
  },
  "stats": {},
  "policy": {
    "levels": {
      "0": {
        "statsUserUplink": true,
        "statsUserDownlink": true
      }
    },
    "system": {
      "statsInboundUplink": true,
      "statsInboundDownlink": true,
      "statsOutboundUplink": true,
      "statsOutboundDownlink": true
    }
  },
  "dns": {
    "servers": [
      "https+local://cloudflare-dns.com/dns-query",
      "1.1.1.1",
      "1.0.0.1",
      "8.8.8.8",
      "8.8.4.4",
      "localhost"
    ]
  },
  "inbounds": [
    {
      "listen": "0.0.0.0",
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": '"$uuid"',
            "flow": "xtls-rprx-vision"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": true,
          "dest": "'"$domain"'",
          "xver": 0,
          "maxTimeDiff": 0,
          "minClientVer": "",
          "serverNames": [
            "'"$domain1"'",
            "'"$domain2"'",
            "'"$domain3"'",
            "'"$domain4"'"    
          ],
          "privateKey": "'"$key"'",
          "shortIds": [
            "16",
            "1688",
            "168888",
            "16888888",
            "1688888888",
            "168888888888",
            "16888888888888",
            "1688888888888888"
          ]
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
      "tag": "direct"
    },
    {
      "protocol": "blackhole",
      "tag": "blocked"
    }
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {
        "inboundTag": [
          "api"
        ],
        "outboundTag": "api",
        "type": "field"
      },
      {
        "domain": [
          "domain:iqiyi.com",
          "domain:video.qq.com",
          "domain:youku.com"
        ],
        "type": "field",
        "outboundTag": "blocked"
      },
      {
        "type": "field",
        "ip": [
          "geoip:cn",
          "geoip:private"
        ],
        "outboundTag": "blocked"
      },
      {
        "protocol": [
          "bittorrent"
        ],
        "type": "field",
        "outboundTag": "blocked"
      }
    ]
  }
}'
echo "$config" > /usr/local/etc/xray/xtls.json
echo "配置文件已生成。"
systemctl start xray@xtls.service
cat /usr/local/etc/xray/uuid
cat /usr/local/etc/xray/key
echo "systemctl status xray@xtls.service"

echo -e " \033[46;33m----------------BSR---------------------------------\033[0m"
#修改系统变量
echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
#保存生效
sysctl -p
echo -e "\033[46;33m--------------------------iptables规则---------------------------------\033[0m"
read -p "输入前三位ip" port1 
read -p "输入3-6位ip" port2 
read -p "第二个输入前三位ip" port3 
read -p "第二个输入3-6位ip" port4
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp -s $port1.$port2.0.0/16 -m state --state NEW --dport $newport -j ACCEPT
iptables -A INPUT -p tcp -s $port3.$port4.0.0/16 -m state --state NEW --dport $newport -j ACCEPT
iptables -A INPUT -m state --state INVALID -j DROP
iptables -A INPUT -p tcp -m tcp --dport 53 -j ACCEPT
iptables -A INPUT -p udp -m udp --dport 53 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --dport 443 -j ACCEPT
iptables -A INPUT -p udp -m udp --dport 443 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
iptables -A INPUT -p udp -m udp --dport 80 -j ACCEPT
iptables -A INPUT -p icmp --icmp-type 13 -s 0/0 -j DROP
iptables -A INPUT -p icmp --icmp-type 8 -s 0/0 -j  DROP 
禁止ping
iptables -A INPUT -p icmp --icmp-type 11 -s 0/0 -j  DROP 
禁止traceroute 
iptables -A INPUT -m state --state INVALID -j DROP
删除 iptables -D INPUT 3  
iptables -A OUTPUT -p tcp -m tcp --dport 443 -j ACCEPT
iptables -A OUTPUT -p tcp -d $port1.$port2.0.0/16 -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp -d $port3.$port4.0.0/16 -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT
iptables -P OUTPUT DROP
iptables -P INPUT DROP
iptables -P FORWARD DROP
ip6tables -P OUTPUT DROP
ip6tables -P INPUT DROP
ip6tables -P FORWARD DROP
iptables-save
ip6tables-save
iptables-save > /etc/iptables.conf
ip6tables-save > /etc/ip6tables.conf

echo -e "\033[46;33m--------------------------编辑该自启动配置文件，内容为启动网络时恢复iptables配置---------------------------------\033[0m"
touch /etc/network/if-pre-up.d/iptables
echo "#!/bin/bash" >> /etc/network/if-pre-up.d/iptables
echo "/sbin/iptables-restore < /etc/iptables.conf" >> /etc/network/if-pre-up.d/iptables
echo "/sbin/ip6tables-restore < /etc/ip6tables.conf" >> /etc/network/if-pre-up.d/iptables
chmod +x /etc/network/if-pre-up.d/iptables #授权执行

echo -e "\033[46;33m--------------------------fail2ban---------------------------------\033[0m"
cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
# 删除 /etc/fail2ban/jail.local 文件中第 280, 281, 282 行
#sed -i '100,115d' /etc/fail2ban/jail.local
sed -i '245,272d' /etc/fail2ban/jail.local
# 在第 42 行后插入新的参数
sed -i '42a\bantime = 100000\nfindtime = 1000\nmaxretry = 2\nmaxmatches = 2' /etc/fail2ban/jail.local
# 在文件末尾添加新的 SSH 限制规则
cat <<EOL >> /etc/fail2ban/jail.local
[sshd]
enabled  = true
port     = ssh
filter   = sshd
logpath  = /var/log/auth.log   # 对于 Ubuntu 和 Debian
# logpath = /var/log/secure     # 对于 CentOS 或 RedHat
maxretry = 3   # 允许最大尝试次数，超过将被封禁
bantime  = 600 # 封禁时间（秒），例如600秒=10分钟
findtime = -1 # 监控时间窗口（秒），在该时间内超过 maxretry 将触发封禁
[sshlongterm]
port = ssh
logpath =  /var/log/auth.log
banaction = iptables-multiport
maxretry = 2
findtime = 3600
bantime = -1
enabled = true
filter = sshd
[v2]
enabled = true
logpath = /var/log/xray/access.log  
port = 443
bantime = -1
maxretry = 3
findtime = 600
EOL

echo -e "\033[46;33mFail2ban SSH 配置修改成功！\033[0m"

echo "bantime 1000000000----findtime 3m----maxretry=2----false=ture"

echo -e "\033[46;33m-------------------------安装完成---------------------------------\033[0m"
cat /usr/local/etc/xray/uuid
cat /usr/local/etc/xray/key
echo "systemctl status xray@xtls.service"
echo "systemctl restart xray@xtls.service"
echo "systemctl start xray@xtls.service"

