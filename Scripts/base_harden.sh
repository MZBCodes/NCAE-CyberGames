if [ "$(id -u)" != "0" ]; then
    echo "This script must be run as root"
    exit 1
fi

FTP_ADDR="172.18.14.9"
WEB_ADDR="192.168.9.5"
DB_ADDR="192.168.9.7"
DNS_ADDR="192.168.9.12"

CURRENT_IP=$(hostname -I | awk '{print $1}')  

randomize_all_passwords() {
    if [[ "$CURRENT_IP" == "$FTP_ADDR" ]]; then
        echo "[!] This machine is the FTP server ($FTP_ADDR). Exiting..."
	echo "[+] Setting up rbash for all non-root shell users..."

	# Ensure rbash exists
	if ! command -v rbash &>/dev/null; then
            echo "[!] rbash not found! Please install it first."
            return
	fi
	
	# Loop through all non-root users with valid shell access
	for u in $(awk -F: '/\/bin\/.*sh/ && $1 != "root" {print $1}' /etc/passwd); do
            echo "[+] Setting rbash for user: $u"
            
            # Change shell to rbash
            usermod -s /bin/rbash "$u"
            
            # Restrict user's home directory
            chmod 750 "/home/$u"
            
            # Create a limited environment for rbash
            mkdir -p "/home/$u/rbin"
            chmod 755 "/home/$u/rbin"
            
            # Restrict PATH to only the user's restricted bin
            echo "export PATH=/home/$u/rbin" >> "/home/$u/.bashrc"
            
            # Restrict editing of profile files
            chattr +i "/home/$u/.bashrc"
            chattr +i "/home/$u/.bash_profile"
	done
	
	echo "[+] rbash setup completed."
	return
    fi

    #randomizes all non root passwords
    for u in $(cat /etc/passwd | grep -E "/bin/.*sh" | grep -v "root" | cut -d":" -f1); do	
	ns=$(date +%N)
	pw=$(echo "${ns}$REPLY" | sha256sum | cut -d" " -f1)	
	
	echo "$u:$pw" | chpasswd	
	
	echo "$u,$pw"
	usermod -s "/bin/false" "$u" 
	
    done
}


lock_all_service_accounts() {
    for u in $(cat /etc/passwd | grep -vE "/bin/.*sh" | cut -d":" -f1); do
	passwd -l $u;
    done
}

harden_sudoers() {
    echo "[+] Hardening Sudoers file..."
    
    # Remove all custom sudoers files
    find /etc/sudoers.d/ -mindepth 1 -delete
    
    # Determine the correct sudo group
    if grep -i "rocky" /etc/os-release; then
        SUDO_GROUP="wheel"
    else
        SUDO_GROUP="sudo"
    fi
    
    # Overwrite /etc/sudoers with a hardened configuration
    cat <<EOF > /etc/sudoers
Defaults env_reset
Defaults mail_badpass
Defaults secure_path=/usr/sbin:/usr/bin:/sbin:/bin

root ALL=(ALL:ALL) ALL
%$SUDO_GROUP ALL=(ALL:ALL) ALL
EOF
    echo "[+] Sudoers file hardened for group: $SUDO_GROUP"
}

disable_cron() {
    echo "[+] Disabling Cron"
    systemctl mask --now cron
}

remove_profiles() {
    echo "[+] Removing all profiles"
    mv /etc/prof{i,y}le.d 2>/dev/null
    mv /etc/prof{i,y}le 2>/dev/null
    for f in '.bash_profile' '.profile' '.bashrc' '.bash_login'; do
	find /home /root -name "$f" -exec rm {} \;
    done
    ln -sf /dev/null /etc/bash.bashrc
}

remove_compilers() {
    echo "[+] Removing Compilers and disabling kernel module insertion"
    /sbin/sysctl -w kernel.modules_disabled=1
    if command -v gcc &> /dev/null; then
	rm `which gcc`
    else
	echo "  - gcc not found"
    fi
    if command -v g++ &> /dev/null; then
        rm `which g++`
    else
        echo "  - g++ not found"
    fi
    if command -v cc &> /dev/null; then
        rm `which cc`
    else
        echo "  - cc not found"
    fi
}

disable_history() {
    echo "[+] Disabling root history"
    ln -sf /dev/null /root/.bash_history
}

clear_ld_preload() {
    echo "[+] Disabling LD Preload"
    export LD_PRELOAD=""
    ln -sf /dev/null /etc/ld.so.preload
}

sysctl_hardening() {
    echo "[+] Hardening sysctl"
    cat <<-EOF >> /etc/sysctl.conf
    net.ipv6.conf.all.disable_ipv6=1
    net.ipv6.conf.default.disable_ipv6=1
    net.ipv4.tcp_syncookies=1
    net.ipv4.tcp_rfc1337=1
    net.ipv4.icmp_ignore_bogus_error_responses=1
    net.ipv4.conf.all.accept_redirects=0
    net.ipv4.icmp_echo_ignore_all=1
    fs.suid_dumpable=0
    kernel.kptr_restrict=2
    kernel.perf_event_paranoid=2
    kernel.randomize_va_space=2
    kernel.yama.ptrace_scope=3
    kernel.ftrace_enabled=0
    kernel.modules_disabled=1
    kernel.kexec_load_disabled=1
    kernel.unprivileged_bpf_disabled=1
    net.core.bpf_jit_harden=2
    net.core.bpf_jit_kallsyms=0
EOF
    sysctl -p

}

harden_sshd() {
    if [[ "$CURRENT_IP" == "$FTP_ADDR" ]]; then
	cat <<EOF >> /etc/ssh/sshd_config
PermitRootLogin no
PubkeyAuthentication yes 
UsePAM no 
UseDNS no
AddressFamily inet
Match Address 172.18.12.15
    PermitRootLogin yes
EOF
    else
	cat <<EOF >> /etc/ssh/sshd_config
PermitRootLogin no
PubkeyAuthentication no
UsePAM no 
UseDNS no
AddressFamily inet
Match Address 172.18.12.15
    PermitRootLogin yes
EOF
    fi
}

remove_admin_users() {
    # Determine the correct sudo group
    if grep -i "rocky" /etc/os-release; then
        SUDO_GROUP="wheel"
    else
        SUDO_GROUP="sudo"
    fi

    users=$(grep "^$SUDO_GROUP:" /etc/group | tr ":" " " | cut -d' ' -f4- | tr "," " ")
    echo "Current admin users: $users"

    echo "[+] Removing old admin users"
    for user in $users; do
        gpasswd -d "$user" $SUDO_GROUP
    done
}

configure_firewall() {
    echo "[+] Disabling firewall wrappers..."
    systemctl stop firewalld 2>/dev/null
    systemctl disable firewalld 2>/dev/null
    systemctl stop ufw 2>/dev/null
    systemctl disable ufw 2>/dev/null
    systemctl stop nftables 2>/dev/null
    systemctl disable nftables 2>/dev/null

    echo "[+] Flushing existing iptables rules..."
    iptables -F
    iptables -X
    iptables -Z

    echo "[+] Setting up new iptables rules..."
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT DROP

    # Allow loopback traffic
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT

    # Allow established connections
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # Allow SSH
    iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT
    iptables -A OUTPUT -p tcp --sport 22 -m conntrack --ctstate ESTABLISHED -j ACCEPT


    # Allow specific services based on the machine's IP
    if [[ "$CURRENT_IP" == "$WEB_ADDR" ]]; then
	echo "[+] This is the web server ($WEB_ADDR), allowing HTTP and HTTPS..."
	iptables -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT
	iptables -A INPUT -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT
    fi
    
    if [[ "$CURRENT_IP" == "$FTP_ADDR" ]]; then
	echo "[+] This is the FTP server ($FTP_ADDR), allowing FTP traffic..."
	iptables -A INPUT -p tcp --dport 21 -m conntrack --ctstate NEW -j ACCEPT
	iptables -A INPUT -p tcp --dport 40000:50000 -m conntrack --ctstate NEW -j ACCEPT  # Passive FTP range
    fi
    
    if [[ "$CURRENT_IP" == "$DNS_ADDR" ]]; then
	echo "[+] This is the DNS server ($DNS_ADDR), allowing DNS traffic..."
	iptables -A INPUT -p udp --dport 53 -j ACCEPT
	iptables -A INPUT -p tcp --dport 53 -j ACCEPT
    fi
    
    if [[ "$CURRENT_IP" == "$DB_ADDR" ]]; then
	echo "[+] This is the database server ($DB_ADDR), allowing PostgreSQL..."
	iptables -A INPUT -p tcp --dport 5432 -m conntrack --ctstate NEW -j ACCEPT
    fi
    
    echo "[+] Saving iptables rules..."
    if command -v iptables-save &>/dev/null; then
	iptables-save > /etc/iptables.rules
	echo "iptables-save completed."
    else
	echo "iptables-save not found, rules may not persist after reboot."
    fi
}

echo "Running Hardening Scripts..."
randomize_all_passwords
lock_all_service_accounts
remove_admin_users
harden_sshd
clear_ld_preload 
harden_sudoers
configure_firewall
disable_history
disable_cron
remove_profiles
sysctl_hardening
remove_compilers
