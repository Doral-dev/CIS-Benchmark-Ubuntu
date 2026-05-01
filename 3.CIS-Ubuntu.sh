#!/usr/bin/env bash

# Ejecutar con este comando:
# sudo bash <nombre_archivo.sh>

set -euo pipefail

MODE="${1:--s}"

if [[ "$EUID" -ne 0 ]]; then
  echo "Ejecuta como root:"
  echo "sudo bash $0 $MODE"
  exit 1
fi

BOLD="$(tput bold 2>/dev/null || true)"
RESET="$(tput sgr0 2>/dev/null || true)"

if [[ "$MODE" != "-s" && "$MODE" != "-d" ]]; then
  echo "Ejecutar script en modo silencioso: sudo bash $0 -s"
  echo "Ejecutar script en modo detallado: sudo bash $0 -d"
  exit 1
fi

echo
echo "------------------------------------------------------------"
echo "${BOLD}SCRIPT DE AUTOMATIZACIÓN - POLÍTICAS DE CUMPLIMIENTO CIS UBUNTU${RESET}"
echo "------------------------------------------------------------"

echo
echo "${BOLD}1. INTRODUCCIÓN${RESET}"
echo "Este script ejecuta correcciones básicas de seguridad en el sistema Ubuntu para aplicar las políticas de cumplimiento del CIS Benchmark de Wazuh."
echo
echo "Ejecutar script en modo silencioso: sudo bash $0 -s"
echo "Ejecutar script en modo detallado: sudo bash $0 -d"
echo
read -rp "Pulsa INTRO para continuar..."

if [[ "$EUID" -ne 0 ]]; then
  echo "Ejecuta como root: sudo bash $0"
  exit 1
fi

echo
echo
echo
echo "${BOLD}2. CONFIGURAR IDIOMA DEL SISTEMA${RESET}"
echo "IMPORTANTE: Wazuh compara textos del sistema. Para que las políticas coincidan y puedan ser aplicadas correctamente, es necesario configurar el idioma del sistema en inglés."
read -rp "¿Quieres cambiar el idioma del sistema a inglés ahora? (s/n): " CHANGE_LANG

if [[ "$MODE" == "-d" ]]; then
  set -x
fi

run() {
  if [[ "$MODE" == "-s" ]]; then
    "$@" >/dev/null 2>&1
  else
    "$@"
  fi
}

wait_apt() {
  while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || fuser /var/lib/dpkg/lock >/dev/null 2>&1; do
    sleep 5
  done
}

if [[ "$CHANGE_LANG" =~ ^[sS]$ ]]; then
  wait_apt
  run apt-get update -qq
  wait_apt
  run apt-get install -y -qq locales
  run locale-gen en_US.UTF-8
  run update-locale LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8 LANGUAGE=en_US:en

  echo "Idioma cambiado a inglés."
  read -rp "Es necesario reiniciar ¿Quieres hacerlo ahora? (s/n): " REBOOT_NOW

  if [[ "$REBOOT_NOW" =~ ^[sS]$ ]]; then
    run systemctl reboot
    exit 0
  fi
fi

BACKUP_DIR="/root/cis_ubuntu_backups/$(date +%Y%m%d_%H%M%S)"
FSTAB="/etc/fstab"
MARK="# CIS-WAZUH"

mkdir -p "$BACKUP_DIR"
cp -a "$FSTAB" "$BACKUP_DIR/fstab.bak"


POLICY_COUNT=0

policy() {
  POLICY_COUNT=$((POLICY_COUNT + 1))
  echo
  echo "------------------------------------------------------------"
  echo "POLÍTICA Nº $POLICY_COUNT"
  echo "ID $1 - $2"
  echo "$3"
}

applied() {
  echo "Política aplicada ✅"
}

not_applied() {
  echo "Esta política no se va a ejecutar ❌"
}

remove_old_cis_entries() {
  sed -i "\|$MARK|d" "$FSTAB"
}

add_fstab_line() {
  echo "$1 $MARK" >> "$FSTAB"
}

ensure_dir() {
  mkdir -p "$1"
}

bind_remount() {
  local target="$1"
  local opts="$2"

  ensure_dir "$target"

  if ! mountpoint -q "$target"; then
    run mount --bind "$target" "$target"
  fi

  run mount -o "remount,bind,$opts" "$target"
}

set_grub_param() {
  local param="$1"

  if grep -q "^GRUB_CMDLINE_LINUX=" /etc/default/grub; then
    if ! grep "^GRUB_CMDLINE_LINUX=" /etc/default/grub | grep -q "$param"; then
      sed -i "s/^\(GRUB_CMDLINE_LINUX=\"[^\"]*\)\"/\1 $param\"/" /etc/default/grub
    fi
  else
    echo "GRUB_CMDLINE_LINUX=\"$param\"" >> /etc/default/grub
  fi
}

ensure_sshd_option() {
  local key="$1"
  local value="$2"
  local file="/etc/ssh/sshd_config.d/00-cis-wazuh.conf"

  mkdir -p /etc/ssh/sshd_config.d

  if [[ ! -f "$file" ]]; then
    touch "$file"
  fi

  sed -i "/^[[:space:]]*$key[[:space:]]\+/Id" "$file"
  echo "$key $value" >> "$file"
}

echo
echo
echo
echo "${BOLD}3. CORRECCIÓN DE POLÍTICAS${RESET}"
echo "Actualizando paquetes del sistema..."
wait_apt
run apt-get update -qq
wait_apt
run apt-get upgrade -y -qq
echo "Se van a corregir las políticas seleccionadas."
read -rp "Pulsa INTRO para continuar..."

remove_old_cis_entries

policy "35509" "Ensure unused filesystems kernel modules are not available." "Filesystem kernel modules are pieces of code that can be dynamically loaded into the Linux kernel to extend its filesystem capabilities."
not_applied

policy "35510" "Ensure /tmp is a separate partition." "The /tmp directory is a world-writable directory used for temporary storage by all users and some applications."
run systemctl unmask tmp.mount || true
add_fstab_line "tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime,size=2G 0 0"
run systemctl daemon-reload
mountpoint -q /tmp || run mount -t tmpfs -o defaults,rw,nosuid,nodev,noexec,relatime,size=2G tmpfs /tmp
run mount -o remount,rw,nosuid,nodev,noexec,relatime,size=2G /tmp
applied

policy "35511" "Ensure nodev option set on /tmp partition." "The nodev mount option specifies that the filesystem cannot contain special devices."
run mount -o remount,rw,nosuid,nodev,noexec,relatime,size=2G /tmp
applied

policy "35512" "Ensure nosuid option set on /tmp partition." "The nosuid mount option specifies that the filesystem cannot contain setuid files."
run mount -o remount,rw,nosuid,nodev,noexec,relatime,size=2G /tmp
applied

policy "35513" "Ensure noexec option set on /tmp partition." "The noexec mount option specifies that the filesystem cannot contain executable binaries."
run mount -o remount,rw,nosuid,nodev,noexec,relatime,size=2G /tmp
applied

policy "35517" "Ensure noexec option set on /dev/shm partition." "The noexec mount option specifies that the filesystem cannot contain executable binaries."
add_fstab_line "tmpfs /dev/shm tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0"
run systemctl daemon-reload
run mount -o remount,rw,nosuid,nodev,noexec,relatime /dev/shm
applied

policy "35518" "Ensure separate partition exists for /home." "The /home directory is used to support disk storage needs of local users."
add_fstab_line "/home /home none bind,nodev,nosuid 0 0"
run systemctl daemon-reload
bind_remount "/home" "nodev,nosuid"
applied

policy "35519" "Ensure nodev option set on /home partition." "The nodev mount option specifies that the filesystem cannot contain special devices."
run mount -o remount,bind,nodev,nosuid /home
applied

policy "35520" "Ensure nosuid option set on /home partition." "The nosuid mount option specifies that the filesystem cannot contain setuid files."
run mount -o remount,bind,nodev,nosuid /home
applied

policy "35521" "Ensure separate partition exists for /var." "The /var directory is used by daemons and other system services to temporarily store dynamic data."
add_fstab_line "/var /var none bind,nodev,nosuid 0 0"
run systemctl daemon-reload
bind_remount "/var" "nodev,nosuid"
applied

policy "35522" "Ensure nodev option set on /var partition." "The nodev mount option specifies that the filesystem cannot contain special devices."
run mount -o remount,bind,nodev,nosuid /var
applied

policy "35523" "Ensure nosuid option set on /var partition." "The nosuid mount option specifies that the filesystem cannot contain setuid files."
run mount -o remount,bind,nodev,nosuid /var
applied

policy "35524" "Ensure separate partition exists for /var/tmp." "The /var/tmp directory is a world-writable directory used for temporary storage by all users and some applications."
add_fstab_line "/var/tmp /var/tmp none bind,nodev,nosuid,noexec 0 0"
run systemctl daemon-reload
bind_remount "/var/tmp" "nodev,nosuid,noexec"
applied

policy "35525" "Ensure nodev option set on /var/tmp partition." "The nodev mount option specifies that the filesystem cannot contain special devices."
run mount -o remount,bind,nodev,nosuid,noexec /var/tmp
applied

policy "35526" "Ensure nosuid option set on /var/tmp partition." "The nosuid mount option specifies that the filesystem cannot contain setuid files."
run mount -o remount,bind,nodev,nosuid,noexec /var/tmp
applied

policy "35527" "Ensure noexec option set on /var/tmp partition." "The noexec mount option specifies that the filesystem cannot contain executable binaries."
run mount -o remount,bind,nodev,nosuid,noexec /var/tmp
applied

policy "35528" "Ensure separate partition exists for /var/log." "The /var/log directory is used by system services to store log data."
add_fstab_line "/var/log /var/log none bind,nodev,nosuid,noexec 0 0"
run systemctl daemon-reload
bind_remount "/var/log" "nodev,nosuid,noexec"
applied

policy "35529" "Ensure nodev option set on /var/log partition." "The nodev mount option specifies that the filesystem cannot contain special devices."
run mount -o remount,bind,nodev,nosuid,noexec /var/log
applied

policy "35530" "Ensure nosuid option set on /var/log partition." "The nosuid mount option specifies that the filesystem cannot contain setuid files."
run mount -o remount,bind,nodev,nosuid,noexec /var/log
applied

policy "35531" "Ensure noexec option set on /var/log partition." "The noexec mount option specifies that the filesystem cannot contain executable binaries."
run mount -o remount,bind,nodev,nosuid,noexec /var/log
applied

policy "35532" "Ensure separate partition exists for /var/log/audit." "The auditing daemon, auditd, stores log data in the /var/log/audit directory."
ensure_dir /var/log/audit
add_fstab_line "/var/log/audit /var/log/audit none bind,nodev,nosuid,noexec 0 0"
run systemctl daemon-reload
bind_remount "/var/log/audit" "nodev,nosuid,noexec"
applied

policy "35533" "Ensure nodev option set on /var/log/audit partition." "The nodev mount option specifies that the filesystem cannot contain special devices."
run mount -o remount,bind,nodev,nosuid,noexec /var/log/audit
applied

policy "35534" "Ensure nosuid option set on /var/log/audit partition." "The nosuid mount option specifies that the filesystem cannot contain setuid files."
run mount -o remount,bind,nodev,nosuid,noexec /var/log/audit
applied

policy "35535" "Ensure noexec option set on /var/log/audit partition." "The noexec mount option specifies that the filesystem cannot contain executable binaries."
run mount -o remount,bind,nodev,nosuid,noexec /var/log/audit
applied

policy "35536" "Ensure AppArmor is installed." "AppArmor provides Mandatory Access Controls."
wait_apt
run apt-get install -y -qq apparmor apparmor-utils
run systemctl enable --now apparmor
applied

policy "35537" "Ensure AppArmor is enabled in the bootloader configuration." "Configure AppArmor to be enabled at boot time and verify that it has not been overwritten by the bootloader boot parameters."
set_grub_param "apparmor=1"
set_grub_param "security=apparmor"
run update-grub
applied

policy "35538" "Ensure all AppArmor Profiles are in enforce or complain mode." "AppArmor profiles define what resources applications are able to access."
wait_apt
run apt-get install -y -qq apparmor-profiles apparmor-profiles-extra
run aa-complain /etc/apparmor.d/* || true
applied

policy "35539" "Ensure all AppArmor Profiles are enforcing." "AppArmor profiles define what resources applications are able to access."
not_applied

policy "35540" "Ensure bootloader password is set." "Setting the boot loader password will require a password before changing boot parameters."
not_applied

policy "35543" "Ensure core dumps are restricted." "A core dump is the memory of an executable program. It is generally used to determine why a program aborted."
echo "* hard core 0" > /etc/security/limits.d/99-cis-core.conf
echo "fs.suid_dumpable = 0" > /etc/sysctl.d/99-cis-core.conf
run sysctl -w fs.suid_dumpable=0
mkdir -p /etc/systemd/coredump.conf.d
cat > /etc/systemd/coredump.conf.d/99-cis.conf <<EOF
[Coredump]
Storage=none
ProcessSizeMax=0
EOF
run systemctl daemon-reload
applied

policy "35545" "Ensure Automatic Error Reporting is not enabled." "The Apport Error Reporting Service automatically generates crash reports for debugging."
run systemctl disable --now apport.service || true
if [[ -f /etc/default/apport ]]; then
  sed -i 's/^enabled=.*/enabled=0/' /etc/default/apport
else
  echo "enabled=0" > /etc/default/apport
fi
applied

policy "35547" "Ensure local login warning banner is configured properly." "The contents of the /etc/issue file are displayed to users prior to login for local terminals."
echo "Authorized users only. All activity may be monitored and reported." > /etc/issue
applied

policy "35548" "Ensure remote login warning banner is configured properly." "The contents of the /etc/issue.net file are displayed to users prior to login for remote connections from configured services."
echo "Authorized users only. All activity may be monitored and reported." > /etc/issue.net
applied

policy "35552" "Ensure GDM is removed." "The GNOME Display Manager manages graphical display servers and graphical user logins."
not_applied

policy "35553" "Ensure GDM login banner is configured." "GDM is the GNOME Display Manager which handles graphical login for GNOME based systems."
not_applied

policy "35562" "Ensure avahi daemon services are not in use." "Avahi is used for multicast DNS and local network service discovery."
run systemctl disable --now avahi-daemon.service avahi-daemon.socket || true
wait_apt
run apt-get purge -y -qq avahi-daemon || true
applied

policy "35571" "Ensure print server services are not in use." "CUPS provides print server services."
run systemctl disable --now cups.service cups.socket || true
wait_apt
run apt-get purge -y -qq cups || true
applied

policy "35573" "Ensure rsync services are not in use." "The rsync service can be used to synchronize files between systems over network links."
run systemctl disable --now rsync.service || true
wait_apt
run apt-get purge -y -qq rsync || true
applied

policy "35580" "Ensure X window server services are not in use." "The X Window System provides a graphical user interface."
not_applied

policy "35585" "Ensure telnet client is not installed." "The telnet client allows connections to other systems using the insecure telnet protocol."
wait_apt
run apt-get purge -y -qq telnet inetutils-telnet || true
applied

policy "35586" "Ensure ldap client is not installed." "LDAP provides a method for looking up information from a central database."
wait_apt
run apt-get purge -y -qq ldap-utils || true
applied

policy "35587" "Ensure ftp client is not installed." "FTP allows file transfer to and from remote network sites."
wait_apt
run apt-get purge -y -qq ftp tnftp || true
applied

policy "35589" "Ensure systemd-timesyncd is enabled and running." "systemd-timesyncd is a daemon for synchronizing the system clock across the network."
not_applied

policy "35591" "Ensure chrony is running as user _chrony." "The chrony package is installed with a dedicated user account _chrony."
wait_apt
run apt-get install -y -qq chrony
run systemctl disable --now systemd-timesyncd.service || true
run systemctl mask systemd-timesyncd.service || true
mkdir -p /etc/chrony/conf.d
echo "user _chrony" > /etc/chrony/conf.d/99-cis-user.conf
run systemctl unmask chrony.service || true
run systemctl enable --now chrony.service
run systemctl restart chrony.service
applied

policy "35592" "Ensure chrony is enabled and running." "chrony is a daemon for synchronizing the system clock across the network."
run systemctl disable --now systemd-timesyncd.service || true
run systemctl mask systemd-timesyncd.service || true
run systemctl unmask chrony.service || true
run systemctl enable --now chrony.service
run systemctl restart chrony.service
applied

policy "35594" "Ensure permissions on /etc/crontab are configured." "The /etc/crontab file is used by cron to control its own jobs."
run chown root:root /etc/crontab
run chmod 600 /etc/crontab
applied

policy "35595" "Ensure permissions on /etc/cron.hourly are configured." "This directory contains system cron jobs that need to run on an hourly basis."
run chown root:root /etc/cron.hourly
run chmod 700 /etc/cron.hourly
applied

policy "35596" "Ensure permissions on /etc/cron.daily are configured." "The /etc/cron.daily directory contains system cron jobs that need to run on a daily basis."
run chown root:root /etc/cron.daily
run chmod 700 /etc/cron.daily
applied

policy "35597" "Ensure permissions on /etc/cron.weekly are configured." "The /etc/cron.weekly directory contains system cron jobs that need to run on a weekly basis."
run chown root:root /etc/cron.weekly
run chmod 700 /etc/cron.weekly
applied

policy "35598" "Ensure permissions on /etc/cron.monthly are configured." "The /etc/cron.monthly directory contains system cron jobs that need to run on a monthly basis."
run chown root:root /etc/cron.monthly
run chmod 700 /etc/cron.monthly
applied

policy "35599" "Ensure permissions on /etc/cron.d are configured." "The /etc/cron.d directory contains system cron jobs that need more granular control."
run chown root:root /etc/cron.d
run chmod 700 /etc/cron.d
applied

policy "35600" "Ensure crontab is restricted to authorized users." "The cron.allow file controls which users are allowed to use crontab."
touch /etc/cron.allow
run chmod 640 /etc/cron.allow
run chown root:root /etc/cron.allow
if [[ -f /etc/cron.deny ]]; then
  run chmod 640 /etc/cron.deny
  run chown root:root /etc/cron.deny
fi
applied

policy "35601" "Ensure at is restricted to authorized users." "The at.allow file controls which users are allowed to use at jobs."
wait_apt
run apt-get install -y -qq at
touch /etc/at.allow
if grep -q '^daemon:' /etc/group; then
  run chown root:daemon /etc/at.allow
else
  run chown root:root /etc/at.allow
fi
run chmod 640 /etc/at.allow
if [[ -f /etc/at.deny ]]; then
  if grep -q '^daemon:' /etc/group; then
    run chown root:daemon /etc/at.deny
  else
    run chown root:root /etc/at.deny
  fi
  run chmod 640 /etc/at.deny
fi
applied

policy "35602" "Ensure wireless interfaces are disabled." "Wireless interfaces allow wireless network connections."
not_applied

policy "35604" "Ensure dccp kernel module is not available." "DCCP is a transport layer protocol that is rarely used."
cat > /etc/modprobe.d/dccp.conf <<EOF
install dccp /bin/false
blacklist dccp
EOF
run modprobe -r dccp || true
applied

policy "35605" "Ensure tipc kernel module is not available." "TIPC is a protocol used for cluster communication."
cat > /etc/modprobe.d/tipc.conf <<EOF
install tipc /bin/false
blacklist tipc
EOF
run modprobe -r tipc || true
applied

policy "35606" "Ensure rds kernel module is not available." "RDS is a protocol mostly used by specialized database environments."
cat > /etc/modprobe.d/rds.conf <<EOF
install rds /bin/false
blacklist rds
EOF
run modprobe -r rds || true
applied

policy "35607" "Ensure sctp kernel module is not available." "SCTP is a transport protocol normally used in telecom or specialized systems."
cat > /etc/modprobe.d/sctp.conf <<EOF
install sctp /bin/false
blacklist sctp
EOF
run modprobe -r sctp || true
applied

policy "35609" "Ensure packet redirect sending is disabled." "Packet redirect sending allows the system to tell other hosts to use a different route."
cat > /etc/sysctl.d/99-cis-network.conf <<EOF
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
EOF
run sysctl -w net.ipv4.conf.all.send_redirects=0
run sysctl -w net.ipv4.conf.default.send_redirects=0
applied

policy "35612" "Ensure icmp redirects are not accepted." "ICMP redirects can change routing decisions and may be abused."
cat >> /etc/sysctl.d/99-cis-network.conf <<EOF
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
EOF
run sysctl -w net.ipv4.conf.all.accept_redirects=0
run sysctl -w net.ipv4.conf.default.accept_redirects=0
run sysctl -w net.ipv6.conf.all.accept_redirects=0 || true
run sysctl -w net.ipv6.conf.default.accept_redirects=0 || true
applied

policy "35613" "Ensure secure icmp redirects are not accepted." "Secure ICMP redirects can still be abused to alter network routes."
cat >> /etc/sysctl.d/99-cis-network.conf <<EOF
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
EOF
run sysctl -w net.ipv4.conf.all.secure_redirects=0
run sysctl -w net.ipv4.conf.default.secure_redirects=0
applied

policy "35614" "Ensure reverse path filtering is enabled." "Reverse path filtering helps block packets with suspicious or spoofed source addresses."
cat >> /etc/sysctl.d/99-cis-network.conf <<EOF
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
EOF
run sysctl -w net.ipv4.conf.all.rp_filter=1
run sysctl -w net.ipv4.conf.default.rp_filter=1
applied

policy "35615" "Ensure source routed packets are not accepted." "Source routed packets allow senders to define the network path."
cat >> /etc/sysctl.d/99-cis-network.conf <<EOF
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
EOF
run sysctl -w net.ipv4.conf.all.accept_source_route=0
run sysctl -w net.ipv4.conf.default.accept_source_route=0
run sysctl -w net.ipv6.conf.all.accept_source_route=0 || true
run sysctl -w net.ipv6.conf.default.accept_source_route=0 || true
applied

policy "35616" "Ensure suspicious packets are logged." "Martian logging records suspicious packets in system logs."
cat >> /etc/sysctl.d/99-cis-network.conf <<EOF
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
EOF
cat > /etc/sysctl.d/99-z-cis-log-martians.conf <<EOF
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
EOF
run sysctl -w net.ipv4.conf.all.log_martians=1
run sysctl -w net.ipv4.conf.default.log_martians=1
run sysctl -w net.ipv4.route.flush=1
applied

policy "35618" "Ensure ipv6 router advertisements are not accepted." "IPv6 router advertisements can automatically configure network routes."
cat >> /etc/sysctl.d/99-cis-network.conf <<EOF
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
EOF
run sysctl -w net.ipv6.conf.all.accept_ra=0 || true
run sysctl -w net.ipv6.conf.default.accept_ra=0 || true
applied

policy "35619" "Ensure a single firewall configuration utility is in use." "Only one firewall management tool should be used to avoid conflicting rules."
wait_apt
run apt-get install -y -qq ufw
run systemctl disable --now nftables.service || true
applied

policy "35622" "Ensure ufw service is enabled." "UFW is the selected firewall utility for this system."
wait_apt
run apt-get install -y -qq ufw
run ufw allow 22/tcp
run ufw allow 1514/tcp
run ufw allow 1515/tcp
run ufw allow 55000/tcp
run ufw --force enable
run systemctl enable --now ufw
applied

policy "35623" "Ensure ufw loopback traffic is configured." "Loopback traffic is internal traffic used by the local system."
run ufw allow in on lo
run ufw allow out on lo
run ufw deny in from 127.0.0.0/8
run ufw deny in from ::1
applied

policy "35624" "Ensure ufw default deny firewall policy." "Default deny blocks unsolicited incoming traffic and controls routed traffic."
not_applied

policy "35625" "Ensure nftables is installed." "nftables provides a new in-kernel packet classification framework."
not_applied

policy "35626" "Ensure ufw is uninstalled or disabled with nftables." "Uncomplicated Firewall (UFW) is a program for managing a netfilter firewall designed to be easy to use."
not_applied

policy "35627" "Ensure iptables are flushed with nftables." "nftables is a replacement for iptables, ip6tables, ebtables and arptables."
not_applied

policy "35628" "Ensure a nftables table exists." "This applies when nftables is used as the firewall."
not_applied

policy "35629" "Ensure nftables base chains exist." "This applies when nftables is used as the firewall."
not_applied

policy "35630" "Ensure nftables default deny firewall policy." "This applies when nftables is used as the firewall."
not_applied

policy "35631" "Ensure nftables service is enabled." "This applies when nftables is used as the firewall."
not_applied

policy "35632" "Ensure nftables rules are permanent." "This applies when nftables is used as the firewall."
not_applied

policy "35633" "Ensure iptables packages are installed." "iptables is a firewall utility."
not_applied

policy "35634" "Ensure nftables is not in use with iptables." "Only one firewall backend should be used to avoid conflicts."
not_applied

policy "35635" "Ensure ufw is not in use with iptables." "UFW should not be mixed with direct iptables management."
not_applied

policy "35636" "Ensure iptables default deny firewall policy." "This applies when iptables is used as the firewall."
not_applied

policy "35637" "Ensure iptables loopback traffic is configured." "This applies when iptables is used as the firewall."
not_applied

policy "35638" "Ensure ip6tables default deny firewall policy." "This applies when iptables is used as the firewall."
not_applied

policy "35639" "Ensure ip6tables loopback traffic is configured." "This applies when iptables is used as the firewall."
not_applied

policy "35640" "Ensure permissions on /etc/ssh/sshd_config are configured." "The /etc/ssh/sshd_config file contains configuration data for sshd."

wait_apt
run apt-get install -y -qq openssh-server
mkdir -p /run/sshd
mkdir -p /etc/ssh/sshd_config.d

if [[ -f /etc/ssh/sshd_config ]]; then
  cp -a /etc/ssh/sshd_config "$BACKUP_DIR/sshd_config.bak"
  run chown root:root /etc/ssh/sshd_config || true
  run chmod 600 /etc/ssh/sshd_config || true
fi

if [[ -d /etc/ssh/sshd_config.d ]]; then
  find /etc/ssh/sshd_config.d -type f -name "*.conf" -exec chown root:root {} \; 2>/dev/null || true
  find /etc/ssh/sshd_config.d -type f -name "*.conf" -exec chmod 600 {} \; 2>/dev/null || true
fi

applied

policy "35643" "Ensure sshd access is configured." "There are several options available to limit which users and group can access the system via SSH."
groupadd -f sshusers

awk -F: '($3 >= 1000 && $1 != "nobody") {print $1}' /etc/passwd | while read -r USERNAME; do
  usermod -aG sshusers "$USERNAME" 2>/dev/null || true
done

if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
  usermod -aG sshusers "$SUDO_USER" 2>/dev/null || true
fi

ensure_sshd_option "AllowGroups" "sshusers"
applied

policy "35644" "Ensure sshd Banner is configured." "The Banner parameter specifies a file whose contents must be sent to the remote user before authentication is permitted."
echo "Authorized users only. All activity may be monitored and reported." > /etc/issue.net
ensure_sshd_option "Banner" "/etc/issue.net"
applied

policy "35646" "Ensure sshd ClientAliveInterval and ClientAliveCountMax are configured." "The two options ClientAliveInterval and ClientAliveCountMax control the timeout of SSH sessions."
ensure_sshd_option "ClientAliveInterval" "15"
ensure_sshd_option "ClientAliveCountMax" "3"
applied

policy "35647" "Ensure sshd DisableForwarding is enabled." "The DisableForwarding parameter disables all forwarding features, including X11, ssh-agent, TCP and StreamLocal."
ensure_sshd_option "DisableForwarding" "yes"
applied

policy "35648" "Ensure sshd GSSAPIAuthentication is disabled." "The GSSAPIAuthentication parameter specifies whether user authentication based on GSSAPI is allowed."
ensure_sshd_option "GSSAPIAuthentication" "no"
applied

policy "35649" "Ensure sshd HostbasedAuthentication is disabled." "The HostbasedAuthentication parameter specifies if authentication is allowed through trusted hosts."
ensure_sshd_option "HostbasedAuthentication" "no"
applied

policy "35650" "Ensure sshd IgnoreRhosts is enabled." "The IgnoreRhosts parameter specifies that .rhosts and .shosts files will not be used."
ensure_sshd_option "IgnoreRhosts" "yes"
applied

policy "35652" "Ensure sshd LoginGraceTime is configured." "The LoginGraceTime parameter specifies the time allowed for successful authentication to the SSH server."
ensure_sshd_option "LoginGraceTime" "60"
applied

policy "35653" "Ensure sshd LogLevel is configured." "SSH provides several logging levels with varying amounts of verbosity."
ensure_sshd_option "LogLevel" "VERBOSE"
applied

policy "35655" "Ensure sshd MaxAuthTries is configured." "The MaxAuthTries parameter specifies the maximum number of authentication attempts permitted per connection."
ensure_sshd_option "MaxAuthTries" "4"
applied

policy "35656" "Ensure sshd MaxSessions is configured." "The MaxSessions parameter specifies the maximum number of open sessions permitted from a given connection."
ensure_sshd_option "MaxSessions" "10"
applied

policy "35657" "Ensure sshd MaxStartups is configured." "The MaxStartups parameter specifies the maximum number of concurrent unauthenticated connections to the SSH daemon."
ensure_sshd_option "MaxStartups" "10:30:60"
applied

policy "35658" "Ensure sshd PermitEmptyPasswords is disabled." "The PermitEmptyPasswords parameter specifies if the SSH server allows login to accounts with empty password strings."
ensure_sshd_option "PermitEmptyPasswords" "no"
applied

policy "35659" "Ensure sshd PermitRootLogin is disabled." "The PermitRootLogin parameter specifies if the root user can log in using SSH."
ensure_sshd_option "PermitRootLogin" "no"
applied

policy "35660" "Ensure sshd PermitUserEnvironment is disabled." "The PermitUserEnvironment option allows users to present environment options to the SSH daemon."
ensure_sshd_option "PermitUserEnvironment" "no"
applied

policy "35661" "Ensure sshd UsePAM is enabled." "The UsePAM directive enables the Pluggable Authentication Module interface."
ensure_sshd_option "UsePAM" "yes"

chown root:root /etc/ssh/sshd_config.d/00-cis-wazuh.conf
chmod 600 /etc/ssh/sshd_config.d/00-cis-wazuh.conf

if command -v sshd >/dev/null 2>&1 && sshd -t; then
  run systemctl enable ssh
  run systemctl restart ssh
  applied
else
  echo "SSH no ha validado correctamente. Revisa con: sudo sshd -t"
  echo "Política NO aplicada ❌"
fi

policy "35664" "Ensure sudo log file exists." "sudo can use a dedicated log file to record sudo command usage."
echo 'Defaults logfile=/var/log/sudo.log' > /etc/sudoers.d/01_cis_sudo_log
run chmod 440 /etc/sudoers.d/01_cis_sudo_log
run chown root:root /etc/sudoers.d/01_cis_sudo_log
touch /var/log/sudo.log
run chmod 600 /var/log/sudo.log
run chown root:root /var/log/sudo.log

if visudo -cf /etc/sudoers.d/01_cis_sudo_log >/dev/null 2>&1; then
  applied
else
  rm -f /etc/sudoers.d/01_cis_sudo_log
  echo "Política NO aplicada ❌"
fi

policy "35668" "Ensure access to the su command is restricted." "The su command allows users to switch to another user account."
run groupadd -f sugroup
if ! grep -q "pam_wheel.so use_uid group=sugroup" /etc/pam.d/su; then
  echo "auth required pam_wheel.so use_uid group=sugroup" >> /etc/pam.d/su
fi
applied

policy "35673" "Ensure pam_faillock module is enabled." "pam_faillock locks accounts after repeated failed login attempts."
wait_apt
run apt-get install -y -qq libpam-modules
cat > /usr/share/pam-configs/faillock <<EOF
Name: Enable pam_faillock to deny access
Default: yes
Priority: 0
Auth-Type: Primary
Auth:
	[default=die] pam_faillock.so authfail
EOF
cat > /usr/share/pam-configs/faillock_notify <<EOF
Name: Notify failed login attempts and reset count
Default: yes
Priority: 1024
Auth-Type: Primary
Auth:
	requisite pam_faillock.so preauth
Account-Type: Primary
Account:
	required pam_faillock.so
EOF
run pam-auth-update --enable faillock --enable faillock_notify --force
applied

policy "35675" "Ensure pam_pwhistory module is enabled." "pam_pwhistory prevents users from reusing old passwords."
wait_apt
run apt-get install -y -qq libpam-pwquality
cat > /usr/share/pam-configs/pwhistory <<EOF
Name: pwhistory password history checking
Default: yes
Priority: 1024
Password-Type: Primary
Password:
	required pam_pwhistory.so remember=24 enforce_for_root try_first_pass use_authtok
	requisite pam_pwhistory.so remember=24 enforce_for_root try_first_pass use_authtok
EOF
run pam-auth-update --enable pwhistory --force
applied

policy "35676" "Ensure password failed attempts lockout is configured." "This sets the number of failed attempts before account lockout."
sed -i 's/^\s*deny\s*=/# &/' /etc/security/faillock.conf 2>/dev/null || true
echo "deny = 5" >> /etc/security/faillock.conf
applied

policy "35677" "Ensure password unlock time is configured." "This sets how long an account remains locked after failed attempts."
sed -i 's/^\s*unlock_time\s*=/# &/' /etc/security/faillock.conf 2>/dev/null || true
echo "unlock_time = 900" >> /etc/security/faillock.conf
applied

policy "35678" "Ensure password failed attempts lockout includes root account." "This includes the root account in failed login lockout policy."
sed -i 's/^\s*root_unlock_time\s*=/# &/' /etc/security/faillock.conf 2>/dev/null || true
sed -i 's/^\s*even_deny_root\s*/# &/' /etc/security/faillock.conf 2>/dev/null || true
echo "even_deny_root" >> /etc/security/faillock.conf
echo "root_unlock_time = 900" >> /etc/security/faillock.conf
applied

policy "35679" "Ensure password number of changed characters is configured." "This requires new passwords to differ from old passwords."
run touch /etc/security/pwquality.conf
sed -i 's/^\s*difok\s*=/# &/' /etc/security/pwquality.conf
echo "difok = 2" >> /etc/security/pwquality.conf
applied

policy "35680" "Ensure minimum password length is configured." "This sets the minimum password length."
sed -i 's/^\s*minlen\s*=/# &/' /etc/security/pwquality.conf
echo "minlen = 14" >> /etc/security/pwquality.conf
applied

policy "35681" "Ensure password complexity is configured." "This requires passwords to use enough character classes."
sed -i 's/^\s*minclass\s*=/# &/' /etc/security/pwquality.conf
echo "minclass = 4" >> /etc/security/pwquality.conf
applied

policy "35682" "Ensure password same consecutive characters is configured." "This limits repeated consecutive characters in passwords."
sed -i 's/^\s*maxrepeat\s*=/# &/' /etc/security/pwquality.conf
echo "maxrepeat = 3" >> /etc/security/pwquality.conf
applied

policy "35683" "Ensure password maximum sequential characters is configured." "This limits sequential characters in passwords."
sed -i 's/^\s*maxsequence\s*=/# &/' /etc/security/pwquality.conf
echo "maxsequence = 3" >> /etc/security/pwquality.conf
applied

policy "35687" "Ensure password history remember is configured." "This sets how many old passwords are remembered."
applied

policy "35688" "Ensure password history is enforced for the root user." "This applies password history rules to root."
applied

policy "35689" "Ensure pam_pwhistory includes use_authtok." "This makes pam_pwhistory use the current password change flow."
if grep -q "pam_unix.so" /etc/pam.d/common-password; then
  sed -i '/pam_unix.so/ { /use_authtok/! s/$/ use_authtok/ }' /etc/pam.d/common-password
fi
applied

policy "35690" "Ensure pam_unix does not include nullok." "This prevents empty passwords from being accepted."
for file in /etc/pam.d/common-account /etc/pam.d/common-auth /etc/pam.d/common-password /etc/pam.d/common-session /etc/pam.d/common-session-noninteractive; do
  [[ -f "$file" ]] && sed -i 's/\bnullok\b//g' "$file"
done
applied

policy "35694" "Ensure password expiration is configured." "This configures maximum password age."
not_applied

policy "35695" "Ensure minimum password days is configured." "This prevents changing passwords too frequently."
not_applied

policy "35698" "Ensure inactive password lock is configured." "This locks inactive accounts after a defined period."
not_applied

policy "35703" "Ensure root user umask is configured." "This sets secure default file permissions for root."
run touch /root/.bashrc /root/.bash_profile
sed -i 's/^\s*umask\s\+.*$/umask 0027/' /root/.bashrc
grep -q "^umask 0027" /root/.bashrc || echo "umask 0027" >> /root/.bashrc
sed -i 's/^\s*umask\s\+.*$/umask 0027/' /root/.bash_profile
grep -q "^umask 0027" /root/.bash_profile || echo "umask 0027" >> /root/.bash_profile
applied

policy "35705" "Ensure default user shell timeout is configured." "This closes inactive shell sessions after a timeout."
cat > /etc/profile.d/99-cis-timeout.sh <<EOF
readonly TMOUT=900
export TMOUT
EOF
run chmod 644 /etc/profile.d/99-cis-timeout.sh
run chown root:root /etc/profile.d/99-cis-timeout.sh
applied

policy "35708" "Ensure journald log file rotation is configured." "This limits journald log growth."
mkdir -p /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/99-cis-rotation.conf <<EOF
[Journal]
SystemMaxUse=1G
SystemKeepFree=500M
RuntimeMaxUse=200M
RuntimeKeepFree=50M
MaxFileSec=1month
EOF
if [[ -f /etc/systemd/journald.conf ]]; then
  cp -a /etc/systemd/journald.conf "$BACKUP_DIR/journald.conf.bak"
fi
sed -i 's/^#\?SystemMaxUse=.*/SystemMaxUse=1G/' /etc/systemd/journald.conf
sed -i 's/^#\?SystemKeepFree=.*/SystemKeepFree=500M/' /etc/systemd/journald.conf
sed -i 's/^#\?RuntimeMaxUse=.*/RuntimeMaxUse=200M/' /etc/systemd/journald.conf
sed -i 's/^#\?RuntimeKeepFree=.*/RuntimeKeepFree=50M/' /etc/systemd/journald.conf
sed -i 's/^#\?MaxFileSec=.*/MaxFileSec=1month/' /etc/systemd/journald.conf
grep -q "^SystemMaxUse=" /etc/systemd/journald.conf || echo "SystemMaxUse=1G" >> /etc/systemd/journald.conf
grep -q "^SystemKeepFree=" /etc/systemd/journald.conf || echo "SystemKeepFree=500M" >> /etc/systemd/journald.conf
grep -q "^RuntimeMaxUse=" /etc/systemd/journald.conf || echo "RuntimeMaxUse=200M" >> /etc/systemd/journald.conf
grep -q "^RuntimeKeepFree=" /etc/systemd/journald.conf || echo "RuntimeKeepFree=50M" >> /etc/systemd/journald.conf
grep -q "^MaxFileSec=" /etc/systemd/journald.conf || echo "MaxFileSec=1month" >> /etc/systemd/journald.conf
run systemctl restart systemd-journald
applied

policy "35710" "Ensure systemd-journal-upload authentication is configured." "This applies when systemd-journal-upload sends logs remotely."
not_applied

policy "35719" "Ensure rsyslog log file creation mode is configured." "This sets secure permissions for new rsyslog log files."
mkdir -p /etc/rsyslog.d
echo '$FileCreateMode 0640' > /etc/rsyslog.d/60-cis-filecreatemode.conf
run systemctl reload-or-restart rsyslog || true
applied

policy "35720" "Ensure rsyslog is configured to send logs to a remote log host." "This sends this system logs to another remote rsyslog server."
not_applied

policy "35722" "Ensure access to all logfiles has been configured." "This tightens permissions on log files."
not_applied

policy "35723" "Ensure auditd packages are installed." "auditd records security-relevant system events."
wait_apt
run apt-get install -y -qq auditd audispd-plugins
applied

policy "35724" "Ensure auditd service is enabled and active." "This enables and starts the auditd service."
run systemctl unmask auditd
run systemctl enable auditd
run systemctl start auditd || true
applied

policy "35725" "Ensure auditing for processes that start prior to auditd is enabled." "This enables audit from early boot."
set_grub_param "audit=1"
run update-grub
applied

policy "35726" "Ensure audit_backlog_limit is sufficient." "This increases audit backlog size during boot."
set_grub_param "audit_backlog_limit=8192"
run update-grub
applied

policy "35728" "Ensure audit logs are not automatically deleted." "The max_log_file_action setting determines how to handle the audit log file reaching the max file size."
sed -i 's/^\s*max_log_file_action\s*=.*/max_log_file_action = keep_logs/' /etc/audit/auditd.conf
grep -q '^max_log_file_action = keep_logs' /etc/audit/auditd.conf || echo 'max_log_file_action = keep_logs' >> /etc/audit/auditd.conf
applied

policy "35729" "Ensure system is disabled when audit logs are full." "The auditd daemon can be configured to halt the system or put the system in single user mode, if no free space is available or an error is detected on the partition that holds the audit log files."
sed -i 's/^\s*disk_full_action\s*=.*/disk_full_action = halt/' /etc/audit/auditd.conf
sed -i 's/^\s*disk_error_action\s*=.*/disk_error_action = syslog/' /etc/audit/auditd.conf
grep -q '^disk_full_action = halt' /etc/audit/auditd.conf || echo 'disk_full_action = halt' >> /etc/audit/auditd.conf
grep -q '^disk_error_action = syslog' /etc/audit/auditd.conf || echo 'disk_error_action = syslog' >> /etc/audit/auditd.conf
applied

policy "35730" "Ensure system warns when audit logs are low on space." "The auditd daemon can be configured to halt the system, put the system in single user mode or send a warning message, if the partition that holds the audit log files is low on space."
sed -i 's/^\s*space_left_action\s*=.*/space_left_action = email/' /etc/audit/auditd.conf
sed -i 's/^\s*admin_space_left_action\s*=.*/admin_space_left_action = single/' /etc/audit/auditd.conf
grep -q '^space_left_action = email' /etc/audit/auditd.conf || echo 'space_left_action = email' >> /etc/audit/auditd.conf
grep -q '^admin_space_left_action = single' /etc/audit/auditd.conf || echo 'admin_space_left_action = single' >> /etc/audit/auditd.conf
applied

mkdir -p /etc/audit/rules.d

policy "35731" "Ensure changes to system administration scope (sudoers) is collected." "Monitor scope changes for system administrators."
cat > /etc/audit/rules.d/50-scope.rules <<EOF
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d -p wa -k scope
EOF
applied

policy "35732" "Ensure actions as another user are always logged." "sudo provides users with temporary elevated privileges to perform operations, either as the superuser or another user."
cat > /etc/audit/rules.d/50-user_emulation.rules <<EOF
-a always,exit -F arch=b64 -C euid!=uid -F auid!=unset -S execve -k user_emulation
-a always,exit -F arch=b32 -C euid!=uid -F auid!=unset -S execve -k user_emulation
EOF
applied

policy "35733" "Ensure events that modify the sudo log file are collected." "Monitor the sudo log file."
cat > /etc/audit/rules.d/50-sudo.rules <<EOF
-w /var/log/sudo.log -p wa -k sudo_log_file
EOF
applied

policy "35734" "Ensure events that modify date and time information are collected." "Capture events where the system date and/or time has been modified."
cat > /etc/audit/rules.d/50-time-change.rules <<EOF
-a always,exit -F arch=b64 -S adjtimex,settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex,settimeofday -k time-change
-a always,exit -F arch=b64 -S clock_settime -F a0=0x0 -k time-change
-a always,exit -F arch=b32 -S clock_settime -F a0=0x0 -k time-change
-w /etc/localtime -p wa -k time-change
EOF
applied

policy "35735" "Ensure events that modify the system's network environment are collected." "Record changes to network environment files or system calls."
cat > /etc/audit/rules.d/50-system_locale.rules <<EOF
-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/networks -p wa -k system-locale
-w /etc/network/ -p wa -k system-locale
-w /etc/netplan/ -p wa -k system-locale
EOF
applied

policy "35736" "Ensure unsuccessful file access attempts are collected." "Monitor for unsuccessful attempts to access files."
UID_MIN_VALUE="$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs | head -n1)"
cat > /etc/audit/rules.d/50-access.rules <<EOF
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=${UID_MIN_VALUE} -F auid!=unset -k access
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=${UID_MIN_VALUE} -F auid!=unset -k access
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=${UID_MIN_VALUE} -F auid!=unset -k access
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=${UID_MIN_VALUE} -F auid!=unset -k access
EOF
applied

policy "35737" "Ensure events that modify user/group information are collected." "Record events affecting the modification of user or group information, including that of passwords and old passwords if in use."
cat > /etc/audit/rules.d/50-identity.rules <<EOF
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-w /etc/nsswitch.conf -p wa -k identity
-w /etc/pam.conf -p wa -k identity
-w /etc/pam.d -p wa -k identity
EOF
applied

policy "35738" "Ensure discretionary access control permission modification events are collected." "Monitor changes to file permissions, attributes, ownership and group."
cat > /etc/audit/rules.d/50-perm_mod.rules <<EOF
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=${UID_MIN_VALUE} -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=${UID_MIN_VALUE} -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=${UID_MIN_VALUE} -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S lchown,fchown,chown,fchownat -F auid>=${UID_MIN_VALUE} -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=${UID_MIN_VALUE} -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=${UID_MIN_VALUE} -F auid!=unset -F key=perm_mod
EOF
applied

policy "35739" "Ensure successful file system mounts are collected." "Monitor the use of the mount system call."
cat > /etc/audit/rules.d/50-mounts.rules <<EOF
-a always,exit -F arch=b32 -S mount -F auid>=${UID_MIN_VALUE} -F auid!=unset -k mounts
-a always,exit -F arch=b64 -S mount -F auid>=${UID_MIN_VALUE} -F auid!=unset -k mounts
EOF
applied

policy "35740" "Ensure session initiation information is collected." "Monitor session initiation events."
cat > /etc/audit/rules.d/50-session.rules <<EOF
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session
EOF
applied

policy "35741" "Ensure login and logout events are collected." "Monitor login and logout events."
mkdir -p /var/run/faillock
cat > /etc/audit/rules.d/50-login.rules <<EOF
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock -p wa -k logins
EOF
applied

policy "35742" "Ensure file deletion events by users are collected." "Monitor the use of system calls associated with the deletion or renaming of files and file attributes."
cat > /etc/audit/rules.d/50-delete.rules <<EOF
-a always,exit -F arch=b64 -S rename,unlink,unlinkat,renameat -F auid>=${UID_MIN_VALUE} -F auid!=unset -F key=delete
-a always,exit -F arch=b32 -S rename,unlink,unlinkat,renameat -F auid>=${UID_MIN_VALUE} -F auid!=unset -F key=delete
EOF
applied

policy "35743" "Ensure events that modify the system's Mandatory Access Controls are collected." "Monitor AppArmor, an implementation of mandatory access controls."
cat > /etc/audit/rules.d/50-MAC-policy.rules <<EOF
-w /etc/apparmor/ -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy
EOF
applied

policy "35744" "Ensure successful and unsuccessful attempts to use the chcon command are collected." "The operating system must generate audit records for successful/unsuccessful uses of the chcon command."
cat > /etc/audit/rules.d/50-perm_chng.rules <<EOF
-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=${UID_MIN_VALUE} -F auid!=unset -k perm_chng
EOF
applied

policy "35745" "Ensure successful and unsuccessful attempts to use the setfacl command are collected." "The operating system must generate audit records for successful/unsuccessful uses of the setfacl command."
cat >> /etc/audit/rules.d/50-perm_chng.rules <<EOF
-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=${UID_MIN_VALUE} -F auid!=unset -k perm_chng
EOF
applied

policy "35746" "Ensure successful and unsuccessful attempts to use the chacl command are collected." "The operating system must generate audit records for successful/unsuccessful uses of the chacl command."
cat >> /etc/audit/rules.d/50-perm_chng.rules <<EOF
-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=${UID_MIN_VALUE} -F auid!=unset -k perm_chng
EOF
applied

policy "35747" "Ensure successful and unsuccessful attempts to use the usermod command are collected." "The operating system must generate audit records for successful/unsuccessful uses of the usermod command."
cat > /etc/audit/rules.d/50-usermod.rules <<EOF
-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=${UID_MIN_VALUE} -F auid!=unset -k usermod
EOF
applied

policy "35748" "Ensure kernel module loading unloading and modification is collected." "Monitor the loading and unloading of kernel modules."
cat > /etc/audit/rules.d/50-kernel_modules.rules <<EOF
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module,create_module,query_module -F auid>=${UID_MIN_VALUE} -F auid!=unset -k kernel_modules
-a always,exit -F path=/usr/bin/kmod -F perm=x -F auid>=${UID_MIN_VALUE} -F auid!=unset -k kernel_modules
EOF
applied

policy "35749" "Ensure the audit configuration is immutable." "Set system audit so that audit rules cannot be modified with auditctl."
cat > /etc/audit/rules.d/99-finalize.rules <<EOF
-e 2
EOF
applied

policy "35752" "Ensure audit configuration files mode is configured." "Audit configuration files control auditd and what events are audited."
find /etc/audit/ -type f \( -name "*.conf" -o -name "*.rules" \) -exec chown root:root {} \; 2>/dev/null || true
find /etc/audit/ -type f \( -name "*.conf" -o -name "*.rules" \) -exec chmod u-x,g-wx,o-rwx {} \; 2>/dev/null || true
applied

policy "35755" "Ensure audit tools mode is configured." "Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records."
for file in /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules; do
  [[ -e "$file" ]] && run chmod go-w "$file"
done
applied

policy "35756" "Ensure audit tools owner is configured." "This makes audit tools owned by root."
for file in /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules; do
  [[ -e "$file" ]] && run chown root "$file"
done
applied

policy "35757" "Ensure audit tools group owner is configured." "This makes audit tools group-owned by root."
for file in /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules; do
  [[ -e "$file" ]] && run chgrp root "$file"
done
applied

policy "35758" "Ensure AIDE is installed." "AIDE checks filesystem integrity."
echo "(Esta política puede tardar 5 minutos o más en aplicarse, hay que ser pacientes)"
read -rp "Pulsa INTRO para omitir esta política o escribe s para aplicarla: " RUN_AIDE

if [[ "$RUN_AIDE" =~ ^[sS]$ ]]; then
  wait_apt
  run apt-get install -y -qq aide aide-common
  run aideinit || true
  if [[ -f /var/lib/aide/aide.db.new ]]; then
    run mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
  fi
  applied
else
  echo "Esta política se ha omitido ❌"
fi

policy "35759" "Ensure filesystem integrity is regularly checked." "This schedules regular AIDE checks."
run systemctl unmask dailyaidecheck.timer dailyaidecheck.service || true
run systemctl enable --now dailyaidecheck.timer || true
applied

policy "35760" "Ensure cryptographic mechanisms are used to protect the integrity of audit tools." "Audit tools should be protected by cryptographic integrity checks."
read -rp "Pulsa INTRO para omitir esta política o escribe s para aplicarla: " RUN_AIDE_AUDIT_TOOLS

if [[ "$RUN_AIDE_AUDIT_TOOLS" =~ ^[sS]$ ]]; then
  {
    echo ""
    echo "# Audit Tools"
    for file in /sbin/auditctl /sbin/auditd /sbin/ausearch /sbin/aureport /sbin/autrace /sbin/augenrules; do
      if [[ -e "$file" ]]; then
        real_file="$(readlink -f "$file")"
        grep -q "^$real_file " /etc/aide/aide.conf 2>/dev/null || echo "$real_file p+i+n+u+g+s+b+acl+xattrs+sha512"
      fi
    done
  } >> /etc/aide/aide.conf
  applied
else
  echo "Esta política se ha omitido ❌"
fi

policy "35770" "Ensure permissions on /etc/security/opasswd are configured." "This secures password history files."
touch /etc/security/opasswd /etc/security/opasswd.old
run chown root:root /etc/security/opasswd /etc/security/opasswd.old
run chmod 600 /etc/security/opasswd /etc/security/opasswd.old
applied

run augenrules --load || true
run systemctl restart auditd || true

echo
echo
echo
echo "${BOLD}4. REINICIO DEL SISTEMA${RESET}"
echo "Para comprobar si las políticas se han ejecutado correctamente dirígete a:"
echo "Wazuh Server Dashboard > Agentes > Agente Ubuntu > CIS"
echo
read -rp "Es muy recomendable reiniciar el sistema, quieres hacerlo ahora? (s/n): " REBOOT_FINAL

if [[ "$REBOOT_FINAL" =~ ^[sS]$ ]]; then
  run systemctl reboot
  exit 0
fi



echo
echo "------------------------------------------------------------"
echo "SCRIPT FINALIZADO"
echo "------------------------------------------------------------"
