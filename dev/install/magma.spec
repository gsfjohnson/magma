
Name: magma
Summary: Lavabit Magma Server
Version: 7.0.0
Release: 1.el6
License: GPL 3
Group: System Environment/Libraries
URL: https://github.com/lavabit/magma/
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root

# Convert from github downloaded format to format that rpmbuild %setup macro expects:
#   cd /tmp
#   curl --location --output /tmp/magma_tmp.tar.gz https://github.com/lavabit/magma/archive/develop.tar.gz
#   mkdir /tmp/magma-7.0.0
#   tar xf /tmp/magma_tmp.tar.gz -C /tmp/magma-7.0.0 --strip-components 1
#   tar czf ~/rpmbuild/SOURCES/magma-7.0.0.tar.gz -C /tmp magma-7.0.0
Source: %{name}-%{version}.tar.gz

#Requires(post): policycoreutils-python
#Requires(postun): policycoreutils-python
#Requires(pre): shadow-utils
#Requires: policycoreutils-python
Requires: shadow-utils

Requires: libbsd
Requires: inotify-tools
Requires: libarchive
Requires: libevent
Requires: rsync
Requires: policycoreutils checkpolicy
Requires: perl-Text-Unidecode
Requires: openssl

Requires: memcached
Requires: mysql mysql-server perl-DBI perl-DBD-MySQL
Requires: haveged
Requires: clamav clamav-db

#Requires: magma-utils

BuildRequires: sysstat
BuildRequires: libstdc++
BuildRequires: valgrind
BuildRequires: texinfo
BuildRequires: libtool
BuildRequires: ncurses
BuildRequires: libgomp mpfr
BuildRequires: perl-Module-Pluggable perl-Pod-Escapes perl-Pod-Simple perl-libs perl-version perl-Time-HiRes

BuildRequires: gcc
BuildRequires: make
BuildRequires: autoconf
BuildRequires: automake
BuildRequires: binutils
BuildRequires: bison
BuildRequires: flex
BuildRequires: gcc-c++
BuildRequires: gettext
BuildRequires: libtool
BuildRequires: make
BuildRequires: cmake
BuildRequires: patch
BuildRequires: pkgconfig
BuildRequires: mysql-server
BuildRequires: memcached
BuildRequires: gettext-devel
BuildRequires: check
BuildRequires: check-devel
BuildRequires: ncurses-devel
BuildRequires: libbsd-devel
BuildRequires: zlib-devel
BuildRequires: valgrind
BuildRequires: valgrind-devel

%description
The magma server daemon, is an encrypted email system with support
for SMTP, POP, IMAP, HTTP and MOLTEN,. Additional support for DMTP
and DMAP is currently in active development.

%package utils
Summary: Lavabit Magma Server Utils
Requires: magma

%description utils
The magma server daemon, is an encrypted email system with support
for SMTP, POP, IMAP, HTTP and MOLTEN,. Additional support for DMTP
and DMAP is currently in active development.

%prep
%setup

%build
# dev/scripts/builders/build.lib.sh all # XXX: memcached check fails

# includes build.lib.sh without the checks
%{__make} all

%install
#%{__rm} -rf %{buildroot}

## XXX: would be nice...
#prefix=%{buildroot} %{__make} install

### system directories ###
%{__install} -d %{buildroot}/var/lib/magma/local
%{__install} -d %{buildroot}/var/lib/magma/storage/tanks
%{__install} -d %{buildroot}/var/spool/magma/data
%{__install} -d %{buildroot}/var/spool/magma/scan
%{__install} -d %{buildroot}/etc/pki/dime/signets
%{__install} -d %{buildroot}/etc/pki/dime/private
%{__install} -d %{buildroot}/var/run/magmad

### haveged ###
%{__install} -d %{buildroot}/etc/chkconfig.d
printf "# chkconfig: - 54 25\n" > %{buildroot}/etc/chkconfig.d/haveged

### init.d ###
%{__install} -d %{buildroot}/etc/rc.d/init.d
%{__install} --no-target-directory dev/install/magmad.sysv.init.sh %{buildroot}/etc/rc.d/init.d/magmad

### sysctl ###
if [ ! -f dev/install/magmad.sysctl.conf ]; then
%{__cat} <<EOF >dev/install/magmad.sysctl.conf
kernel.random.read_wakeup_threshold = 64
kernel.random.write_wakeup_threshold = 2048

net.core.netdev_max_backlog = 65536
net.core.optmem_max = 25165824
net.core.rmem_default = 31457280
net.core.rmem_max = 12582912
net.core.somaxconn = 32768
net.core.wmem_default = 31457280
net.core.wmem_max = 12582912

net.ipv4.neigh.default.gc_thresh1 = 1024
net.ipv4.neigh.default.gc_thresh2 = 4096
net.ipv4.neigh.default.gc_thresh3 = 8192
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_fin_timeout = 20
net.ipv4.tcp_keepalive_intvl = 60
net.ipv4.tcp_keepalive_probes = 8
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_max_syn_backlog = 32768
net.ipv4.tcp_max_tw_buckets = 2621440
net.ipv4.tcp_mem = 65536 131072 262144
net.ipv4.tcp_rfc1337 = 1
net.ipv4.tcp_rmem = 8192 87380 16777216
net.ipv4.tcp_syn_retries = 3
net.ipv4.tcp_synack_retries = 3
net.ipv4.tcp_tw_recycle = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_wmem = 8192 65536 16777216
net.ipv4.udp_mem = 65536 131072 262144
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384

net.ipv6.conf.all.disable_ipv6 = 1

vm.dirty_background_ratio = 2
vm.dirty_ratio = 60
vm.swappiness = 10
EOF
fi
%{__install} -d %{buildroot}/etc/sysctl.d
%{__install} --no-target-directory dev/install/magmad.sysctl.conf %{buildroot}/etc/sysctl.d/magmad.conf

### freshclam example config ###
%{__cat} <<EOF >freshclam.conf.example
Bytecode yes
LogSyslog yes
SafeBrowsing yes
LogFileMaxSize 8M
DatabaseOwner clam
CompressLocalDatabase no
DatabaseDirectory /var/lib/clamav
DatabaseMirror database.clamav.net
UpdateLogFile /var/log/clamav/freshclam.log
EOF
# --> installed via %doc

### resources ###
%{__install} -d %{buildroot}/var/lib/magma/resources
%{__cp} res/{fonts,pages,templates,sql,config} %{buildroot}/var/lib/magma/resources

### daemon ###
%{__install} -d %{buildroot}/usr/libexec
%{__install} --strip --target-directory=%{buildroot}/usr/libexec magmad magmad.so

### security limits ###
if [ ! -f dev/install/magmad.security.limits.d.conf ]; then
%{__cat} <<EOF >dev/install/magmad.security.limits.d.conf
root     soft    stack      unlimited
root     hard    stack      unlimited
root     soft    memlock    sedHALFMEM
root     hard    memlock    sedHALFMEM
root     soft    nofile     262144
root     hard    nofile     262144

magma    soft    stack      unlimited
magma    hard    stack      unlimited
magma    soft    memlock    sedHALFMEM
magma    hard    memlock    sedHALFMEM
magma    soft    nofile     262144
magma    hard    nofile     262144
EOF
fi
%{__install} -d %{buildroot}/etc/security/limits.d
%{__install} --no-target-directory dev/install/magmad.security.limits.d.conf %{buildroot}/etc/security/limits.d/50-magmad.conf

### daemon config ###
%{__cat} <<EOF >magmad.config
magma.library.file = /usr/libexec/magmad.so
magma.iface.database.user = magma
magma.iface.database.host = localhost
magma.iface.database.schema = Magma
magma.iface.database.password = DefaultMagmaPassword
magma.iface.database.socket_path = /var/lib/mysql/mysql.sock
magma.iface.database.pool.connections = 1

magma.relay[1].port = 2525
magma.relay[1].name = localhost
magma.iface.cache.host[1].port = 11211
magma.iface.cache.host[1].name = localhost

magma.library.file = /usr/libexec/magmad.so
magma.system.worker_threads = 16
magma.secure.memory.length = 268435456
EOF
%{__install} --no-target-directory magmad.config %{buildroot}/etc/magmad.config
#%{__cp} res/config/magma.config.stub magmad.config.example

### daemon log and cleanup ###
%{__install} -d %{buildroot}/var/log/magma
%{__install} -d %{buildroot}/etc/cron.d
printf "32 0 * * * root find /var/log/magma/ -name magmad.[0-9]*.log -mmin +8639 -exec rm --force {} \;\n" > %{buildroot}/etc/cron.d/magma-log-cleanup

### postfix logrotate ###
%{__install} -d %{buildroot}/etc/logrotate.d
printf "/var/log/maillog {\n\tdaily\n\trotate 7\n\tmissingok\n}\n" > %{buildroot}/etc/logrotate.d/postfix

### pki dkim ###
%{__install} -d %{buildroot}/etc/pki/dkim/private

### utils ###
%{__install} -d %{buildroot}/usr/bin
%{__install} --strip --no-target-directory signet %{buildroot}/usr/bin/signet
%{__install} --strip --no-target-directory dime %{buildroot}/usr/bin/dime
%{__install} --strip --no-target-directory genrec %{buildroot}/usr/bin/genrec

### extra documentation ###
%{__cp} dev/install/magmad.config.sql .

### patch ###
sed -i 's:cd\ \$BASE/../../../::; s:res/:/var/lib/magma/resources/:' dev/scripts/database/schema.init.sh
sed -i "s:MAGMA_VERSION=.*:MAGMA_VERSION=\$(/usr/libexec/magmad -v | grep version | awk '{print \$2}'):" dev/scripts/database/schema.init.sh

%clean
%{__rm} -rf %{buildroot}

%files
%doc COPYRIGHT INSTALL LICENSE README.md magmad.config.sql freshclam.conf.example dev/scripts/
%defattr(-, magma, magma, 0755)
%dir /var/lib/magma
%dir /var/spool/magma
%dir /var/spool/magma/data
%dir /var/spool/magma/scan
%dir /var/log/magma
%dir /var/run/magmad
%dir /etc/pki/dime
%dir /etc/pki/dime/signets
%dir /etc/pki/dime/private
%dir /etc/pki/dkim
%dir /etc/pki/dkim/private
%defattr(-, root, root, 0600)
%config /etc/cron.d/magma-log-cleanup
%config /etc/sysctl.d/magmad.conf
%config /etc/magmad.config
%config /etc/security/limits.d/50-magmad.conf
%config /etc/chkconfig.d/haveged
%config /etc/logrotate.d/postfix
%defattr(-, root, root, 0755)
/etc/rc.d/init.d/magmad
/usr/libexec/magmad
/usr/libexec/magmad.so
%defattr(-, magma, magma, 0644)
/var/lib/magma/resources

%files utils
%defattr(-, root, root, 0755)
/usr/bin/signet
/usr/bin/dime
/usr/bin/genrec

%pre
fx_printf () {
  /usr/bin/printf "$@"
}
fx_useradd () {
  /bin/echo useradd "$@"
  /usr/sbin/useradd "$@" >/dev/null 2>&1
}
fx_passwd_l () {
  /bin/echo passwd -l "$1"
  /usr/sbin/passwd -l "$1" >/dev/null 2>&1
}
getent passwd magma >/dev/null 2>&1 || \
  fx_useradd --system --no-create-home --home-dir /var/lib/magma --shell /sbin/nologin --comment "Lavabit Magma Daemon" magma && \
  fx_passwd_l magma
#
fx_printf "\n"
exit 0

%post
fx_chcon () {
  # 1: context, 2: filename
  /bin/echo chcon "$@"
  /usr/bin/chcon "$@"
}
fx_chown () {
  # 1: context, 2: filename
  /bin/echo chown "$@"
  /bin/chown "$@"
}
fx_chmod () {
  # 1: context, 2: filename
  /bin/echo chmod "$@"
  /bin/chmod "$@"
}
fx_sysctl () {
  /bin/echo sysctl -p "$@"
  /sbin/sysctl -p "$@" >/dev/null 2>&1 || :
}
fx_sed_i () {
  /bin/echo sed --in-place "$@"
  /bin/sed --in-place "$@"
}
fx_printf () {
  /usr/bin/printf "$@"
}
fx_openssl () {
  # 1: context, 2: filename
  /bin/echo openssl "$@"
  /usr/bin/openssl "$@" >/dev/null 2>&1
}
#
# default domain
DOMAIN="$(/bin/hostname -f)"
[ "$DOMAIN" == "" ] && DOMAIN=example
#
# default selector
SELECTOR="$(/bin/hostname -s)"
[ "$SELECTOR" == "" ] && SELECTOR=`openssl rand -hex 6`
#
# generate dkim key unless exists
DKIMKEY="/etc/pki/dkim/private/${DOMAIN}.pem"
if [ ! -f $DKIMKEY ]; then
  fx_openssl genrsa -out $DKIMKEY 2048
  fx_chmod 600 $DKIMKEY
  fx_chcon unconfined_u:object_r:cert_t:s0 $DKIMKEY
  #
  # provide dkim TXT
  fx_printf "\n\nPublish the following record to ensure DKIM signatures operate properly.\n\n"
  fx_openssl rsa -in "/etc/pki/dkim/private/${DOMAIN}.pem" -pubout -outform PEM | \
    sed -r "s/-----BEGIN PUBLIC KEY-----$//" | \
    sed -r "s/-----END PUBLIC KEY-----//" | \
    tr -d [:space:] | \
    awk "{ print \"$SELECTOR._domainkey IN TXT \\\"v=DKIM1; k=rsa; p=\" substr(\$1, 1, 208) \"\\\" \\\"\" substr(\$1, 209) \"\\\" ; ----- DKIM $DOMAIN\" }"
fi
#
# generate tls key unless exists
TLSKEY="/etc/pki/tls/private/${DOMAIN}.pem"
if [ ! -f $TLSKEY ]; then
  fx_openssl req -x509 -text -nodes -batch -days 1826 -newkey rsa:4096 -keyout "$TLSKEY" -out "$TLSKEY"
  fx_chmod 600 $TLSKEY
  fx_chcon unconfined_u:object_r:cert_t:s0 $TLSKEY
fi
#
fx_printf "\nReset ownership, mode, and selinux contexts.\n"
fx_chcon -R system_u:object_r:cert_t:s0 /etc/pki/dime
fx_chcon -R system_u:object_r:cert_t:s0 /etc/pki/dkim
fx_chcon system_u:object_r:bin_t:s0 /usr/libexec/magmad
fx_chcon system_u:object_r:bin_t:s0 /usr/libexec/magmad.so
fx_chown -R magma:magma /var/spool/magma
fx_chcon -R system_u:object_r:var_spool_t:s0 /var/spool/magma
fx_chcon -R system_u:object_r:var_log_t:s0 /var/log/magma
fx_chmod 600 /etc/cron.d/magma-log-cleanup
fx_chcon system_u:object_r:system_cron_spool_t:s0 /etc/cron.d/magma-log-cleanup
fx_chcon -R system_u:object_r:var_lib_t:s0 /var/lib/magma
fx_chcon system_u:object_r:initrc_exec_t:s0 /etc/rc.d/init.d/magmad
fx_chcon system_u:object_r:var_run_t:s0 /var/run/magmad
fx_chcon system_u:object_r:etc_t:s0 /etc/logrotate.d/postfix
fx_chcon system_u:object_r:etc_t:s0 /etc/security/limits.d/50-magmad.conf
fx_chcon system_u:object_r:etc_t:s0 /etc/sysctl.d/magmad.conf
#
TOTALMEM=`free -k | grep -E "^Mem:" | awk -F' ' '{print $2}'`
HALFMEM=`echo $(($TOTALMEM/2))`
MAGMA_SEC_LIMITS=/etc/security/limits.d/50-magmad.conf
/bin/grep "sedHALFMEM" $MAGMA_SEC_LIMITS >/dev/null 2>&1 && \
  fx_sed_i "s:sedHALFMEM:$HALFMEM:g" $MAGMA_SEC_LIMITS
#
fx_sysctl /etc/sysctl.d/magmad.conf
#
fx_printf "\nQuickstart:\n"
fx_printf "  1. Enable & start services:  haveged, memcached, mysql\n"
fx_printf "  2. Create database, database credential, & access grant.\n"
fx_printf "       mysqladmin -uroot --force=true create Magma\n"
fx_printf "       PMAGMA=\`openssl rand -base64 30 | sed -e 's/\//@-/g; s/\+/_\?/g'\`\n"
fx_printf "       mysql --execute=\"CREATE USER 'magma'@'localhost' IDENTIFIED BY '\$PMAGMA'\"\n"
fx_printf "       mysql --execute=\"GRANT ALL ON *.* TO 'magma'@'localhost'\"\n"
fx_printf "       mysql --execute=\"GRANT SELECT, INSERT, UPDATE, DELETE ON Lavabit.* TO 'magma'@'localhost'\"\n"
fx_printf "  3. Init database schema.\n"
fx_printf "       cd /usr/share/doc/magma-x.x.x\n"
fx_printf "       ./scripts/database/schema.init.sh magma \$PMAGMA Magma\n"
fx_printf "  4. Configure database credentials in /etc/magmad.config\n"
fx_printf "  5. Create dime key and signet\n"
fx_printf "       cd /etc/pki/dime/private; signet -g orgid\n"
fx_printf "  6. Update postfix config & reload it\n"
fx_printf "  7. Enable & start service: magmad\n"
#
fx_printf "\n"
exit 0

%changelog
* Sun May 3 2020 Glen <gfjohnson@redwain.com> - 7.0.0-1.el6
- Created spec
