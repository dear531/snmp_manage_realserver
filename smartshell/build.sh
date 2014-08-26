#!/bin/sh -x


VERSION="v0.0.1T"
PLATFORM=`uname -i`
SVNVERSION=""

if [ $# == 1 ]; then
	VERSION=$1;
fi

if [ -e .svn -a -e /usr/bin/svn ]; then
	LANG="C" SVNVERSION=`svn info | grep Revision | awk '{print $2}'`
fi

export CFLAGS="-O2 -Werror -Wall -rdynamic"

installfile="install_shell_"$PLATFORM"_"$VERSION"_"$SVNVERSION".bin"
target="/SmartGrid/shell/"
mtarget="\/SmartGrid\/shell\/"
# compile code.

for i in neighbor_adv script4 daemon4 auth crl_downloader console_login status upgrade_netmask vmware_daemon arp_check; do
	make -C $i clean;
	make -C $i ACTION=release VERSION=$VERSION || exit -1;
done

rm -f install_shell_*
rm -fr .install
mkdir .install
cp -af script4/script4 .install
cp -af auth/smartauth .install
cp -af auth/smart_ldap_auth .install
cp -af auth/smart_radius_auth .install
cp -af daemon4/daemon4 .install
cp -af crl_downloader/crl_downloader .install
cp -af vmware_daemon/vmware_daemon .install
cp -af daemon4/log4crc .install
cp -af console_login/console_login .install
cp -af status/smartstatus .install 
cp -af neighbor_adv/na .install 
cp -af upgrade_netmask/upgrade_netmask .install 
cp -af arp_check/arp_check .install 

cat > $installfile << EOF
#!/bin/sh

killall -9 daemon4 > /dev/null 2>&1
killall -9 crl_downloader > /dev/null 2>&1
killall -9 smartstatus vmware_daemon > /dev/null 2>&1

mkdir -p $target
sed -n '0,/^0011-ANHK-BLANK$/!p'  \$0 > .install.tgz

tar zxf .install.tgz -m
cp -af .install/* $target

## na 
chmod 755 $target/na

## daemon4
chmod 755 $target/daemon4

## crl_downloader
chmod 755 $target/crl_downloader
## vmware_daemon
chmod 755 $target/vmware_daemon
## script4
chmod 755 $target/script4 
chmod a+s $target/script4

## smartauth
chmod 755 $target/smartauth
chmod a+s $target/smartauth

## console_login
chmod 755 $target/console_login

##smartstatus
chmod 755 $target/smartstatus
chmod a+s $target/smartstatus

##arp_check
chmod 755 $target/arp_check

## execute upgrade_netmask
$target/upgrade_netmask mask2bits

rm -fr /usr/bin/script4 /usr/bin/smartstat /usr/bin/smartauth 
rm -fr /usr/bin/na /usr/bin/arp_check
rm -fr /usr/bin/crl_downloader /bin/console_login /usr/bin/vmware_daemon
ln -s $target/na /usr/bin/
ln -s $target/arp_check /usr/bin/
ln -s $target/script4 /usr/bin/
ln -s $target/smartauth /usr/bin/
ln -s $target/crl_downloader /usr/bin/
ln -s $target/vmware_daemon /usr/bin/
ln -s $target/console_login /bin/
cp -af $target/smart_ldap_auth /etc/pam.d/
cp -af $target/smart_radius_auth /etc/pam.d/

rm -fr .install .install.tgz

sed -i "/^root:/s#/bin/bash#/bin/console_login#" /etc/passwd

sed -i '/$mtarget/d' /etc/rc.local;
echo "$target/daemon4" >> /etc/rc.local;
echo "$target/crl_downloader" >> /etc/rc.local;
echo "$target/vmware_daemon" >> /etc/rc.local;

##add smartstatus to crontab
result=\`grep -c 'smartstatus' /var/spool/cron/root 2>/dev/null\`
if [ -f /var/spool/cron/root ]
then
    if [ "\$result" -le "0"  ]
    then
        echo "* * * * * /SmartGrid/shell/smartstatus" >> /var/spool/cron/root
    fi  
else
    echo "* * * * * /SmartGrid/shell/smartstatus" >> /var/spool/cron/root
fi

##add arp_check to crontab
sed -i '/arp_check/d' /var/spool/cron/root
echo "* * * * * /SmartGrid/shell/arp_check" >> /var/spool/cron/root

## modify syslog.conf for arp_check
sed -i '/kern.alert/d' /etc/syslog.conf
sed -i '3a kern.alert            /var/log/kern_alert' /etc/syslog.conf

$target/daemon4;
$target/crl_downloader;
$target/vmware_daemon;

exit;
0011-ANHK-BLANK
EOF


tar zcf .install.tgz .install

cat .install.tgz >> $installfile

rm -fr .install .install.tgz

if [ -d ../for_install/$VERSION ]; then
        cp -af $installfile ../for_install/$VERSION/
        echo "sh $installfile" >> ../for_install/$VERSION/install.sh
        cd ../for_install/$VERSION/; md5sum $installfile > $installfile.md5; cd - > /dev/null 2>&1
fi
