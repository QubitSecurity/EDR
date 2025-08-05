#!/bin/bash

export PLURA_DIR=/etc/plura

TARGET=$1

prepare_install ()
{
	# tar
	if [ ! -f /usr/bin/tar ]; then
		if [ -f /usr/bin/dnf ]; then
			/usr/bin/dnf -y install tar
		elif [ -f /usr/bin/yum ]; then
			/usr/bin/yum -y install tar
		elif [ -f /usr/bin/apt ]; then
			/usr/bin/apt -y install tar
		fi
		if [ ! -f /usr/bin/tar ]; then
			echo Install tar, please ...
			echo install-E1
			exit
		fi
	fi

	case $TARGET in
		commax32|commax64)
			PLURA_USER_HOME=/user/plura
			mkdir -p $PLURA_USER_HOME
			if [ ! -L $PLURA_DIR ]; then
				ln -fs $PLURA_USER_HOME $PLURA_DIR
			fi
			;;
		*)
			mkdir -p $PLURA_DIR
			;;
	esac
	if [ ! -d "$PLURA_DIR" ]; then
		echo install-E2
		exit
	fi
	cd $PLURA_DIR
}

check_binary ()
{
	arch=$(uname -m)
	case $arch in
		i686|i586|i486|i386|x86)
			binary=x86
			;;
		aarch64)
			binary=aarch64
			;;
		*) 
			if [ $(uname -r|cut -d '.' -f1) -lt 3 ]; then
				binary=linux2
			else
				binary=linux
			fi
			;;
	esac
	
	echo binary=$binary
}

download_package ()
{
	curl --noproxy "*" -s https://repo.plura.io/v4/$1/manifest -o manifest
	if [ ! -f manifest ]; then
		echo download_package-E1
		exit
	fi

	while read line
	do
		file=$(echo $line|cut -d' ' -f2)
		curl --noproxy "*" -s https://repo.plura.io/v4/$1/$file -o $file

		hash1=$(echo $line|cut -d' ' -f1)
		hash2=$(sha256sum $file|cut -d' ' -f1)
		if [ "$hash1" != "$hash2" ]; then
			echo download_package-E2
			exit
		fi

	done < manifest
	
	rm -f manifest
}

config_commanx ()
{
	#
	echo "arch=$1" > arch
	#
	curl --noproxy "*" -s https://repo.plura.io/v4/module/plura/conf/plura-commax.sh -o plura.sh
	chmod +x plura.sh
}

config_agent_type ()
{
	plura_conf=$PLURA_DIR/conf/plura.conf

	if [ -f $plura_conf ]; then
		sed -i "/agent_type/d" $plura_conf
	else
		echo -e '# plura.conf\n' > $plura_conf
	fi
	echo "agent_type = $1" >> $plura_conf
}

config ()
{
	case $TARGET in
		commax32)
			config_commanx 32
			;;
		commax64)
			config_commanx 64
			;;
		logcollector|PLC)
			curl --noproxy "*" -s https://repo.plura.io/v5/module/rsyslog/80-udp.conf -o /etc/rsyslog.d/80-udp.conf
			config_agent_type $TARGET
			;;
		firewall|haproxy|squid)
			config_agent_type $TARGET
			;;
	esac
}

install ()
{
	echo "Installing plura ..."

	#
	# prepare
	#
	prepare_install

	#
	# download package
	#
	check_binary
	download_package agent/$binary

	if [ ! -f plura.tar.gz ]; then
		echo install-E2
		exit
	fi

	#
	# unpack
	#
	tar xfz plura.tar.gz
	rm -f plura.tar.gz
	
	#
	# config
	#
	config

	#
	# setup
	#
	$PLURA_DIR/plura.sh setup

	echo "Completely installed."
	echo "Next step) plura register [license-key]"
}

install
