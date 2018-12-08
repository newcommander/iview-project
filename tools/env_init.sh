#/bin/bash

ccw=118.31.41.233
basedir=/root/base_dir
tardir=$basedir/tars
remote_tardir=/opt/tars
running_dir=$(pwd)

ccw_private_key="
-----BEGIN_RSA_PRIVATE_KEY-----
MIIEogIBAAKCAQEA5ChtO02tLb+Nq7PFLGFX7CgiZqwFWRoxyEJpJ1FFHv5IAmBf
cfdEtkhvqYVLiOBwFdKj118LPs/pBTjQj12JHv4hlnqBdhcFljPdpBhIvQdA7Mh0
RgQiUsEtuqZBcRnzbwxHgJY1GuPjdfgdBxHgG+k9fcYpofDNqViCWeSPNq3lLuX3
Nt1w0hlLJYZrpuBxhVfrfLjgvAzdjjscW5RSGNxcWCsxcOmPsa3b314Hh+Gih1vh
0wOxeAO4RXfcDgrEkO2qoIPfojQbm4O1wh1CwHYEn8NXr2SGTcQ8UDPkYCpotCw2
/ajUPjK4ML/OcSyCmj/AiE4YSNDRRV67nevkvwIBIwKCAQAGhM/rwGQInxKtImS4
IAnTjB49cqERLKJWLch9d1m/DpRX1t4n091kSzZj7d2WMkxYZRqfwOMQbFcdaAX1
d7N16gD1q7qOWG3fuFbKLJRdLBfMQD3WHWAQ/jSBrPqOM/EDLDyOpTS3oBxxFbev
vq6htjT09wiA+EBj7JYCkYBvRr4z7+16+zRhqVEUk6GeOh/V4Bz4Hkqza0LknAbv
UYF9WrabCtb550EXEc8s/iTF4y2yhkdhQfEhrc2eHpCSU58rxSoOFTcrVpSeYp1C
BtVo6yIq4E4n/jHv1BHAL+3uspJwd9/ZnJ4+nYiimLPEW2znNoP6ZlkYJlbvbBWh
R4w7AoGBAP9KG82mTNubbxztqjmx16FDPscU2qda9PTM8cRZCmgFIDdcVa7cJIfD
g1+dQINgPb2anr7v/v9GKxuICiTaXR5P/46/xaxcwM5YjgRe2QbqFZAPUyaUD/p5
/W/nHgdf6zaSK6WX2TBBW0ERYhFtDznrzYfwYuzLmKzCwSHjKFEZAoGBAOTK/LHA
OGvchBhnrRlTFnYEdS57ugLZbcN/9GVKZTXwVS3JWh5qJyHGuykbXn0ZlKWEYWCX
ALqXFYAfP/MyPuNE+Vvz16hYnPubejFcVQ5+OsizxYGjk7gJyF8iiFVd1SzBnPal
ZgFtTcjkfSkrnWUR/i1b7P0v+kHG1qSt+2eXAoGBAKfC/FPw8K2SBzBEaIxQS98A
TdNIN+pRtuoDBUaDp8Cy6UjziMNddxdjORLyTvc/PoPpQ79NQSton/wmMo0/Cf36
DlZ+BY6GGE0Vnydxh02vxQblf8jk9I6n76/vpgTYoeIISJFjyTz3v5/JmDdWS9Wa
9McLrrjdkDcDo3yrN8BDAoGAE5xezWg/WbPQzuRQqmY1IA8Cutdntxnzdyg5hQZg
clZts3eoo4VxEYYQCtZ10DVkgzc7i++vmvcB18gqDYf2wwXpfOkD2zrLoImrY1EO
mteeo30fjsTgxqHAt7KAttwoNwlH9+JKkmh0Ya0vTKv3jFH/2ACQp/zMTsfmgyTb
COECgYEAtWZnVA3lRGc29PNs7R/mYNuTtFg4DwesxLilcPqnPWD1mmNdq/fH0gGl
EcmEsTIv/HS3q56FMPovzBHb12s+ooAYDG00tX18B1jZQTaH7PscwtOl5ynaQPgp
Flxrj+00kc5ebYihbFtH0jiDTyrQWIxrC//O4AmPX+dM6bV0/qg=
-----END_RSA_PRIVATE_KEY-----
"

check_cmd_exist () {
	cmd=$1
	should_install=0
	if [ "$2" = "install" ]
	then
		should_install=1
	fi
	which $cmd &>/dev/null
	if [ $? -ne 0 ]; then
		if [ $should_install -eq 1 ]
		then
			tool=$cmd
			if [ "$cmd" = "autoreconf" ]
			then
				tool=autoconf
			fi
			yum install -y $tool
			if [ $? -ne 0 ]
			then
				echo "Install '$tool' failed."
				return 1
			fi
		else
			echo "Cannot find cmd '$cmd'."
			return 1
		fi
	fi
	return 0
}

before_running_check () {
	if [ $UID -ne 0 ]; then
		echo "Need root privilege to run this scpript."
		return 1
	fi

	check_cmd_exist git install
	if [ $? -ne 0 ]
	then
		return 1
	fi

	check_cmd_exist automake install
	if [ $? -ne 0 ]
	then
		return 1
	fi

	check_cmd_exist autoreconf install
	if [ $? -ne 0 ]
	then
		return 1
	fi

	yum install -y libtool libsysfs lz4-devel lzo-devel pam-devel

	ping -c 2 -W 10 $ccw
	if [ $? -ne 0 ]
	then
		echo "Cannot reach ccw."
		return 1
	fi

	return 0
}

clone_git_repositories () {
	if [ ! -d openvpn ]
	then
		git clone git://github.com/newcommander/openvpn
		if [ $? -ne 0 ]
		then
			echo "Clone openvpn failed."
			return 1
		fi
	fi

	if [ ! -d iview-project ]
	then
		git clone git://github.com/newcommander/iview-project
		if [ $? -ne 0 ]
		then
			echo "Clone iview-project failed."
			return 1
		fi
	fi

	return 0
}

download_tars () {
	random="$(hexdump -e '1/4 "%02x"' -n 4 /dev/random)"

	key_file=/tmp/ccw_key_$random
	echo $ccw_private_key > $key_file
	sed -i 's/ /\n/g' $key_file
	sed -i 's/_/ /g' $key_file
	chmod 600 $key_file

	local_list=($(md5sum $tardir/*))
	remote_list=($(ssh -i $key_file ccw md5sum $remote_tardir/* | sed 's/\s\+/ /g'))

	for i in ${!remote_list[@]}
	do
		if [ $[$i%2] -eq 1 ]
		then
			continue
		fi

		exist=0
		for j in ${!local_list[@]}
		do
			if [ $[$j%2] -eq 1 ]
			then
				continue
			fi

			if [ "${remote_list[$i]}" == "${local_list[$j]}" ]
			then
				exist=1
			fi
		done

		if [ $exist -eq 0 ]
		then
			scp -i $key_file ccw:${remote_list[$[$i+1]]} $tardir/
		fi
	done

	rm -f $key_file

	return 0
}

build_openssl () {
	openssl_tar="$(ls $tardir | grep -v openssl-fips | grep openssl.*.tar.gz)"
	if [ -z $openssl_tar ]
	then
		echo "Cannot find openssl .tar.gz failed."
		return 1
	fi

	openssl_dir="$(echo $openssl_tar | sed 's/.tar.gz//g')"
	if [ ! -d $openssl_dir ]
	then
		cd $tardir
		tar xf $openssl_tar
		openssl_dir="$(ls $tardir | grep openssl | grep -v tar.gz)"
		if [ ! -d $openssl_dir ]
		then
			echo "Cannot find openssl dir."
			return 1
		fi
	fi

	cd $tardir/$openssl_dir
	./config --prefix=/usr/local
	if [ $? -ne 0 ]
	then
		echo "openssl config failed."
		return 1
	fi

	make
	if [ $? -ne 0 ]
	then
		echo "openssl make failed."
		return 1
	fi

	make install
	if [ $? -ne 0 ]
	then
		echo "openssl make failed."
		return 1
	fi

	ldconfig

	cd $basedir

	return 0

	openssl_fips_tar="$(ls $tardir | grep openssl-fips.*.tar.gz)"
	if [ -z $openssl_fips_tar ]
	then
		echo "Cannot find openssl-fips .tar.gz failed."
		return 1
	fi

	openssl_fips_dir="$(echo $openssl_fips_tar | sed 's/.tar.gz//g')"
	if [ ! -d $openssl_fips_dir ]
	then
		cd $tardir
		tar xf $openssl_fips_tar
		openssl_fips_dir="$(ls $tardir | grep openssl-fips | grep -v tar.gz)"
		if [ ! -d $openssl_fips_dir ]
		then
			echo "Cannot find openssl-fips dir."
			return 1
		fi
	fi

	cd $tardir/$openssl_fips_dir
	./config fips --prefix=/usr/local
	if [ $? -ne 0 ]
	then
		echo "openssl fips config failed."
		return 1
	fi

	make
	if [ $? -ne 0 ]
	then
		echo "openssl fips make failed."
		return 1
	fi

	make install
	if [ $? -ne 0 ]
	then
		echo "openssl fips make install failed."
		return 1
	fi

	ldconfig

	cd $basedir

	return 0
}

build_openvpn () {
	cd $basedir/openvpn
	pkill openvpn

	git checkout shuobu
	if [ $? -ne 0 ]
	then
		echo "openvpn checkout shuobu failed."
		return 1
	fi

	sed -i 's/#define SHUOBU_BIT_REVERSAL/\/\/#define SHUOBU_BIT_REVERSAL/g' src/openvpn/socket.h

	autoreconf -i -v -f
	if [ $? -ne 0 ]
	then
		echo "openvpn autoreconf failed."
		return 1
	fi

	./configure --prefix=/usr/local
	if [ $? -ne 0 ]
	then
		echo "openvpn ./configure failed."
		return 1
	fi

	make
	if [ $? -ne 0 ]
	then
		echo "openvpn make failed."
		return 1
	fi

	make install
	if [ $? -ne 0 ]
	then
		echo "openvpn make install failed."
		return 1
	fi

	git checkout .

	autoreconf -i -v -f
	if [ $? -ne 0 ]
	then
		echo "openvpn reserve bit autoreconf failed."
		return 1
	fi

	./configure --prefix=/usr/local
	if [ $? -ne 0 ]
	then
		echo "openvpn reserve bit ./configure failed."
		return 1
	fi

	make
	if [ $? -ne 0 ]
	then
		echo "openvpn reserve bit make failed."
		return 1
	fi

	cp src/openvpn/openvpn /usr/local/sbin/openvpn-reserve-bit

	cd $basedir

	return 0
}

build_targets () {
	build_openssl
	if [ $? -ne 0 ]
	then
		return 1
	fi

	build_openvpn
	if [ $? -ne 0 ]
	then
		return 1
	fi

	return 0
}

start_openvpn () {
	cd $tardir

	openvpn_conf_tar="$(ls $tardir | grep openvpn.*.tar.gz)"
	if [ -z $openvpn_conf_tar ]
	then
		echo "Cannot find openvpn config tarball"
		return 1
	fi
	openvpn_conf_dir="$(echo $openvpn_conf_tar | sed 's/.tar.gz//g')"
	if [ -z $openvpn_conf_dir ]
	then
		echo "Cannot get openvpn config dir."
		return 1
	fi

	if [ -d $openvpn_conf_dir ]
	then
		rm -rf $openvpn_conf_dir
	fi

	if [ -d /opt/openvpn ]
	then
		rm -rf /opt/openvpn
	fi

	tar xf $openvpn_conf_tar
	if [ $? -ne 0 ]
	then
		echo "decompress openvpn_conf tarball failed."
		return 1
	fi

	mv $openvpn_conf_dir /opt/openvpn

	grep "/usr/local/lib64" /etc/ld.so.conf &>/dev/null
	if [ $? -ne 0 ]
	then
		echo "/usr/local/lib64" >> /etc/ld.so.conf
	fi
	ldconfig

	openvpn-reserve-bit /opt/openvpn/server.conf
	if [ $? -ne 0 ]
	then
		echo "Start openvpn daemon failed."
		return 1
	fi

	eth0_addr="$(ifconfig eth0 | grep "inet " | sed 's/\s\+/ /g' | sed 's/^ //g' | cut -d' ' -f2)"
	if [ -z $eth0_addr ]
	then
		echo "Cannot get eth0 address."
		return 1
	fi

	echo 1 > /proc/sys/net/ipv4/ip_forward

	iptables -t nat -A POSTROUTING -d 0.0.0.0/0 -j SNAT --to-source $eth0_addr --random
	if [ $? -ne 0 ]
	then
		echo "set iptables failed."
		return 1
	fi

	cd $basedir

	return 0
}

before_running_check
if [ $? -ne 0 ]
then
	exit 1
fi

if [ ! -d $basedir ]
then
	mkdir $basedir
fi
cd $basedir

clone_git_repositories
if [ $? -ne 0 ]
then
	exit 1
fi

if [ ! -d $tardir ]
then
	mkdir $tardir
fi

download_tars
if [ $? -ne 0 ]
then
	exit 1
fi

build_targets
if [ $? -ne 0 ]
then
	exit 1
fi

start_openvpn
if [ $? -ne 0 ]
then
	exit 1
fi

echo "Work done!"
exit 0
