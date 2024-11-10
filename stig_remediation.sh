#!/usr/bin/env bash

<<"COM"
	Description: This is a bash script that will remediate hits listed in scan_results_11-05-2024.html
	Author: i-stackz
	Date: 11/05/2024
COM

# check if running as root
if [[ $(id -u) != 0 ]]
then
	# display message
	echo -e "\nError! Script must be ran as root. Try again!";

	# error exit
	exit 1;
fi

# STIGREF: SV-258230r926677_rule
# Configure System Cryptography Policy

# display STIGREF
echo -e "\nSV-258230r926677_rule";

# check if crypto policy is set to FIPS
if [[ $(update-crypto-policies --show) != 'FIPS' ]]
then
	# set crypto policy to FIPS
	update-crypto-policies --set FIPS;

	# alternative
	fips-mode-setup --enable;

	# display message
	echo -e "\nSystem requires a reboot in order for policy to take effect";
fi

# double check
if [[ $(update-crypto-policies --show) == 'FIPS' ]]
then
	echo -e "\nCurrent crypto policy is set to FIPS";
fi

# STIGREF: SV-257989r943014_rule and SV-257988r925951_rule
# Configure SSH Server to Use FIPS 140-2 Validated Ciphers: opensshserver.config and openssh.conf

# display STIGREF
echo -e "\nSV-257989r943014_rule and SV-257988r925951_rule";

# array containing file paths
FILES=("/etc/crypto-policies/back-ends/openssh.config" "/etc/crypto-policies/back-ends/opensshserver.config");

for FILE in ${FILES[@]}
do
	# backup /etc/crypto-policies/back-ends/opensshserver.config
	cp -n $FILE $FILE.bak;

	# check /etc/crypto-policies/back-ends/opensshserver.config
	if [[ $(grep -i '^ciphers' $FILE | cut -d ' ' -f 2) != 'aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-ctr,aes128-gcm@openssh.com,aes128-ctr' ]]
	then
		# search and replace
		sed -r -i 's/^Ciphers..+/Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-ctr,aes128-gcm@openssh.com,aes128-ctr/1' $FILE;
	else
		# display message
		echo -e "\nParameter 'Ciphers' is already set to 'aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-ctr,aes128-gcm@openssh.com,aes128-ctr'";
	fi
done

# STIGREF: SV-257777r925318_rule
# The Installed Operating System Is Vendor Supported

# display STIGREF
echo -e "\nSV-257777r925318_rule";

# NOTE: This hit would have to be a risk acceptance because we are utlizing ROCKY Linux 9
echo -e "\nThis hit would have to be a risk acceptance";

# STIGREF: SV-257839r925504_rule
# Ensure gnutls-utils is installed

# display STIGREF
echo -e "\nSV-257839r925504_rule";

# check if gnutls-utils is installed
if [[ -z $(yum list installed | grep -i 'gnutls-utils') ]]
then
	# display message
	echo -e "\nPackage 'gnutls-utils' is not installed. Will install it now.";

	# install package
	yum install -y gnutls-utils;
else
	# display message
	echo -e "\nPackage 'gnutls-utils' is already installed on this system.";
fi

# STIGREF: SV-257840r925507_rule
# Ensure nss-tools is installed

# display STIGREF
echo -e "\nSV-257840r925507_rule"

# check if nss-tools package is installed
if [[ -z $(rpm -qa 'nss-tools') ]]
then
	# install package
	yum install -y nss-tools;
else
	# display message
	echo -e "\nPackage 'nss-tools' is already installed on this system";
fi

# STIGREF: SV-257825r925462_rule
# Install subscription-manager package

# display STIGREF
echo -e "\nSV-257825r925462_rule";

# command to check if subscription-manager is installed
if ! [[ $(yum list installed | grep -i 'subscription-manager' ) ]]
then
	# install package
	yum install -y subscription-manager;
fi

# STIGREF: SV-257821r925450_rule
# Ensure gpgcheck Enabled for Local Packages

# display STIGREF
echo -e "\nSV-257821r925450_rule";

# check /etc/dnf/dnf.conf for the localpkg_gpgcheck parameter and ensure it is set to 1
if [[ $(grep -i '^localpkg_gpgcheck' /etc/dnf/dnf.conf) ]]
then
	# make sure the parameter is set correctly
	if [[ $(grep -i '^localpkg_gpgcheck' /etc/dnf/dnf.conf | cut -d '=' -f 2) != 1 ]]
	then
		# search and replace
		sed -r -i 's/^localpkg_gpgcheck..+/localpkg_gpgcheck=1/1' /etc/dnf/dnf.conf;
	fi
else
	# display message
	echo -e "\nParameter 'localpkg_gpgcheck' is not found within '/etc/dnf/dnf.conf', will add it now";

	# add line to file
	sed -i '$a localpkg_gpgcheck=1' /etc/dnf/dnf.conf;
fi

# STIGREF: SV-257778r925321_rule
# Ensure Software Patches Installed

# display STIGREF
echo -e "\nSV-257778r925321_rule";

# command to check if there are any updates available
if [[ -z $(yum check-update) ]]
then
	# dislay message
	echo -e "\nSystem is up to date";
else
	# run system updates
	yum update -y;
fi

# STIGREF: SV-258096r926275_rule and SV-258095r926272_rule
# Configure the Use of the pam_faillock.so Module in the /etc/pam.d/password-auth File

# display STIGREF
echo -e "\nSV-258096r926275_rule and SV-258095r926272_rule";

# create backup of /etc/pam.d/system-auth and password-auth
cp -n /etc/pam.d/system-auth /etc/pam.d/system-auth.bak;
cp -n /etc/pam.d/password-auth /etc/pam.d/password-auth.bak;

# array containing password-auth and system-auth as values
PAM_FILES=("/etc/pam.d/system-auth" "/etc/pam.d/password-auth");

# for loop to iterate through PAM_FILES array
for FILE in ${PAM_FILES[@]}
do
	# if statement to check its contents for the pam_faillock parameter/setting
	if ! [[ $(grep -E '^\s*auth\s+required\s+pam_faillock\.so\s+(preauth silent|authfail).*$' $FILE) ]]
	then
		# sed commands to add lines to file
		sed -r -i --follow-symlinks '/^auth.*sufficient.*pam_unix\.so.*/i auth    required     pam_faillock.so preauth silent' $FILE;
		sed -r -i --follow-symlinks '/^auth.*required.*pam_deny\.so.*/i auth    required     pam_faillock.so authfail' $FILE;
		sed -r -i --follow-symlinks '/^account.*required.*pam_unix\.so.*/i account    required     pam_faillock.so' $FILE;
	fi
done

# STIGREF: SV-258092r926263_rule and SV-258093r926266_rule
# Limit Password Reuse: password-auth and system-auth

# display STIGREF
echo -e "\nSV-258092r926263_rule and SV-258093r926266_rule";

# array containing password-auth and system-auth
PAM_FILES=("/etc/pam.d/password-auth" "/etc/pam.d/system-auth");

# for loop to iterate through array
for FILE in ${PAM_FILES[@]}
do
	# check /etc/pam.d/password-auth for 'password (requisite|required)	pam_pwhistory.so remember=5 retry=1'
	if ! [[ $(grep -E '^\s*password\s+(requisite|required)\s+pam_pwhistory\.so\s+remember\=[0-9]\s+retry\=[0-9].*$' $FILE) ]]
	then
		# sed commands to add line to file
		sed -r -i --follow-symlinks '/^password.*sufficient.*pam_unix\.so.*/a password	requisite     pam_pwhistory.so remember=5 retry=1' $FILE;
	fi
done

# STIGREF: SV-258070r926197_rule
# Account Lockouts Must Be Logged

# display STIGREF
echo -e "\nSV-258070r926197_rule";

# check that /etc/security/faillock.conf exists
if [[ -e /etc/security/faillock.conf ]]
then
	# backup the file
	cp -n /etc/security/faillock.conf;

	# check that it contains the parameter 'audit'
	if ! [[ $(grep -i '^audit' /etc/security/faillock.conf) ]]
	then
		# add line to file
		sed -i '$a audit' /etc/security/faillock.conf;
	fi
fi

# STIGREF: SV-258054r926149_rule
# Lock Accounts After Failed Password Attempts

# display STIGREF
echo -e "\nSV-258054r926149_rule";

# check /etc/security/faillock.conf for 'deny = 3'
if [[ $(grep -w -i '^deny' /etc/security/faillock.conf) ]]
then
	# check that parameter is set correctly
	if [[ $(grep -w -i '^deny' /etc/security/faillock.conf | cut -d '=' -f 2) != 3 ]]
	then
		sed -i -r 's/^deny..+/deny = 3/1' /etc/security/faillock.conf;
	fi
else
	# add line to file
	sed -i '$a deny = 3' /etc/security/faillock.conf;
fi

# STIGREF: SV-258055r926152_rule
# Configure the root Account for Failed Password Attempts

# display STIGREF
echo -e "\nSV-258055r926152_rule";

# check /etc/security/faillock.conf file for 'even_deny_root'
if ! [[ $(grep -i '^even_deny_root' /etc/security/faillock.conf) ]]
then
	# add line to file
	sed -i '$a even_deny_root' /etc/security/faillock.conf;
fi

# STIGREF SV-258060r926167_rule
# Lock Accounts Must Persist

# display STIGREF
echo -e "\nSV-258060r926167_rule";

# check /etc/security/faillock.conf for 'dir' parameter
if [[ $(grep -i '^dir' /etc/security/faillock.conf) ]]
then
	# check that parameter is set to '/var/log/faillock'
	if [[ $(grep -w -i '^dir' /etc/security/faillock.conf | cut -d '=' -f 2) != '/var/log/faillock' ]]
	then
		# search and replace
		sed -r -i 's/^dir..+/dir = \/var\/log\/faillock/1' /etc/security/faillock.conf;
	fi
else
	# add line to file
	sed -i '$a dir = /var/log/faillock' /etc/security/faillock.conf;
fi

# STIGREF SV-258056r926155_rule
# Set Interval For Counting Failed Password Attempts

# display STIGREF
echo -e "\nSV-258056r926155_rule";

# check /etc/security/faillock.conf for 'fail_interval' parameter
if [[ $(grep -i '^fail_interval' /etc/security/faillock.conf) ]]
then
	# check if parameter is set to 900
	if [[ $(grep -w -i '^fail_interval' /etc/security/faillock.conf | cut -d '=' -f 2) != 900 ]]
	then
		# search and replace
		sed -r -i 's/^fail_interval..+/fail_interval = 900/1' /etc/security/faillock.conf;
	fi
else
	# add line to file
	sed -i '$a fail_interval = 900' /etc/security/faillock.conf;
fi

# STIGREF SV-258057r926158_rule
# Set Lockout Time for Failed Password Attempts

# display STIGREF
echo -e "\nSV-258057r926158_rule";

# check /etc/security/faillock.conf for 'unlock_time = 0'
if [[ $(grep -i '^unlock_time' /etc/security/faillock.conf) ]]
then
	# check if parameter is set to 0
	if [[ $(grep -w -i '^unlock_time' /etc/security/faillock.conf | cut -d '=' -f 2) != 0 ]]
	then
		# search and replace
		sed -r -i 's/^unlock_time..+/unlock_time = 0/1' /etc/security/faillock.conf;
	fi
else
	# add line to file
	sed -i '$a unlock_time = 0' /etc/security/faillock.conf;
fi

# STIGREF SV-258103r926296_rule
# Ensure PAM Enforces Password Requirements - Minimum Digit Characters

# display STIGREF
echo -e "\nSV-258103r926296_rule";

# check to see if /etc/security/pwquality.conf exists
if [[ -e /etc/security/pwquality.conf ]]
then
	# create a backup
	cp -n /etc/security/pwquality.conf /etc/security/pwquality.conf.bak;

	# check for 'dcredit' within file
	if [[ $(grep -w -i '^dcredit' /etc/security/pwquality.conf) ]]
	then
		# ensure parameter is set to negative one
		if [[ $(grep -w -i '^dcredit' /etc/security/pwquality.conf | cut -d '=' -f 2) != -1 ]]
		then
			# search and replace
			sed -r -i 's/^dcredit..+/dcredit = -1/1' /etc/security/pwquality.conf;
		fi
	else
		# add parameter to file
		sed -i '$a dcredit = -1' /etc/security/pwquality.conf;
	fi
else
	# display message
	echo -e "\nError! file /etc/security/pwquality.conf' does not exist";
fi

# STIGREF: SV-258110r926317_rule
# Ensure PAM Enforces Password Requirements - Prevent the Use of Dictionary Words

# display STIGREF:
echo -e "\nSV-258110r926317_rule"

# check for 'dictcheck' within /etc/security/pwquality.conf
if [[ $(grep -w -i '^dictcheck' /etc/security/pwquality.conf) ]]
then
	# check if parameter is set to 1
	if [[ $(grep -w -i '^dictcheck' /etc/security/pwquality.conf | cut -d '=' -f 2) != 1 ]]
	then
		# search and replace
		sed -r -i 's/^dictcheck..+/dictcheck = 1/1' /etc/security/pwquality.conf;
	fi
else
	# add parameter to file
	sed -i '$a dictcheck = 1' /etc/security/pwquality.conf;
fi

# STIGREF: SV-258112r926323_rule
# Ensure PAM Enforces Password Requirements - Minimum Different Characters

# display STIGREF
echo -e "\nSV-258112r926323_rule";

# check if /etc/security/pwquality.conf file contains 'difok'
if [[ $(grep -w -i '^difok' /etc/security/pwquality.conf) ]]
then
	# check if 'difok' is set to 8
	if [[ $(grep -w -i '^difok' /etc/security/pwquality.conf | cut -d '=' -f 2) != 8 ]]
	then
		# search and replace
		sed -r -i 's/^difok..+/difok = 8/1' /etc/security/pwquality.conf;
	fi
else
	# add line to file
	sed -i '$a difok = 8' /etc/security/pwquality.conf;
fi

# STIGREF: SV-258101r926290_rule
# Ensure PAM Enforces Password Requirements - Enforce for root User

# display STIGREF
echo -e "\nSV-258101r926290_rule";

# check /etc/security/pwquality.conf for 'enforce_for_root' parameter
if ! [[ $(grep -i '^enforce_for_root' /etc/security/pwquality.conf) ]]
then
	# add line to file
	sed -i '$a enforce_for_root' /etc/security/pwquality.conf;
fi

# STIGREF: SV-258102r926293_rule
# Ensure PAM Enforces Password Requirements - Minimum Lowercase Characters

# display STIGREF
echo -e "\nSV-258102r926293_rule";

# check /etc/security/pwquality.conf for 'lcredit' parameter
if [[ $(grep -i '^lcredit' /etc/security/pwquality.conf) ]]
then
	# ensure parameter is set correctly
	if [[ $(grep -w -i '^lcredit' /etc/security/pwquality.conf | cut -d '=' -f 2) != -1 ]]
	then
		# search and replace
		sed -r -i 's/^lcredit..+/lcredit = -1/1' /etc/security/pwquality.conf;
	fi
else
	# add parameter to file
	sed -i '$a lcredit = -1' /etc/security/pwquality.conf;
fi

# STIGREF: SV-258113r926326_rule
# Ensure PAM Enforces Password Requirements - Maximum Consecutive Repeating Characters from Same Character Class

# display STIGREF
echo -e "\nSV-258113r926326_rule";

# check /etc/security/pwquality.conf for 'maxclassrepeat'
if [[ $(grep -i '^maxclassrepeat' /etc/security/pwquality.conf) ]]
then
	# ensure parameter is set correctly (4)
	if [[ $(grep -i -w '^maxclassrepeat' /etc/security/pwquality.conf | cut -d '=' -f 2) != 4 ]]
	then
		# search and repeat
		sed -r -i 's/^maxclassrepeat..+/maxclassrepeat = 4/1' /etc/security/pwquality.conf;
	fi
else
	# add parameter to file
	sed -i '$a maxclassrepeat = 4' /etc/security/pwquality.conf;
fi

# STIGREF: SV-258114r926329_rule
# Set Password Maximum Consecutive Repeating Characters

# display STIGREF
echo -e "\nSV-258114r926329_rule";

# check pwquality.conf for 'maxrepeat'
if [[ $(grep -i '^maxrepeat' /etc/security/pwquality.conf) ]]
then
	# check if parameter is set to 3
	if [[ $(grep -w -i '^maxrepeat' /etc/security/pwquality.conf | cut -d '=' -f 2) != 3 ]]
	then
		# search and replace
		sed -r -i 's/^maxrepeat..+/maxrepeat = 3/1' /etc/security/pwquality.conf;
	fi
else
	# add line to file
	sed -i '$a maxrepeat = 3' /etc/security/pwquality.conf;
fi

# STIGREF: SV-258115r926332_rule
# Ensure PAM Enforces Password Requirements - Minimum Different Categories 

# display STIGREF
echo -e "\nSV-258115r926332_rule";

# check pwquality for 'minclass' 
if [[ $(grep -i '^minclass' /etc/security/pwquality.conf) ]]
then
	# check that parameter is set to 4
	if [[ $(grep -w -i '^minclass' /etc/security/pwquality.conf | cut -d '=' -f 2) != 4 ]]
	then
		# search and replace
		sed -r -i 's/^minclass..+/minclass = 4/1' /etc/security/pwquality.conf;
	fi
else
	# add line to file
	sed -i '$a minclass = 4' /etc/security/pwquality.conf;
fi

# STIGREF: SV-258107r926308_rule
# Ensure PAM Enforces Password Requirements - Minimum Length 

# display STIGREF
echo -e "\nSV-258107r926308_rule";

# check pwquality for 'minlen'
if [[ $(grep -i '^minlen' /etc/security/pwquality.conf) ]]
then
	# ensure parameter is set to 15
	if [[ $(grep -w -i '^minlen' /etc/security/pwquality.conf | cut -d '=' -f 2) != 15 ]]
	then
		# search and replace
		sed -r -i 's/^minlen..+/minlen = 15/1' /etc/security/pwquality.conf;
	fi
else
	# add line to file
	sed -i '$a minlen = 15' /etc/security/pwquality.conf;
fi

# STIGREF: SV-258109r926314_rule
# Ensure PAM Enforces Password Requirements - Minimum Special Characters

# display STIGREF
echo -e "\nSV-258109r926314_rule";

# check pwquality.conf for 'ocredit'
if [[ $(grep -i '^ocredit' /etc/security/pwqulaity.conf) ]]
then
	# ensure it is set to -1
	if [[ $(grep -w -i '^ocredit' /etc/security/pwquality.conf | cut -d '=' -f 2) != -1 ]]
	then
		# search and replace
		sed -r -i 's/^ocredit..+/ocredit = -1/1' /etc/security/pwquality.conf;
	fi
else
	# add line to file 
	sed -i '$a ocredit = -1' /etc/security/pwquality.conf;
fi

# STIGREF: SV-258111r926320_rule
# Ensure PAM Enforces Password Requirements - Minimum Uppercase Characters

# display STIGREF
echo -e "\nSV-258111r926320_rule";

# check pwquality for 'ucredit'
if [[ $(grep -i '^ucredit' /etc/security/pwquality.conf) ]]
then
	# ensure parameter is set to -1
	if [[ $(grep -w -i '^ucredit' /etc/security/pwquality.conf | cut -d '=' -f 2) != -1 ]]
	then
		# search and replace
		sed -r -i 's/^ucredit..+/ucredit = -1/1' /etc/security/pwquality.conf;
	fi
else
	# add line to file
	sed -i '$a ucredit = -1' /etc/security/pwquality.conf;
fi

# STIGREF: SV-258049r926134_rule
# Set Account Expiration Following Inactivity

# display STIGREF
echo -e "\nSV-258049r926134_rule";

# check if /etc/default/useradd exists
if [[ -e /etc/default/useradd ]]
then
	# check the contents of useradd for the 'Inactive' parameter
	if [[ $(grep -i '^inactive' /etc/default/useradd) ]]
	then
		# check if the parameter is set to 35
		if [[ $(grep -i '^inactive' /etc/default/useradd | cut -d '=' -f 2) != 35 ]]
		then
			# search and replace
			sed -r -i 's/^INACTIVE..+/INACTIVE=35/1' /etc/default/useradd;
		fi
	else
		# add line to file
		sed -i '$a INACTIVE=35' /etc/default/useradd;
	fi
fi

# STIGREF: SV-258041r926110_rule
# Set Password Maximum Age 

# display STIGREF
echo -e "\nSV-258041r926110_rule";

# check if /etc/login.defs exists
if [[ -e /etc/login.defs ]]
then
	# check if 'PASS_MAX_DAYS' exist
	if [[ $(grep -i '^pass_max_days' /etc/login.defs) ]]
	then
		# ensure parameter is set correctly
		if [[ $(grep -w -i '^pass_max_days' /etc/login.defs) != 'PASS_MAX_DAYS 60' ]]
		then
			# search and replace
			sed -r -i 's/^PASS_MAX_DAYS..+/PASS_MAX_DAYS 60/1' /etc/login.defs;
		fi
	else
		# add line to file
		sed -i '$a PASS_MAX_DAYS 60' /etc/login.defs;
	fi
fi

# STIGREF: SV-258104r926299_rule
# Set Password Minimum Age

# display STIGREF
echo -e "\nSV-258104r926299_rule";

# check for 'PASS_MIN_DAYS 1'
if [[ $(grep -i '^pass_min_days' /etc/login.defs) ]]
then
	# check to see if parameter is set to 1
	if [[ $(grep -w -i '^pass_min_days' /etc/login.defs | cut -d ' ' -f 2) != 1 ]]
	then
		# search and replace
		sed -r -i 's/^PASS_MIN_DAYS..+/PASS_MIN_DAYS 1/1' /etc/login.defs;
	fi
else
	# add line to file 
	sed -i '$a PASS_MIN_DAYS 1' /etc/login.defs;
fi

# STIGREF: SV-258108r926311_rule
# Set Password Minimum Length in login.defs 

# display STIGREF
echo -e "\nSV-258108r926311_rule";

# check for 'PASS_MIN_LEN'
if [[ $(grep -i '^PASS_MIN_LEN' /etc/login.defs) ]]
then
	# make sure it is set to '15'
	if [[ $(grep -w -i '^pass_min_len' /etc/login.defs | cut -d ' ' -f 2) != 15 ]]
	then
		# search and replace
		sed -r -i 's/^PASS_MIN_LEN..+/PASS_MIN_LEN 15/1' /etc/login.defs;
	fi
else
	# add line to file 
	sed -i '$a PASS_MIN_LEN 15' /etc/login.defs;
fi

# STIGREF: SV-258099r926284_rule and SV-258100r926287_rule
# Set number of Password Hashing Rounds - password-auth and system-auth

# display STIGREF
echo -e "\nSV-258099r926284_rule and SV-258100r926287_rule";

PAM_FILES=("/etc/pam.d/password-auth" "/etc/pam.d/system-auth");

for FILE in "${PAM_FILES[@]}"
do
	# check /etc/pam.d/password-auth/system-auth for 'password sufficient...' exists
	if [[ $(grep -E -w '^password\s+sufficient..+' $FILE) ]]
	then
		# check if that line has 'rounds=5000'
		if [[ $(grep -E -w '^password\s+sufficient..+' $FILE | grep -i 'rounds' | cut -d '=' -f 2) != 5000 ]]
		then
			# search and replace
			sed -r -i '/^password\s+sufficient\s+pam_unix\.so/ {s/rounds=..+/rounds=5000/}' $FILE;
		else
			# append 'rounds=5000' to line
			sed -r -i '/^password\s+sufficient\s+pam_unix\.so/ {/rounds=/! s/$/ rounds=5000/}' $FILE;
		fi
	else
		# add line to file
		sed -r -i '/password\s+requisite\s+pam_pwquality\.so.*/a password    sufficient    pam_unix.so rounds=5000' $FILE;
	fi
done

# STIGREF: SV-258088r926251_rule
# Enforce usage of pam_wheel for su authentication

# display STIGREF
echo -e "\nSV-258088r926251_rule";

# check if /etc/pam.d/su exists
if [[ -e /etc/pam.d/su ]]
then
	# create a backup
	cp -n /etc/pam.d/su /etc/pam.d/su.bak;

	# check if parameter 'auth required pam_wheel.so use_id' exists within file
	if [[ $(grep -E -w -i '^auth\s+required\s+pam_wheel.so' /etc/pam.d/su) ]]
	then
		# ensure that line contains use_id
		if ! [[ $(grep -E -w -i '^auth\s+required\s+pam_wheel.so' /etc/pam.d/su | grep -i 'use_uid') ]]
		then
			# search and replace
			sed -r -i '/^auth\s+required.*/ {/pam_wheel.so/ s/$/ use_uid/}' /etc/pam.d/su
		fi
	else
		# add line to file
		sed -r -i '/auth\s+substack\s+system-auth.*/i auth            required        pam_wheel.so use_uid' /etc/pam.d/su;
	fi
fi

# STIGREF: SV-258072r926203_rule
# Ensure the Default Bash Umask is Set Correctly

# display STIGREF
echo -e "\nSV-258072r926203_rule";

# create backup of file
cp -n /etc/bashrc /etc/bashrc.bak;

# check if umask is set within /etc/bashrc
if [[ $(grep -i '^umask' /etc/bashrc) ]]
then
	# check if it is set to 077 (umask set the reverse default value of a chmod permission)
	if [[ $(grep -i '^umask' /etc/bashrc | cut -d ' ' -f 2) != 077 ]]
	then
		# search and replace
		sed -r -i 's/^umask..+/umask 077/1' /etc/bashrc;
	fi
else
	# add line to file
	echo -e "\n# setting umask to 077 as required by stig" >> /etc/bashrc;
	sed -i '$a umask 077' /etc/bashrc;
fi

# set the umask in the system
if [[ $(grep -i '^umask' /etc/bashrc | cut -d ' ' -f 2) == 077 ]] && [[ $(umask) != 077 ]]
then
	# have the system run command to set umask
	umask 077;
fi

# STIGREF SV-258073r926206_rule
# Ensure the Default C Shell Umask is Set Correctly

# dispaly STIGREF
echo -e "\nSV-258073r926206_rule";

# check if file exists
if [[ -e /etc/csh.cshrc ]]
then
	# create backup of file
	cp -n /etc/csh.cshrc /etc/csh.cshrc.bak;

	# check for umask
	if [[ $(grep -i '^umask' /etc/csh.cshrc) ]]
	then
		# check if it is set to 077
		if [[ $(grep -i '^umask' /etc/csh.cshrc | cut -d ' ' -f 2) != 077 ]]
		then
			# search and replace
			sed -r -i 's/^umask..+/umask 077/1' /etc/csh.cshrc;
		fi
	else
		# add umask to file
		echo -e "\nSetting umask value as required by stig" >> /etc/csh.cshrc;
		sed -i '$a umask 077' /etc/csh.cshrc;
	fi
fi

# STIGREF: SV-258074r926209_rule
# Ensure the Default Umask is Set Correctly in login.defs

# display STIGREF
echo -e "\nSV-258074r926209_rule";

# check if file exists
if [[ -e /etc/login.defs ]]
then
	# create a backup of file
	cp -n /etc/login.defs /etc/login.defs.bak;

	# check file for 'umask' word
	if [[ $(grep -i '^umask' /etc/login.defs) ]]
	then
		# check if parameter is set to 077
		if [[ $(grep -i '^umask' /etc/login.defs | cut -d ' ' -f 2) != 077 ]]
		then
			# search and replace
			sed -r -i 's/^umask..+/umask 077/1' /etc/login.defs;
		fi
	else
		# add line to file
		echo -e "\nSetting umask value to 077 as required by stig" >> /etc/login.defs;
		sed -i '$a umask 077' /etc/login.defs;
	fi
fi

# STIGREF: SV-258075r926212_rule
# Ensure the Default Umask is Set Correctly in /etc/profile

# display STIGREF
echo -e "\nSV-258075r926212_rule";

# check if file exists
if [[ -e /etc/profile ]]
then
	# check file for 'umask' word
	if [[ $(grep -i '^umask' /etc/profile) ]]
	then
		# check that umask is set to 077
		if [[ $(grep -i '^umask' /etc/profile | cut -d ' ' -f 2) != 077 ]]
		then
			# search and replace
			sed -r -i 's/^umask..+/umask 077/1' /etc/profile;
		fi
	else
		# add line to file
		echo -e "\nSetting umask to 077 as required by stig" >> /etc/profile;
		sed -i '$a umask 077' /etc/profile;
	fi
fi

# STIGREF: SV-258071r926200_rule
# Ensure the Logon Failure Delay is Set Correctly in login.defs

# display STIGREF
echo -e "\nSV-258071r926200_rule";

# check /etc/login.defs for 'FAIL_DELAY' word
if [[ $(grep -i '^fail_delay' /etc/login.defs) ]]
then
	# check to see if parameter is set to '4'
	if [[ $(grep -i '^fail_delay' /etc/login.defs | cut -d ' ' -f 2) != 4 ]]
	then
		# search and replace
		sed -r -i 's/^FAIL_DELAY..+/FAIL_DELAY 4/1' /etc/login.defs;
	fi
else
	# add line to file
	echo -e "\nSetting parameter as required by stig";
	sed -i '$a FAIL_DELAY 4' /etc/login.defs;
fi

# STIGREF: SV-258069r926194_rule
# Limit the Number of Concurrent Login Sessions Allowed Per User 

# display STIGREF
echo -e "\nSV-258069r926194_rule";

# check if file exists
if [[ -e /etc/security/limits.conf ]]
then
	# create a backup of the file
	cp -n /etc/security/limits.conf /etc/security/limits.conf.bak;

	# check if file contains '* hard maxlogins' in /etc/security/limits.conf
	if [[ $(grep -i '\* hard maxlogins' /etc/security/limits.conf) ]]
	then
		# check if parameter is set to 10
		if [[ $(grep -w -i '\* hard maxlogins' /etc/security/limits.conf | cut -d ' ' -f 2) != 10 ]]
		then
			# search and replace
			sed -r -i 's/\* hard maxlogins..+/\* hard maxlogins 10/1' /etc/security/limits.conf;
		fi
	else
		# add line to file
		echo -e "\nSetting '* hard maxlogins' to 10 as required by stig" >> /etc/security/limits.conf;
		sed -i '$a \* hard maxlogins 10' /etc/security/limits.conf;

	fi
fi

# STIGREF: SV-257889r925654_rule
# Ensure All User Initialization Files Have Mode 0740 Or Less Permissive

# display STIGREF
echo -e "\nSV-257889r925654_rule";

# check /root and /home/<user> directories for dot-files (initialization files) and ensure their permissions are correct
for FILE in $(find /root /home -type f -name ".*")
do
	# check the permissions of each file
	
	# variables
	PERMS=$(stat -c '%a' $FILE); # grabs the permissions set for each file
	LENGTH=${#PERMS}; # grabs the length of the PERMS variable

	# check if the Length variable is equal to 4
	if [[ ${LENGTH} == 4 ]]
	then
		# variables (file permission values)
		STICKY=${PERMS:0:1};
		USER=${PERMS:1:1};
		GROUP=${PERMS:2:1};
		OTHER=${PERMS:3:1};

		# set change the perms for group 
		if [[ ${GROUP} != 4 ]]
		then
			# change the value of GROUP variable
			GROUP=4;

			# use chmod to change the permission for GROUP owner while keeping the rest of the values the same
			chmod ${STICKY}${USER}${GROUP}${OTHER} $FILE;
		fi

		if [[ $(OTHER) != 0 ]]
		then
			# change the value of OTHER variable
			OTHER=0;

			# use chmod to modify the OTHER permissions of the file while keeping the rest of the values the same
			chmod ${STICKY}${USER}${GROUP}${OTHER} $FILE;
		fi
	fi

	# check if the LENGTH variable is equal to 3
	if [[ ${LENGTH} == 3 ]]
	then
		# variables (file permission values)
		USER=${PERMS:0:1};
		GROUP=${PERMS:1:1};
		OTHER=${PERMS:2:1};

		# check GROUP variable value
		if [[ ${GROUP} != 4 ]]
		then
			# change GROUP variable value
			GROUP=4;

			# chmod command to change permissions while keeping all other values the same
			chmod ${USER}${GROUP}${OTHER} $FILE;
		fi
 
		if [[ ${OTHER} != 0 ]]
		then
			# change value of OTHER variable
			OTHER=0;

			# use chmod to modify permissions
			chmod ${USER}${GROUP}${OTHER} $FILE;
		fi
	fi
done

# STIGREF: SV-257954r925849_rule
# Install libreswan Package 

# display STIGREF
echo -e "\nSV-257954r925849_rule";

# check if package is installed 
if ! [[ $(yum list installed | grep -i 'libreswan') ]]
then
	# install the package
	yum install libreswan -y;
fi

# STIGREF: SV-257929r925774_rule
# Verify that All World-Writable Directories Have Sticky Bits Set

# display STIGREF
echo -e "\nSV-257929r925774_rule";

# command to find directories within the local filesystem that are world writable, do not have the sticky bit set, and add stickybit
find $(df --local -P) -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null -exec {} \;;

# mutliline comment (heredoc syntax)
<<"COM"
	NOTES:
	a command to list out local filesystem directories
	"df --local -P | awk '{if (NR!=1) print $6}" or "df --local -P | awk '{print $6}'| sed '/^Mounted/d'"

	alterantive command:
	df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '$6' find '$6' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null -exec chmod a+t {} +
COM

# STIGREF: SV-257812r925423_rule
# Disable core dump backtraces

# display STIGREF
echo -e "\nSV-257812r925423_rule";

# check if /etc/systemd/coredump.conf exists
if [[ -e /etc/systemd/coredump.conf ]]
then 
	# create file backup
	cp -n /etc/systemd/coredump.conf /etc/systemd/coredump.conf.bak;

	# check file for 'ProcessSizeMax' parameter
	if [[ $(grep -i '^processsizemax' /etc/systemd/coredump.conf) ]]
	then
		# check if it is set to 1
		if [[ $(grep -w -i '^processsizemax' /etc/systemd/coredump.conf | cut -d '=' -f 2) != 1 ]]
		then
			# search and replace
			sed -r -i 's/^ProcessSizeMax..+/ProcessSizeMax=0/1' /etc/systemd/coredump.conf
		fi
	else
		# add line to file
		sed -i '/\[CoreDump\]/a ProcessSizeMax=0' /etc/systemd/coredump.conf;
	fi
else
	# create file and add parameter to it
	cat <<"COM" > /etc/systemd/coredump.conf
[CoreDump]
ProcessSizeMax=0
COM
fi

# STIGREF: SV-257813r925426_rule
# Disable storing core dump

# display SV-257813r925426_rule
echo -e "\nSV-257813r925426_rule";

# check file for 'Storage'
if [[ $(grep -i '^storage' /etc/systemd/coredump.conf) ]]
then
	# check if the parameter is set correctly
	if [[ $(grep -i '^storage' /etc/systemd/coredump.conf | cut -d '=' -f 2) != 'none' ]]
	then
		# search and replace
		sed -r -i 's/^Storage..+/Storage=none/1' /etc/systemd/coredump.conf;
	fi
else
	# add line to file
	sed -i '/\[CoreDump\]/a Storage=none' /etc/systemd/coredump.conf;
fi

# STIGREF SV-257814r925429_rule
# Disable Core Dumps for All Users

# display STIGREF
echo -e "\nSV-257814r925429_rule";

# check if file exists
if [[ -e /etc/security/limits.conf ]]
then
	# create a backup
	cp -n /etc/security/limits.conf /etc/security/limits.conf;

	# check file for '* hard core 0'
	if ! [[ $(grep -i '^\* hard core 0' /etc/security/limits.conf) ]]
	then
		# add line to file
		sed -i '$a \* hard core 0' /etc/security/limits.conf;
	fi
else
	# create file
	echo '* hard core 0' > /etc/security/limits.conf;
fi