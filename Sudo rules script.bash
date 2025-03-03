#!/bin/bash
#*******Begin Comment**************
.SYNOPSIS
#This script is to audit linux servers their privileged accounts.
#  Script for privileged accounts
# version 01 Debian
# Autor: Saith Barreto
# Fecha: Septiembre 2020
#*******End Comment**************
#PATH=$PATH:/sbin:/bin:/usr/sbin:/usr/bin

#export $PATH

tmpFile=/tmp/`hostname`-PrivID.csv
echo $tmpFile | grep "-mgt" 2> /dev/null
RS=$?
if [ $RS -ne 0 ]; then
        tmpFile=/tmp/`hostname`-mgt-PrivID.csv
fi

cat /dev/null > $tmpFile

echo -e "HostName;User Name;UID;Location;Privileges;User Description;Login Shell;Groups;Last Login Time;Password Strength;Password Expires on;Cron Jobs;Encryption on Server;Minimum Password Length;Maximum Password Days;Minimum Password Days;Password Warning Days" > $tmpFile

##
## Local IDs Privilege Reports
###############################################

egrep "^password[[:space:]].*sufficient" /etc/pam.d/common-password  | grep -q sha512
RS1=$?
#authconfig --test | grep "password hashing" | grep -q sha512 2> /dev/null
RS2=0
if [ $RS1 -eq 0 ] && [ $RS2 -eq 0 ]; then
        ENCR_SRVR="SHA512 Enabled"
else
        ENCR_SRVR="Encryption is not correct"
fi
MIN_PASS_LEN=`grep ^PASS_MIN_LEN /etc/login.defs| awk '{print $2}'`
MAX_PASS_DYS=`grep ^PASS_MAX_DAYS /etc/login.defs| awk '{print $2}'`
MIN_PASS_DYS=`grep ^PASS_MIN_DAYS /etc/login.defs| awk '{print $2}'`
PASS_WRN_DYS=`grep ^PASS_WARN_AGE /etc/login.defs| awk '{print $2}'`

for USR in $(cat /etc/passwd | awk -F ':' '($3 == 0 || $3 >= 500) {print $1}')
do
        Sudo_Privileges=$(/usr/bin/sudo -l -U $USR | tail -1|tr ',' ' ')
        Check_No_Priv=$(echo $Sudo_Privileges | awk '{print $1}')
        if [ "$Check_No_Priv" == "User" ]; then
                Sudo_STR="No Privileges for $USR on this host"
        else
                Sudo_STR=$Sudo_Privileges
        fi
        GRPS=`groups $USR | awk -F: '{print $2}' | tr ' ' ':'`
        PSWD_STRNT=`grep $USR /etc/shadow| awk -F: '{print $2}'`
        PSWD_EXPRY=`chage -l $USR | grep "Password expires" | awk -F: '{print $2}'|tr ',' ' '`
        Cron_long=`/usr/bin/crontab -l -u $USR 2>/dev/null | grep -v ^# | awk '{print $6,$7}' | tr '\n' '|'`
        [ "$Cron_long" == "" ] && Cron_long="No Cron Jobs"
        cat /dev/null > /tmp/tempo
        STRING1=$(echo -e "`hostname|awk -F '.' '{print $1}'`;$USR;`id -u $USR`;Local Account;$Sudo_STR;`grep -w "^$USR" /etc/passwd | awk -F ':' '{print $5,";",$7}'`;$GRPS;`last $USR | head -1 | awk '{print $4" "$5" "$6" "$7}'`;$PSWD_STRNT;$PSWD_EXPRY;$Cron_long;$ENCR_SRVR;$MIN_PASS_LEN;$MAX_PASS_DYS;$MIN_PASS_DYS;$PASS_WRN_DYS")
        echo $STRING1 >> $tmpFile
done

##
## Centralized IDs Privilege Reports
###############################################

for USRGROUP in $(grep "^%" /etc/sudoers | awk '{print $1}' | tr -d '%')
do
        for USR in $(getent group $USRGROUP | awk -F ':' '{print $4}'| tr ',' ' ')
        do
                grep -q $USR $tmpFile
                RS=$?
                if [ $RS -ne 0 ]; then
                        Sudo_Privileges=$(/usr/bin/sudo -l -U $USR | tail -1|tr ',' ' ')
                        Check_No_Priv=$(echo $Sudo_Privileges | awk '{print $1}')
                        if [ "$Check_No_Priv" == "User" ]; then
                                Sudo_STR="No Privileges for $USR on this host"
                        else
                                Sudo_STR=$Sudo_Privileges
                        fi
                        Cron_long=`/usr/bin/crontab -l -u $USR 2>/dev/null | grep -v ^# | awk '{print $6,$7}' | tr '\n' '|'`
                        [ "$Cron_long" == "" ] && Cron_long="No Cron Jobs"
                        cat /dev/null > /tmp/tempo
                        STRING1=$(echo -e "`hostname|awk -F '.' '{print $1}'`;$USR;`id -u $USR`;Domain Account;$Sudo_STR;NA;/bin/bash;$USRGROUP;`last $USR | head -1 | awk '{print $4" "$5" "$6" "$7}'`;NA;Check in AD;$Cron_long;NA;NA;NA;NA;NA")
                        echo $STRING1 >> $tmpFile
                fi
        done
done

for USR in `grep ALL /etc/sudoers | egrep -vi "^#|^%" | awk '{print $1}' | sort | uniq`
do
        grep -q $USR $tmpFile
        RS=$?
        if [ $RS -ne 0 ]; then
                Sudo_Privileges=$(/usr/bin/sudo -l -U $USR | tail -1|tr ',' ' ')
                Check_No_Priv=$(echo $Sudo_Privileges | awk '{print $1}')
                if [ "$Check_No_Priv" == "User" ]; then
                        Sudo_STR="No Privileges for $USR on this host"
                else
                        Sudo_STR=$Sudo_Privileges
                fi
                Cron_long=`/usr/bin/crontab -l -u $USR 2>/dev/null | grep -v ^# | awk '{print $6,$7}' | tr '\n' '|'`
                [ "$Cron_long" == "" ] && Cron_long="No Cron Jobs"
                cat /dev/null > /tmp/tempo
                STRING1=$(echo -e "`hostname|awk -F '.' '{print $1}'`;$USR;`id -u $USR`;Domain Account;$Sudo_STR;NA;/bin/bash;$USRGROUP;`last $USR | head -1 | awk '{print $4" "$5" "$6" "$7}'`;NA;Check in AD;$Cron_long;NA;NA;NA;NA;NA")
                echo $STRING1 >> $tmpFile
        fi
done

chmod 644 $tmpFile
