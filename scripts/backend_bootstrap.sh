#!/bin/bash -e
# Bastion Bootstrapping
# authors: tonynv@amazon.com, sancard@amazon.com, ianhill@amazon.com, logan.rakai@cloudacademy.com
# NOTE: This requires GNU getopt. On Mac OS X and FreeBSD you must install GNU getopt and mod the checkos function so that it's supported


# Configuration
PROGRAM='Backend'

##################################### Functions Definitions
function checkos () {
    platform='unknown'
    unamestr=`uname`
    if [[ "${unamestr}" == 'Linux' ]]; then
        platform='linux'
    else
        echo "[WARNING] This script is not supported on MacOS or freebsd"
        exit 1
    fi
    echo "${FUNCNAME[0]} Ended"
}

function setup_environment_variables() {
  REGION=$(curl -sq http://169.254.169.254/latest/meta-data/placement/availability-zone/)
    #ex: us-east-1a => us-east-1
  REGION=${REGION: :-1}

  ETH0_MAC=$(/sbin/ip link show dev eth0 | /bin/egrep -o -i 'link/ether\ ([0-9a-z]{2}:){5}[0-9a-z]{2}' | /bin/sed -e 's,link/ether\ ,,g')

  _userdata_file="/var/lib/cloud/instance/user-data.txt"

  INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)

  LOCAL_IP_ADDRESS=$(curl -sq 169.254.169.254/latest/meta-data/network/interfaces/macs/${ETH0_MAC}/local-ipv4s/)

  CWG=$(grep CLOUDWATCHGROUP ${_userdata_file} | sed 's/CLOUDWATCHGROUP=//g')

  # LOGGING CONFIGURATION
  BACKEND_MNT="/var/log/backend"
  BACKEND_LOG="backend.log"
  echo "Setting up backend session log in ${BACKEND_MNT}/${BACKEND_LOG}"
  mkdir -p ${BACKEND_MNT}
  BACKEND_LOGFILE="${BACKEND_MNT}/${BACKEND_LOG}"
  BACKEND_LOGFILE_SHADOW="${BACKEND_MNT}/.${BACKEND_LOG}"
  touch ${BACKEND_LOGFILE}
  ln ${BACKEND_LOGFILE} ${BACKEND_LOGFILE_SHADOW}
  mkdir -p /usr/bin/backend
  touch /tmp/messages
  chmod 770 /tmp/messages

  export REGION ETH0_MAC CWG BACKEND_MNT BACKEND_LOG BACKEND_LOGFILE BACKEND_LOGFILE_SHADOW \
          LOCAL_IP_ADDRESS INSTANCE_ID
}

function verify_dependencies(){
  if [[ "a$(which aws)" == "a" ]]; then
    pip install awscli
  fi
  echo "${FUNCNAME[0]} Ended"
}

function usage() {
    echo "$0 <usage>"
    echo " "
    echo "options:"
    echo -e "--help \t Show options for this script"
}

function chkstatus () {
    if [ $? -eq 0 ]
    then
        echo "Script [PASS]"
    else
        echo "Script [FAILED]" >&2
        exit 1
    fi
}

function osrelease () {
    OS=`cat /etc/os-release | grep '^NAME=' |  tr -d \" | sed 's/\n//g' | sed 's/NAME=//g'`
    if [ "${OS}" == "Ubuntu" ]; then
        echo "Ubuntu"
    elif [ "${OS}" == "Amazon Linux AMI" ] || [ "${OS}" == "Amazon Linux" ]; then
        echo "AMZN"
    elif [ "${OS}" == "CentOS Linux" ]; then
        echo "CentOS"
    else
        echo "Operating System Not Found"
    fi
    echo "${FUNCNAME[0]} Ended" >> /var/log/cfn-init.log
}

function harden_ssh_security () {
    # Allow ec2-user only to access this folder and its content
    #chmod -R 770 /var/log/backend
    #setfacl -Rdm other:0 /var/log/backend

    # Make OpenSSH execute a custom script on logins
    echo -e "\nForceCommand /usr/bin/backend/shell" >> /etc/ssh/sshd_config



cat <<'EOF' >> /usr/bin/backend/shell
BACKEND_mnt="/var/log/backend"
BACKEND_log="backend.log"
# Check that the SSH client did not supply a command. Only SSH to instance should be allowed.
export Allow_SSH="ssh"
export Allow_SCP="scp"
if [[ -z $SSH_ORIGINAL_COMMAND ]] || [[ $SSH_ORIGINAL_COMMAND =~ ^$Allow_SSH ]] || [[ $SSH_ORIGINAL_COMMAND =~ ^$Allow_SCP ]]; then
#Allow ssh to instance and log connection
    if [ -z "$SSH_ORIGINAL_COMMAND" ]; then
        /bin/bash
        exit 0
    else
        $SSH_ORIGINAL_COMMAND
    fi
log_shadow_file_location="${BACKEND_mnt}/.${BACKEND_log}"
log_file=`echo "$log_shadow_file_location"`
DATE_TIME_WHOAMI="`whoami`:`date "+%Y-%m-%d %H:%M:%S"`"
LOG_ORIGINAL_COMMAND=`echo "$DATE_TIME_WHOAMI:$SSH_ORIGINAL_COMMAND"`
echo "$LOG_ORIGINAL_COMMAND" >> "${BACKEND_mnt}/${BACKEND_log}"
log_dir="/var/log/backend/"

else
# The "script" program could be circumvented with some commands
# (e.g. bash, nc). Therefore, I intentionally prevent users
# from supplying commands.

echo "This backend supports interactive sessions only. Do not supply a command"
exit 1
fi
EOF

    # Make the custom script executable
    chmod a+x /usr/bin/backend/shell

    release=$(osrelease)
    if [ "${release}" == "CentOS" ]; then
        semanage fcontext -a -t ssh_exec_t /usr/bin/backend/shell
    fi

    echo "${FUNCNAME[0]} Ended"
}

function amazon_os () {
    echo "${FUNCNAME[0]} Started"
    chown root:ec2-user /usr/bin/script
    service sshd restart
    echo -e "\nDefaults env_keep += \"SSH_CLIENT\"" >>/etc/sudoers
cat <<'EOF' >> /etc/bashrc
#Added by linux backend bootstrap
declare -rx IP=$(echo $SSH_CLIENT | awk '{print $1}')
EOF

    echo " declare -rx BACKEND_LOG=${BACKEND_MNT}/${BACKEND_LOG}" >> /etc/bashrc

cat <<'EOF' >> /etc/bashrc
declare -rx PROMPT_COMMAND='history -a >(logger -t "ON: $(date)   [FROM]:${IP}   [USER]:${USER}   [PWD]:${PWD}" -s 2>>${BACKEND_LOG})'
EOF
    chown root:ec2-user  ${BACKEND_MNT}
    chown root:ec2-user  ${BACKEND_LOGFILE}
    chown root:ec2-user  ${BACKEND_LOGFILE_SHADOW}
    chmod 662 ${BACKEND_LOGFILE}
    chmod 662 ${BACKEND_LOGFILE_SHADOW}
    chattr +a ${BACKEND_LOGFILE}
    chattr +a ${BACKEND_LOGFILE_SHADOW}
    touch /tmp/messages
    chown root:ec2-user /tmp/messages
    #Install CloudWatch Log service on AMZN
    yum update -y
    yum install -y awslogs
    echo "file = ${BACKEND_LOGFILE_SHADOW}" >> /tmp/groupname.txt
    echo "log_group_name = ${CWG}" >> /tmp/groupname.txt

cat <<'EOF' >> ~/cloudwatchlog.conf

[/var/log/backend]
datetime_format = %b %d %H:%M:%S
buffer_duration = 5000
log_stream_name = {instance_id}
initial_position = start_of_file
EOF

    LINE=$(cat -n /etc/awslogs/awslogs.conf | grep '\[\/var\/log\/messages\]' | awk '{print $1}')
    END_LINE=$(echo $((${LINE}-1)))
    head -${END_LINE} /etc/awslogs/awslogs.conf > /tmp/awslogs.conf
    cat /tmp/awslogs.conf > /etc/awslogs/awslogs.conf
    cat ~/cloudwatchlog.conf >> /etc/awslogs/awslogs.conf
    cat /tmp/groupname.txt >> /etc/awslogs/awslogs.conf
    export TMPREGION=$(grep region /etc/awslogs/awscli.conf)
    sed -i.back "s/${TMPREGION}/region = ${REGION}/g" /etc/awslogs/awscli.conf

    #Restart awslogs service
    local OS=`cat /etc/os-release | grep '^NAME=' |  tr -d \" | sed 's/\n//g' | sed 's/NAME=//g'`
    if [ "$OS"  == "Amazon Linux" ]; then # amazon linux 2
        systemctl start awslogsd.service
        systemctl enable awslogsd.service
    else
        service awslogs restart
        chkconfig awslogs on
    fi

    #Run security updates
cat <<'EOF' >> ~/mycron
0 0 * * * yum -y update --security
EOF
    crontab ~/mycron
    rm ~/mycron
    echo "${FUNCNAME[0]} Ended"
}

function ubuntu_os () {
    chown syslog:adm /var/log/backend
    chown root:ubuntu /usr/bin/script
cat <<'EOF' >> /etc/bash.bashrc
#Added by linux backend bootstrap
declare -rx IP=$(who am i --ips|awk '{print $5}')
EOF

    echo " declare -rx BACKEND_LOG=${BACKEND_MNT}/${BACKEND_LOG}" >> /etc/bash.bashrc

cat <<'EOF' >> /etc/bash.bashrc
declare -rx PROMPT_COMMAND='history -a >(logger -t "ON: $(date)   [FROM]:${IP}   [USER]:${USER}   [PWD]:${PWD}" -s 2>>${BACKEND_LOG})'
EOF
    chown root:ubuntu ${BACKEND_MNT}
    chown root:ubuntu  ${BACKEND_LOGFILE}
    chown root:ubuntu  ${BACKEND_LOGFILE_SHADOW}
    chmod 662 ${BACKEND_LOGFILE}
    chmod 662 ${BACKEND_LOGFILE_SHADOW}
    chattr +a ${BACKEND_LOGFILE}
    chattr +a ${BACKEND_LOGFILE_SHADOW}
    touch /tmp/messages
    chown root:ubuntu /tmp/messages
    #Install CloudWatch logs on Ubuntu
    echo "file = ${BACKEND_LOGFILE_SHADOW}" >> /tmp/groupname.txt
    echo "log_group_name = ${CWG}" >> /tmp/groupname.txt

cat <<'EOF' >> ~/cloudwatchlog.conf
[general]
state_file = /var/awslogs/state/agent-state

[/var/log/backend]
log_stream_name = {instance_id}
datetime_format = %b %d %H:%M:%S
EOF
    cat /tmp/groupname.txt >> ~/cloudwatchlog.conf

    curl https://s3.amazonaws.com/aws-cloudwatch/downloads/latest/awslogs-agent-setup.py -O
    export DEBIAN_FRONTEND=noninteractive
    apt-get install -y python
    chmod +x ./awslogs-agent-setup.py
    ./awslogs-agent-setup.py -n -r ${REGION} -c ~/cloudwatchlog.conf

    #Install Unit file for Ubuntu 16.04
    ubuntu=`cat /etc/os-release | grep VERSION_ID | tr -d \VERSION_ID=\"`
    if [ "${ubuntu}" == "16.04" ]; then
cat <<'EOF' >> /etc/systemd/system/awslogs.service
[Unit]
Description=The CloudWatch Logs agent
After=rc-local.service

[Service]
Type=simple
Restart=always
KillMode=process
TimeoutSec=infinity
PIDFile=/var/awslogs/state/awslogs.pid
ExecStart=/var/awslogs/bin/awslogs-agent-launcher.sh --start --background --pidfile $PIDFILE --user awslogs --chuid awslogs &

[Install]
WantedBy=multi-user.target
EOF
    fi

    #Restart awslogs service
    service awslogs restart
    export DEBIAN_FRONTEND=noninteractive
    apt-get install sysv-rc-conf -y
    sysv-rc-conf awslogs on

    #Restart SSH
    service ssh stop
    service ssh start

    #Run security updates
    apt-get install unattended-upgrades
    echo "0 0 * * * unattended-upgrades -d" >> ~/mycron
    crontab ~/mycron
    rm ~/mycron
    echo "${FUNCNAME[0]} Ended"
}

function cent_os () {
    echo -e "\nDefaults env_keep += \"SSH_CLIENT\"" >>/etc/sudoers
    echo -e "#Added by the Linux Bastion Bootstrap\ndeclare -rx IP=$(echo ${SSH_CLIENT} | awk '{print $1}')" >> /etc/bashrc

    echo "declare -rx BACKEND_LOG=${BACKEND_MNT}/${BACKEND_LOG}" >> /etc/bashrc

    cat <<- EOF >> /etc/bashrc
    declare -rx PROMPT_COMMAND='history -a >(logger -t "ON: $(date)   [FROM]:${IP}   [USER]:${USER}   [PWD]:${PWD}" -s 2>>${BACKEND_LOG})'
EOF

    chown root:centos ${BACKEND_MNT}
    chown root:centos /usr/bin/script
    chown root:centos  /var/log/backend/backend.log
    chmod 770 /var/log/backend/backend.log
    touch /tmp/messages
    chown root:centos /tmp/messages
    restorecon -v /etc/ssh/sshd_config
    /bin/systemctl restart sshd.service

    # Install CloudWatch Log service on Centos Linux
    centos=`cat /etc/os-release | grep VERSION_ID | tr -d \VERSION_ID=\"`
    if [ "${centos}" == "7" ]; then
        echo "file = ${BACKEND_LOGFILE_SHADOW}" >> /tmp/groupname.txt
        echo "log_group_name = ${CWG}" >> /tmp/groupname.txt

        cat <<EOF >> ~/cloudwatchlog.conf
        [general]
        state_file = /var/awslogs/state/agent-state
        use_gzip_http_content_encoding = true
        logging_config_file = /var/awslogs/etc/awslogs.conf

        [/var/log/backend]
        datetime_format = %Y-%m-%d %H:%M:%S
        file = /var/log/messages
        buffer_duration = 5000
        log_stream_name = {instance_id}
        initial_position = start_of_file
EOF
        cat /tmp/groupname.txt >> ~/cloudwatchlog.conf

        curl https://s3.amazonaws.com/aws-cloudwatch/downloads/latest/awslogs-agent-setup.py -O
        chmod +x ./awslogs-agent-setup.py
        ./awslogs-agent-setup.py -n -r ${REGION} -c ~/cloudwatchlog.conf
        cat << EOF >> /etc/systemd/system/awslogs.service
        [Unit]
        Description=The CloudWatch Logs agent
        After=rc-local.service

        [Service]
        Type=simple
        Restart=always
        KillMode=process
        TimeoutSec=infinity
        PIDFile=/var/awslogs/state/awslogs.pid
        ExecStart=/var/awslogs/bin/awslogs-agent-launcher.sh --start --background --pidfile $PIDFILE --user awslogs --chuid awslogs &

        [Install]
        WantedBy=multi-user.target
EOF
        service awslogs restart
        chkconfig awslogs on
  else
        chown root:centos /var/log/backend
        yum update -y
        yum install -y awslogs
        export TMPREGION=`cat /etc/awslogs/awscli.conf | grep region`
        sed -i.back "s/${TMPREGION}/region = ${REGION}/g" /etc/awslogs/awscli.conf
        echo "file = ${BACKEND_LOGFILE_SHADOW}" >> /tmp/groupname.txt
        echo "log_group_name = ${CWG}" >> /tmp/groupname.txt

        cat <<EOF >> ~/cloudwatchlog.conf
        [/var/log/backend]
        datetime_format = %b %d %H:%M:%S
        buffer_duration = 5000
        log_stream_name = {instance_id}
        initial_position = start_of_file
EOF
        export TMPGROUP=`cat /etc/awslogs/awslogs.conf | grep ^log_group_name`
        export TMPGROUP=`echo ${TMPGROUP} | sed 's/\//\\\\\//g'`
        sed -i.back "s/${TMPGROUP}/log_group_name = ${CWG}/g" /etc/awslogs/awslogs.conf
        cat ~/cloudwatchlog.conf >> /etc/awslogs/awslogs.conf
        cat /tmp/groupname.txt >> /etc/awslogs/awslogs.conf
        yum install ec2-metadata -y
        export TMPREGION=`cat /etc/awslogs/awscli.conf | grep region`
        sed -i.back "s/${TMPREGION}/region = ${REGION}/g" /etc/awslogs/awscli.conf
        sleep 3
        service awslogs stop
        sleep 3
        service awslogs start
        chkconfig awslogs on
    fi

    #Run security updates
    echo "0 0 * * * yum -y update --security" > ~/mycron
    crontab ~/mycron
    rm ~/mycron
    echo "${FUNCNAME[0]} Ended"
}

function prevent_process_snooping() {
    # Prevent backend host users from viewing processes owned by other users.
    mount -o remount,rw,hidepid=2 /proc
    awk '!/proc/' /etc/fstab > temp && mv temp /etc/fstab
    echo "proc /proc proc defaults,hidepid=2 0 0" >> /etc/fstab
    echo "${FUNCNAME[0]} Ended"
}

##################################### End Function Definitions

# Call checkos to ensure platform is Linux
checkos
# Verify dependencies are installed.
verify_dependencies
# Assuming it is, setup environment variables.
setup_environment_variables

# Read the options from cli input
TEMP=`getopt -o h:  --long help -n $0 -- "$@"`
eval set -- "${TEMP}"


# extract options and their arguments into variables.
while true; do
    case "$1" in
        -h | --help)
            usage
            exit 1
            ;;
        --)
            break
            ;;
        *)
            break
            ;;
    esac
done

release=$(osrelease)
# Ubuntu Linux
if [ "${release}" == "Ubuntu" ]; then
    #Call function for Ubuntu
    ubuntu_os
# AMZN Linux
elif [ "${release}" == "AMZN" ]; then
    #Call function for AMZN
    amazon_os
# CentOS Linux
elif [ "${release}" == "CentOS" ]; then
    #Call function for CentOS
    cent_os
else
    echo "[ERROR] Unsupported Linux Bastion OS"
    exit 1
fi

prevent_process_snooping

echo "Bootstrap complete."
