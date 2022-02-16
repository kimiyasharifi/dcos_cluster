#!/bin/bash
#
# BASH script to install DC/OS on a node
#
# Usage:
#
#   dcos_install.sh <role>...
#
#
# Metadata:
#   dcos image commit: 4eee4048fe9b8e2899f39a486d55a60a82998215
#   generation date: 2021-11-24 09:10:11.447959
#
# Copyright 2017 Mesosphere, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -o errexit -o nounset -o pipefail

declare -i OVERALL_RC=0
declare -i PREFLIGHT_ONLY=0
declare -i DISABLE_PREFLIGHT=0
declare -i SYSTEMCTL_NO_BLOCK=0

declare ROLES=""
declare RED=""
declare BOLD=""
declare NORMAL=""

# Check if this is a terminal, and if colors are supported, set some basic
# colors for outputs
if [ -t 1 ]; then
    colors_supported=$(tput colors)
    if [[ $colors_supported -ge 8 ]]; then
        RED='\e[1;31m'
        BOLD='\e[1m'
        NORMAL='\e[0m'
    fi
fi

# Setup getopt argument parser
ARGS=$(getopt -o dph --long "disable-preflight,preflight-only,help,no-block-dcos-setup" -n "$(basename "$0")" -- "$@")

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root" 1>&2
    exit 1
fi

function setup_directories() {
    echo -e "Creating directories under /etc/mesosphere"
    mkdir -p /etc/mesosphere/roles
    mkdir -p /etc/mesosphere/setup-flags
}

function setup_dcos_roles() {
    # Set DC/OS roles
    for role in $ROLES
    do
        echo "Creating role file for ${role}"
        touch "/etc/mesosphere/roles/$role"
    done
}

# Set DC/OS machine configuration
function configure_dcos() {
echo -e 'Configuring DC/OS'
mkdir -p `dirname /etc/mesosphere/setup-flags/repository-url`
cat <<'EOF' > "/etc/mesosphere/setup-flags/repository-url"
http://192.168.114.87:8081

EOF
chmod 0644 /etc/mesosphere/setup-flags/repository-url

mkdir -p `dirname /etc/mesosphere/setup-flags/cluster-package-list`
cat <<'EOF' > "/etc/mesosphere/setup-flags/cluster-package-list"
525b3dde726f47079dcde8506f72e369b3000dea

EOF
chmod 0644 /etc/mesosphere/setup-flags/cluster-package-list

mkdir -p `dirname /etc/systemd/journald.conf.d/dcos.conf`
cat <<'EOF' > "/etc/systemd/journald.conf.d/dcos.conf"
[Journal]
MaxLevelConsole=warning

EOF
chmod 0644 /etc/systemd/journald.conf.d/dcos.conf

mkdir -p `dirname /etc/rexray/config.yml`
cat <<'EOF' > "/etc/rexray/config.yml"
rexray:
  loglevel: info
  modules:
    default-docker:
      disabled: true
  service: vfs

EOF
chmod 0644 /etc/rexray/config.yml


}

# Install the DC/OS services, start DC/OS
function setup_and_start_services() {

echo -e 'Setting and starting DC/OS'
mkdir -p `dirname /etc/systemd/system/dcos-link-env.service`
cat <<'EOF' > "/etc/systemd/system/dcos-link-env.service"
[Unit]
Before=dcos.target
[Service]
Type=oneshot
StandardOutput=journal+console
StandardError=journal+console
ExecStartPre=/usr/bin/mkdir -p /etc/profile.d
ExecStart=/usr/bin/ln -sf /opt/mesosphere/bin/add_dcos_path.sh /etc/profile.d/dcos.sh

EOF
chmod 0644 /etc/systemd/system/dcos-link-env.service

mkdir -p `dirname /etc/systemd/system/dcos-download.service`
cat <<'EOF' > "/etc/systemd/system/dcos-download.service"
[Unit]
Description=Pkgpanda: Download DC/OS to this host.
After=network-online.target
Wants=network-online.target
ConditionPathExists=!/opt/mesosphere/active/
[Service]
Type=oneshot
StandardOutput=journal+console
StandardError=journal+console
ExecStartPre=/usr/bin/curl --keepalive-time 2 -fLsSv --retry 20 -Y 100000 -y 60 -o /tmp/bootstrap.tar.xz http://192.168.114.87:8081/bootstrap/0a2557abaf32e0fd67cbe32e3b0be100850c338a.bootstrap.tar.xz
ExecStartPre=/usr/bin/mkdir -p /opt/mesosphere
ExecStart=/usr/bin/tar -axf /tmp/bootstrap.tar.xz -C /opt/mesosphere
ExecStartPost=-/usr/bin/rm -f /tmp/bootstrap.tar.xz

EOF
chmod 0644 /etc/systemd/system/dcos-download.service

mkdir -p `dirname /etc/systemd/system/dcos-setup.service`
cat <<'EOF' > "/etc/systemd/system/dcos-setup.service"
[Unit]
Description=Pkgpanda: Specialize DC/OS for this host.
Requires=dcos-download.service
After=dcos-download.service
[Service]
Type=oneshot
StandardOutput=journal+console
StandardError=journal+console
EnvironmentFile=/opt/mesosphere/environment
ExecStart=/opt/mesosphere/bin/pkgpanda setup --no-block-systemd
[Install]
WantedBy=multi-user.target

EOF
chmod 0644 /etc/systemd/system/dcos-setup.service


systemctl restart systemd-journald
systemctl restart docker
systemctl start dcos-link-env
systemctl enable dcos-setup

if (( $SYSTEMCTL_NO_BLOCK == 1 )); then
    systemctl start dcos-setup --no-block
else
    systemctl start dcos-setup
fi

}

set +e

declare -i DISABLE_VERSION_CHECK=0

# check if sort -V works
function check_sort_capability() {
    $( command -v sort >/dev/null 2>&1 || exit 1 )
    RC1=$?
    $( echo '1' | sort -V >/dev/null 2>&1 )
    RC2=$?
    if [[ "$RC1" -eq "1" || "$RC2" -eq "2" ]]; then
        echo -e "${RED}Disabling version checking as sort -V is not available${NORMAL}"
        DISABLE_VERSION_CHECK=1
    fi
}

function version_gt() {
    # sort -V does version-aware sort
    HIGHEST_VERSION="$(echo "$@" | tr " " "
" | sort -V | tail -n 1)"
    test $HIGHEST_VERSION == "$1"
}

function print_status() {
    CODE_TO_TEST=$1
    EXTRA_TEXT=${2:-}
    if [[ $CODE_TO_TEST == 0 ]]; then
        echo -e "${BOLD}PASS $EXTRA_TEXT${NORMAL}"
    else
        echo -e "${RED}FAIL $EXTRA_TEXT${NORMAL}"
    fi
}

function print_warning() {
    MESSAGE=${1:-}
    echo -e "${RED}WARNING${NORMAL} $MESSAGE"
}

function check_command_exists() {
    COMMAND=$1
    DISPLAY_NAME=${2:-$COMMAND}

    echo -e -n "Checking if $DISPLAY_NAME is installed and in PATH: "
    $( command -v $COMMAND >/dev/null 2>&1 || exit 1 )
    RC=$?
    print_status $RC
    (( OVERALL_RC += $RC ))
    return $RC
}

function check_version() {
    COMMAND_NAME=$1
    VERSION_ATLEAST=$2
    COMMAND_VERSION=$3
    DISPLAY_NAME=${4:-$COMMAND}

    echo -e -n "Checking $DISPLAY_NAME version requirement (>= $VERSION_ATLEAST): "
    version_gt $COMMAND_VERSION $VERSION_ATLEAST
    RC=$?
    print_status $RC "${NORMAL}($COMMAND_VERSION)"
    (( OVERALL_RC += $RC ))
    return $RC
}

function check_selinux() {
  ENABLED=$(getenforce)
  RC=0

  if [[ "$ENABLED" == "Enforcing" ]]; then
    LOADED_POLICY_LINE=$(sestatus | grep "Loaded policy name:")
    # We expect that the loaded policy name line will look like:
    # "Loaded policy name:             targeted"
    # But we do not want to rely on the number of spaces before the policy name.
    LOADED_POLICY=$(echo "$LOADED_POLICY_LINE" | rev | cut -d ' ' -f1 | rev)
    ALLOWED_LOADED_POLICY="targeted"
    if [ "$LOADED_POLICY" != "$ALLOWED_LOADED_POLICY" ]; then
      RC=1
    fi
  fi

  MESSAGE="Is SELinux in disabled mode, permissive mode or in enforcing mode with the targeted policy loaded?"
  print_status $RC "$MESSAGE"
  (( OVERALL_RC += $RC ))
  return $RC
}

function check() {
    # Wrapper to invoke both check_commmand and version check in one go
    if [[ $# -eq 4 ]]; then
       DISPLAY_NAME=$4
    elif [[ $# -eq 2 ]]; then
       DISPLAY_NAME=$2
    else
       DISPLAY_NAME=$1
    fi
    check_command_exists $1 $DISPLAY_NAME
    # check_version takes {3,4} arguments
    if [[ "$?" -eq 0 && "$#" -ge 3 && $DISABLE_VERSION_CHECK -eq 0 ]]; then
        check_version $*
    fi
}

function check_docker_running() {
    check_command_exists "docker" "docker"
    echo -e -n "Checking if Docker is running: "
    docker info >/dev/null 2>&1
    RC=$?
    print_status $RC
    (( OVERALL_RC += $RC ))
    return $RC
}

function check_service() {
  PORT=$1
  NAME=$2
  echo -e -n "Checking if port $PORT (required by $NAME) is in use: "
  RC=0
  cat /proc/net/{udp*,tcp*} | cut -d: -f3 | cut -d' ' -f1 | grep -q $(printf "%04x" $PORT) && RC=1
  print_status $RC
  (( OVERALL_RC += $RC ))
}

function empty_dir() {
    # Return 0 if $1 is a directory containing no files.
    DIRNAME=$1

    RC=0
    if [[ ( ! -d "$DIRNAME" ) || $(ls -A "$DIRNAME") ]]; then
        RC=1
    fi
    return $RC
}

function check_preexisting_dcos() {
    echo -e -n 'Checking if DC/OS is already installed: '
    if (
        # dcos.target exists and is a directory, OR
        [[ -d /etc/systemd/system/dcos.target ]] ||
        # dcos.target.wants exists and is a directory, OR
        [[ -d /etc/systemd/system/dcos.target.wants ]] ||
        # /opt/mesosphere exists and is not an empty directory
        ( [[ -a /opt/mesosphere ]] && ( ! empty_dir /opt/mesosphere ) )
    ); then
        # this will print: Checking if DC/OS is already installed: FAIL (Currently installed)
        print_status 1 "${NORMAL}(Currently installed)"
        echo
        cat <<EOM
Found an existing DC/OS installation. To reinstall DC/OS on this this machine you must
first uninstall DC/OS then run dcos_install.sh. To uninstall DC/OS, follow the product
documentation provided with DC/OS.
EOM
        echo
        exit 1
    else
        print_status 0 "${NORMAL}(Not installed)"
    fi
}


function check_docker_device_mapper_loopback() {
    echo -e -n 'Checking Docker is configured with a production storage driver: '

  storage_driver="$(docker info | grep 'Storage Driver' | cut -d ':' -f 2  | tr -d '[[:space:]]')"

  if [ "$storage_driver" != "devicemapper" ]; then
      print_status 0 "${NORMAL}(${storage_driver})"
      return
  fi

  data_file="$(docker info | grep 'Data file' | cut -d ':' -f 2  | tr -d '[[:space:]]')"

  if [[ "${data_file}" == /dev/loop* ]]; then
    print_status 1 "${NORMAL}(${storage_driver}, ${data_file})"
    echo
    cat <<EOM
Docker is configured to use the devicemapper storage driver with a loopback
device behind it. This is highly recommended against by Docker and the
community at large for production use[0][1]. See the docker documentation on
selecting an alternate storage driver, or use alternate storage than loopback
for the devicemapper driver.

[0] https://docs.docker.com/engine/userguide/storagedriver/device-mapper-driver/
[1] http://www.projectatomic.io/blog/2015/06/notes-on-fedora-centos-and-docker-storage-drivers/
EOM
        echo
        exit 1
    else
        print_status 0 "${NORMAL}(${storage_driver} ${data_file})"
    fi
}

function d_type_enabled_if_xfs()
{
    # Return 1 if $1 is a directory on XFS volume with ftype ! = 1
    # otherwise return 0
    DIRNAME="$1"

    RC=0
    # "df", the command being used to get the filesystem device and type,
    # fails if the directory does not exist, hence we need to iterate up the
    # directory chain to find a directory that exists before executing the command
    while [[ ! -d "$DIRNAME" ]]; do
        DIRNAME="$(dirname "$DIRNAME")"
    done
    read -r filesystem_device filesystem_type filesystem_mount <<<"$(df --portability         --print-type "$DIRNAME" | awk 'END{print $1,$2,$7}')"
    # -b $filesystem_device check is there prevent this from failing in certain special dcos-docker configs
    # see https://jira.mesosphere.com/browse/DCOS_OSS-3549
    if [[ "$filesystem_type" == "xfs" && -b "$filesystem_device" ]]; then
        echo -n -e "Checking if $DIRNAME is mounted with "ftype=1": "
        ftype_value="$(xfs_info $filesystem_mount | grep -oE ftype=[0-9])"
        if [[ "$ftype_value" != "ftype=1" ]]; then
            RC=1
        fi
        print_status $RC "${NORMAL}(${ftype_value})"
    fi
    return $RC
}

# check node storage has d_type (ftype=1) support enabled if using XFS
function check_xfs_ftype() {
    RC=0

    mesos_agent_dir="/var/lib/mesos/slave"
    # Check if ftype=1 on the volume, for $mesos_agent_dir, if its on XFS filesystem
    ( d_type_enabled_if_xfs "$mesos_agent_dir" ) || RC=1

    # Check if ftype=1 on the volume, for docker root dir, if its on XFS filesystem
    docker_root_dir="$(docker info | grep 'Docker Root Dir' | cut -d ':' -f 2  | tr -d '[[:space:]]')"
    ( d_type_enabled_if_xfs "$docker_root_dir" ) || RC=1

    (( OVERALL_RC += $RC ))
    return $RC
}

function warn_unloaded_dss_kernel_module() {
    # Print a warning if $1, a kernel module that's required for DSS to
    # function properly, is not loaded
    MODULE="$1"

    echo -e -n "Checking if kernel module $MODULE is loaded: "

    lsmod | grep -q -E "^$MODULE"
    RC=$?

    if [ "$RC" -eq "0" ]; then
      print_status $RC
    else
      print_warning "Kernel module $MODULE is not loaded. DC/OS Storage Service (DSS) depends on it."
    fi
}

function check_all() {
    # Disable errexit because we want the preflight checks to run all the way
    # through and not bail in the middle, which will happen as it relies on
    # error exit codes
    set +e
    echo -e "${BOLD}Running preflight checks${NORMAL}"
    AGENT_ONLY=0
    for ROLE in $ROLES; do
        if [[ $ROLE = "slave" || $ROLE = "slave_public" ]]; then
            AGENT_ONLY=1
            break
        fi
    done

    check_preexisting_dcos
    check_selinux
    check_sort_capability

    check_docker_running

    local docker_version=$(command -v docker >/dev/null 2>&1         && docker version --format '{{printf "%s\n%s" .Server.Version .Client.Version}}'         | sort -V         | head -n 1)

    # CoreOS stable as of Aug 2015 has 1.6.2
    check docker 1.6 "$docker_version"

    check curl
    check bash
    check ping
    check tar
    check xz
    check unzip
    check ipset
    check systemd-notify

    # $ systemctl --version ->
    # systemd nnn
    # compiler option string
    # Pick up just the first line of output and get the version from it
    check systemctl 200 $(systemctl --version | head -1 | cut -f2 -d' ') systemd

    # Run service check on master node only
    if [[ $AGENT_ONLY -eq 0 ]]; then
        # master node service checks
        for service in             "53 dcos-net"             "80 adminrouter"             "443 adminrouter"             "1050 dcos-diagnostics"             "2181 zookeeper"             "5050 mesos-master"             "7070 cosmos"             "8080 marathon"             "8101 dcos-oauth"             "8123 mesos-dns"             "8181 exhibitor"             "9000 metronome"             "9942 metronome"             "9990 cosmos"             "15055 dcos-history"             "36771 marathon"             "41281 zookeeper"             "46839 metronome"             "61053 mesos-dns"             "61091 telegraf"             "62020 fluent-bit"             "62080 dcos-net"             "62501 dcos-net"
        do
            check_service $service
        done
    else
        # agent / public agent node service checks
        for service in             "53 dcos-net"             "5051 mesos-agent"             "61001 agent-adminrouter"             "61091 telegraf"             "62020 fluent-bit"             "62080 dcos-net"             "62501 dcos-net"
        do
            check_service $service
        done
        check_xfs_ftype
    fi

    # Check we're not in docker on devicemapper loopback as storage driver.
    check_docker_device_mapper_loopback

    warn_unloaded_dss_kernel_module "raid1"
    warn_unloaded_dss_kernel_module "dm_raid"

    for role in "$ROLES"
    do
        if [ "$role" != "master" -a "$role" != "slave" -a "$role" != "slave_public" -a "$role" != "minuteman" ]; then
            echo -e "${RED}FAIL Invalid role $role. Role must be one of {master,slave,slave_public}${NORMAL}"
            (( OVERALL_RC += 1 ))
        fi
    done


    return $OVERALL_RC
}

function setup_exhibitor_tls_bootstrap()
{
    read -d '' ca_data << 'EOF' || true

EOF

    if [ -n "$ca_data" ]; then
        echo "$ca_data" > /dev/null
    fi
}

function dcos_install()
{
    # Enable errexit
    set -e

    setup_directories
    setup_dcos_roles
    setup_exhibitor_tls_bootstrap
    configure_dcos
    setup_and_start_services

}

function usage()
{
    echo -e "${BOLD}Usage: $0 [--disable-preflight|--preflight-only] <roles>${NORMAL}"
}

function main()
{
    eval set -- "$ARGS"

    while true ; do
        case "$1" in
            -d|--disable-preflight) DISABLE_PREFLIGHT=1;  shift  ;;
            -p|--preflight-only) PREFLIGHT_ONLY=1 ; shift  ;;
            --no-block-dcos-setup) SYSTEMCTL_NO_BLOCK=1;  shift ;;
            -h|--help) usage; exit 1 ;;
            --) shift ; break ;;
            *) usage ; exit 1 ;;
        esac
    done

    ROLES=$@

    if [[ $PREFLIGHT_ONLY -eq 1 ]] ; then
        check_all
    else
        if [[ -z $ROLES ]] ; then
            echo -e 'Atleast one role name must be specified'
            usage
            exit 1
        fi
        echo -e "${BOLD}Starting DC/OS Install Process${NORMAL}"
        if [[ $DISABLE_PREFLIGHT -eq 0 ]] ; then
            check_all
            RC=$?
            if [[ $RC -ne 0 ]]; then
                echo 'Preflight checks failed. Exiting installation. Please consult product documentation'
                exit $RC
            fi
        fi
        # Run actual install
        dcos_install
    fi

}

# Run it all
main

