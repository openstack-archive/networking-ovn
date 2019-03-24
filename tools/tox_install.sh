#!/usr/bin/env bash

# Many of neutron's repos suffer from the problem of depending on neutron,
# but it not existing on pypi.

# This wrapper for tox's package installer will use the existing package
# if it exists, else use zuul-cloner if that program exists, else grab it
# from neutron master via a hard-coded URL. That last case should only
# happen with devs running unit tests locally.

# From the tox.ini config page:
# install_command=ARGV
# default:
# pip install {opts} {packages}

ZUUL_CLONER=/usr/zuul-env/bin/zuul-cloner
BRANCH_NAME=stable/queens
neutron_installed=$(echo "import neutron" | python 2>/dev/null ; echo $?)
NEUTRON_DIR=$HOME/neutron

set -e
set -x

install_cmd="pip install -c$1"
shift

# The devstack based functional tests have neutron checked out in
# $NEUTRON_DIR on the test systems - with the change to test in it.
# Use this directory if it exists, so that this script installs the
# neutron version to test here.
# Note that the functional tests use sudo to run tox and thus
# variables used for zuul-cloner to check out the correct version are
# lost.
if [ -d "$NEUTRON_DIR" ]; then
    echo "FOUND Neutron code at $NEUTRON_DIR - using"
    $install_cmd -U -e $NEUTRON_DIR
elif [ $neutron_installed -eq 0 ]; then
    echo "ALREADY INSTALLED" > /tmp/tox_install.txt
    location=$(python -c "import neutron; print(neutron.__file__)")
    echo "ALREADY INSTALLED at $location"

    echo "Neutron already installed; using existing package"
elif [ -x "$ZUUL_CLONER" ]; then
    echo "ZUUL CLONER" > /tmp/tox_install.txt
    # Make this relative to current working directory so that
    # git clean can remove it. We cannot remove the directory directly
    # since it is referenced after $install_cmd -e.
    mkdir -p .tmp
    NEUTRON_DIR=$(/bin/mktemp -d -p $(pwd)/.tmp)
    pushd $NEUTRON_DIR
    $ZUUL_CLONER --cache-dir \
        /opt/git \
        --branch $BRANCH_NAME \
        https://git.openstack.org \
        openstack/neutron
    cd openstack/neutron
    $install_cmd -e .
    popd
else
    echo "PIP HARDCODE" > /tmp/tox_install.txt
    if [ -z "$NEUTRON_PIP_LOCATION" ]; then
        NEUTRON_PIP_LOCATION="git+https://git.openstack.org/openstack/neutron@$BRANCH_NAME#egg=neutron"
    fi
    $install_cmd -U -e ${NEUTRON_PIP_LOCATION}
fi

# TODO(lucasagomes): Remove the "|| true" after
# https://review.openstack.org/#/c/561593/ is merged. This is just a
# workaround to avoid the pip warning "ERROR: You must give at least one
# requirement to install (see "pip help install")" from breaking the gate
$install_cmd -U $* || true
exit $?
