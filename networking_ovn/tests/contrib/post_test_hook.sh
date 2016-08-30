#!/usr/bin/env bash

set -xe

NETWORKING_OVN_DIR="$BASE/new/networking-ovn"
SCRIPTS_DIR="/usr/os-testr-env/bin/"
GATE_STACK_USER=stack

venv=${1:-"dsvm-functional"}

function generate_testr_results {
    # Give job user rights to access tox logs
    sudo -H -u $owner chmod o+rw .
    sudo -H -u $owner chmod o+rw -R .testrepository
    if [ -f ".testrepository/0" ] ; then
        .tox/$venv/bin/subunit-1to2 < .testrepository/0 > ./testrepository.subunit
        $SCRIPTS_DIR/subunit2html ./testrepository.subunit testr_results.html
        gzip -9 ./testrepository.subunit
        gzip -9 ./testr_results.html
        sudo mv ./*.gz /opt/stack/logs/
    fi
}

if [[ "$venv" == dsvm-functional* ]]
then
    owner=$GATE_STACK_USER
    sudo_env=

    # Set owner permissions according to job's requirements.
    cd $NETWORKING_OVN_DIR
    sudo chown -R $owner:$owner $NETWORKING_OVN_DIR

    # Run tests
    echo "Running networking-ovn $venv test suite"
    set +e
    sudo -H -u $owner $sudo_env tox -e $venv
    testr_exit_code=$?
    set -e

    # Collect and parse results
    generate_testr_results
    exit $testr_exit_code
fi
