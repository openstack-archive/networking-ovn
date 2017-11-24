#!/usr/bin/env bash

set -xe

NETWORKING_OVN_DIR="$BASE/new/networking-ovn"
SCRIPTS_DIR="/usr/os-testr-env/bin/"
GATE_STACK_USER=stack

venv=${1:-"dsvm-functional"}

function generate_testr_results {
    # Give job user rights to access tox logs
    sudo -H -u $owner chmod o+rw .
    sudo -H -u $owner chmod o+rw -R .stestr
    if [ -f ".stestr/0" ] ; then
        .tox/$venv/bin/subunit-1to2 < .stestr/0 > ./stestr.subunit
        $SCRIPTS_DIR/subunit2html ./stestr.subunit testr_results.html
        gzip -9 ./stestr.subunit
        gzip -9 ./testr_results.html
        sudo mv ./*.gz /opt/stack/logs/
    fi
}

function generate_log_index {
    local xtrace
    xtrace=$(set +o | grep xtrace)
    set +o xtrace

    # honor job flavors like -python35
    case $venv in
    *"dsvm-functional"*)
        venv="dsvm-functional"
        ;;
    *)
        echo "Unrecognized environment $venv".
        exit 1
    esac

    virtualenv /tmp/os-log-merger
    /tmp/os-log-merger/bin/pip install -U os-log-merger==1.1.0
    files=$(find /opt/stack/logs/$venv-logs -name '*.txt' -o -name '*.log')
    # -a3 to truncate common path prefix
    # || true to avoid the whole run failure because of os-log-merger crashes and such
    # TODO(ihrachys) remove || true when we have more trust in os-log-merger
    contents=$(/tmp/os-log-merger/bin/os-log-merger -a3 $files || true)
    echo "$contents" | sudo tee /opt/stack/logs/$venv-index.txt > /dev/null

    $xtrace
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
    generate_log_index
    exit $testr_exit_code
fi
