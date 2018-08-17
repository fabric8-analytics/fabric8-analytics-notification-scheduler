#!/bin/bash

set -e
set -x

here=$(cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd)

# test coverage threshold
COVERAGE_THRESHOLD=25

TIMESTAMP="$(date +%F-%H-%M-%S)"

gc() {
  retval=$?
  deactivate
  rm -rf venv/
  exit $retval
}

trap gc EXIT SIGINT

function prepare_venv() {
    VIRTUALENV=$(which virtualenv) || :
    if [ -z "$VIRTUALENV" ]
    then
        # python34 which is in CentOS does not have virtualenv binary
        VIRTUALENV=$(which virtualenv-3)
    fi

    ${VIRTUALENV} -p python3 venv && source venv/bin/activate
    if [ $? -ne 0 ]
    then
        printf "%sPython virtual environment can't be initialized%s" "${RED}" "${NORMAL}"
        exit 1
    fi
}

prepare_venv
pip3 install -r requirements.txt

pip3 install -r tests/requirements.txt

python3 "$(which pytest)" --cov=f8a_notification/ --cov-report term-missing --cov-fail-under=$COVERAGE_THRESHOLD -vv tests

echo "Test suite passed \\o/"