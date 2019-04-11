#!/bin/bash

set -e
set -x

# test coverage threshold
COVERAGE_THRESHOLD=60

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
        # python36 which is in CentOS does not have virtualenv binary
        VIRTUALENV=$(which virtualenv-3)
    fi

    ${VIRTUALENV} -p python3 venv && source venv/bin/activate
    if [ $? -ne 0 ]
    then
        printf "%sPython virtual environment can't be initialized%s" "${RED}" "${NORMAL}"
        exit 1
    fi
}
PYTHONPATH=$(pwd)/f8a_notification/
export PYTHONPATH
prepare_venv
pip3 install -r requirements.txt

pip3 install -r tests/requirements.txt

python3 "$(which pytest)" --cov=f8a_notification/ --cov-report term-missing --cov-fail-under=$COVERAGE_THRESHOLD -vv tests

codecov --token=3a540a46-f7e9-4050-b36a-97f81b948bcb

echo "Test suite passed \\o/"
