
function is_set_or_fail() {
    local name=$1
    local value=$2

    if [ ! -v value ] || [ "${value}" == "not-set" ]; then
        echo "You have to set $name" >&2
        exit 1
    fi
}

function tool_is_installed() {
# Check if given command is available on this machine
    local cmd=$1

    if ! [ -x "$(command -v $cmd)" ]; then
        echo "Error: ${cmd} command is not available. Please install it. See README.md file for more information." >&2
        exit 1
    fi
}

function oc_process_apply() {
    echo -e "\\n Processing template - $1 ($2) \\n"
    # Don't quote $2 as we need it to split into individual arguments
    oc process -f "$1" $2 | oc apply -f -
}

function openshift_login() {
    oc login "${OC_URI}" --token="${OC_TOKEN}" --insecure-skip-tls-verify=true
}


function remove_project_resources() {
    echo "Removing all openshift resources from selected project"
    oc delete all,cm,secrets --all
    
}


function create_or_reuse_project() {
    if oc get project "${OC_PROJECT}"; then
        oc project "${OC_PROJECT}"
        remove_project_resources
    else
        oc new-project "${OC_PROJECT}"
    fi
}
