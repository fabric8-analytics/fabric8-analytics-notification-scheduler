#!/bin/bash -e

# Deploy fabric8-analytics to Openshift

here=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source ./helpers.sh

#Check for configuration file
if ! [ -f "${here}/env.sh" ]
then
    echo '`env.sh` configuration file is missing. You can create one from the template:'
    echo 'cp env-template.sh env.sh'
    echo
    echo 'Modify the `env.sh` configuration file as necessary. See README.md file for more information.'
    exit 1
fi

#Check if required commands are available
tool_is_installed oc

#Load configuration from env variables
source ./env.sh

#Check if required env variables are set
is_set_or_fail OC_USERNAME "${OC_USERNAME}"
is_set_or_fail OC_PASSWD "${OC_PASSWD}"

openshift_login
create_or_reuse_project


oc_process_apply "f8a-notification.yaml"
