#!/bin/bash

set -ex

. cico_setup.sh

docker_login

make test

build_image

push_image