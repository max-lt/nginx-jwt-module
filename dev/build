#!/bin/bash

SCRIPT_PATH="$( cd "$(dirname "$0")" ; pwd -P )"

cd ${SCRIPT_PATH}

# usage: ./build.sh [sX] # With X the step to begin with (default 0)

set -e

# STEP from first arg, defaulting to step 0
STEP=${1:-"s0"}
BRANCH=$(git branch 2> /dev/null | sed -e '/^[^*]/d' -e 's/* \(.*\)/\1/')
BRANCH=${BRANCH:-undefined}

# Copy resources in docker's scope
mkdir -p tmp && cp -r ../config ../resources ../src tmp

case "$STEP" in
  "s0" )
    echo "Step 0: get env"
    docker build --file Dockerfile.s0 -t jwt-nginx-s0 .
    echo "done step 0"
    ;&
  "s1" )
    echo "Step 1: install libjwt"
    docker build --file Dockerfile.s1 -t jwt-nginx-s1 .
    echo "done step 1"
    ;&
   "s2")
    echo "Step 2: get nginx"
    docker build --file Dockerfile.s2 -t jwt-nginx-s2 .
    echo "done step 2"
    ;&
   "s3")
    echo "Step 3: build nginx"
    docker build --file Dockerfile.s3 -t jwt-nginx-s3 .
    echo "done step 3"
    ;&
   "s4" )
    echo "Step 4: copy test files"
    docker build --file Dockerfile.s4 -t jwt-nginx-s4 .
    echo "done step 4"
    ;;
   * )
    echo "Invalid step $STEP"
    exit 1
    ;;
esac

docker tag jwt-nginx-s0 jwt-nginx-s0:$BRANCH
docker tag jwt-nginx-s1 jwt-nginx-s1:$BRANCH
docker tag jwt-nginx-s2 jwt-nginx-s2:$BRANCH
docker tag jwt-nginx-s3 jwt-nginx-s3:$BRANCH
docker tag jwt-nginx-s4 jwt-nginx-s4:$BRANCH

rm -rf tmp
