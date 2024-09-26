#!/usr/bin/env bash

# Exit on error
set -e

RED='\033[01;31m'
GREEN='\033[01;32m'
YELLOW='\033[01;33m'
NONE='\033[00m'

# 1: current, 2: local
USE_CURRENT=0

# used to run test image
if [[ "$1" == "--local" ]]; then
  USE_CURRENT=2
  DOCKER_CONTAINER_NAME=0
# build test image if no image name passed
elif [[ "$1" == "--current" ]]; then
  USE_CURRENT=1
  DOCKER_CONTAINER_NAME=${2:-0}
  if [[ "$DOCKER_CONTAINER_NAME" == "0" ]]; then
    echo -e "${YELLOW}Warning: configuration tests needs the container identifier as second argument${NONE}"
  fi
# build test image if no image name passed
elif [ -z "$1" ]; then
  echo "Building test image from jwt-nginx"
  DOCKER_IMAGE_NAME=jwt-nginx-test
  cd test-image
  docker build -t ${DOCKER_IMAGE_NAME} .
  cd ..
  if [ $? -ne 0 ]
  then
    echo -e "${RED}Build Failed${NONE}";
    exit 1;
  fi
# use a specific image
else
  DOCKER_IMAGE_NAME=$1
  echo "Using image ${DOCKER_IMAGE_NAME} for tests"
  shift
fi

if [[ "$USE_CURRENT" == "0" ]]; then
  DOCKER_CONTAINER_NAME=container-${DOCKER_IMAGE_NAME}
  docker run --rm --name "${DOCKER_CONTAINER_NAME}" -d -p 8000:8000 ${DOCKER_IMAGE_NAME}
fi

if [[ "$OSTYPE" == "darwin"* ]] || [[ "$OSTYPE" == "linux"* ]]; then
  # Mac OSX / Linux
  MACHINE_IP='localhost'
else
  # Windows
  MACHINE_IP=`docker-machine ip 2> /dev/null`
fi

b64enc() { openssl enc -base64 -A | tr '+/' '-_' | tr -d '='; }
hs_sign() { openssl dgst -binary -sha"${1}" -hmac "$2"; }
rs_sign() { openssl dgst -binary -sha"${1}" -sign <(printf '%s\n' "$2"); }

make_jwt() {
  local alg=$1
  local key=$2
  local alg_size=${alg#RS} # alg without RS prefix
  local header=`echo -n "{\"alg\":\"$alg\"}" | b64enc`
  local payload=`echo -n '{}' | b64enc`
  local secret=`cat ./test-image/nginx/keys/$key`
  local sig=`echo -n "$header.$payload" | rs_sign "$alg_size" "$secret" | b64enc`
  echo -n "$header.$payload.$sig"
  return 0
}

# Disable exit on error
set +e

VALID_RS256=`make_jwt RS256 rsa-private.pem`
VALID_RS512=`make_jwt RS512 rsa-private.pem`
BAD_RS256=`make_jwt RS256 rsa-wrong-private.pem`
VALID_JWT="eyJhbGciOiJIUzI1NiJ9.e30.-gVyhFDs5NeX0yvaAoTPVgrDfrg_qk7dF0sNj_-Bu-c" # secret = 'inherited-secret' (utf8)
BAD_SIG="eyJhbGciOiJIUzI1NiJ9.e30.nmwH1lIcnA-g8CEV_fWIlAV7h98_Wwy1gIqIabAdrIs" # secret = 'invalid' (utf8)

TEST_TOTAL_COUNT=0
TEST_FAIL_COUNT=0

test_for_tab () {
  local test=`grep $'\t' src/ngx_http_auth_jwt_module.c | wc -l | awk '{$1=$1};1'`
  local name='Indent test'
  if [ "$test" == "0" ];then
    echo -e "${GREEN}${name}: passed${NONE}";
  else
    echo -e "${RED}${name}: failed (found ${test} tabs instead of 0)${NONE}";
  fi
}

if [[ "$USE_CURRENT" != "2" ]]; then
  test_for_tab
fi

test_jwt () {
  ((TEST_TOTAL_COUNT++))

  local name=$1
  local path=$2
  local expect=$3
  local extra=$4

  cmd="curl -X GET -o /dev/null --silent --head --write-out '%{http_code}' http://$MACHINE_IP:8000$path -H 'cache-control: no-cache' $extra"

  test=$( eval $cmd )
  if [ "$test" -eq "$expect" ];then
    echo -e "${GREEN}${name}: passed (${test})${NONE}";
  else
    echo -e "${RED}${name}: failed (${test} instead of ${expect})${NONE}";
    ((TEST_FAIL_COUNT++))
  fi
}

test_conf_docker () {
  ((TEST_TOTAL_COUNT++))
  local target=$DOCKER_CONTAINER_NAME
  local config=$1
  local expect=$2

  match=`docker exec -it $target nginx -t -c "/etc/nginx/${config}.conf" | grep "$expect" | wc -l | awk '{$1=$1};1'`

  if [ "$match" -ne "0" ];then
    echo -e "${GREEN}Config test ${config}: passed (${match})${NONE}";
  else
    ((TEST_FAIL_COUNT++))
    echo -e "${RED}Config test ${config}: failed (no match for '${expect}')${NONE}";
    docker exec -it $target nginx -t -c "/etc/nginx/${config}.conf"
  fi
}

test_conf_local () {
  ((TEST_TOTAL_COUNT++))
  local config=$1
  local expect="$2"

  match=`nginx -t -c "/etc/nginx/${config}.conf" 2>&1 | grep "$expect" | wc -l | awk '{$1=$1};1'`

  if [ "$match" -ne "0" ];then
    echo -e "${GREEN}Config test ${config}: passed (${match})${NONE}";
  else
    ((TEST_FAIL_COUNT++))
    echo -e "${RED}Config test ${config}: failed (no match for '${expect}')${NONE}";
    nginx -t -c "/etc/nginx/${config}.conf"
  fi
}

test_conf () {
  if [[ "$USE_CURRENT" == "2" ]]; then
    test_conf_local $@
  else
    test_conf_docker $@
  fi
}


echo "# Test jwt presence"
test_jwt "Calling auth-disabled without jwt should return 201" "/auth-disabled" "201"
test_jwt "Calling secure-cookie without jwt should return 401" "/secure-cookie" "401"
test_jwt "Calling secure-auth-h without jwt should return 401" "/secure-auth-header" "401"

echo "# Basic tests"
test_jwt "Valid jwt in cookie on auth-disabled should return 201" "/auth-disabled" "201" "--cookie \"rampartjwt=${VALID_JWT}\""
test_jwt "Valid jwt in header on auth-disabled should return 201" "/auth-disabled" "201" "--cookie \"Authorization: Bearer ${VALID_JWT}\""
test_jwt "Valid jwt in cookie on secure-cookie should return 201" "/secure-cookie" "201" "--cookie \"rampartjwt=${VALID_JWT}\""
test_jwt "Valid jwt in header on secure-cookie should return 401" "/secure-cookie" "401" "--header \"Authorization: Bearer ${VALID_JWT}\""
test_jwt "Valid jwt in cookie on secure-auth-header should return 401" "/secure-auth-header" "401" "--cookie \"rampartjwt=${VALID_JWT}\""
test_jwt "Valid jwt in header on secure-auth-header should return 201" "/secure-auth-header" "201" "--header \"Authorization: Bearer ${VALID_JWT}\""

echo "# Test exp claim with expired jwt (2022-01-01)"
JWT='eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2NDA5OTUyMDB9.xRKe3S3RDg9l2_OlVhDnbd5taYo0pl9D22AABCWrHYk'
test_jwt "Expired jwt in cookie on auth-disabled should return 201" "/auth-disabled" "201" "--cookie \"rampartjwt=${JWT}\""
test_jwt "Expired jwt in header on auth-disabled should return 201" "/auth-disabled" "201"  "--header \"Authorization: Bearer ${JWT}\""
test_jwt "Expired jwt on secure-cookie should return 401" "/secure-cookie"      "401" "--cookie \"rampartjwt=${JWT}\""
test_jwt "Expired jwt on secure-auth-h should return 401" "/secure-auth-header" "401" "--header \"Authorization: Bearer ${JWT}\""

echo "# Test float exp claim" # { "exp": 1698742245.336421 }
JWT='eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2OTg3NDIyNDUuMzM2NDIxfQ.Wh-6szLG-7TcO19Efwh5A7IBoMWPPfttxwgUFKBhDJA'
test_jwt "Expired jwt on secure-auth-h should return 401" "/secure-auth-header" "401" "--header \"Authorization: Bearer ${JWT}\""

echo "# Test invalid exp" # { "exp": "1698742245" }
JWT='eyJhbGciOiJIUzI1NiJ9.eyJleHAiOiIxNjk4NzQyMjQ1In0.Vpvf77sGNljk6gmGnaDPE1LTD_wEo-GTFZrCWiAfVgM'
test_jwt "Expired jwt on secure-auth-h should return 401" "/secure-auth-header" "401" "--header \"Authorization: Bearer ${JWT}\""

echo "# Test exp claim with non-expired jwt (2032-01-01)"
JWT='eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjE5NTY1MjgwMDB9.3rTJLB2KJxDoTImIsyMC4Bo5R1IY-d9dhr75llFiw_8'
test_jwt "Calling secure-cookie with non-expired jwt should return 201" "/secure-cookie"      "201" "--cookie \"rampartjwt=${JWT}\""
test_jwt "Calling secure-auth-h with non-expired jwt should return 201" "/secure-auth-header" "201" "--header \"Authorization: Bearer ${JWT}\""

echo "# Test cookie name"
test_jwt "Calling secure-cookie with valid jwt in cookie but wrong cookie name should return 401" "/secure-cookie" "401" "--cookie \"invalid_name=${VALID_JWT}\""

echo "# Test payload"
test_jwt "Calling secure-cookie with invalid payload should return 401" "/secure-cookie" "401" "--cookie \"rampartjwt=invalid\""
test_jwt "Calling secure-auth-h with invalid payload should return 401" "/secure-auth-header" "401" "--header \"Authorization: invalid\""
JWT='eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjE5NT1MjgwMDB9.3rTJLB2KJxDoTImIsyMC4Bo5R1IY-d9dhr75llFiw_8'
test_jwt "Calling secure-cookie with invalid payload should return 401" "/secure-cookie" "401" "--cookie \"rampartjwt=${JWT}\""
test_jwt "Calling secure-auth-h with invalid payload should return 401" "/secure-auth-header" "401" "--header \"Authorization: Bearer ${JWT}\""

echo "# Test signature"
test_jwt "Calling secure-cookie with invalid signature should return 401" "/secure-cookie"      "401" "--cookie \"rampartjwt=${BAD_SIG}\""
test_jwt "Calling secure-auth-h with invalid signature should return 401" "/secure-auth-header" "401" "--header \"Authorization: Bearer ${BAD_SIG}\""

echo "# Test auth header (check for overflows)"
test_jwt "Invalid jwt in header should return 401" "/secure-auth-header" "401" "--header \"Authorization: \\0\""
test_jwt "Invalid jwt in header should return 401" "/secure-auth-header" "401" "--header \"Authorization: x\""
test_jwt "Invalid jwt in header should return 401" "/secure-auth-header" "401" "--header \"Authorization: Beare\""
test_jwt "Invalid jwt in header should return 401" "/secure-auth-header" "401" "--header \"Authorization: Bearer\""
test_jwt "Invalid jwt in header should return 401" "/secure-auth-header" "401" "--header \"Authorization: BearerXa\""
test_jwt "Invalid jwt in header should return 401" "/secure-auth-header" "401" "--header \"Authorization: BearAr a\""
test_jwt "Invalid jwt in header should return 401" "/secure-auth-header" "401" "--header \"Authorization: BearAuthorization\""

echo "# Test key encodings"
JWT='eyJhbGciOiJIUzI1NiJ9.e30.XmNK3GpH3Ys_7wsYBfq4C3M6goz71I7dTgUkuIa5lyQ'
test_jwt "Calling string-encoded with valid jwt should return 201" "/string-encoded" "201" "--header \"Authorization: Bearer ${JWT}\""
test_jwt "Calling base64-encoded with valid jwt should return 201" "/base64-encoded" "201" "--header \"Authorization: Bearer ${JWT}\""

echo "# Test RSA files as keys"
test_jwt "Valid jwt (RS256)" "/rsa-file-encoded" "201" "--header \"Authorization: Bearer ${VALID_RS256}\""
test_jwt "Valid jwt (RS512)" "/rsa-file-encoded" "201" "--header \"Authorization: Bearer ${VALID_RS512}\""
test_jwt "Valid jwt header with expected alg (RS256) but bad signature" "/rsa-file-encoded/" "401" "--header \"Authorization: Bearer ${BAD_RS256}\""
test_jwt "Valid jwt header with expected alg (RS256)" "/rsa-file-encoded-alg-256" "201" "--header \"Authorization: Bearer ${VALID_RS256}\""
test_jwt "Valid jwt header with expected alg (RS512)" "/rsa-file-encoded-alg-512" "201" "--header \"Authorization: Bearer ${VALID_RS512}\""
test_jwt "Valid jwt header but bad alg (RS512 instead of RS256)" "/rsa-file-encoded-alg-256/" "401" "--header \"Authorization: Bearer ${VALID_RS512}\""
test_jwt "Valid jwt header but bad alg (RS256 instead of RS512)" "/rsa-file-encoded-alg-512/" "401" "--header \"Authorization: Bearer ${VALID_RS256}\""

echo "# Test any alg"
test_jwt "Calling any-alg with RS256 alg should return 201" "/any-alg" "201" "--header \"Authorization: Bearer ${VALID_RS256}\""
test_jwt "Calling any-alg with RS512 alg should return 201" "/any-alg" "201" "--header \"Authorization: Bearer ${VALID_RS512}\""
test_jwt "Calling any-alg with invalid signature should return 401" "/any-alg" "401" "--header \"Authorization: Bearer ${BAD_SIG}\""
test_jwt "Calling any-alg with invalid signature (RS256) should return 401" "/any-alg" "401" "--header \"Authorization: Bearer ${BAD_RS256}\""

echo "# Test with multiple cookies"
test_jwt "Calling with valid jwt cookie and some cookies" "/secure-cookie" "201" "--cookie \"rampartjwt=${VALID_JWT}; session=${VALID_JWT}\""
test_jwt "Calling with some cookies and valid jwt cookie" "/secure-cookie" "201" "--cookie \"rampartjwt=${VALID_JWT}; session=${VALID_JWT}\""

echo "# Test auth_jwt_require"
JWT='eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYWRtaW4ifQ.AnK-9_1YHP4LqTSGBMbv6GnRiZ-eGOcquN2kxHukPQo' # { "role": "admin" }
test_jwt "Calling with expected claim (role==admin) should return 201" "/auth-require" "201" "--header \"Authorization: Bearer ${JWT}\""
JWT='eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoidXNlciJ9.wlUY-DvK0sM6uiNlUrMsey8sMkn5xHCaml--Yg6VRCc' # { "role": "user" }
test_jwt "Calling with expected claim (role!=admin) should return 403" "/auth-require" "403" "--header \"Authorization: Bearer ${JWT}\""
JWT='eyJhbGciOiJIUzI1NiJ9.eyJzY29wZSI6InB1YmxpYyJ9.Ho4ZSmMDQ61wxqB-uRNdXHENSnxrrTiW91vFL9vApTY' # { "scope": "public" }
test_jwt "Calling without expected claim (role) should return 403" "/auth-require" "403" "--header \"Authorization: Bearer ${JWT}\""
# compound
JWT='eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYWRtaW4ifQ.AnK-9_1YHP4LqTSGBMbv6GnRiZ-eGOcquN2kxHukPQo' # { "role": "admin" }
test_jwt "Test claim with valid jwt but partial claim (a/ab) should return 403" "/auth-compound-require" "403" "--header \"Authorization: Bearer ${JWT}\""
JWT='eyJhbGciOiJIUzI1NiJ9.eyJzY29wZSI6InJlc3RyaWN0ZWQifQ.qD7C6CC8P3PCfl7lVMzcybQs0tZuq3bSx1Rtkz-fioE' # { "scope": "restricted" }
test_jwt "Test claim with valid jwt but partial claim (b/ab) should return 403" "/auth-compound-require" "403" "--header \"Authorization: Bearer ${JWT}\""
JWT='eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYWRtaW4iLCJzY29wZSI6InJlc3RyaWN0ZWQifQ.Q7wrUA1Ao3Bt-lQpE3ubnYfn_Yu2FCbEENC8JiED5ZY' # { "role": "admin", "scope": "restricted" }
test_jwt "Test claim with valid jwt and expected claim should return 201" "/auth-compound-require" "201" "--header \"Authorization: Bearer ${JWT}\""


if [[ "$USE_CURRENT" == "1" ]] && [[ "$DOCKER_CONTAINER_NAME" == "0" ]]; then
  echo -e "${YELLOW}Warning: container identifier not set -> skipping configuration tests${NONE}"
else
  echo "# Test configurations"
  test_conf 'invalid-nginx-1' '"auth_jwt_key" directive is duplicate in /etc/nginx/invalid-nginx.conf:18'
  test_conf 'invalid-nginx-2' 'JWT: key not set in /etc/nginx/invalid-nginx-2.conf:10'
  test_conf 'invalid-arg-1' 'invalid number of arguments in "auth_jwt" directive in /etc/nginx/invalid-arg-1.conf:6'
  test_conf 'invalid-arg-2' 'invalid number of arguments in "auth_jwt_key" directive in /etc/nginx/invalid-arg-2.conf:5'
  test_conf 'invalid-arg-3' 'Invalid key in /etc/nginx/invalid-arg-3.conf:5'
  test_conf 'invalid-arg-4' 'No such file or directory (2: No such file or directory) in /etc/nginx/invalid-arg-4.conf:5'
  test_conf 'invalid-arg-5' 'No such file or directory (2: No such file or directory) in /etc/nginx/invalid-arg-5.conf:5'
  test_conf 'invalid-key-1' 'Failed to turn hex key into binary in /etc/nginx/invalid-key-1.conf:5'
  test_conf 'invalid-key-2' 'Failed to turn base64 key into binary in /etc/nginx/invalid-key-2.conf:5'
  test_conf 'invalid-require-1' 'invalid error code 402 in /etc/nginx/invalid-require-1.conf:17'
  test_conf 'invalid-require-2' 'error=403 cannot be the single element of jwt_auth_require directive in /etc/nginx/invalid-require-2.conf:17'
  test_conf 'invalid-require-3' 'error=401 must be the last element of jwt_auth_require directive in /etc/nginx/invalid-require-3.conf:17'
  test_conf 'invalid-require-4' 'invalid variable name "admin=true" in /etc/nginx/invalid-require-6.conf:13'
  test_conf 'invalid-require-5' 'unknown "jwt_has_admin_role" variable'
  test_conf 'invalid-require-6' '"auth_jwt_require" directive is duplicate in /etc/nginx/invalid-require-6.conf:23'
fi

if [[ "$USE_CURRENT" == "0" ]]; then
  echo stopping container $DOCKER_CONTAINER_NAME
  docker stop ${DOCKER_CONTAINER_NAME} > /dev/null
fi

if [[ "$TEST_FAIL_COUNT" != "0" ]]; then
  echo -e "${RED}Test suite failed $TEST_FAIL_COUNT / $TEST_TOTAL_COUNT ${NONE}";
  exit 1
else
  echo -e "${GREEN}Tests passed successfully${NONE}";
fi
