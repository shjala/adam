#!/bin/sh
set -x

# you need Eden installed and built, get it from here: 
# https://github.com/lf-edge/eden

# change the following variables to match your environment
PORT=9090
DOMAIN=zedcloud.local.zededa.net
SERVER=$DOMAIN:$PORT
SERVER_URL=https://$SERVER
# this is the default location where eden stores certificates
# no need to change this if you are using the default location.
EDEN_CERTS=~/.eden/certs
# change this to the location of your eden binary
EDEN_BIN=~/shah-dev/eden/eden
# change this to the location of your eve configuration
EVE_CONFIG=~/shah-dev/eve/conf
# change this to the serial number of your EVE device
EVE_SERIAL="shahshah"

STORE=run/adam
CERTS=run/certs
ADAM_BIN=./bin/adam
ADAM_CMD="$ADAM_BIN admin --server $SERVER_URL --server-ca $CERTS/server.pem"

add_device() {
   # wait for adam to run, then add and onboard a device
   sleep 3
   # add a device
   $ADAM_CMD device add --path $EVE_CONFIG/onboard.cert.pem --onboard-path $EVE_CONFIG/onboard.cert.pem --serial $EVE_SERIAL
   UUID=$($ADAM_CMD device list | head -1)
   if [ -n "$UUID" ]; then
      # add the default configuration to the device
      cp samples/simple.json run/default-config.json
      $ADAM_CMD device config set --uuid $UUID --config-path run/default-config.json
   fi
}

# remove the existing store
rm -rf $STORE

# generate required certificates using eden
ln -s $EDEN_BIN eden
rm -rf $EDEN_CERTS
./eden utils certs --domain $DOMAIN
cp -r $EDEN_CERTS run/

# copy root certificate to eve
rm -f $EVE_CONFIG/root-certificate.pem
cp $CERTS/root-certificate.pem $EVE_CONFIG/

add_device &
# run Aadam, and wait for eve to connect
$ADAM_BIN server \
    --server-cert $CERTS/server.pem \
    --server-key $CERTS/server-key.pem \
    --signing-cert $CERTS/signing.pem \
    --signing-key $CERTS/signing-key.pem \
    --encrypt-cert $CERTS/encrypt.pem \
    --encrypt-key $CERTS/encrypt-key.pem \
    --conf-dir run/adam \
    --port $PORT