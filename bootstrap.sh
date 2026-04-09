#!/bin/sh

# change the following variables to match your environment
PORT=9090
SERVER="192.168.178.87:$PORT"
SERVER_URL=https://$SERVER

# change this to the location of your eve configuration
EVE_CONFIG=/data/dev/eve/eve/conf
# change this to the serial number of your EVE device
EVE_SERIAL="shahshah"

STORE=run/adam
CERTS=run/certs
ADAM_BIN=./bin/adam
ADAM_CMD="$ADAM_BIN admin --server $SERVER_URL --server-ca $CERTS/rootCA.crt"

RUN_ONLY=0
for arg in "$@"; do
   if [ "$arg" = "--run" ]; then
      RUN_ONLY=1
   fi
done

# if adam is not built, ask to build it
if [ ! -f $ADAM_BIN ]; then
   echo "Adam is not built. Please build it first."
   exit 1
fi

if [ "$RUN_ONLY" = "1" ]; then
   add_device &
   echo ""
   echo "Admin UI: $SERVER_URL/"
   echo ""
   $ADAM_BIN server \
       --server-cert $CERTS/server-tls.crt \
       --server-key $CERTS/server-tls.key \
       --server-ca $CERTS/rootCA.crt \
       --base-url $SERVER_URL \
       --signing-cert $CERTS/server-signing.crt \
       --signing-key $CERTS/server-signing.key \
       --encrypt-cert $CERTS/server-ecdh_exchange.crt \
       --encrypt-key $CERTS/server-ecdh_exchange.key \
       --conf-dir run/adam \
       --port $PORT
   exit 0
fi

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

   echo "Run eve with $EVE_SERIAL as serial number"
   echo "Adam devices:"
   $ADAM_CMD device list
}

# remove the existing store
rm -rf $STORE

mkdir -p run/certs

echo "Generating root CA..."
CA_KEY_FILE=run/certs/rootCA.key CA_CERT_FILE=run/certs/rootCA.crt ./scripts/cert/gen-root-ca.sh

echo "Generating server certificates..."
SERVER_KEY_FILE=run/certs/server-tls.key SERVER_CERT_FILE=run/certs/server-tls.crt \
   ./scripts/cert/gen-server-cert.sh server-tls -c "run/certs/rootCA.crt" -k "run/certs/rootCA.key" \
   -i "127.0.0.1" -i "192.168.178.87" -d "localhost"

echo "Generating server signing certificates..."
SERVER_KEY_FILE=run/certs/server-signing.key SERVER_CERT_FILE=run/certs/server-signing.crt \
   ./scripts/cert/gen-server-cert.sh server-signing -c "run/certs/rootCA.crt" -k "run/certs/rootCA.key" \
   -i "127.0.0.1" -i "192.168.178.87" -d "localhost"

echo "Generating server encryption certificates..."
SERVER_KEY_FILE=run/certs/server-ecdh_exchange.key SERVER_CERT_FILE=run/certs/server-ecdh_exchange.crt \
   ./scripts/cert/gen-server-cert.sh server-ecdh_exchange -c "run/certs/rootCA.crt" -k "run/certs/rootCA.key" \
   -i "127.0.0.1" -i "192.168.178.87" -d "localhost"

echo "Copying onboarding certificate..."
cp certs/default.onboard.cert.pem "$EVE_CONFIG/onboard.cert.pem"
cp certs/default.onboard.key.pem "$EVE_CONFIG/onboard.key.pem"

echo "Copying pinned certificates..."
cp run/certs/rootCA.crt  "$EVE_CONFIG/root-certificate.pem"
cp certs/default.v2tlsbaseroot-certificates.pem "$EVE_CONFIG/v2tlsbaseroot-certificates.pem"
cat run/certs/rootCA.crt >> "$EVE_CONFIG/v2tlsbaseroot-certificates.pem"

echo "Set server URL in EVE configuration..."
echo $SERVER > "$EVE_CONFIG/server"

# add the device after a short delay
add_device &

# run Adam, and wait for eve to connect
$ADAM_BIN server \
    --server-cert $CERTS/server-tls.crt \
    --server-key $CERTS/server-tls.key \
    --server-ca $CERTS/rootCA.crt \
    --base-url $SERVER_URL \
    --signing-cert $CERTS/server-signing.crt \
    --signing-key $CERTS/server-signing.key \
    --encrypt-cert $CERTS/server-ecdh_exchange.crt \
    --encrypt-key $CERTS/server-ecdh_exchange.key \
    --conf-dir run/adam \
    --port $PORT