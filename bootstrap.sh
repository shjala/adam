#!/bin/sh

# change the following variables to match your environment
PORT=9090

# Auto-detect the host IP: the address on the interface that has the default route.
# Override by setting HOST_IP in the environment before running this script.
if [ -z "$HOST_IP" ]; then
    HOST_IP=$(ip route get 1.1.1.1 2>/dev/null | awk '/src/ { for(i=1;i<=NF;i++) if($i=="src") { print $(i+1); exit } }')
fi
if [ -z "$HOST_IP" ]; then
    echo "ERROR: could not auto-detect host IP. Set HOST_IP=<your-ip> and re-run." >&2
    exit 1
fi

SERVER="$HOST_IP:$PORT"
SERVER_URL=https://$SERVER

EVE_CONFIG="${EVE_CONFIG:-/data/dev/eve/eve/conf}"
EVE_SERIAL="${EVE_SERIAL:-shahshah}"

STORE=run/adam
CERTS=run/certs
ADAM_BIN=./bin/adam
ADAM_CMD="$ADAM_BIN admin --server $SERVER_URL"

RUN_ONLY=0
OVERWRITE_YES=false
for arg in "$@"; do
   case "$arg" in
      --run)  RUN_ONLY=1 ;;
      --yes)  OVERWRITE_YES=true ;;
   esac
done
export OVERWRITE_YES

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

# Fail early if the port is already in use.
if lsof -ti tcp:"$PORT" > /dev/null 2>&1; then
    echo "ERROR: port $PORT is already in use. Stop the existing process and re-run." >&2
    exit 1
fi

# remove the existing store
rm -rf $STORE

mkdir -p run/certs

echo "Generating root CA..."
CA_KEY_FILE=run/certs/rootCA.key CA_CERT_FILE=run/certs/rootCA.crt ./scripts/cert/gen-root-ca.sh

echo "Generating server certificates..."
SERVER_KEY_FILE=run/certs/server-tls.key SERVER_CERT_FILE=run/certs/server-tls.crt \
   ./scripts/cert/gen-server-cert.sh server-tls -c "run/certs/rootCA.crt" -k "run/certs/rootCA.key" \
   -i "127.0.0.1" -i "$HOST_IP" -d "localhost"

echo "Generating server signing certificates..."
SERVER_KEY_FILE=run/certs/server-signing.key SERVER_CERT_FILE=run/certs/server-signing.crt \
   ./scripts/cert/gen-server-cert.sh server-signing -c "run/certs/rootCA.crt" -k "run/certs/rootCA.key" \
   -i "127.0.0.1" -i "$HOST_IP" -d "localhost"

echo "Generating server encryption certificates..."
SERVER_KEY_FILE=run/certs/server-ecdh_exchange.key SERVER_CERT_FILE=run/certs/server-ecdh_exchange.crt \
   ./scripts/cert/gen-server-cert.sh server-ecdh_exchange -c "run/certs/rootCA.crt" -k "run/certs/rootCA.key" \
   -i "127.0.0.1" -i "$HOST_IP" -d "localhost"

echo "Copying onboarding certificate..."
cp certs/default.onboard.cert.pem "$EVE_CONFIG/onboard.cert.pem"
cp certs/default.onboard.key.pem "$EVE_CONFIG/onboard.key.pem"

echo "Copying pinned certificates..."
cp run/certs/rootCA.crt  "$EVE_CONFIG/root-certificate.pem"
cp certs/default.v2tlsbaseroot-certificates.pem "$EVE_CONFIG/v2tlsbaseroot-certificates.pem"
cat run/certs/rootCA.crt >> "$EVE_CONFIG/v2tlsbaseroot-certificates.pem"

echo "Set server URL in EVE configuration..."
echo $SERVER > "$EVE_CONFIG/server"

# Copy rootCA to the location the adam admin client expects for TLS verification.
mkdir -p run/adam
cp run/certs/rootCA.crt run/adam/server.pem

# add the device after a short delay
add_device &

# run Adam, and wait for eve to connect
$ADAM_BIN server \
    --server-cert $CERTS/server-tls.crt \
    --server-key $CERTS/server-tls.key \
    --signing-cert $CERTS/server-signing.crt \
    --signing-key $CERTS/server-signing.key \
    --encrypt-cert $CERTS/server-ecdh_exchange.crt \
    --encrypt-key $CERTS/server-ecdh_exchange.key \
    --conf-dir run/adam \
    --port $PORT