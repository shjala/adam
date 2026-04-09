#!/bin/bash
# Generate Server Certificate Script
# Generates a server certificate with ECDSA P-256 key, signed by a CA

set -e

# Default configuration
DEFAULT_IP="127.0.0.1"
DEFAULT_CURVE="prime256v1"  # P-256 curve
DEFAULT_VALIDITY_DAYS=3650  # 10 years
DEFAULT_COUNTRY="US"
DEFAULT_ORGANIZATION="Seth Opensource Controller"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_usage() {
    echo "Usage: $0 <name> [options]"
    echo
    echo "Required:"
    echo "  name                 Common Name for the certificate (e.g., server-001, device-uuid)"
    echo
    echo "Options:"
    echo "  -d, --domain         Domain name for DNS SAN (can be used multiple times)"
    echo "  -i, --ip             IP address for IP SAN (default: $DEFAULT_IP, can be used multiple times)"
    echo "  -s, --serial         Serial number for the certificate (default: random)"
    echo "  -c, --ca-cert        CA certificate file (default: rootCA.crt)"
    echo "  -k, --ca-key         CA private key file (default: rootCA.key)"
    echo "  -o, --output-prefix  Output file prefix (default: server-<name>)"
    echo "  -v, --validity       Validity in days (default: $DEFAULT_VALIDITY_DAYS)"
    echo "  --country            Country code (default: $DEFAULT_COUNTRY)"
    echo "  --organization       Organization name (default: $DEFAULT_ORGANIZATION)"
    echo "  --curve              EC curve (default: $DEFAULT_CURVE)"
    echo "  -h, --help           Show this help message"
    echo
    echo "Examples:"
    echo "  $0 server-001"
    echo "  $0 device-uuid-123 -d example.com -d www.example.com"
    echo "  $0 api-server -i 192.168.1.100 -i 10.0.0.100 -d api.local"
    echo "  $0 edge-device -s 12345 --ca-cert myCA.crt --ca-key myCA.key"
}

# Parse command line arguments
if [[ $# -eq 0 ]]; then
    print_error "Missing required argument: name"
    print_usage
    exit 1
fi

NAME="$1"
shift

# Initialize arrays and variables
DOMAINS=()
IPS=("$DEFAULT_IP")
SERIAL=""
CA_CERT="rootCA.crt"
CA_KEY="rootCA.key"
OUTPUT_PREFIX=""
VALIDITY_DAYS="$DEFAULT_VALIDITY_DAYS"
COUNTRY="$DEFAULT_COUNTRY"
ORGANIZATION="$DEFAULT_ORGANIZATION"
CURVE="$DEFAULT_CURVE"
IP_PROVIDED=false

# Parse options
while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--domain)
            DOMAINS+=("$2")
            shift 2
            ;;
        -i|--ip)
            if [[ "$IP_PROVIDED" == false ]]; then
                IPS=()  # Clear default IP when first IP is provided
                IP_PROVIDED=true
            fi
            IPS+=("$2")
            shift 2
            ;;
        -s|--serial)
            SERIAL="$2"
            shift 2
            ;;
        -c|--ca-cert)
            CA_CERT="$2"
            shift 2
            ;;
        -k|--ca-key)
            CA_KEY="$2"
            shift 2
            ;;
        -o|--output-prefix)
            OUTPUT_PREFIX="$2"
            shift 2
            ;;
        -v|--validity)
            VALIDITY_DAYS="$2"
            shift 2
            ;;
        --country)
            COUNTRY="$2"
            shift 2
            ;;
        --organization)
            ORGANIZATION="$2"
            shift 2
            ;;
        --curve)
            CURVE="$2"
            shift 2
            ;;
        -h|--help)
            print_usage
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            print_usage
            exit 1
            ;;
    esac
done

# Set output prefix if not provided
if [[ -z "$OUTPUT_PREFIX" ]]; then
    OUTPUT_PREFIX="server-$NAME"
fi

# Output files
SERVER_KEY_FILE=${SERVER_KEY_FILE:-"${OUTPUT_PREFIX}.key"}
SERVER_CERT_FILE=${SERVER_CERT_FILE:-"${OUTPUT_PREFIX}.crt"}
SERVER_CONFIG_FILE=${SERVER_CONFIG_FILE:-"${OUTPUT_PREFIX}.conf"}
SERVER_CSR_FILE=${SERVER_CSR_FILE:-"${OUTPUT_PREFIX}.csr"}

# Generate random serial if not provided
if [[ -z "$SERIAL" ]]; then
    SERIAL=$(openssl rand -hex 8 | tr 'a-f' 'A-F')
    SERIAL_DEC=$((16#$SERIAL))
else
    SERIAL_DEC="$SERIAL"
    SERIAL=$(printf "%X" "$SERIAL_DEC")
fi

print_info "Generating Server Certificate"
print_info "Name (CN): $NAME"
print_info "Country: $COUNTRY"
print_info "Organization: $ORGANIZATION"
print_info "Serial Number: $SERIAL_DEC (0x$SERIAL)"
print_info "Curve: $CURVE"
print_info "Validity: $VALIDITY_DAYS days"
print_info "CA Certificate: $CA_CERT"
print_info "CA Key: $CA_KEY"

# Check if CA files exist
if [[ ! -f "$CA_CERT" ]]; then
    print_error "CA certificate file not found: $CA_CERT"
    exit 1
fi

if [[ ! -f "$CA_KEY" ]]; then
    print_error "CA private key file not found: $CA_KEY"
    exit 1
fi

# Check if output files already exist
if [[ -f "$SERVER_KEY_FILE" ]] || [[ -f "$SERVER_CERT_FILE" ]]; then
    print_warning "Server certificate files already exist:"
    [[ -f "$SERVER_KEY_FILE" ]] && echo "  - $SERVER_KEY_FILE"
    [[ -f "$SERVER_CERT_FILE" ]] && echo "  - $SERVER_CERT_FILE"

    if [[ "${OVERWRITE_YES:-false}" == "true" ]]; then
        print_info "Overwriting existing files (--yes)"
    else
        read -p "Do you want to overwrite them? (y/N): " -r
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_info "Aborted by user"
            exit 0
        fi
    fi
fi

# Create OpenSSL configuration file for the server certificate
cat > "$SERVER_CONFIG_FILE" << EOF
[req]
default_bits = 256
prompt = no
distinguished_name = req_distinguished_name
req_extensions = v3_req
encrypt_key = no

[req_distinguished_name]
C = $COUNTRY
O = $ORGANIZATION
CN = $NAME

[v3_req]
# Basic constraints: this is NOT a CA certificate
basicConstraints = critical,CA:FALSE

# Key usage
keyUsage = critical,digitalSignature,keyEncipherment

# Extended key usage: server and client authentication
# This might be problematic depending how you look at it
extendedKeyUsage = serverAuth, clientAuth

# Subject Key Identifier
subjectKeyIdentifier = hash

EOF

# Add Subject Alternative Names if provided
if [[ ${#IPS[@]} -gt 0 ]] || [[ ${#DOMAINS[@]} -gt 0 ]]; then
    echo "# Subject Alternative Names" >> "$SERVER_CONFIG_FILE"
    echo -n "subjectAltName = " >> "$SERVER_CONFIG_FILE"

    san_entries=()

    # Add IP addresses
    for ip in "${IPS[@]}"; do
        san_entries+=("IP:$ip")
    done

    # Add DNS names
    for domain in "${DOMAINS[@]}"; do
        san_entries+=("DNS:$domain")
    done

    # Join entries with comma
    printf "%s" "${san_entries[0]}" >> "$SERVER_CONFIG_FILE"
    for ((i=1; i<${#san_entries[@]}; i++)); do
        printf ",%s" "${san_entries[i]}" >> "$SERVER_CONFIG_FILE"
    done
    echo >> "$SERVER_CONFIG_FILE"
fi

print_info "Created OpenSSL configuration file: $SERVER_CONFIG_FILE"

# Display SAN information
if [[ ${#IPS[@]} -gt 0 ]]; then
    print_info "IP SANs: ${IPS[*]}"
fi
if [[ ${#DOMAINS[@]} -gt 0 ]]; then
    print_info "DNS SANs: ${DOMAINS[*]}"
fi

# Generate ECDSA private key (P-256 curve)
print_info "Generating ECDSA private key (curve: $CURVE)..."
openssl ecparam -genkey -name "$CURVE" -out "$SERVER_KEY_FILE"

if [[ $? -ne 0 ]]; then
    print_error "Failed to generate ECDSA private key"
    exit 1
fi

# Generate Certificate Signing Request (CSR)
print_info "Generating Certificate Signing Request..."
openssl req -new -key "$SERVER_KEY_FILE" -out "$SERVER_CSR_FILE" -config "$SERVER_CONFIG_FILE"

if [[ $? -ne 0 ]]; then
    print_error "Failed to generate CSR"
    exit 1
fi

# Sign the certificate with the CA
print_info "Signing certificate with CA..."
openssl x509 -req -in "$SERVER_CSR_FILE" \
    -CA "$CA_CERT" \
    -CAkey "$CA_KEY" \
    -out "$SERVER_CERT_FILE" \
    -days "$VALIDITY_DAYS" \
    -set_serial "0x$SERIAL" \
    -sha256 \
    -extensions v3_req \
    -extfile "$SERVER_CONFIG_FILE"

if [[ $? -eq 0 ]]; then
    print_success "Server certificate generated successfully"
else
    print_error "Failed to generate server certificate"
    exit 1
fi

# Clean up temporary files
rm -f "$SERVER_CSR_FILE"
if [[ "${KEEP_CONFIG:-false}" != "true" ]]; then
    rm -f "$SERVER_CONFIG_FILE"
    print_info "Removed temporary configuration files"
fi

# Display certificate information
print_info "Certificate Information:"
echo "----------------------------------------"
openssl x509 -in "$SERVER_CERT_FILE" -text -noout | grep -E "(Subject:|Issuer:|Not Before|Not After|Serial Number|Public-Key:|Signature Algorithm)"

print_info "Certificate Details:"
echo "----------------------------------------"
openssl x509 -in "$SERVER_CERT_FILE" -noout -subject -issuer -dates -serial

# Verify the certificate against the CA
print_info "Verifying certificate against CA..."
if openssl verify -CAfile "$CA_CERT" "$SERVER_CERT_FILE"; then
    print_success "Certificate verification passed"
else
    print_error "Certificate verification failed"
    exit 1
fi

# Display certificate extensions
print_info "Certificate Extensions:"
echo "----------------------------------------"
openssl x509 -in "$SERVER_CERT_FILE" -text -noout | sed -n '/X509v3 extensions:/,/Signature Algorithm:/p' | head -n -1

print_success "Server certificate generation completed!"
print_info "Files created:"
print_info "  Certificate: $SERVER_CERT_FILE"
print_info "  Private Key: $SERVER_KEY_FILE"
print_info ""

# Optional: Generate fingerprints
print_info "Certificate fingerprints:"
echo "  SHA256: $(openssl x509 -in "$SERVER_CERT_FILE" -noout -fingerprint -sha256 | cut -d= -f2)"
echo "  SHA1:   $(openssl x509 -in "$SERVER_CERT_FILE" -noout -fingerprint -sha1 | cut -d= -f2)"

print_info ""
print_info "Key Information:"
echo "  Algorithm: $(openssl x509 -in "$SERVER_CERT_FILE" -noout -text | grep "Public Key Algorithm" | cut -d: -f2 | xargs)"
echo "  Key Size: $(openssl x509 -in "$SERVER_CERT_FILE" -noout -text | grep "ASN1 OID" | cut -d: -f2 | xargs)"
