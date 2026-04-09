#!/bin/bash
# Generate Root CA Certificate Script
# Generates a root CA certificate with RSA 4096-bit key

set -e

# Configuration (adjust these values as needed)
COUNTRY="${CA_COUNTRY:-US}"
ORGANIZATION="${CA_ORGANIZATION:-ACME Corporation}"
COMMON_NAME="Root CA"
VALIDITY_DAYS=3650  # 10 years
KEY_SIZE=4096
SERIAL_NUMBER=1

# Output files
CA_KEY_FILE="${CA_KEY_FILE:-rootCA.key}"
CA_CERT_FILE="${CA_CERT_FILE:-rootCA.crt}"
CA_CONFIG_FILE="${CA_CONFIG_FILE:-rootCA.conf}"

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

# Check if OpenSSL is installed
if ! command -v openssl &> /dev/null; then
    print_error "OpenSSL is not installed or not in PATH"
    exit 1
fi

print_info "Generating Root CA Certificate"
print_info "Country: $COUNTRY"
print_info "Organization: $ORGANIZATION"
print_info "Common Name: $COMMON_NAME"
print_info "Key Size: $KEY_SIZE bits"
print_info "Validity: $VALIDITY_DAYS days"

# Check if files already exist
if [[ -f "$CA_KEY_FILE" ]] || [[ -f "$CA_CERT_FILE" ]]; then
    print_warning "CA files already exist:"
    [[ -f "$CA_KEY_FILE" ]] && echo "  - $CA_KEY_FILE"
    [[ -f "$CA_CERT_FILE" ]] && echo "  - $CA_CERT_FILE"

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

# Create OpenSSL configuration file for the root CA
cat > "$CA_CONFIG_FILE" << EOF
[req]
default_bits = $KEY_SIZE
prompt = no
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
encrypt_key = no

[req_distinguished_name]
C = $COUNTRY
O = $ORGANIZATION
CN = $COMMON_NAME

[v3_ca]
# Basic constraints: this is a CA certificate
basicConstraints = critical,CA:TRUE,pathlen:2

# Key usage: certificate signing and CRL signing
keyUsage = critical,keyCertSign,cRLSign

# Subject Key Identifier
subjectKeyIdentifier = hash

# Authority Key Identifier
authorityKeyIdentifier = keyid:always,issuer:always

EOF

print_info "Created OpenSSL configuration file: $CA_CONFIG_FILE"

# Generate the root CA private key and certificate in one command
print_info "Generating RSA private key ($KEY_SIZE bits) and root CA certificate..."

# Calculate the not-before time
NOT_BEFORE=$(date -u -d '10 seconds ago' '+%Y%m%d%H%M%SZ')
NOT_AFTER=$(date -u -d "+$VALIDITY_DAYS days" '+%Y%m%d%H%M%SZ')

# Generate private key and self-signed certificate
openssl req -new -x509 \
    -config "$CA_CONFIG_FILE" \
    -keyout "$CA_KEY_FILE" \
    -out "$CA_CERT_FILE" \
    -days "$VALIDITY_DAYS" \
    -set_serial "$SERIAL_NUMBER" \
    -sha256

if [[ $? -eq 0 ]]; then
    print_success "Root CA certificate and private key generated successfully"
else
    print_error "Failed to generate root CA certificate"
    exit 1
fi

# Display certificate information
print_info "Certificate Information:"
echo "----------------------------------------"
openssl x509 -in "$CA_CERT_FILE" -text -noout | grep -E "(Subject:|Issuer:|Not Before|Not After|Serial Number|Public-Key:|Signature Algorithm)"

print_info "Certificate Details:"
echo "----------------------------------------"
openssl x509 -in "$CA_CERT_FILE" -noout -subject -issuer -dates -serial

# Verify the certificate
print_info "Verifying certificate..."
if openssl x509 -in "$CA_CERT_FILE" -noout -verify; then
    print_success "Certificate verification passed"
else
    print_error "Certificate verification failed"
    exit 1
fi

# Display certificate extensions
print_info "Certificate Extensions:"
echo "----------------------------------------"
openssl x509 -in "$CA_CERT_FILE" -text -noout | sed -n '/X509v3 extensions:/,/Signature Algorithm:/p' | head -n -1

# Cleanup configuration file (optional)
if [[ "${KEEP_CONFIG:-false}" != "true" ]]; then
    rm -f "$CA_CONFIG_FILE"
fi

print_success "Root CA generation completed!"

# Optional: Generate fingerprints
print_info "Certificate fingerprints:"
echo "  SHA256: $(openssl x509 -in "$CA_CERT_FILE" -noout -fingerprint -sha256 | cut -d= -f2)"
echo "  SHA1:   $(openssl x509 -in "$CA_CERT_FILE" -noout -fingerprint -sha1 | cut -d= -f2)"
