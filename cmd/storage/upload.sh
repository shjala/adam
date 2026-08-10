#!/bin/bash
#
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# upload.sh - upload an EVE rootfs image to the demo storage service, and
#             optionally capture a reference measurement by booting it.
#
# Usage: ./upload.sh [options] <rootfs.img> [version]
#
# Uploads an EVE rootfs image to the storage service, and optionally captures a
# reference measurement for it.
#
# A reference measurement is the TCG event log and PCR values a machine produces
# when it boots this exact image. A controller needs one to work out what a device
# running the image should report, without asking the device.
#
# Capturing one boots EVE's own live disk for the release under QEMU with a fresh
# software TPM, drives the serial console to read the log and the PCR values out of
# the running system, and checks the log against a digest the guest computes for
# itself. The storage service then replays the log against those PCR values before
# it publishes the measurement, so a garbled capture is refused rather than served.
#
# Options:
#   --reference              Capture a reference measurement by booting the image.
#   --firmware <dir>         OVMF_CODE.fd and OVMF_VARS.fd. Defaults to the
#                            firmware/ directory of the image's own build, which is
#                            the only one its bootloader is known to work with.
#   --live-image <live.raw>  EVE's live disk for the reference boot. Defaults to
#                            live.raw beside the rootfs image, where a release
#                            build leaves it.
#   --mem <MB>               Guest memory, default 4096.
#   --keep-vm                Leave the reference VM running, for debugging.
#
# The version defaults to the eve_version file beside the image.
#
# STORAGE_URL selects the service, default http://localhost:8888.

set -euo pipefail


STORAGE_URL="${STORAGE_URL:-http://localhost:8888}"

WANT_REFERENCE=false
FIRMWARE_DIR=""
MEM=4096
KEEP_VM=false
LIVE_IMAGE=""
IMAGE=""
VERSION=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --reference) WANT_REFERENCE=true; shift ;;
        --firmware)  FIRMWARE_DIR="$2"; shift 2 ;;
        --mem)       MEM="$2"; shift 2 ;;
        --keep-vm)   KEEP_VM=true; shift ;;
        --live-image) LIVE_IMAGE="$2"; shift 2 ;;
        -*)          echo "[ERROR] Unknown option: $1" >&2; exit 1 ;;
        *)
            if [[ -z "$IMAGE" ]]; then IMAGE="$1"; else VERSION="$1"; fi
            shift ;;
    esac
done

log_info()  { echo "[INFO]  $*" >&2; }
log_error() { echo "[ERROR] $*" >&2; }
fail()      { log_error "$*"; exit 1; }

[[ -n "$IMAGE" ]] || {
    echo "Usage: $0 [--reference] <rootfs.img> [version]" >&2
    exit 1
}
[[ -f "$IMAGE" ]] || fail "No such file: $IMAGE"
command -v curl &>/dev/null || fail "curl is required"

IMAGE="$(cd "$(dirname "$IMAGE")" && pwd)/$(basename "$IMAGE")"
NAME=$(basename "$IMAGE")

# A version has to identify the build. EVE's artifact is always called
# rootfs.img, so stripping the extension yields the useless string "rootfs"; the
# version EVE wrote beside it is the real one.
if [[ -z "$VERSION" ]]; then
    eve_version_file="$(dirname "$IMAGE")/eve_version"
    if [[ -f "$eve_version_file" ]]; then
        VERSION=$(tr -d '\r\n' < "$eve_version_file")
    fi
fi
[[ -n "$VERSION" ]] ||
    fail "no version given, and no eve_version file beside $IMAGE to take one from"

# ── upload the image ──────────────────────────────────────────────────────────

log_info "Uploading $IMAGE ($(du -h "$IMAGE" | cut -f1)) as version $VERSION"

# -T streams the file instead of buffering it, which matters for rootfs images
RESPONSE=$(curl -sS -f -X POST -T "$IMAGE" \
    -H "Content-Type: application/octet-stream" \
    "$STORAGE_URL/api/v1/images?name=$NAME&version=$VERSION" 2>&1) ||
    fail "Upload failed: $RESPONSE"

IMAGE_ID=$(echo "$RESPONSE" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')
[[ -n "$IMAGE_ID" ]] || fail "Could not read the image id from: $RESPONSE"
log_info "Stored as image $IMAGE_ID"

if ! $WANT_REFERENCE; then
    echo "$RESPONSE"
    exit 0
fi

# ── prepare the reference boot ────────────────────────────────────────────────

for t in qemu-system-x86_64 qemu-img swtpm socat base64; do
    command -v "$t" &>/dev/null || fail "Required tool not found: $t"
done

# EVE ships its own OVMF and boots on it. The firmware measures PCR 0-7 and the
# GPT into PCR 5, so a different build measures differently. The firmware comes
# from the image's own build directory (or --firmware); the host's /usr/share/OVMF
# is never used. Each EVE release ships its own OVMF, and its bootloader is only
# known to work with that one; a mismatched build can hang before Linux starts.
if [[ -z "$FIRMWARE_DIR" ]]; then
    FIRMWARE_DIR="$(dirname "$(readlink -f "$IMAGE")")/firmware"
fi
[[ -f "$FIRMWARE_DIR/OVMF_CODE.fd" && -f "$FIRMWARE_DIR/OVMF_VARS.fd" ]] ||
    fail "no OVMF_CODE.fd/OVMF_VARS.fd in $FIRMWARE_DIR; pass --firmware <dir>"

log_info "Using EVE firmware from $FIRMWARE_DIR"

WORK=$(mktemp -d)
REF_LOG="$WORK/reference-eventlog.bin"
REF_PCRS="$WORK/reference-pcrs.txt"
REF_MC="$WORK/reference-measureconfig.bin"
SWTPM_DIR="$WORK/swtpm"
CONSOLE_SOCK="$WORK/console.sock"
CONSOLE_OUT="$WORK/console.log"
CONSOLE_IN="$WORK/console.in"
QEMU_PID_FILE="$WORK/qemu.pid"
QEMU_LOG="$WORK/qemu.log"

# EVE's serial console comes up with an automatic root login, so it is the way
# in: no SSH, no key, no network. socat bridges it to a pair of files we can
# write commands into and read output from.
# A serial console submits a line with CRLF. With only one of the two the text
# is echoed back but never runs.
# Writes a line to the guest.
#
# Bounded: fd 3 is a pipe into the guest's console, and a guest that stops draining
# its UART would otherwise block here forever, past every console_wait timeout,
# with no diagnostic. Children inherit fd 3, so the timeout applies to the write.
console_send() {
    timeout 30 sh -c 'printf "%s\r\n" "$1" >&3' _ "$*" ||
        fail "the guest stopped accepting console input"
}

# Waits until needle has appeared at least `count` times, default once. The
# count matters when a command is retried: the marker from an earlier attempt is
# still in the log, so waiting for the marker to merely exist returns at once
# and the reply that follows is read before it arrives.
console_wait() {
    local needle="$1" timeout="$2" want="${3:-1}" elapsed=0 count
    while true; do
        # grep -c prints the count and exits non-zero when it is zero, so the
        # status is ignored and the number is what matters.
        count=$(grep -c "$needle" "$CONSOLE_OUT" 2>/dev/null) || true
        case "$count" in
            ''|*[!0-9]*) count=0 ;;
        esac
        if [ "$count" -ge "$want" ]; then
            return 0
        fi
        sleep 2
        elapsed=$((elapsed + 2))
        if [ "$elapsed" -ge "$timeout" ]; then
            return 1
        fi
        if [ $((elapsed % 60)) -eq 0 ]; then
            log_info "  still waiting for '$needle' ($count/$want)... (${elapsed}s)"
        fi
    done
}

# Pulls whatever the guest printed between two markers. The command line itself
# is echoed back by the console, so the marker appears twice; taking the text
# after the last start marker skips that echo.
# Returns the text between the last complete pair of markers. A command that is
# retried leaves several pairs in the log, and the interesting one is the last.
console_extract() {
    local start="$1" end="$2"
    tr -d '\000\r' < "$CONSOLE_OUT" |
        awk -v s="$start" -v e="$end" '
            $0 ~ s { buf = ""; collecting = 1; next }
            $0 ~ e { if (collecting) { last = buf; collecting = 0 } ; next }
            collecting { buf = buf $0 "\n" }
            END { printf "%s", last }'
}

CAPTURED=false

cleanup() {
    # Idempotent: EXIT can be reached more than once, and tearing down twice
    # produces confusing errors about processes that are already gone.
    [ -n "${CLEANED:-}" ] && return 0
    CLEANED=1

    if $KEEP_VM; then
        log_info "Leaving the reference VM running (state in $WORK)"
        return
    fi
    exec 3>&- 2>/dev/null || true
    # Everything this script started, in the order that lets each shut down
    # cleanly, with a fallback for anything that ignores SIGTERM.
    for pidfile in "$QEMU_PID_FILE" "$SWTPM_DIR/swtpm.pid"; do
        [[ -f "$pidfile" ]] || continue
        pid=$(cat "$pidfile" 2>/dev/null) || continue
        [[ -n "$pid" ]] || continue
        kill "$pid" 2>/dev/null || true
    done
    [[ -n "${SOCAT_PID:-}" ]] && kill "$SOCAT_PID" 2>/dev/null || true
    sleep 2
    for pidfile in "$QEMU_PID_FILE" "$SWTPM_DIR/swtpm.pid"; do
        [[ -f "$pidfile" ]] || continue
        pid=$(cat "$pidfile" 2>/dev/null) || continue
        [[ -n "$pid" ]] && kill -9 "$pid" 2>/dev/null || true
    done
    [[ -n "${SOCAT_PID:-}" ]] && kill -9 "$SOCAT_PID" 2>/dev/null || true
    # Keep the disk, console transcript and logs when something went wrong;
    # they are the only record of why.
    if $CAPTURED; then
        rm -rf "$WORK"
    else
        log_error "Reference capture failed. Working state kept at $WORK"
        log_error "  console transcript: $WORK/console.log"
        log_error "  qemu log:           $WORK/qemu.log"
    fi
}
trap cleanup EXIT
# A signal only needs to leave; the EXIT trap does the teardown. Running cleanup
# from the handler as well tears down twice, and a handler that returns instead of
# exiting lets the script carry on against what it has just killed.
trap 'exit 130' INT
trap 'exit 143' TERM

# The reference boot uses EVE's own live disk, not a disk assembled here.
#
# An assembled disk gets the ESP wrong, and the ESP is measured. A real EVE disk
# has an installer-written grub.cfg that calls gptprio.next to pick the active
# partition; a hand-written one that hardcodes the partition produces a different
# command sequence in PCR 8, a different file hash in PCR 9, and a different
# bootloader in PCR 4. Booting live.raw gives the same ESP, the same two-stage
# handover and the same partition layout a device has.
#
# In CI this is what a release build already produces next to rootfs.img, so the
# capture needs no disk tooling of its own.
if [[ -z "$LIVE_IMAGE" ]]; then
    # dist/<arch>/current/installer/rootfs.img -> dist/<arch>/current/live.raw
    guess="$(dirname "$(dirname "$(readlink -f "$IMAGE")")")/live.raw"
    [[ -f "$guess" ]] && LIVE_IMAGE="$guess"
fi
[[ -n "$LIVE_IMAGE" && -f "$LIVE_IMAGE" ]] ||
    fail "--reference needs EVE's live disk; pass --live-image <live.raw> (a release build writes it beside installer/)"

# The boot writes to the disk (partition state, /persist), so it cannot run
# against the release artifact directly. A qcow2 overlay keeps those writes
# separate without copying several gigabytes per capture.
DISK="$WORK/disk.qcow2"
log_info "Reference boot uses EVE's live disk: $LIVE_IMAGE"
qemu-img create -f qcow2 -b "$(readlink -f "$LIVE_IMAGE")" -F raw "$DISK" >/dev/null 2>&1 ||
    fail "could not create an overlay on $LIVE_IMAGE"

# A fresh vTPM, so the captured measurement describes this image and nothing
# that ran before it.
mkdir -p "$SWTPM_DIR"
swtpm socket --daemon --terminate \
    --tpmstate dir="$SWTPM_DIR" \
    --ctrl type=unixio,path="$SWTPM_DIR/swtpm-sock" \
    --log file="$SWTPM_DIR/swtpm.log",level=1 \
    --pid file="$SWTPM_DIR/swtpm.pid" \
    --tpm2 || fail "could not start swtpm"

# OVMF_VARS is written by the guest, so work on a copy and leave the original
# alone. Booting the same image twice then starts from identical firmware state.
cp "$FIRMWARE_DIR/OVMF_VARS.fd" "$WORK/OVMF_VARS.fd"

ACCEL_OPTS="-machine q35 -cpu SandyBridge"
if [[ -r /dev/kvm ]]; then
    ACCEL_OPTS="-machine q35,accel=kvm,usb=off,dump-guest-core=off -cpu host,invtsc=on,kvmclock=off"
else
    log_info "No /dev/kvm, falling back to emulation (slower)"
fi

log_info "Booting the reference disk"
# shellcheck disable=SC2086
qemu-system-x86_64 \
    -display none \
    -m "$MEM" -smp 4 \
    $ACCEL_OPTS \
    -drive if=pflash,format=raw,unit=0,readonly=on,file="$FIRMWARE_DIR/OVMF_CODE.fd" \
    -drive if=pflash,format=raw,unit=1,file="$WORK/OVMF_VARS.fd" \
    -pidfile "$QEMU_PID_FILE" \
    -serial "unix:$CONSOLE_SOCK,server,nowait" \
    -global ICH9-LPC.noreboot=false \
    -rtc base=utc,clock=rt \
    -netdev "user,id=eth0,net=192.168.1.0/24,dhcpstart=192.168.1.10" \
    -device virtio-net-pci,netdev=eth0,romfile="" \
    -chardev "socket,id=chrtpm,path=$SWTPM_DIR/swtpm-sock" \
    -tpmdev emulator,id=tpm0,chardev=chrtpm \
    -device tpm-tis,tpmdev=tpm0 \
    -drive "file=$DISK,format=qcow2,id=uefi-disk" \
    > "$QEMU_LOG" 2>&1 &

# ── capture ───────────────────────────────────────────────────────────────────

# QEMU creates the console socket as it starts, so wait for it rather than
# racing it.
for _ in $(seq 1 60); do
    [[ -S "$CONSOLE_SOCK" ]] && break
    sleep 1
done
[[ -S "$CONSOLE_SOCK" ]] || {
    log_error "QEMU never created the console socket. qemu log:"
    tail -20 "$QEMU_LOG" >&2
    fail "giving up"
}

# Bridge the guest console. The FIFO is held open on fd 3 so the connection
# survives between commands.
mkfifo "$CONSOLE_IN"
socat "UNIX-CONNECT:$CONSOLE_SOCK" - < "$CONSOLE_IN" > "$CONSOLE_OUT" 2>&1 &
SOCAT_PID=$!
exec 3> "$CONSOLE_IN"

# Either the guest starts talking or socat reports it could not attach. Wait for
# whichever comes first rather than guessing how long the connect takes.
for _ in $(seq 1 30); do
    grep -q "E connect" "$CONSOLE_OUT" 2>/dev/null &&
        fail "socat could not attach to the console: $(head -1 "$CONSOLE_OUT")"
    kill -0 "$SOCAT_PID" 2>/dev/null || fail "socat exited: $(head -1 "$CONSOLE_OUT")"
    [ -s "$CONSOLE_OUT" ] && break
    sleep 1
done

# boot_to_shell waits for EVE's boot banner and then probes until the console
# runs a command. occurrence is which banner to wait for, so it works across a
# reboot where the banner reappears in the accumulating log. echoCmd/needle carry
# the shell probe: the marker is split in echoCmd so the echoed command line
# cannot match needle, which would mistake an echo for a working shell.
boot_to_shell() {
    local occurrence="$1" echoCmd="$2" needle="$3"
    log_info "Waiting for EVE to finish booting (auto-login on the serial console)..."
    console_wait "Edge Virtualization Engine" 900 "$occurrence" ||
        { log_error "EVE did not boot. Last console output:"; tail -20 "$CONSOLE_OUT" >&2; fail "giving up"; }

    log_info "Probing for a shell that runs commands..."
    local shell_up=false
    local _
    for _ in $(seq 1 40); do
        console_send ""
        console_send "$echoCmd"
        if console_wait "$needle" 10; then
            shell_up=true
            break
        fi
    done
    $shell_up || {
        log_error "the console never ran a command. Last output:"
        tr -d '\000\r' < "$CONSOLE_OUT" | tail -15 >&2
        fail "giving up"
    }
    log_info "Console shell is up"
}

boot_to_shell 1 "echo REA''DY_$$" "READY_$$"

# Capture a production-like /config: EVE creates /config/device.cert.pem on boot
# (tpmmgr, from the TPM), but measure-config runs before that on the first boot,
# so its log would record the certificate absent. A real device is baselined
# after a reboot, with the certificate present. Wait for the certificate, then
# reboot once so the measure-config log captured below matches a real device.
log_info "Waiting for the device certificate so /config matches a real device..."
cert_ready=false
for _ in $(seq 1 60); do
    console_send "test -f /config/device.cert.pem && echo DEVCERT''_OK_$$"
    if console_wait "DEVCERT_OK_$$" 5; then
        cert_ready=true
        break
    fi
done
$cert_ready || fail "the reference never created /config/device.cert.pem"

log_info "Rebooting the reference so measure-config records the steady state..."
banner_count=$(grep -c "Edge Virtualization Engine" "$CONSOLE_OUT" 2>/dev/null) || true
case "$banner_count" in ''|*[!0-9]*) banner_count=0 ;; esac
console_send "reboot"
boot_to_shell "$((banner_count + 1))" "echo REB''OOT_READY_$$" "REBOOT_READY_$$"

log_info "Reading the TCG event log over the console..."
console_send "echo ELS''TART; base64 /sys/kernel/security/tpm0/binary_bios_measurements; echo ELE''ND"
console_wait "ELEND" 300 || fail "the event log never came back over the console"
# EVE keeps logging to this console while the transfer runs, so a status line
# can land in the middle of the base64. Keep only lines that are entirely
# base64, which drops any interleaved log output.
console_extract "ELSTART" "ELEND" |
    grep -E '^[A-Za-z0-9+/=]+$' | tr -d '\n' | base64 -d > "$REF_LOG" 2>/dev/null ||
    fail "could not decode the event log from the console"
[[ -s "$REF_LOG" ]] || fail "the reference VM produced an empty event log"

# The log crosses a console that EVE is logging to at the same time, so ask the
# guest what it should hash to and check. A replay against the captured PCRs
# catches damage to the log's structure, but not a flipped byte inside an event's
# data: the replay extends the digests the log carries, so the data can rot
# without the digests noticing, and the prediction reads that data.
console_send "echo SUMS''TART; sha256sum /sys/kernel/security/tpm0/binary_bios_measurements; echo SUME''ND"
console_wait "SUMEND" 60 || fail "the guest never reported the event log digest"
guest_sum=$(console_extract "SUMSTART" "SUMEND" | grep -oE '^[0-9a-f]{64}' | head -1)
local_sum=$(sha256sum "$REF_LOG" | cut -d' ' -f1)
[[ -n "$guest_sum" ]] || fail "could not read the event log digest from the guest"
[[ "$guest_sum" == "$local_sum" ]] ||
    fail "event log was corrupted in transit: guest says $guest_sum, received $local_sum"
log_info "Event log digest matches the guest: ${local_sum:0:16}..."

log_info "Reading PCR values from the vtpm container..."
# The console is usable before EVE finishes starting: `eve exec` needs
# containerd, and the vtpm container has to be running before tpm2 exists
# inside it. How long that takes varies by release, so retry rather than
# assuming the shell being up means the container is.
#
# tpm2-tools ships as a single multi-call binary in EVE's vtpm container,
# so it is "tpm2 pcrread", not "tpm2_pcrread".
pcrs_read=false
for attempt in $(seq 1 20); do
    # The marker carries the attempt number, so waiting for it cannot be satisfied
    # by an earlier attempt's output and a lost marker desynchronises nothing.
    #
    # The name is split in the command that is sent and whole in what is matched:
    # the guest echoes the command line back over the same console, and a marker
    # that survived that echo would match the echo instead of the reply.
    start="PCRSTART$attempt"
    end="PCREND$attempt"
    console_send "echo PCRS''TART$attempt; eve exec vtpm tpm2 pcrread sha256; echo PCRE''ND$attempt"
    console_wait "$end" 60 || continue
    # containerd writes deprecation warnings to the same console; keep only the
    # algorithm header and the "<index> : 0x<hex>" lines.
    console_extract "$start" "$end" |
        grep -E '^[[:space:]]*(sha[0-9]+:|[0-9]+[[:space:]]*:[[:space:]]*0[xX])' > "$REF_PCRS" || true
    # The heading alone proves nothing; count the value lines. A transcript that
    # lost them to interleaved logging still carries the heading.
    if grep -q "sha256:" "$REF_PCRS" &&
       [ "$(grep -cE '^[[:space:]]*[0-9]+[[:space:]]*:[[:space:]]*0[xX][0-9a-fA-F]{64}' "$REF_PCRS")" -ge 8 ]; then
        pcrs_read=true
        break
    fi
    [ "$attempt" -eq 1 ] && log_info "  vtpm container not ready yet, retrying..."
    sleep 10
done
$pcrs_read || {
    log_error "tpm2 pcrread never produced PCR values. Last console output:"
    console_extract "$start" "$end" | tail -5 >&2
    fail "could not read PCR values"
}

log_info "Captured a $(stat -c%s "$REF_LOG") byte event log and $(grep -cE '^[[:space:]]*[0-9]+[[:space:]]*:' "$REF_PCRS") PCR values"

# PCR 14 is not in the firmware log. EVE's measure-config service writes its own
# event log describing the /config partition, and PCR 14 is replayed from it. It
# has run by now, because reading PCRs above already needed the vtpm container up.
log_info "Reading the measure-config event log over the console..."
console_send "echo MCS''TART; base64 /persist/status/measurefs_tpm_event_log; echo MCE''ND"
console_wait "MCEND" 120 || fail "the measure-config event log never came back over the console"
console_extract "MCSTART" "MCEND" |
    grep -E '^[A-Za-z0-9+/=]+$' | tr -d '\n' | base64 -d > "$REF_MC" 2>/dev/null ||
    fail "could not decode the measure-config event log from the console"
[[ -s "$REF_MC" ]] || fail "the reference VM produced an empty measure-config event log"

# Same console, same interleaving risk as the firmware log, so check the digest.
console_send "echo MCSUMS''TART; sha256sum /persist/status/measurefs_tpm_event_log; echo MCSUME''ND"
console_wait "MCSUMEND" 60 || fail "the guest never reported the measure-config log digest"
mc_guest_sum=$(console_extract "MCSUMSTART" "MCSUMEND" | grep -oE '^[0-9a-f]{64}' | head -1)
mc_local_sum=$(sha256sum "$REF_MC" | cut -d' ' -f1)
[[ -n "$mc_guest_sum" ]] || fail "could not read the measure-config log digest from the guest"
[[ "$mc_guest_sum" == "$mc_local_sum" ]] ||
    fail "measure-config log was corrupted in transit: guest says $mc_guest_sum, received $mc_local_sum"
log_info "Measure-config log digest matches the guest: ${mc_local_sum:0:16}..."

log_info "Attaching the reference measurement to image $IMAGE_ID"
curl -sS -f -X POST --data-binary "@$REF_LOG" \
    -H "Content-Type: application/octet-stream" \
    "$STORAGE_URL/api/v1/images/$IMAGE_ID/reference/eventlog" >/dev/null ||
    fail "could not attach the reference event log"

curl -sS -f -X POST --data-binary "@$REF_MC" \
    -H "Content-Type: application/octet-stream" \
    "$STORAGE_URL/api/v1/images/$IMAGE_ID/reference/measureconfig" >/dev/null ||
    fail "could not attach the reference measure-config log"

# The PCR values go last: the service publishes the measurement only when all
# three artifacts are present, and that is where it replays both logs against
# these values.
curl -sS -f -X POST --data-binary "@$REF_PCRS" \
    -H "Content-Type: text/plain" \
    "$STORAGE_URL/api/v1/images/$IMAGE_ID/reference/pcrs" >/dev/null ||
    fail "could not attach the reference PCR values"

# Only now is the working state safe to remove: all three artifacts are stored,
# and accepting the last one is where the service replays the logs against them.
CAPTURED=true

# The image metadata is this script's output. It is read back from the service
# rather than echoed from what was sent, so hasReference reflects what the service
# actually accepted, including its replay of the log against the PCR values.
curl -sS -f "$STORAGE_URL/api/v1/images/$IMAGE_ID" ||
    fail "could not read back the metadata for image $IMAGE_ID"
