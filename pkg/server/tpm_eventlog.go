// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// This file is the storage layer for TPM event logs: where a device's logs,
// PCR values and baseline pointer live on disk, and nothing about what any of
// it means. The decisions are in baseline.go.

package server

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/lf-edge/adam/pkg/driver"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/lf-edge/eve-api/go/attest"
)

const (
	tpmEventLogDir           = "tpm-event-log"
	tpmEventLogStateFile     = "tpm-event-log-state.json"
	tpmEventLogStateActive   = "active"
	tpmEventLogStateInactive = "inactive"
	tpmEventLogIncomingFile  = "tpm-event-log-incoming.bin"
	tpmEventLogIncomingPCRs  = "tpm-event-log-incoming-pcrs.yaml"
	// An operator drops this file in to say "the next boot that checks out is
	// the one to trust". It is removed once a baseline is taken from it.
	tpmEventLogTrustRequest = "trust-next-boot"
)

// tpmEventLogState points at the device's current baseline and records how it
// got there. It is persisted next to the baseline files themselves.
type tpmEventLogState struct {
	BaselineFile     string `json:"baselineFile"`
	BaselinePCRsFile string `json:"baselinePcrsFile"`
	// PreviousBaselineFile is the baseline this one replaced, empty on first
	// use. Old baseline files are kept, so this records the lineage.
	PreviousBaselineFile string `json:"previousBaselineFile,omitempty"`
	// Version is the EVE version whose /config origin stamp the device carries.
	// The stamp is written at install time and never changes, so this is set at
	// the first baseline and carried forward across updates. It supplies the
	// device's origin stamp when predicting a later update's PCR 14.
	Version   string    `json:"version,omitempty"`
	LogHash   string    `json:"logHash"`
	State     string    `json:"state"`
	CreatedAt time.Time `json:"createdAt"`
}

// isLog reports whether rawLog is the log this baseline was built from.
func (s *tpmEventLogState) isLog(rawLog []byte) bool {
	return s.LogHash == hashEventLog(rawLog)
}

// hashEventLog is how event logs are identified on disk and compared.
func hashEventLog(rawLog []byte) string {
	sum := sha256.Sum256(rawLog)
	return hex.EncodeToString(sum[:])
}

// eventLogDir returns the tpm-event-log subdirectory for the device, creating it if needed.
func eventLogDir(deviceDir string) (string, error) {
	dir := filepath.Join(deviceDir, tpmEventLogDir)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("failed to create event log dir: %w", err)
	}
	return dir, nil
}

// storeIncomingEventLog records the log and its quoted PCR values as received.
// Both files are overwritten on every attestation, so they always show the most
// recent boot whether or not it was accepted.
func storeIncomingEventLog(deviceDir string, rawLog []byte, pcrValues []*attest.TpmPCRValue) error {
	logDir, err := eventLogDir(deviceDir)
	if err != nil {
		return err
	}

	if err := os.WriteFile(filepath.Join(logDir, tpmEventLogIncomingFile), rawLog, 0600); err != nil {
		return fmt.Errorf("failed to write incoming log: %w", err)
	}
	if err := writePCRValues(filepath.Join(logDir, tpmEventLogIncomingPCRs), pcrValues); err != nil {
		return fmt.Errorf("failed to write incoming PCR values: %w", err)
	}
	return nil
}

// baselineRequested reports whether an operator has asked for the next verified
// boot to become this device's trusted baseline.
func baselineRequested(deviceDir string) (bool, error) {
	_, err := os.Stat(filepath.Join(deviceDir, tpmEventLogDir, tpmEventLogTrustRequest))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// requestBaseline asks for the next verified boot to become the baseline. This
// is the operator's side of the trust gate.
func requestBaseline(deviceDir string) error {
	logDir, err := eventLogDir(deviceDir)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(logDir, tpmEventLogTrustRequest), nil, 0600)
}

// clearBaselineRequest consumes the request, so one request establishes one
// baseline rather than standing open.
func clearBaselineRequest(deviceDir string) error {
	err := os.Remove(filepath.Join(deviceDir, tpmEventLogDir, tpmEventLogTrustRequest))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// loadTrustedBaseline returns the device's active baseline pointer, or nil if it
// has none. A device with no state file has never been baselined, and one whose
// state is not active has had its trust deliberately cleared; neither is an error.
func loadTrustedBaseline(deviceDir string) (*tpmEventLogState, error) {
	state, err := loadEventLogState(deviceDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if state.State != tpmEventLogStateActive {
		return nil, nil
	}
	return state, nil
}

// readBaselineEventLog returns the event log bytes the baseline points at.
func readBaselineEventLog(deviceDir string, state *tpmEventLogState) ([]byte, error) {
	return os.ReadFile(filepath.Join(deviceDir, tpmEventLogDir, state.BaselineFile))
}

// writeEventLogBaseline writes a log and its PCR values as the device's trusted
// baseline and marks it active. Whether the device has earned that is the
// caller's decision, not this function's.
//
// Baseline files are named by date and content hash and are never removed, so
// moving the baseline only writes new files and repoints the state at them.
// previousFile records where the pointer moved from, empty on first use.
//
// The PCR values are stored with the log because they are what it replays
// against; without them a stored baseline cannot be re-verified later.
func writeEventLogBaseline(deviceDir string, rawLog []byte, pcrValues []*attest.TpmPCRValue, previousFile, version string) error {
	logDir, err := eventLogDir(deviceDir)
	if err != nil {
		return err
	}

	hashHex := hashEventLog(rawLog)
	date := time.Now().UTC().Format("20060102-150405")
	baselineFile := fmt.Sprintf("tpm-event-log-%s-%s.bin", date, hashHex)
	baselinePCRsFile := fmt.Sprintf("tpm-event-log-%s-%s-pcrs.yaml", date, hashHex)

	if err := os.WriteFile(filepath.Join(logDir, baselineFile), rawLog, 0600); err != nil {
		return fmt.Errorf("failed to write baseline: %w", err)
	}
	if err := writePCRValues(filepath.Join(logDir, baselinePCRsFile), pcrValues); err != nil {
		return fmt.Errorf("failed to write baseline PCR values: %w", err)
	}

	return saveEventLogState(deviceDir, &tpmEventLogState{
		BaselineFile:         baselineFile,
		BaselinePCRsFile:     baselinePCRsFile,
		PreviousBaselineFile: previousFile,
		LogHash:              hashHex,
		Version:              version,
		State:                tpmEventLogStateActive,
		CreatedAt:            time.Now().UTC(),
	})
}

// loadEventLogState reads the state file from the device directory.
// Returns an error if the file does not exist or cannot be parsed.
func loadEventLogState(deviceDir string) (*tpmEventLogState, error) {
	p := filepath.Join(deviceDir, tpmEventLogDir, tpmEventLogStateFile)
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var state tpmEventLogState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("unmarshal state: %w", err)
	}
	return &state, nil
}

// saveEventLogState writes the state file to the tpm-event-log subdirectory.
func saveEventLogState(deviceDir string, state *tpmEventLogState) error {
	logDir, err := eventLogDir(deviceDir)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}

	// Written whole or not at all. This file names the device's active baseline,
	// and a half-written one reads as a device that has none, which re-arms
	// first-use trust.
	final := filepath.Join(logDir, tpmEventLogStateFile)
	tmp, err := os.CreateTemp(logDir, ".state-*")
	if err != nil {
		return fmt.Errorf("creating a temporary state file: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("writing the state file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("flushing the state file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing the state file: %w", err)
	}
	if err := os.Chmod(tmp.Name(), 0600); err != nil {
		return fmt.Errorf("setting state file permissions: %w", err)
	}
	return os.Rename(tmp.Name(), final)
}

// pcrAlgoNames maps a quoted hash algorithm to the name evepcr's ReadPCRs expects,
// which is the lowercase form tpm2 pcrread emits.
var pcrAlgoNames = map[attest.TpmHashAlgo]string{
	attest.TpmHashAlgo_TPM_HASH_ALGO_SHA1:   "sha1",
	attest.TpmHashAlgo_TPM_HASH_ALGO_SHA256: "sha256",
	attest.TpmHashAlgo_TPM_HASH_ALGO_SHA512: "sha512",
}

// writePCRValues writes the quoted PCR values in the tpm2 pcrread layout:
//
//	sha256:
//	  0: 0xabcd...
//	  1: 0xef01...
//
// This is the format evepcr's ReadPCRs and GetAttestedPCRs parse, so a stored
// event log and its PCR file can be replayed against each other later.
func writePCRValues(path string, pcrValues []*attest.TpmPCRValue) error {
	byAlgo := make(map[string]map[int]string)
	for _, pcr := range pcrValues {
		name, ok := pcrAlgoNames[pcr.GetHashAlgo()]
		if !ok {
			continue
		}
		if byAlgo[name] == nil {
			byAlgo[name] = make(map[int]string)
		}
		byAlgo[name][int(pcr.GetIndex())] = hex.EncodeToString(pcr.GetValue())
	}

	algos := make([]string, 0, len(byAlgo))
	for name := range byAlgo {
		algos = append(algos, name)
	}
	sort.Strings(algos)

	var buf bytes.Buffer
	for _, name := range algos {
		fmt.Fprintf(&buf, "%s:\n", name)
		indexes := make([]int, 0, len(byAlgo[name]))
		for idx := range byAlgo[name] {
			indexes = append(indexes, idx)
		}
		sort.Ints(indexes)
		for _, idx := range indexes {
			fmt.Fprintf(&buf, "  %d: 0x%s\n", idx, byAlgo[name][idx])
		}
	}

	return os.WriteFile(path, buf.Bytes(), 0600)
}

// gunzip decompresses a gzip-compressed byte slice.
func gunzip(data []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

// adoptTemplateForVersion makes the PCR values a device just reported the template
// for the version it now runs.
//
// This runs only after a change has been explained by a prediction. The template
// is not what let the device through, so moving it afterwards does not weaken
// that decision; it means enforcement covers the new release on its own for every
// later attestation, instead of each one needing a prediction.
func adoptTemplateForVersion(manager driver.DeviceManager, version string, quote *attest.ZAttestQuote) error {
	options, err := getGlobalOptions(manager)
	if err != nil {
		return fmt.Errorf("reading global options: %w", err)
	}

	template := extractQuoteAttestTemplate(quote)
	template.EveVersion = version

	replaced := false
	for i, existing := range options.PCRTemplates {
		if existing.EveVersion == version {
			options.PCRTemplates[i] = template
			replaced = true
			break
		}
	}
	if !replaced {
		options.PCRTemplates = append(options.PCRTemplates, template)
	}

	data, err := json.MarshalIndent(options, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding global options: %w", err)
	}
	if err := manager.SetGlobalOptions(data); err != nil {
		return fmt.Errorf("storing global options: %w", err)
	}
	return nil
}

// targetedVersion returns the EVE version this controller last sent the device in
// its configuration, or "" if none was.
//
// A device names the version it is running, and that name only picks which image
// to predict from. Comparing it against what was actually rolled out is what stops
// a move onto some other published release, including an older one.
func targetedVersion(deviceDir string) string {
	raw, err := os.ReadFile(filepath.Join(deviceDir, "config.json"))
	if err != nil {
		return ""
	}
	var config struct {
		BaseOS struct {
			BaseOsVersion string `json:"base_os_version"`
		} `json:"baseos"`
	}
	if err := json.Unmarshal(raw, &config); err != nil {
		return ""
	}
	return config.BaseOS.BaseOsVersion
}
