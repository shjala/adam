// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	evepcr "github.com/zededa/evepcr"

	"github.com/lf-edge/adam/pkg/driver"
	"github.com/lf-edge/eve-api/go/attest"
	uuid "github.com/satori/go.uuid"
)

const (
	tpmEventLogDir           = "tpm-event-log"
	tpmEventLogStateFile     = "tpm-event-log-state.json"
	tpmEventLogStateActive   = "active"
	tpmEventLogStateInactive = "inactive"
	tpmEventLogIncomingFile  = "tpm-event-log-incoming.bin"
)

// tpmEventLogState is persisted to disk alongside the baseline event log file.
type tpmEventLogState struct {
	BaselineFile string    `json:"baselineFile"`
	LogHash      string    `json:"logHash"`
	State        string    `json:"state"`
	CreatedAt    time.Time `json:"createdAt"`
}

// eventLogDir returns the tpm-event-log subdirectory for the device, creating it if needed.
func eventLogDir(deviceDir string) (string, error) {
	dir := filepath.Join(deviceDir, tpmEventLogDir)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("failed to create event log dir: %w", err)
	}
	return dir, nil
}

// updateEventLogBaseline stores the incoming event log as the baseline for the device.
// If no baseline exists, it is created with state inactive.
// If the baseline is inactive and the incoming log has a different hash, the baseline
// file and its pointer are updated, keeping the state as inactive.
// If the baseline is active, it is left untouched.
// State is never set to active here; that transition is done externally.
func updateEventLogBaseline(manager driver.DeviceManager, u uuid.UUID, rawLog []byte) error {
	hash := sha256.Sum256(rawLog)
	hashHex := hex.EncodeToString(hash[:])

	deviceDir := manager.GetDevicePath(u)
	state, err := loadEventLogState(deviceDir)
	if err == nil && state.State == tpmEventLogStateActive {
		return nil
	}
	if err == nil && state.LogHash == hashHex {
		return nil
	}

	logDir, err := eventLogDir(deviceDir)
	if err != nil {
		return err
	}

	date := time.Now().UTC().Format("20060102-150405")
	baselineFile := fmt.Sprintf("tpm-event-log-%s-%s.bin", date, hashHex)
	if err := os.WriteFile(filepath.Join(logDir, baselineFile), rawLog, 0600); err != nil {
		return fmt.Errorf("failed to write baseline: %w", err)
	}

	state = &tpmEventLogState{
		BaselineFile: baselineFile,
		LogHash:      hashHex,
		State:        tpmEventLogStateInactive,
		CreatedAt:    time.Now().UTC(),
	}
	if err := saveEventLogState(deviceDir, state); err != nil {
		return fmt.Errorf("failed to save state file: %w", err)
	}

	return nil
}

// verifyEventLog validates the incoming event log against the attested PCR values.
func verifyEventLog(rawLog []byte, pcrValues []*attest.TpmPCRValue) error {
	pcrMap := make(map[int][]byte)
	for _, pcr := range pcrValues {
		if pcr.GetHashAlgo() == attest.TpmHashAlgo_TPM_HASH_ALGO_SHA256 {
			pcrMap[int(pcr.GetIndex())] = pcr.GetValue()
		}
	}

	if _, err := evepcr.ValidateEventLogFromBytes(rawLog, pcrMap); err != nil {
		return fmt.Errorf("event log replay failed: %w", err)
	}

	return nil
}

// pcrIndicesToVerify is the set of PCR indices we check against predicted values.
var pcrIndicesToVerify = map[int]bool{
	0: true, 1: true, 2: true, 3: true, 4: true,
	5: true, 6: true, 7: true, 8: true, 9: true,
	13: true, 14: true,
}

// verifyPCRPrediction predicts all candidate PCR values from the baseline and
// incoming event logs and checks that every SHA-256 PCR value in pcrValues
// matches one of the predicted candidates. Only PCRs in pcrIndicesToVerify are
// checked. Mismatches are logged but do not cause an error; only failures in
// the prediction itself are returned as errors.
func verifyPCRPrediction(manager driver.DeviceManager, u uuid.UUID, incomingLog []byte, pcrValues []*attest.TpmPCRValue) error {
	predicted, err := predictPCRsFromEventLogs(manager, u, incomingLog)
	if err != nil {
		return err
	}

	for _, pcr := range pcrValues {
		if pcr.GetHashAlgo() != attest.TpmHashAlgo_TPM_HASH_ALGO_SHA256 {
			continue
		}
		idx := int(pcr.GetIndex())
		if !pcrIndicesToVerify[idx] {
			continue
		}
		candidates, ok := predicted[idx]
		if !ok {
			log.Printf("DEBUG [predictPCRs] device=%s: PCR[%d] not in predicted set", u, idx)
			continue
		}
		matched := false
		for _, candidate := range candidates {
			if bytes.Equal(candidate, pcr.GetValue()) {
				matched = true
				break
			}
		}
		if matched {
			log.Printf("DEBUG [predictPCRs] device=%s: PCR[%d] matched a predicted value", u, idx)
		} else {
			log.Printf("DEBUG [predictPCRs] device=%s: PCR[%d] MISMATCH: quoted=%x not in %d predicted candidate(s)",
				u, idx, pcr.GetValue(), len(candidates))
		}
	}

	return nil
}

// predictPCRsFromEventLogs uses the stored baseline event log and the incoming
// raw event log to predict the full set of PCR values the device will have after
// any OS transition.
func predictPCRsFromEventLogs(manager driver.DeviceManager, u uuid.UUID, incomingLog []byte) (map[int][][]byte, error) {
	deviceDir := manager.GetDevicePath(u)

	log.Printf("DEBUG [predictPCRs] device=%s: loading event log state", u)

	state, err := loadEventLogState(deviceDir)
	if err != nil {
		return nil, fmt.Errorf("cannot load event log state: %w", err)
	}
	log.Printf("DEBUG [predictPCRs] device=%s: state=%s baseline=%s logHash=%s",
		u, state.State, state.BaselineFile, state.LogHash)

	baselinePath := filepath.Join(deviceDir, tpmEventLogDir, state.BaselineFile)
	baselineLog, err := os.ReadFile(baselinePath)
	if err != nil {
		return nil, fmt.Errorf("baseline file missing (%s): %w", baselinePath, err)
	}
	log.Printf("DEBUG [predictPCRs] device=%s: loaded baseline (%d bytes) from %s",
		u, len(baselineLog), baselinePath)

	// Write incoming log to a fixed-name file in the event log dir so it can be
	// inspected for debugging. It is overwritten on every attestation.
	logDir, err := eventLogDir(deviceDir)
	if err != nil {
		return nil, err
	}
	incomingPath := filepath.Join(logDir, tpmEventLogIncomingFile)
	if err := os.WriteFile(incomingPath, incomingLog, 0600); err != nil {
		log.Printf("DEBUG [predictPCRs] device=%s: failed to write incoming log for debugging: %v", u, err)
	} else {
		log.Printf("DEBUG [predictPCRs] device=%s: wrote incoming log (%d bytes) to %s",
			u, len(incomingLog), incomingPath)
	}

	log.Printf("DEBUG [predictPCRs] device=%s: calling PredictPCRs(src=%d bytes, dst=%d bytes)",
		u, len(baselineLog), len(incomingLog))
	predicted, err := evepcr.PredictPCRs(baselineLog, incomingLog, nil)
	if err != nil {
		return nil, fmt.Errorf("PredictPCRs failed: %w", err)
	}

	log.Printf("DEBUG [predictPCRs] device=%s: prediction complete, %d PCR indices returned",
		u, len(predicted))
	for idx, vals := range predicted {
		log.Printf("DEBUG [predictPCRs] device=%s: PCR[%d] has %d candidate value(s)", u, idx, len(vals))
		for i, v := range vals {
			log.Printf("DEBUG [predictPCRs] device=%s: PCR[%d][%d] = %x", u, idx, i, v)
		}
	}

	return predicted, nil
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
	return os.WriteFile(filepath.Join(logDir, tpmEventLogStateFile), data, 0600)
}
