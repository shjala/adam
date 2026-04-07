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
	"os"
	"path/filepath"
	"time"

	evepcr "eve_pcr_prediction"

	"github.com/lf-edge/adam/pkg/driver"
	"github.com/lf-edge/eve-api/go/attest"
	uuid "github.com/satori/go.uuid"
)

const (
	tpmEventLogStateFile     = "tpm-event-log-state.json"
	tpmEventLogStateActive   = "active"
	tpmEventLogStateInactive = "inactive"
)

// tpmEventLogState is persisted to disk alongside the baseline event log file.
type tpmEventLogState struct {
	BaselineFile string    `json:"baselineFile"`
	LogHash      string    `json:"logHash"`
	State        string    `json:"state"`
	CreatedAt    time.Time `json:"createdAt"`
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

	baselineFile := fmt.Sprintf("tpm-event-log-%s.bin", hashHex)
	if err := os.WriteFile(filepath.Join(deviceDir, baselineFile), rawLog, 0600); err != nil {
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
	p := filepath.Join(deviceDir, tpmEventLogStateFile)
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

// saveEventLogState writes the state file to the device directory.
func saveEventLogState(deviceDir string, state *tpmEventLogState) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}
	p := filepath.Join(deviceDir, tpmEventLogStateFile)
	return os.WriteFile(p, data, 0600)
}
