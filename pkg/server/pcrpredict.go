// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/google/go-attestation/attest"
	zattest "github.com/lf-edge/eve-api/go/attest"
	uuid "github.com/satori/go.uuid"
	epp "github.com/shjala/eve-pcr-prediction"
	"gopkg.in/yaml.v2"
)

func findEveGrubStageOne(eventlog *attest.EventLog) (int, error) {
	for i, event := range eventlog.Events(attest.HashSHA256) {
		if event.Type.String() == "EV_EFI_BOOT_SERVICES_APPLICATION" {
			if i+1 < len(eventlog.Events(epp.DefaultAlgo)) {
				nextEvent := eventlog.Events(attest.HashSHA256)[i+1]
				if nextEvent.Type.String() == "EV_IPL" && bytes.Contains(nextEvent.Data, []byte("gptprio.next")) {
					return i, nil
				}
			}
		}
	}
	return -1, fmt.Errorf("EVE GRUB Stage 1 event not found")
}

// Because the predictor overrides events, we need to apply a transformation
// function to fix grub stage one so it matches what is in the device (currently
// grub stage one can not be updated, so it shouln't change),
// first find EV_EFI_BOOT_SERVICES_APPLICATION event and if the event after
// it is a EV_IPL "gptprio.next", then replace the it with the one from old
// event log so it matches what is in the device.
func fixEveGrubStageOne(originalOld *attest.EventLog, old *attest.EventLog, new *attest.EventLog) error {
	// get the stage one data from original event log
	oldStageOneIndex, err := findEveGrubStageOne(originalOld)
	if err != nil {
		return fmt.Errorf("error finding EVE GRUB Stage 1 event: %v", err)
	}
	oldData, oldDigest, err := originalOld.GetEventData(oldStageOneIndex)
	if err != nil {
		return fmt.Errorf("error getting old EVE GRUB Stage 1 event data: %v", err)
	}
	// replace the data so the prediction will match the what is expected
	err = old.SetEventData(oldStageOneIndex, oldData, oldDigest)
	if err != nil {
		return fmt.Errorf("error setting old EVE GRUB Stage 1 event data: %v", err)
	}

	return nil
}

func pcrExpected(m map[int][][]byte, key int, val []byte) bool {
	slices, ok := m[key]
	if !ok {
		return false
	}

	for _, b := range slices {
		if bytes.Equal(b, val) {
			return true
		}
	}
	return false
}

func PcrsMatchExpectedValues(expectedPCRs map[int][][]byte, baselinePcrYml, currentPcrsYml string) error {
	attestPCRs, err := epp.GetAttestedPCRs(currentPcrsYml)
	if err != nil {
		return fmt.Errorf("GetAttestedPCRs failed: %v", err)
	}
	reportedPCRs := map[int][]byte{}
	for _, pcr := range attestPCRs {
		reportedPCRs[pcr.Index] = pcr.Digest
	}

	// get the old pcrs too, we expect some of them to match
	oldPcrsValues, err := epp.GetAttestedPCRs(baselinePcrYml)
	if err != nil {
		return fmt.Errorf("GetAttestedPCRs failed: %v", err)
	}
	oldPCRs := map[int][]byte{}
	for _, pcr := range oldPcrsValues {
		oldPCRs[pcr.Index] = pcr.Digest
	}

	for index, _ := range expectedPCRs {
		switch index {
		case 0, 1, 2, 3, 4, 6, 7, 8, 9, 13:
			if pcrExpected(expectedPCRs, index, reportedPCRs[index]) {
				log.Printf("[PASS] PCR %d value %s matches expected", index, hex.EncodeToString(reportedPCRs[index]))
			} else {
				log.Printf("[ERROR!!!] PCR %d value %s does not match expected", index, hex.EncodeToString(reportedPCRs[index]))
			}
		case 5:
			// we have a special case for PCR 5, just print it for now
			log.Printf("[SPECIAL] PCR 5 value: %s", hex.EncodeToString(reportedPCRs[index]))
		case 14:
			// PCR 14 must match the exact value of the previously reported known good value,
			// just print it for now
			if bytes.Equal(oldPCRs[14], reportedPCRs[14]) {
				log.Printf("[PASS] PCR 14 value %s matches old known good value", hex.EncodeToString(reportedPCRs[index]))
			} else {
				log.Printf("[ERROR!!!] PCR 14 value %s does not match old known good value", hex.EncodeToString(reportedPCRs[index]))
			}
		default:
			// every other PCR must match the old value
			if bytes.Equal(oldPCRs[index], reportedPCRs[index]) {
				log.Printf("[PASS] PCR %d value %s matches old known good value", index, hex.EncodeToString(reportedPCRs[index]))
			} else {
				log.Printf("[ERROR!!!] PCR %d value %s does not match old known good value", index, hex.EncodeToString(reportedPCRs[index]))
			}
			continue
		}
	}

	return nil
}

func savePCRsToYAML(quote *zattest.ZAttestQuote, path string) error {
	pcrData := epp.PcrYml{
		HashAlgo: make(map[string]map[int]string),
	}

	// Group PCRs by hash algorithm
	for _, pcr := range quote.GetPcrValues() {
		var hashAlgoStr string
		switch pcr.GetHashAlgo() {
		case zattest.TpmHashAlgo_TPM_HASH_ALGO_SHA256:
			hashAlgoStr = "sha256"
		case zattest.TpmHashAlgo_TPM_HASH_ALGO_SHA1:
			hashAlgoStr = "sha1"
		default:
			hashAlgoStr = "unknown"
		}

		if pcrData.HashAlgo[hashAlgoStr] == nil {
			pcrData.HashAlgo[hashAlgoStr] = make(map[int]string)
		}

		pcrData.HashAlgo[hashAlgoStr][int(pcr.GetIndex())] = "0x" + strings.ToUpper(hex.EncodeToString(pcr.GetValue()))
	}

	// Marshal to YAML
	yamlData, err := yaml.Marshal(pcrData)
	if err != nil {
		return fmt.Errorf("failed to marshal PCR data to YAML: %v", err)
	}

	// Fix the YAML output to ensure all hex values are unquoted
	yamlStr := string(yamlData)
	yamlStr = strings.ReplaceAll(yamlStr, "\"", "")
	err = os.WriteFile(path, []byte(yamlStr), 0644)
	if err != nil {
		return fmt.Errorf("failed to write PCR YAML file: %v", err)
	}

	return nil
}

func ValidateEvePcrFive(oldEventLog, currEventLog string) error {
	// PCR 5 can vary based on the hard disk configuration, but it also shouldn't change
	// much except attribues of IMAGA/IMGB partition.
	oldTable, err := epp.GetGptPartitionTable(oldEventLog, nil, nil, nil, false)
	if err != nil {
		return fmt.Errorf("GetPartitionTable failed: %v", err)
	}

	currTable, err := epp.GetGptPartitionTable(currEventLog, nil, nil, nil, false)
	if err != nil {
		return fmt.Errorf("GetPartitionTable failed: %v", err)
	}

	if len(oldTable) == 0 || len(currTable) == 0 {
		return fmt.Errorf("partition table is empty")
	}

	if len(oldTable) != len(currTable) {
		return fmt.Errorf("partition table length mismatch: old %d, new %d", len(oldTable), len(currTable))
	}

	for i := range len(oldTable) {
		oldEntry := oldTable[i].Entry
		oldName := oldTable[i].Name
		newEntry := currTable[i].Entry
		newName := currTable[i].Name

		if oldName != newName {
			return fmt.Errorf("partition %d name mismatch: old %s, new %s", i, oldName, newName)
		}

		if oldEntry.PartitionTypeGUID != newEntry.PartitionTypeGUID {
			return fmt.Errorf("partition %d type GUID mismatch: old %s, new %s", i,
				oldEntry.PartitionTypeGUID, newEntry.PartitionTypeGUID)
		}
		if oldEntry.UniquePartitionGUID != newEntry.UniquePartitionGUID {
			return fmt.Errorf("partition %d unique GUID mismatch: old %s, new %s", i,
				oldEntry.UniquePartitionGUID, newEntry.UniquePartitionGUID)
		}
		if oldEntry.StartingLBA != newEntry.StartingLBA {
			return fmt.Errorf("partition %d starting LBA mismatch: old %d, new %d", i,
				oldEntry.StartingLBA, newEntry.StartingLBA)
		}
		if oldEntry.EndingLBA != newEntry.EndingLBA {
			return fmt.Errorf("partition %d ending LBA mismatch: old %d, new %d", i,
				oldEntry.EndingLBA, newEntry.EndingLBA)
		}
		// We skip the Attribute check for IMAG/IMGB, as it can vary based on partiton state
		// being unused, updating, active, etc.
		if oldName != "IMAGA" && oldName != "IMGB" {
			if oldEntry.Attributes != newEntry.Attributes {
				return fmt.Errorf("partition %d attributes mismatch: old %d, new %d", i,
					oldEntry.Attributes, newEntry.Attributes)
			}
		}
		if oldEntry.PartitionName != newEntry.PartitionName {
			return fmt.Errorf("partition %d name mismatch: old %s, new %s", i,
				oldEntry.PartitionName, newEntry.PartitionName)
		}
	}

	return nil
}

func ValidateReportedPCRs(msg *zattest.ZAttestReq, u uuid.UUID) error {
	gzipReader, err := gzip.NewReader(bytes.NewReader(msg.Quote.TpmBinaryEventLog))
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %s", err)
	}
	defer gzipReader.Close()
	eventLogData, err := io.ReadAll(gzipReader)
	if err != nil {
		return fmt.Errorf("failed to read TPM event log: %s", err)
	}

	deviceAttestDir := fmt.Sprintf("run/adam/device/%s/attest", u.String())
	if err := os.MkdirAll(deviceAttestDir, 0755); err != nil {
		return fmt.Errorf("failed to create device attest directory: %s", err)
	}

	// Define file paths
	baselineEventLogPath := fmt.Sprintf("%s/baseline_tmp_eventlog.bin", deviceAttestDir)
	currentEventLogPath := fmt.Sprintf("%s/current_tmp_eventlog.bin", deviceAttestDir)
	baselinePcrsYamlPath := fmt.Sprintf("%s/baseline_pcrs.yaml", deviceAttestDir)
	currentPcrsYamlPath := fmt.Sprintf("%s/current_pcrs.yaml", deviceAttestDir)

	// Save current PCR values to YAML
	if err := savePCRsToYAML(msg.Quote, currentPcrsYamlPath); err != nil {
		return fmt.Errorf("failed to save PCRs to YAML: %s", err)
	}

	// Save current event log
	err = os.WriteFile(currentEventLogPath, eventLogData, 0644)
	if err != nil {
		return fmt.Errorf("failed to write current TPM event log: %s", err)
	}

	// Make sure reported PCR values match the event log
	if err := epp.ValidateEventLogFromFile(currentEventLogPath, currentPcrsYamlPath); err != nil {
		return fmt.Errorf("event log validation failed: %s", err)
	} else {
		log.Printf("Event log validation succeeded for device %s", u.String())
	}

	// Save baseline event log and PCRs only if it doesn't exist
	if _, err := os.Stat(baselineEventLogPath); os.IsNotExist(err) {
		err = os.WriteFile(baselineEventLogPath, eventLogData, 0644)
		if err != nil {
			return fmt.Errorf("failed to write baseline TPM event log: %s", err)
		}

		if err := savePCRsToYAML(msg.Quote, baselinePcrsYamlPath); err != nil {
			return fmt.Errorf("failed to save PCRs to YAML: %s", err)
		}

		// there is no base line so skip the pcr prediction
		log.Printf("Baseline event log saved for device %s, skipping PCR prediction", u.String())
		return nil
	}

	// If baseline and current event logs are identical, skip PCR prediction
	baselineData, err := os.ReadFile(baselineEventLogPath)
	if err != nil {
		return fmt.Errorf("failed to read baseline TPM event log: %s", err)
	}
	if bytes.Equal(baselineData, eventLogData) {
		log.Printf("Baseline and current event logs are identical for device %s, skipping PCR prediction", u.String())
		return nil
	}

	// Get expected PCRs by predicting them from the baseline event log
	// and current version (updating)
	allPCrs, err := epp.PredictAllPCRs(baselineEventLogPath,
		deviceAttestDir+"/binary_bios_measurements_IMGA_active",
		deviceAttestDir+"/binary_bios_measurements_IMGA_updating",
		deviceAttestDir+"/binary_bios_measurements_IMGB_active",
		deviceAttestDir+"/binary_bios_measurements_IMGB_updating",
		fixEveGrubStageOne, nil, nil, nil)
	if err != nil {
		return fmt.Errorf("PredictAllPCRs failed: %s", err)
	}

	if err := PcrsMatchExpectedValues(allPCrs, baselinePcrsYamlPath, currentPcrsYamlPath); err != nil {
		return fmt.Errorf("PcrsMatchExpectedValues failed: %s", err)
	}

	// Finally, validate partition table from event log
	if err := ValidateEvePcrFive(baselineEventLogPath, currentEventLogPath); err != nil {
		log.Printf("PCR 5 validation failed: %s", err)
		// dump partition tables for debugging
		log.Printf("Old partition table:")
		epp.GetGptPartitionTable(baselineEventLogPath, nil, nil, nil, true)
		log.Printf("New partition table:")
		epp.GetGptPartitionTable(currentEventLogPath, nil, nil, nil, true)
	} else {
		log.Printf("PCR 5 validation succeeded for device %s", u.String())
	}

	return nil
}
