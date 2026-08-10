// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	evepcr "github.com/zededa/evepcr"
)

// measureConfigPCR is the PCR EVE's measure-config service extends. The captured
// reference PCRs must carry this index for the measure-config log to be checked.
const measureConfigPCR = 14

// Image is the metadata recorded for one uploaded rootfs image.
//
// A reference measurement is the event log and PCR values captured by booting
// this exact image once in a controlled VM. It lets a controller predict what a
// device will measure after taking this image, including the parts a rootfs
// hash alone cannot describe, such as the GRUB command trace in PCR 8.
type Image struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Version      string    `json:"version"`
	SizeBytes    int64     `json:"sizeBytes"`
	SHA256       string    `json:"sha256"`
	RootfsHash   string    `json:"rootfsHash"`
	URI          string    `json:"uri"`
	UploadedAt   time.Time `json:"uploadedAt"`
	HasReference bool      `json:"hasReference"`
	// set only when HasReference
	ReferenceEventLogURI      string     `json:"referenceEventLogUri,omitempty"`
	ReferencePCRsURI          string     `json:"referencePcrsUri,omitempty"`
	ReferenceMeasureConfigURI string     `json:"referenceMeasureConfigUri,omitempty"`
	ReferenceCapturedAt       *time.Time `json:"referenceCapturedAt,omitempty"`
}

// Store keeps images and their metadata as files under a single directory.
// Each image is stored as <id>.img with its metadata in <id>.json.
type Store struct {
	dir string
}

func NewStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("creating data dir: %w", err)
	}
	return &Store{dir: dir}, nil
}

// Put streams an image to disk, hashes it, and records its metadata.
//
// Two digests are recorded and they are not interchangeable. SHA256 covers the
// whole file and is what a device checks after downloading. RootfsHash is what
// GRUB's measurefs extends into PCR 13, computed over the squashfs payload only,
// and is the value PCR prediction needs.
//
// The image ID is derived from the file digest, so re-uploading the same image
// replaces its entry rather than creating a duplicate.
func (s *Store) Put(name, version string, r io.Reader) (*Image, error) {
	tmp, err := os.CreateTemp(s.dir, "upload-*.tmp")
	if err != nil {
		return nil, fmt.Errorf("creating temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	size, err := io.Copy(tmp, r)
	if err != nil {
		tmp.Close()
		return nil, fmt.Errorf("writing upload: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("closing upload: %w", err)
	}

	content, err := os.ReadFile(tmpName)
	if err != nil {
		return nil, fmt.Errorf("reading back upload: %w", err)
	}

	fileDigest := sha256.Sum256(content)
	fileHash := hex.EncodeToString(fileDigest[:])

	rootfsHash, err := evepcr.HashRootfsImage(content)
	if err != nil {
		return nil, fmt.Errorf("hashing rootfs image: %w", err)
	}

	img := &Image{
		ID:         fileHash[:16],
		Name:       name,
		Version:    version,
		SizeBytes:  size,
		SHA256:     fileHash,
		RootfsHash: hex.EncodeToString(rootfsHash),
		UploadedAt: time.Now().UTC(),
	}

	if err := os.Rename(tmpName, s.ImagePath(img.ID)); err != nil {
		return nil, fmt.Errorf("storing image: %w", err)
	}
	if err := s.writeMeta(img); err != nil {
		return nil, err
	}
	return img, nil
}

// Get returns the metadata for one image.
func (s *Store) Get(id string) (*Image, error) {
	data, err := os.ReadFile(s.metaPath(id))
	if err != nil {
		return nil, err
	}
	var img Image
	if err := json.Unmarshal(data, &img); err != nil {
		return nil, fmt.Errorf("unmarshal metadata: %w", err)
	}
	return &img, nil
}

// List returns every stored image, newest upload first.
func (s *Store) List() ([]*Image, error) {
	matches, err := filepath.Glob(filepath.Join(s.dir, "*.json"))
	if err != nil {
		return nil, err
	}

	images := make([]*Image, 0, len(matches))
	for _, m := range matches {
		id := filepath.Base(m[:len(m)-len(".json")])
		img, err := s.Get(id)
		if err != nil {
			return nil, err
		}
		images = append(images, img)
	}
	sort.Slice(images, func(i, j int) bool {
		return images[i].UploadedAt.After(images[j].UploadedAt)
	})
	return images, nil
}

// ImagePath is where the image bytes for an ID live on disk.
func (s *Store) ImagePath(id string) string {
	return filepath.Join(s.dir, id+".img")
}

// ReferencePath is where one reference artifact for an ID lives on disk.
// kind is "eventlog" or "pcrs".
func (s *Store) ReferencePath(id, kind string) string {
	ext := ".bin"
	if kind == referencePCRs {
		ext = ".yaml"
	}
	return filepath.Join(s.dir, id+"-reference-"+kind+ext)
}

const (
	referenceEventLog      = "eventlog"
	referencePCRs          = "pcrs"
	referenceMeasureConfig = "measureconfig"
)

// PutReference stores one reference artifact captured from booting the image,
// and marks the image as having a reference measurement once both are present.
func (s *Store) PutReference(id, kind string, r io.Reader) error {
	img, err := s.Get(id)
	if err != nil {
		return err
	}

	data, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("reading reference %s: %w", kind, err)
	}
	if len(data) == 0 {
		return fmt.Errorf("reference %s is empty", kind)
	}
	if err := os.WriteFile(s.ReferencePath(id, kind), data, 0644); err != nil {
		return fmt.Errorf("storing reference %s: %w", kind, err)
	}

	// The three artifacts are only useful together: the boot log and the
	// measure-config log are what prediction replays, the PCR values are what
	// prove both logs were not garbled in transit. The measurement is only
	// published once all three are present AND both logs actually replay to the
	// captured values, because they travel over a serial console that EVE is
	// logging to at the same time.
	_, logErr := os.Stat(s.ReferencePath(id, referenceEventLog))
	_, pcrErr := os.Stat(s.ReferencePath(id, referencePCRs))
	_, mcErr := os.Stat(s.ReferencePath(id, referenceMeasureConfig))
	if logErr == nil && pcrErr == nil && mcErr == nil && !img.HasReference {
		if err := s.verifyReference(id); err != nil {
			return fmt.Errorf("reference measurement for %s is not self-consistent: %w", id, err)
		}
		now := time.Now().UTC()
		img.HasReference = true
		img.ReferenceCapturedAt = &now
		return s.writeMeta(img)
	}
	return nil
}

// verifyReference replays the stored event log against the PCR values captured
// from the same boot. A log that does not replay is a log that was corrupted on
// the way out of the VM, and predicting from it would produce values no device
// can ever report.
func (s *Store) verifyReference(id string) error {
	rawLog, err := os.ReadFile(s.ReferencePath(id, referenceEventLog))
	if err != nil {
		return fmt.Errorf("reading the event log: %w", err)
	}

	pcrs, err := evepcr.ReadPCRs(s.ReferencePath(id, referencePCRs), false)
	if err != nil {
		return fmt.Errorf("reading the PCR values: %w", err)
	}
	want := make(map[int][]byte)
	for index, value := range pcrs["sha256"] {
		digest, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(value), "0x"))
		if err != nil {
			return fmt.Errorf("PCR %d is not hex: %w", index, err)
		}
		want[index] = digest
	}
	if len(want) == 0 {
		return fmt.Errorf("no SHA-256 PCR values were captured")
	}

	if _, err := evepcr.VerifyEventLogFromBytes(rawLog, want); err != nil {
		return fmt.Errorf("the %d byte event log does not replay to the %d captured PCR values: %w",
			len(rawLog), len(want), err)
	}

	// The measure-config log predicts PCR 14, which the boot log never touches.
	// It must reproduce the captured PCR 14 value or a device would be predicted
	// against a config measurement the capture never actually produced.
	mcLog, err := os.ReadFile(s.ReferencePath(id, referenceMeasureConfig))
	if err != nil {
		return fmt.Errorf("reading the measure-config log: %w", err)
	}
	pcr14, err := evepcr.PredictPCR14FromMeasureConfigLog(mcLog)
	if err != nil {
		return fmt.Errorf("replaying the measure-config log: %w", err)
	}
	want14, ok := want[measureConfigPCR]
	if !ok {
		return fmt.Errorf("no PCR %d value was captured to check the measure-config log against", measureConfigPCR)
	}
	if !bytes.Equal(pcr14, want14) {
		return fmt.Errorf("the measure-config log predicts PCR %d %x but the capture recorded %x",
			measureConfigPCR, pcr14, want14)
	}
	return nil
}

func (s *Store) metaPath(id string) string {
	return filepath.Join(s.dir, id+".json")
}

func (s *Store) writeMeta(img *Image) error {
	data, err := json.MarshalIndent(img, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}
	return os.WriteFile(s.metaPath(img.ID), data, 0644)
}
