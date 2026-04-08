// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

const imageMetaFile = "meta.json"

// ImageMeta holds metadata for an uploaded EVE OS image.
type ImageMeta struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Version    string    `json:"version"`
	Filename   string    `json:"filename"`
	Sha256     string    `json:"sha256"`
	SizeBytes  int64     `json:"sizeBytes"`
	UploadedAt time.Time `json:"uploadedAt"`
}

// ImageStore manages EVE OS images stored under a base directory.
// Each image lives in its own subdirectory: {baseDir}/{id}/
type ImageStore struct {
	baseDir string
}

func newImageStore(baseDir string) (*ImageStore, error) {
	if err := os.MkdirAll(baseDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create image store dir: %w", err)
	}
	return &ImageStore{baseDir: baseDir}, nil
}

// Save writes the image data to disk, computes its SHA-256, and persists metadata.
func (s *ImageStore) Save(id, name, version, filename string, r io.Reader) (*ImageMeta, error) {
	dir := filepath.Join(s.baseDir, id)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create image dir: %w", err)
	}

	imgPath := filepath.Join(dir, filename)
	f, err := os.OpenFile(imgPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to create image file: %w", err)
	}
	defer f.Close()

	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), r)
	if err != nil {
		os.RemoveAll(dir)
		return nil, fmt.Errorf("failed to write image: %w", err)
	}

	meta := &ImageMeta{
		ID:         id,
		Name:       name,
		Version:    version,
		Filename:   filename,
		Sha256:     hex.EncodeToString(h.Sum(nil)),
		SizeBytes:  n,
		UploadedAt: time.Now().UTC(),
	}
	if err := s.saveMeta(id, meta); err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	return meta, nil
}

// Get returns the metadata for a single image by ID.
func (s *ImageStore) Get(id string) (*ImageMeta, error) {
	return s.loadMeta(id)
}

// List returns metadata for all stored images.
func (s *ImageStore) List() ([]*ImageMeta, error) {
	entries, err := os.ReadDir(s.baseDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var images []*ImageMeta
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		meta, err := s.loadMeta(e.Name())
		if err != nil {
			continue
		}
		images = append(images, meta)
	}
	return images, nil
}

// Delete removes the image directory for the given ID.
func (s *ImageStore) Delete(id string) error {
	dir := filepath.Join(s.baseDir, id)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return fmt.Errorf("image not found: %s", id)
	}
	return os.RemoveAll(dir)
}

// FilePath returns the full path to the image file for serving.
func (s *ImageStore) FilePath(id, filename string) string {
	return filepath.Join(s.baseDir, id, filename)
}

func (s *ImageStore) saveMeta(id string, meta *ImageMeta) error {
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal meta: %w", err)
	}
	return os.WriteFile(filepath.Join(s.baseDir, id, imageMetaFile), data, 0600)
}

func (s *ImageStore) loadMeta(id string) (*ImageMeta, error) {
	data, err := os.ReadFile(filepath.Join(s.baseDir, id, imageMetaFile))
	if err != nil {
		return nil, err
	}
	var meta ImageMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, fmt.Errorf("unmarshal meta: %w", err)
	}
	return &meta, nil
}
