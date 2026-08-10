// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// storage is a minimal image server for the EVE PCR prediction demo.
//
// It accepts rootfs image uploads, computes the digest GRUB's measurefs extends
// into PCR 13, and serves both the metadata and the image itself. The controller
// reads the metadata to predict PCR values; the device downloads the image from
// the URI in that same metadata.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
)

type server struct {
	store   *Store
	baseURL string
}

func main() {
	addr := flag.String("addr", ":8888", "listen address")
	dataDir := flag.String("data", "./data", "directory holding images and metadata")
	baseURL := flag.String("base-url", "", "public base URL for image URIs; defaults to the request host")
	flag.Parse()

	store, err := NewStore(*dataDir)
	if err != nil {
		log.Fatalf("storage: %v", err)
	}

	srv := &server{store: store, baseURL: *baseURL}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/images", srv.upload)
	mux.HandleFunc("GET /api/v1/images", srv.list)
	mux.HandleFunc("GET /api/v1/images/{id}", srv.get)
	mux.HandleFunc("GET /api/v1/images/{id}/download", srv.download)
	mux.HandleFunc("POST /api/v1/images/{id}/reference/{kind}", srv.putReference)
	mux.HandleFunc("GET /api/v1/images/{id}/reference/{kind}", srv.getReference)

	abs, _ := filepath.Abs(*dataDir)
	log.Printf("storage listening on %s, data in %s", *addr, abs)
	log.Fatal(http.ListenAndServe(*addr, mux))
}

// upload stores the raw request body as an image. The name and version are
// passed as query parameters; the version is what GRUB measures into PCR 8, so
// PCR prediction needs it to be the exact EVE version string.
func (s *server) upload(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		httpError(w, http.StatusBadRequest, "missing name parameter")
		return
	}
	version := r.URL.Query().Get("version")
	if version == "" {
		httpError(w, http.StatusBadRequest, "missing version parameter")
		return
	}

	img, err := s.store.Put(name, version, r.Body)
	if err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.addURIs(r, img)

	log.Printf("stored %s version=%s id=%s rootfsHash=%s", img.Name, img.Version, img.ID, img.RootfsHash)
	writeJSON(w, http.StatusCreated, img)
}

// list returns stored images, newest upload first. A version query parameter
// narrows the result to that version, which is how the controller looks up the
// rootfs hash for a release it is about to roll out.
//
// Uploading a changed image under an existing version is allowed, so a version
// can match more than one entry. The newest match comes first.
func (s *server) list(w http.ResponseWriter, r *http.Request) {
	images, err := s.store.List()
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if version := r.URL.Query().Get("version"); version != "" {
		matched := make([]*Image, 0, len(images))
		for _, img := range images {
			if img.Version == version {
				matched = append(matched, img)
			}
		}
		images = matched
	}

	for _, img := range images {
		s.addURIs(r, img)
	}
	writeJSON(w, http.StatusOK, map[string]any{"images": images})
}

func (s *server) get(w http.ResponseWriter, r *http.Request) {
	img, err := s.store.Get(r.PathValue("id"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			httpError(w, http.StatusNotFound, "no such image")
			return
		}
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.addURIs(r, img)
	writeJSON(w, http.StatusOK, img)
}

// download serves the image bytes. This is the URI a device fetches when it
// applies the update.
func (s *server) download(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	img, err := s.store.Get(id)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			httpError(w, http.StatusNotFound, "no such image")
			return
		}
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", img.Name))
	http.ServeFile(w, r, s.store.ImagePath(id))
}

// putReference attaches a reference measurement captured by booting this image
// in a controlled VM. kind is "eventlog" (the raw TCG binary log), "pcrs"
// (tpm2_pcrread output), or "measureconfig" (EVE's measure-config event log that
// PCR 14 replays from). The body is the artifact itself.
func (s *server) putReference(w http.ResponseWriter, r *http.Request) {
	id, kind := r.PathValue("id"), r.PathValue("kind")
	if !isReferenceKind(kind) {
		httpError(w, http.StatusBadRequest,
			fmt.Sprintf("kind must be %q, %q, or %q", referenceEventLog, referencePCRs, referenceMeasureConfig))
		return
	}

	if err := s.store.PutReference(id, kind, r.Body); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			httpError(w, http.StatusNotFound, "no such image")
			return
		}
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}

	img, err := s.store.Get(id)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.addURIs(r, img)
	log.Printf("stored reference %s for image %s (complete=%v)", kind, id, img.HasReference)
	writeJSON(w, http.StatusCreated, img)
}

// getReference serves a stored reference artifact. This is what a controller
// fetches to predict the PCR values a device will report after taking the image.
func (s *server) getReference(w http.ResponseWriter, r *http.Request) {
	id, kind := r.PathValue("id"), r.PathValue("kind")
	if !isReferenceKind(kind) {
		httpError(w, http.StatusBadRequest, "unknown reference kind")
		return
	}
	path := s.store.ReferencePath(id, kind)
	if _, err := os.Stat(path); err != nil {
		httpError(w, http.StatusNotFound, "no reference measurement for this image")
		return
	}
	if kind == referencePCRs {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	} else {
		w.Header().Set("Content-Type", "application/octet-stream")
	}
	http.ServeFile(w, r, path)
}

func (s *server) imageURI(r *http.Request, id string) string {
	return fmt.Sprintf("%s/api/v1/images/%s/download", s.base(r), id)
}

// addURIs fills in the absolute URIs, which depend on how the caller reached us
// and so are not stored with the metadata.
func (s *server) addURIs(r *http.Request, img *Image) {
	img.URI = s.imageURI(r, img.ID)
	if !img.HasReference {
		return
	}
	img.ReferenceEventLogURI = fmt.Sprintf("%s/api/v1/images/%s/reference/%s",
		s.base(r), img.ID, referenceEventLog)
	img.ReferencePCRsURI = fmt.Sprintf("%s/api/v1/images/%s/reference/%s",
		s.base(r), img.ID, referencePCRs)
	img.ReferenceMeasureConfigURI = fmt.Sprintf("%s/api/v1/images/%s/reference/%s",
		s.base(r), img.ID, referenceMeasureConfig)
}

// isReferenceKind reports whether kind names a reference artifact this service
// stores.
func isReferenceKind(kind string) bool {
	return kind == referenceEventLog || kind == referencePCRs || kind == referenceMeasureConfig
}

func (s *server) base(r *http.Request) string {
	if s.baseURL != "" {
		return s.baseURL
	}
	return "http://" + r.Host
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("writing response: %v", err)
	}
}

func httpError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
