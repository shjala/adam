// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Getting the artifacts a prediction needs from the storage service.
//
// The version being looked up comes out of a device's quote and the URL to fetch
// comes out of the service's response, so both are treated as untrusted input.

package server

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lf-edge/eve-api/go/attest"
)

const (
	// maxVersionLength bounds the version string taken from a device's quote
	// before it is put in a URL.
	maxVersionLength = 256
	// maxReferenceLogSize bounds a downloaded reference event log. Real ones are
	// tens of kilobytes.
	maxReferenceLogSize = 16 << 20
	// storageTimeout bounds each request, so an unresponsive service cannot hold
	// up attestation indefinitely.
	storageTimeout = 30 * time.Second
)

// storageImage is the part of the storage service's metadata that matters here.
type storageImage struct {
	Version                   string `json:"version"`
	RootfsHash                string `json:"rootfsHash"`
	URI                       string `json:"uri"`
	HasReference              bool   `json:"hasReference"`
	ReferenceEventLogURI      string `json:"referenceEventLogUri"`
	ReferenceMeasureConfigURI string `json:"referenceMeasureConfigUri"`
}

// referenceForVersion returns the prediction inputs the controller published for
// an EVE version: the rootfs hash, the firmware boot log, and the measure-config
// event log, both logs captured by booting that image in a controlled VM.
//
// These must come from the controller rather than from the device, so anything
// that cannot be confirmed is an error rather than a fallback to something weaker.
func referenceForVersion(storageURL, version string) (rootfsHash, referenceLog, measureConfigLog []byte, err error) {
	if err := checkVersionString(version); err != nil {
		return nil, nil, nil, err
	}

	client := &http.Client{Timeout: storageTimeout}
	img, err := fetchImageMetadata(client, storageURL, version)
	if err != nil {
		return nil, nil, nil, err
	}

	rootfsHash, err = hex.DecodeString(img.RootfsHash)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("rootfs hash for %s is not hex: %w", version, err)
	}
	if len(rootfsHash) != 32 {
		return nil, nil, nil, fmt.Errorf("rootfs hash for %s is %d bytes, want 32", version, len(rootfsHash))
	}
	if !img.HasReference {
		return nil, nil, nil, fmt.Errorf("%s has no reference measurement", version)
	}

	referenceLog, err = fetchReferenceBlob(client, storageURL, img.ReferenceEventLogURI, "event log")
	if err != nil {
		return nil, nil, nil, err
	}
	measureConfigLog, err = fetchReferenceBlob(client, storageURL, img.ReferenceMeasureConfigURI, "measure-config log")
	if err != nil {
		return nil, nil, nil, err
	}
	return rootfsHash, referenceLog, measureConfigLog, nil
}

// checkVersionString rejects anything that cannot be an EVE version. The string
// arrives from a device's quote and goes into a URL.
func checkVersionString(version string) error {
	if version == "" {
		return fmt.Errorf("no version to look up")
	}
	if len(version) > maxVersionLength {
		return fmt.Errorf("version is %d characters, over the %d limit", len(version), maxVersionLength)
	}
	for _, r := range version {
		if r <= ' ' || r > '~' {
			return fmt.Errorf("version contains a character that cannot appear in an EVE version")
		}
	}
	return nil
}

// fetchImageMetadata asks the storage service about one EVE version.
func fetchImageMetadata(client *http.Client, storageURL, version string) (*storageImage, error) {
	endpoint, err := url.Parse(strings.TrimSuffix(storageURL, "/") + "/api/v1/images")
	if err != nil {
		return nil, fmt.Errorf("bad storage URL %q: %w", storageURL, err)
	}
	q := endpoint.Query()
	q.Set("version", version)
	endpoint.RawQuery = q.Encode()

	resp, err := client.Get(endpoint.String())
	if err != nil {
		return nil, fmt.Errorf("querying storage for version %q: %w", version, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("storage returned %s for version %q", resp.Status, version)
	}

	var body struct {
		Images []*storageImage `json:"images"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return nil, fmt.Errorf("decoding storage response: %w", err)
	}
	if len(body.Images) == 0 {
		return nil, fmt.Errorf("storage has no image for version %q", version)
	}

	// The service answered about something; confirm it is what was asked for.
	// Without this a version could resolve to another image's metadata and the
	// device would be predicted against the wrong artifact.
	img := body.Images[0]
	if img.Version != version {
		return nil, fmt.Errorf("storage answered about %q when asked about %q", img.Version, version)
	}
	return img, nil
}

// fetchReferenceBlob downloads one reference artifact. what names it for error
// messages, e.g. "event log" or "measure-config log".
//
// The URL comes from the service's response, so it is confined to the host the
// controller already chose to talk to. Otherwise a misconfigured or compromised
// storage service could point the controller at anything it can reach.
func fetchReferenceBlob(client *http.Client, storageURL, uri, what string) ([]byte, error) {
	if uri == "" {
		return nil, fmt.Errorf("storage published no reference %s URL", what)
	}
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("bad reference %s URL %q: %w", what, uri, err)
	}
	base, err := url.Parse(strings.TrimSuffix(storageURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("bad storage URL %q: %w", storageURL, err)
	}
	if u.Scheme != base.Scheme || u.Host != base.Host {
		return nil, fmt.Errorf("reference %s URL %q is not on the storage service %q", what, uri, storageURL)
	}

	resp, err := client.Get(u.String())
	if err != nil {
		return nil, fmt.Errorf("fetching the reference %s: %w", what, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("storage returned %s for the reference %s", resp.Status, what)
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxReferenceLogSize+1))
	if err != nil {
		return nil, fmt.Errorf("reading the reference %s: %w", what, err)
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("the reference %s is empty", what)
	}
	if len(raw) > maxReferenceLogSize {
		return nil, fmt.Errorf("the reference %s exceeds the %d byte limit", what, maxReferenceLogSize)
	}
	return raw, nil
}

// eveVersionFromQuote returns the EVE version the device reports running.
//
// This is not covered by the TPM signature, so it is only ever used to look an
// image up. What the device is actually running is settled by comparing PCR
// values against the prediction.
func eveVersionFromQuote(quote *attest.ZAttestQuote) string {
	for _, v := range quote.GetVersions() {
		if v.GetVersionType() == attest.AttestVersionType_ATTEST_VERSION_TYPE_EVE {
			return v.GetVersion()
		}
	}
	return ""
}
