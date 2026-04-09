// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	"github.com/lf-edge/adam/pkg/driver"
	"github.com/lf-edge/adam/pkg/driver/common"
	ax "github.com/lf-edge/adam/pkg/x509"
	"github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve-api/go/info"
	uuid "github.com/satori/go.uuid"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

const (
	StreamHeader        = "X-Stream"
	StreamValue         = "true"
	imageUploadFilename = "rootfs.img"
)

type upgradeRequest struct {
	ImageID string `json:"imageId"`
}

type adminHandler struct {
	manager         driver.DeviceManager
	imageStore      *ImageStore
	logChannel      chan []byte
	infoChannel     chan []byte
	requestsChannel chan []byte
	// caCertPath is the path to the CA cert used to sign adam's TLS cert.
	// Included in DatastoreConfig.DsCertPEM so EVE's downloader trusts adam's TLS cert.
	caCertPath string
	// baseURL is adam's public HTTPS base URL as seen by EVE (e.g. "https://192.168.1.1:9090").
	// Used as the datastore Fqdn for upgrades. Falls back to the HTTP request Host header if empty.
	baseURL string
}

// OnboardCert encoding for sending an onboard cert and serials via json
// swagger:parameters onboard
type OnboardCert struct {
	// a Cert for onboarding
	//
	// unique: true
	// in: query
	Cert []byte
	// a Serial for onboarding
	//
	// unique: true
	// in: query
	Serial string
}

// DeviceInfo encoding for sending a device information, including device cert, onboard cert, and serial, if any
type DeviceInfo struct {
	Cert         []byte
	Onboard      []byte
	Serial       string
	Onboarded    bool
	CacheKeys    bool
	KeyCacheBase uint64
	KeyCacheMax  uint64
}

func (h *adminHandler) deviceAdd(w http.ResponseWriter, r *http.Request) {
	// extract certificate and serials from request body
	contentType := r.Header.Get(contentType)
	if contentType != mimeJSON {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	decoder := json.NewDecoder(r.Body)
	var (
		t       DeviceInfo
		cert    *x509.Certificate
		onboard *x509.Certificate
	)
	err := decoder.Decode(&t)
	if err != nil {
		log.Printf("deviceAdd: Decode error: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	cert, err = ax.ParseCert(t.Cert)
	if err != nil {
		log.Printf("deviceAdd: ParseCert device error: %v", err)
		http.Error(w, fmt.Sprintf("bad device cert: %v", err), http.StatusBadRequest)
		return
	}
	if len(t.Onboard) > 0 {
		onboard, err = ax.ParseCert(t.Onboard)
		if err != nil {
			log.Printf("deviceAdd: ParseCert onboard error: %v", err)
			http.Error(w, fmt.Sprintf("bad onboard cert: %v", err), http.StatusBadRequest)
			return
		}
	}
	// generate a new uuid
	unew, err := uuid.NewV4()
	if err != nil {
		log.Printf("deviceAdd: error generating a new device UUID: %v", err)
		http.Error(w, fmt.Sprintf("error generating a new device UUID: %v", err), http.StatusBadRequest)
		return
	}
	if err := h.manager.DeviceRegister(unew, cert, onboard, t.Serial, common.CreateBaseConfig(unew)); err != nil {
		log.Printf("deviceAdd: DeviceRegister error: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func (h *adminHandler) deviceList(w http.ResponseWriter, r *http.Request) {
	uids, err := h.manager.DeviceList()
	if err != nil {
		log.Printf("deviceList: DeviceList error: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// convert the UUIDs
	ids := make([]string, 0, len(uids))
	for _, i := range uids {
		if i != nil {
			ids = append(ids, i.String())
		}
	}
	w.WriteHeader(http.StatusOK)
	body := strings.Join(ids, "\n")
	w.Header().Add(contentType, mimeTextPlain)
	w.Write([]byte(body))
}

func (h *adminHandler) deviceGet(w http.ResponseWriter, r *http.Request) {
	u := mux.Vars(r)["uuid"]
	uid, err := uuid.FromString(u)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	deviceCert, onboardCert, serial, onboarded, err := h.manager.DeviceGet(&uid)
	_, isNotFound := err.(*common.NotFoundError)
	switch {
	case err != nil && isNotFound:
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
	case err != nil:
		log.Printf("deviceGet: DeviceGet error: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
	case deviceCert == nil:
		http.Error(w, "found device information, but cert was empty", http.StatusInternalServerError)
	default:
		dc := DeviceInfo{
			Cert:      ax.PemEncodeCert(deviceCert.Raw),
			Onboard:   ax.PemEncodeCert(onboardCert.Raw),
			Serial:    serial,
			Onboarded: onboarded,
		}
		body, err := json.Marshal(dc)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(body))
	}
}

func (h *adminHandler) deviceRemove(w http.ResponseWriter, r *http.Request) {
	u := mux.Vars(r)["uuid"]
	uid, err := uuid.FromString(u)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	err = h.manager.DeviceRemove(&uid)
	_, isNotFound := err.(*common.NotFoundError)
	switch {
	case err != nil && isNotFound:
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
	case err != nil:
		log.Printf("deviceRemove: DeviceRemove error: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
	default:
		w.WriteHeader(http.StatusOK)
	}
}

func (h *adminHandler) deviceClear(w http.ResponseWriter, r *http.Request) {
	err := h.manager.DeviceClear()
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

func (h *adminHandler) deviceConfigGet(w http.ResponseWriter, r *http.Request) {
	u := mux.Vars(r)["uuid"]
	uid, err := uuid.FromString(u)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	deviceConfig, err := h.manager.GetConfig(uid)
	_, isNotFound := err.(*common.NotFoundError)
	switch {
	case err != nil && isNotFound:
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
	case err != nil:
		log.Printf("deviceConfigGet: GetConfig error: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
	case deviceConfig == nil:
		http.Error(w, "found device information, but cert was empty", http.StatusInternalServerError)
	default:
		if acceptJSON(r) {
			var deviceConfigObj config.EdgeDevConfig
			err = proto.Unmarshal(deviceConfig, &deviceConfigObj)
			if err != nil {
				log.Printf("deviceConfigGet: Unmarshal error: %v", err)
				http.Error(w, "cannot unmarshal stored EdgeDevConfig", http.StatusInternalServerError)
				return
			}
			deviceConfig, err = protojson.Marshal(&deviceConfigObj)
			if err != nil {
				log.Printf("deviceConfigGet: Marshal error: %v", err)
				http.Error(w, "cannot marshal stored EdgeDevConfig", http.StatusInternalServerError)
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		w.Write(deviceConfig)
	}
}

func (h *adminHandler) deviceConfigSet(w http.ResponseWriter, r *http.Request) {
	u := mux.Vars(r)["uuid"]
	uid, err := uuid.FromString(u)
	if err != nil {
		http.Error(w, "bad UUID", http.StatusBadRequest)
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("bad body: %v", err), http.StatusBadRequest)
		return
	}
	var deviceConfig config.EdgeDevConfig
	if contentTypeJSON(r) {
		err = json.Unmarshal(body, &deviceConfig)
	} else {
		err = proto.Unmarshal(body, &deviceConfig)
	}
	if err != nil {
		log.Printf("deviceConfigSet: Unmarshal config error: %v", err)
		http.Error(w, fmt.Sprintf("failed to marshal json message into protobuf: %v", err), http.StatusBadRequest)
		return
	}
	// before setting the config, set any necessary defaults
	// check for UUID and/or version mismatch
	var (
		existingId     *config.UUIDandVersion
		existingConfig config.EdgeDevConfig
	)
	existingConfigB, err := h.manager.GetConfig(uid)
	_, isNotFound := err.(*common.NotFoundError)
	switch {
	case err != nil && isNotFound:
		http.Error(w, fmt.Sprintf("device not found %s", u), http.StatusNotFound)
		return
	case err != nil:
		log.Printf("deviceConfigSet: GetConfig error: %v", err)
		http.Error(w, fmt.Sprintf("error retrieving existing config for device %s: %v", u, err), http.StatusBadRequest)
		return
	case len(existingConfigB) == 0:
		http.Error(w, "found device information, but had no config", http.StatusInternalServerError)
		return
	}
	// convert it to protobuf so we can work with it
	if err := proto.Unmarshal(existingConfigB, &existingConfig); err != nil {
		log.Printf("deviceConfigSet: processing existing config error: %v", err)
		http.Error(w, fmt.Sprintf("error processing existing config: %v", err), http.StatusInternalServerError)
		return
	}
	existingId = existingConfig.Id

	// we only can bump the version if it is a valid integer
	newVersion, versionError := strconv.Atoi(existingId.Version)
	if versionError == nil {
		newVersion++
	}
	if deviceConfig.Id == nil {
		if versionError != nil {
			http.Error(w, fmt.Sprintf("cannot automatically non-number bump version %s", existingId.Version), http.StatusBadRequest)
			return
		}
		deviceConfig.Id = &config.UUIDandVersion{
			Uuid:    u,
			Version: strconv.Itoa(newVersion),
		}
	} else {
		if deviceConfig.Id.Uuid == "" {
			deviceConfig.Id.Uuid = u
		}
		if deviceConfig.Id.Version == "" {
			if versionError != nil {
				http.Error(w, fmt.Sprintf("cannot automatically non-number bump version %s", existingId.Version), http.StatusBadRequest)
				return
			}
			deviceConfig.Id.Version = strconv.Itoa(newVersion)
		}
		if deviceConfig.Id.Uuid != u {
			http.Error(w, fmt.Sprintf("mismatched UUID, setting %s for device %s", deviceConfig.Id.Uuid, u), http.StatusBadRequest)
			return
		}
	}

	jb, err := json.MarshalIndent(&deviceConfig, "", "  ")
	if err != nil {
		log.Printf("deviceConfigSet: Marshal error: %v", err)
		http.Error(w, fmt.Sprintf("error processing device config: %v", err), http.StatusBadRequest)
		return
	}
	err = h.manager.SetConfig(uid, jb)
	_, isNotFound = err.(*common.NotFoundError)
	switch {
	case err != nil && isNotFound:
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
	case err != nil:
		log.Printf("deviceConfigSet: SetConfig error: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
	default:
		w.WriteHeader(http.StatusOK)
	}
}

func (h *adminHandler) deviceLogsGet(w http.ResponseWriter, r *http.Request) {
	h.deviceDataGet(w, r, h.logChannel, h.manager.GetLogsReader, nil)
}

func (h *adminHandler) deviceInfoGet(w http.ResponseWriter, r *http.Request) {
	h.deviceDataGet(w, r, h.infoChannel, h.manager.GetInfoReader, func(in []byte) ([]byte, error) {
		var err error
		msg := &info.ZInfoMsg{}
		if err = proto.Unmarshal(in, msg); err != nil {
			return nil, fmt.Errorf("error parsing info message: %v", err)
		}
		var entryBytes []byte
		if entryBytes, err = protojson.Marshal(msg); err != nil {
			return nil, fmt.Errorf("failed to marshal info message: %v", err)
		}
		return entryBytes, nil
	})
}

func (h *adminHandler) deviceRequestsGet(w http.ResponseWriter, r *http.Request) {
	h.deviceDataGet(w, r, h.requestsChannel, h.manager.GetRequestsReader, nil)
}

func (h *adminHandler) deviceDataGet(w http.ResponseWriter, r *http.Request, c <-chan []byte, readerFunc func(u uuid.UUID) (common.ChunkReader, error), conversionFunc func(in []byte) ([]byte, error)) {
	u := mux.Vars(r)["uuid"]
	uid, err := uuid.FromString(u)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	conversionRequired := false
	if conversionFunc != nil {
		conversionRequired = acceptJSON(r)
	}
	watch := r.Header.Get(StreamHeader)
	if watch == StreamValue {
		// get a close notifier so we can catch it and close ourselves
		cn, ok := w.(http.CloseNotifier)
		if !ok {
			http.NotFound(w, r)
			return
		}
		// get a flusher to send out data when streaming
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.NotFound(w, r)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-type", "application/json")
		flusher.Flush()

		for {
			select {
			case b := <-c:
				if conversionRequired {
					b, err = conversionFunc(b)
					if err != nil {
						log.Printf("conversionFunc failed: %v", err)
						continue
					}
				}
				w.Write(append(b, 0x0a))
				flusher.Flush()
			case <-cn.CloseNotify():
				// client stopped listening
				return
			}
		}
	} else {
		for {
			chunk, err := readerFunc(uid)
			_, isNotFound := err.(*common.NotFoundError)
			switch {
			case err != nil && isNotFound:
				http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			case err != nil:
				log.Printf("deviceDataGet: readerFunc error: %v", err)
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			default:
				w.WriteHeader(http.StatusOK)
				w.Header().Set("Content-type", "application/json")
				for {
					reader, size, err := chunk.Next()
					if reader == nil {
						return
					}
					if err != nil && err != io.EOF {
						http.Error(w, fmt.Sprintf("error reading chunkSize: %v", err), http.StatusInternalServerError)
						continue
					}
					buf := make([]byte, size)
					_, err = io.ReadFull(reader, buf)
					if err != nil && err != io.EOF {
						http.Error(w, fmt.Sprintf("error reading data: %v", err), http.StatusInternalServerError)
						continue
					}
					if conversionRequired {
						buf, err = conversionFunc(buf)
						if err != nil {
							log.Printf("conversionFunc failed: %v", err)
							continue
						}
					}
					w.Write(append(buf, 0x0a))
				}
			}
		}
	}
}

func (h *adminHandler) deviceCertsGet(w http.ResponseWriter, r *http.Request) {
	u := mux.Vars(r)["uuid"]
	uid, err := uuid.FromString(u)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	deviceAttest, err := h.manager.GetCerts(uid)
	_, isNotFound := err.(*common.NotFoundError)
	switch {
	case err != nil && isNotFound:
		log.Printf("deviceCertsGet: %v", err)
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
	case err != nil:
		log.Printf("deviceCertsGet: %v", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
	case deviceAttest == nil:
		http.Error(w, "found device information, but certs was empty", http.StatusInternalServerError)
	default:
		w.WriteHeader(http.StatusOK)
		w.Write(deviceAttest)
	}
}

func (h *adminHandler) deviceOptionsGet(w http.ResponseWriter, r *http.Request) {
	u := mux.Vars(r)["uuid"]
	uid, err := uuid.FromString(u)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	deviceOptions, err := h.manager.GetDeviceOptions(uid)
	_, isNotFound := err.(*common.NotFoundError)
	switch {
	case err != nil && isNotFound:
		log.Printf("deviceOptionsGet: %v", err)
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
	case err != nil:
		log.Printf("deviceOptionsGet: %v", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
	case deviceOptions == nil:
		http.Error(w, "found device information, but options was empty", http.StatusInternalServerError)
	default:
		w.WriteHeader(http.StatusOK)
		w.Write(deviceOptions)
	}
}

func (h *adminHandler) deviceOptionsSet(w http.ResponseWriter, r *http.Request) {
	u := mux.Vars(r)["uuid"]
	uid, err := uuid.FromString(u)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("bad body: %v", err), http.StatusBadRequest)
		return
	}
	var deviceOptions common.DeviceOptions
	err = json.Unmarshal(body, &deviceOptions)
	if err != nil {
		log.Printf("deviceOptionsSet: Unmarshal options error: %v", err)
		http.Error(w, fmt.Sprintf("failed to marshal json message into json: %v", err), http.StatusBadRequest)
		return
	}
	err = h.manager.SetDeviceOptions(uid, body)
	if err != nil {
		log.Printf("deviceOptionsSet: %s", err)
		http.Error(w, fmt.Sprintf("failed to set device options: %s", err), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *adminHandler) globalOptionsGet(w http.ResponseWriter, _ *http.Request) {
	globalOptions, err := h.manager.GetGlobalOptions()
	_, isNotFound := err.(*common.NotFoundError)
	switch {
	case err != nil && isNotFound:
		log.Printf("globalOptionsGet: %v", err)
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
	case err != nil:
		log.Printf("globalOptionsGet: %v", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
	case globalOptions == nil:
		http.Error(w, "found information, but options was empty", http.StatusInternalServerError)
	default:
		w.WriteHeader(http.StatusOK)
		w.Write(globalOptions)
	}
}

func (h *adminHandler) globalOptionsSet(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("bad body: %v", err), http.StatusBadRequest)
		return
	}
	var globalOptions common.GlobalOptions
	err = json.Unmarshal(body, &globalOptions)
	if err != nil {
		log.Printf("globalOptionsSet: Unmarshal options error: %v", err)
		http.Error(w, fmt.Sprintf("failed to marshal json message into protobuf: %v", err), http.StatusBadRequest)
		return
	}
	err = h.manager.SetGlobalOptions(body)
	if err != nil {
		log.Printf("globalOptionsSet: %s", err)
		http.Error(w, fmt.Sprintf("failed to set global options: %s", err), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// deviceEventLogStateGet returns the current TPM event log state for the device.
func (h *adminHandler) deviceEventLogStateGet(w http.ResponseWriter, r *http.Request) {
	uid, err := uuidFromVars(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	deviceDir := h.manager.GetDevicePath(uid)
	state, err := loadEventLogState(deviceDir)
	if err != nil {
		http.Error(w, "no event log baseline found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(state)
}

// deviceEventLogActivate sets the TPM event log baseline state to active.
func (h *adminHandler) deviceEventLogActivate(w http.ResponseWriter, r *http.Request) {
	uid, err := uuidFromVars(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	deviceDir := h.manager.GetDevicePath(uid)
	state, err := loadEventLogState(deviceDir)
	if err != nil {
		http.Error(w, "no event log baseline found", http.StatusNotFound)
		return
	}

	state.State = tpmEventLogStateActive
	if err := saveEventLogState(deviceDir, state); err != nil {
		log.Printf("deviceEventLogActivate: save failed: %s", err)
		http.Error(w, "failed to save state", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

type sshKeyRequest struct {
	PublicKey string `json:"publicKey"`
}

// deviceSSHKeySet sets the SSH public key in the device config and enables SSH access.
// The key is stored as ConfigItem "debug.enable.ssh", which EVE reads to authorize the key.
func (h *adminHandler) deviceSSHKeySet(w http.ResponseWriter, r *http.Request) {
	uid, err := uuidFromVars(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}

	var req sshKeyRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if req.PublicKey == "" {
		http.Error(w, "publicKey is required", http.StatusBadRequest)
		return
	}

	existingConfigB, err := h.manager.GetConfig(uid)
	_, isNotFound := err.(*common.NotFoundError)
	switch {
	case err != nil && isNotFound:
		http.Error(w, fmt.Sprintf("device not found: %s", uid), http.StatusNotFound)
		return
	case err != nil:
		log.Printf("deviceSSHKeySet: GetConfig failed: %s", err)
		http.Error(w, "failed to get device config", http.StatusInternalServerError)
		return
	}

	var deviceConfig config.EdgeDevConfig
	if err := protojson.Unmarshal(existingConfigB, &deviceConfig); err != nil {
		log.Printf("deviceSSHKeySet: Unmarshal failed: %s", err)
		http.Error(w, "failed to parse device config", http.StatusInternalServerError)
		return
	}

	// Set or update debug.enable.ssh config item.
	const sshConfigKey = "debug.enable.ssh"
	found := false
	for _, item := range deviceConfig.ConfigItems {
		if item.Key == sshConfigKey {
			item.Value = req.PublicKey
			found = true
			break
		}
	}
	if !found {
		deviceConfig.ConfigItems = append(deviceConfig.ConfigItems, &config.ConfigItem{
			Key:   sshConfigKey,
			Value: req.PublicKey,
		})
	}

	// Bump config version.
	if deviceConfig.Id != nil {
		if v, err := strconv.Atoi(deviceConfig.Id.Version); err == nil {
			deviceConfig.Id.Version = strconv.Itoa(v + 1)
		}
	}

	jb, err := json.MarshalIndent(&deviceConfig, "", "  ")
	if err != nil {
		log.Printf("deviceSSHKeySet: Marshal failed: %s", err)
		http.Error(w, "failed to serialize config", http.StatusInternalServerError)
		return
	}

	if err := h.manager.SetConfig(uid, jb); err != nil {
		log.Printf("deviceSSHKeySet: SetConfig failed: %s", err)
		http.Error(w, "failed to save config", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// uuidFromVars extracts and parses the {uuid} path variable from the request.
func uuidFromVars(r *http.Request) (uuid.UUID, error) {
	u := mux.Vars(r)["uuid"]
	uid, err := uuid.FromString(u)
	if err != nil {
		return uuid.UUID{}, fmt.Errorf("invalid UUID %q: %w", u, err)
	}
	return uid, nil
}

// deviceUpgrade sets a BaseOS upgrade in the device config pointing to the selected image.
// EVE will download and install the image on the next config poll.
// Any existing upgrade datastore and content tree entries are replaced.
func (h *adminHandler) deviceUpgrade(w http.ResponseWriter, r *http.Request) {
	uid, err := uuidFromVars(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var req upgradeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ImageID == "" {
		http.Error(w, "imageId is required", http.StatusBadRequest)
		return
	}

	meta, err := h.imageStore.Get(req.ImageID)
	if err != nil {
		http.Error(w, "image not found", http.StatusNotFound)
		return
	}

	existingConfigB, err := h.manager.GetConfig(uid)
	_, isNotFound := err.(*common.NotFoundError)
	switch {
	case err != nil && isNotFound:
		http.Error(w, fmt.Sprintf("device not found: %s", uid), http.StatusNotFound)
		return
	case err != nil:
		log.Printf("deviceUpgrade: GetConfig failed: %s", err)
		http.Error(w, "failed to get device config", http.StatusInternalServerError)
		return
	}

	var deviceConfig config.EdgeDevConfig
	if err := protojson.Unmarshal(existingConfigB, &deviceConfig); err != nil {
		log.Printf("deviceUpgrade: Unmarshal failed: %s", err)
		http.Error(w, "failed to parse device config", http.StatusInternalServerError)
		return
	}

	// Use the configured public base URL so EVE can reach adam regardless of how the UI was accessed.
	baseURL := h.baseURL
	if baseURL == "" {
		baseURL = "https://" + r.Host
	}

	dsUUID, _ := uuid.NewV4()
	ctUUID, _ := uuid.NewV4()
	dsID := dsUUID.String()
	ctID := ctUUID.String()

	ds := &config.DatastoreConfig{
		Id:    dsID,
		DType: config.DsType_DsHttps,
		Fqdn:  baseURL,
	}
	if h.caCertPath != "" {
		caPEM, err := os.ReadFile(h.caCertPath)
		if err != nil {
			log.Printf("deviceUpgrade: reading CA cert %s: %s", h.caCertPath, err)
		} else {
			ds.DsCertPEM = [][]byte{caPEM}
		}
	}

	ct := &config.ContentTree{
		Uuid:         ctID,
		DsId:         dsID,
		URL:          "images/" + meta.ID + "/" + meta.Filename,
		Iformat:      config.Format_RAW,
		Sha256:       meta.Sha256,
		MaxSizeBytes: uint64(meta.SizeBytes),
		DisplayName:  meta.Name + " " + meta.Version,
		DsIdsList:    []string{dsID},
	}

	// Increment RetryUpdate counter from any existing baseos config.
	// This changes the config hash so EVE always reprocesses it.
	var retryCounter uint32 = 1
	if deviceConfig.Baseos != nil && deviceConfig.Baseos.RetryUpdate != nil {
		retryCounter = deviceConfig.Baseos.RetryUpdate.Counter + 1
	}

	baseos := &config.BaseOS{
		ContentTreeUuid: ctID,
		Activate:        true,
		BaseOsVersion:   meta.Version,
		RetryUpdate:     &config.DeviceOpsCmd{Counter: retryCounter},
	}

	// Remove any previous upgrade datastores and content trees, keep everything else.
	if deviceConfig.Baseos != nil {
		oldCtID := deviceConfig.Baseos.ContentTreeUuid
		var keepCT []*config.ContentTree
		for _, c := range deviceConfig.ContentInfo {
			if c.Uuid != oldCtID {
				keepCT = append(keepCT, c)
			}
		}
		// Remove the old datastore that served only the upgrade content tree.
		oldDsIDs := map[string]bool{}
		for _, c := range deviceConfig.ContentInfo {
			if c.Uuid == oldCtID {
				for _, d := range c.DsIdsList {
					oldDsIDs[d] = true
				}
			}
		}
		var keepDS []*config.DatastoreConfig
		for _, d := range deviceConfig.Datastores {
			if !oldDsIDs[d.Id] {
				keepDS = append(keepDS, d)
			}
		}
		deviceConfig.ContentInfo = keepCT
		deviceConfig.Datastores = keepDS
	}

	deviceConfig.Datastores = append(deviceConfig.Datastores, ds)
	deviceConfig.ContentInfo = append(deviceConfig.ContentInfo, ct)
	deviceConfig.Baseos = baseos

	// Bump config version.
	if deviceConfig.Id != nil {
		if v, convErr := strconv.Atoi(deviceConfig.Id.Version); convErr == nil {
			deviceConfig.Id.Version = strconv.Itoa(v + 1)
		}
	}

	jb, err := json.MarshalIndent(&deviceConfig, "", "  ")
	if err != nil {
		log.Printf("deviceUpgrade: Marshal failed: %s", err)
		http.Error(w, "failed to serialize config", http.StatusInternalServerError)
		return
	}

	if err := h.manager.SetConfig(uid, jb); err != nil {
		log.Printf("deviceUpgrade: SetConfig failed: %s", err)
		http.Error(w, "failed to save config", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

type upgradeStatus struct {
	Active  bool   `json:"active"`
	Version string `json:"version,omitempty"`
	ImageID string `json:"imageId,omitempty"`
}

// deviceUpgradeGet returns the current upgrade config for a device.
func (h *adminHandler) deviceUpgradeGet(w http.ResponseWriter, r *http.Request) {
	uid, err := uuidFromVars(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	existingConfigB, err := h.manager.GetConfig(uid)
	_, isNotFound := err.(*common.NotFoundError)
	switch {
	case err != nil && isNotFound:
		http.Error(w, fmt.Sprintf("device not found: %s", uid), http.StatusNotFound)
		return
	case err != nil:
		http.Error(w, "failed to get device config", http.StatusInternalServerError)
		return
	}

	var deviceConfig config.EdgeDevConfig
	if err := protojson.Unmarshal(existingConfigB, &deviceConfig); err != nil {
		http.Error(w, "failed to parse device config", http.StatusInternalServerError)
		return
	}

	status := upgradeStatus{}
	if deviceConfig.Baseos != nil && deviceConfig.Baseos.ContentTreeUuid != "" {
		status.Active = true
		status.Version = deviceConfig.Baseos.BaseOsVersion
		// Find the content tree to get the image URL, then match to an image in the store.
		ctID := deviceConfig.Baseos.ContentTreeUuid
		for _, ct := range deviceConfig.ContentInfo {
			if ct.Uuid == ctID {
				// Extract image ID from URL: "images/{id}/rootfs.img"
				parts := strings.Split(ct.URL, "/")
				if len(parts) >= 2 {
					status.ImageID = parts[1]
				}
				break
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

// deviceUpgradeCancel removes the current BaseOS upgrade from the device config.
func (h *adminHandler) deviceUpgradeCancel(w http.ResponseWriter, r *http.Request) {
	uid, err := uuidFromVars(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	existingConfigB, err := h.manager.GetConfig(uid)
	_, isNotFound := err.(*common.NotFoundError)
	switch {
	case err != nil && isNotFound:
		http.Error(w, fmt.Sprintf("device not found: %s", uid), http.StatusNotFound)
		return
	case err != nil:
		log.Printf("deviceUpgradeCancel: GetConfig failed: %s", err)
		http.Error(w, "failed to get device config", http.StatusInternalServerError)
		return
	}

	var deviceConfig config.EdgeDevConfig
	if err := protojson.Unmarshal(existingConfigB, &deviceConfig); err != nil {
		log.Printf("deviceUpgradeCancel: Unmarshal failed: %s", err)
		http.Error(w, "failed to parse device config", http.StatusInternalServerError)
		return
	}

	if deviceConfig.Baseos == nil || deviceConfig.Baseos.ContentTreeUuid == "" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Remove the upgrade content tree, its datastore, and clear baseos.
	oldCtID := deviceConfig.Baseos.ContentTreeUuid
	oldDsIDs := map[string]bool{}
	for _, c := range deviceConfig.ContentInfo {
		if c.Uuid == oldCtID {
			for _, d := range c.DsIdsList {
				oldDsIDs[d] = true
			}
		}
	}
	var keepCT []*config.ContentTree
	for _, c := range deviceConfig.ContentInfo {
		if c.Uuid != oldCtID {
			keepCT = append(keepCT, c)
		}
	}
	var keepDS []*config.DatastoreConfig
	for _, d := range deviceConfig.Datastores {
		if !oldDsIDs[d.Id] {
			keepDS = append(keepDS, d)
		}
	}
	deviceConfig.ContentInfo = keepCT
	deviceConfig.Datastores = keepDS
	deviceConfig.Baseos = nil

	if deviceConfig.Id != nil {
		if v, convErr := strconv.Atoi(deviceConfig.Id.Version); convErr == nil {
			deviceConfig.Id.Version = strconv.Itoa(v + 1)
		}
	}

	jb, err := json.MarshalIndent(&deviceConfig, "", "  ")
	if err != nil {
		log.Printf("deviceUpgradeCancel: Marshal failed: %s", err)
		http.Error(w, "failed to serialize config", http.StatusInternalServerError)
		return
	}
	if err := h.manager.SetConfig(uid, jb); err != nil {
		log.Printf("deviceUpgradeCancel: SetConfig failed: %s", err)
		http.Error(w, "failed to save config", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// imageList returns all uploaded images as JSON.
func (h *adminHandler) imageList(w http.ResponseWriter, r *http.Request) {
	images, err := h.imageStore.List()
	if err != nil {
		log.Printf("imageList: %s", err)
		http.Error(w, "failed to list images", http.StatusInternalServerError)
		return
	}
	if images == nil {
		images = []*ImageMeta{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(images)
}

// imageUpload accepts a multipart form with fields: name, version, file (rootfs.img).
func (h *adminHandler) imageUpload(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(2 << 30); err != nil { // 2 GiB limit
		http.Error(w, "failed to parse form", http.StatusBadRequest)
		return
	}

	name := r.FormValue("name")
	version := r.FormValue("version")
	if name == "" || version == "" {
		http.Error(w, "name and version are required", http.StatusBadRequest)
		return
	}

	file, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "file is required", http.StatusBadRequest)
		return
	}
	defer file.Close()

	idUUID, _ := uuid.NewV4()
	meta, err := h.imageStore.Save(idUUID.String(), name, version, imageUploadFilename, file)
	if err != nil {
		log.Printf("imageUpload: save failed: %s", err)
		http.Error(w, "failed to save image", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(meta)
}

// imageDelete removes an image by ID.
func (h *adminHandler) imageDelete(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if err := h.imageStore.Delete(id); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// imageServe serves the raw image file for EVE to download.
func (h *adminHandler) imageServe(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	meta, err := h.imageStore.Get(id)
	if err != nil {
		http.Error(w, "image not found", http.StatusNotFound)
		return
	}
	http.ServeFile(w, r, h.imageStore.FilePath(id, meta.Filename))
}
