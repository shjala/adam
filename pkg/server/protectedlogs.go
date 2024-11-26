// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bufio"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"sync"

	"github.com/lf-edge/adam/pkg/driver"
	"github.com/lf-edge/adam/pkg/driver/common"
	"github.com/lf-edge/eve-api/go/logs"
	uuid "github.com/satori/go.uuid"
	"github.com/schollz/progressbar/v3"
)

type secLogMetadata struct {
	AggSig  string `json:"aggSig"`
	KeyIter int    `json:"keyIter"`
}

type secLogConfig struct {
	KeyCacheBase uint64 `json:"keyCacheBase"`
	KeyCacheMax  uint64 `json:"keyCacheMax"`
	KeyCachePath string `json:"keyCachePath"`
}

var (
	writeLogsLock sync.Mutex
	logConfig     *secLogConfig

	// this is the initial key, shared between EVE and controller, in production
	// this should be securely shared between the two parties.
	sk0 = []byte{
		0x12, 0x34, 0x56, 0x78,
		0x9A, 0xBC, 0xDE, 0xF0,
		0x11, 0x22, 0x33, 0x44,
		0x55, 0x66, 0x77, 0x88,
	}
)

const (
	// default values
	DefaultKeyCacheBase = uint64(1000)
	DefaultKeyCacheMax  = uint64(50000)
	cachedKeysDir       = "cachedseclogkeys"
	cachedKeysConfFile  = "seclogconfig.json"
)

// CacheSecLogKeys precomputes the keys and caches them.
// This is a performance optimization, and should be done only once
// when the device is provisioned. The keys are used to verify the
// protected logs.
func CacheSecLogKeys(initialKey []byte, devicePath string, keyCacheBase uint64, KeyCacheMax uint64) error {
	err := saveSecLogConfig(devicePath, keyCacheBase, KeyCacheMax)
	if err != nil {
		return fmt.Errorf("failed to save seclogconfig: %s", err)
	}

	// create the directory to store the keys
	keysPath := path.Join(devicePath, cachedKeysDir)
	err = os.Mkdir(keysPath, 0755)
	if err != nil {
		return fmt.Errorf("failed to create seclogkeys directory: %s", err)
	}

	// precompute keys to the reqested range and cache them
	bar := progressbar.Default(int64(KeyCacheMax / keyCacheBase))
	for i := keyCacheBase; i <= KeyCacheMax; i += keyCacheBase {
		keyPath := path.Join(keysPath, fmt.Sprintf("key_%d", i))

		// compute the key and chache it
		key := common.EvolveKey(initialKey, uint64(i))
		err = cacheKeyOnDisk(keyPath, key)
		if err != nil {
			return fmt.Errorf("failed to save key file: %v", err)
		}

		bar.Add(1)
	}

	return nil
}

// cacheKeyOnDisk saves the key in plain text on disk,
// this is a security risk and should never be done in production code.
func cacheKeyOnDisk(keysPath string, key []byte) error {
	fd, err := os.Create(keysPath)
	if err != nil {
		return fmt.Errorf("failed to create key file: %s", err)
	}

	// NEVER EVER DO THIS IN PRODUCTION CODE!!! This is a security risk.
	// We are writing the key to disk in plain text. This is only for
	// demonstration purposes. In production, you should encrypt the key
	// before saving it (disk or db) or even better, compute it at runtime
	// and keep in a locked memory area.
	fd.Write(key)
	fd.Close()
	return nil
}

// saveSecLogConfig saves the seclogconfig to disk for later use,
// when server restarts, it will load the config from disk.
func saveSecLogConfig(devicePath string, keyCacheBase uint64, keyCacheMax uint64) error {
	configPath := path.Join(devicePath, cachedKeysConfFile)
	fd, err := os.Create(configPath)
	if err != nil {
		return fmt.Errorf("failed to create seclogconfig file: %s", err)
	}
	defer fd.Close()

	conf := secLogConfig{
		KeyCacheBase: keyCacheBase,
		KeyCacheMax:  keyCacheMax,
		KeyCachePath: path.Join(devicePath, cachedKeysDir),
	}
	enc := json.NewEncoder(fd)
	err = enc.Encode(conf)
	if err != nil {
		return fmt.Errorf("failed to save seclogconfig file: %s", err)
	}

	return nil
}

// loadSecLogConfig loads the seclogconfig from disk, if it exists.
func loadSecLogConfig(devicePath string, conf *secLogConfig) error {
	configPath := path.Join(devicePath, cachedKeysConfFile)
	fd, err := os.Open(configPath)
	if err != nil {
		return fmt.Errorf("failed to open seclogconfig file: %s", err)
	}
	defer fd.Close()

	dec := json.NewDecoder(fd)
	err = dec.Decode(conf)
	if err != nil {
		return fmt.Errorf("failed to decode seclogconfig file: %s", err)
	}

	return nil
}

// getLogVerficiationMetadata extracts the metadata from the gzip comment
// and returns the aggregated signature and the key iteration.
func getLogVerficiationMetadata(gwComment string) ([]byte, uint64, error) {
	var msg secLogMetadata
	err := json.Unmarshal([]byte(gwComment), &msg)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to unmarshal metadata: %s", err)
	}

	// decode the signature
	mac, err := base64.StdEncoding.DecodeString(msg.AggSig)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to decode signature: %s", err)
	}

	return mac, uint64(msg.KeyIter), nil
}

// isProtectedLog checks if the log is protected by checking the gzip comment
// for the metadata. If the metadata is present, the log is considered protected.
func isProtectedLog(reader io.Reader) bool {
	gr, err := gzip.NewReader(reader)
	if err != nil {
		return false
	}
	_, _, err = getLogVerficiationMetadata(gr.Comment)
	return err == nil
}

// tagVerfiedLogEntry tags the log entry as verified by adding a "verified" field
// to the log entry.
func tagVerfiedLogEntry(entry []byte) ([]byte, error) {
	entryMap := make(map[string]interface{})
	if err := json.Unmarshal(entry, &entryMap); err != nil {
		return nil, fmt.Errorf("failed to unmarshal log entry: %v", err)
	}

	// tag the entry as verified
	entryMap["verified"] = true
	taggedEntry, err := json.MarshalIndent(entryMap, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal log entry: %v", err)
	}

	return taggedEntry, nil
}

// getClosestCachedKey returns the closest cached key to the requested key iteration.
func getClosestCachedKey(keyIter uint64, conf secLogConfig) ([]byte, uint64) {
	if keyIter < conf.KeyCacheBase {
		return nil, 0
	}

	// keyIndex is the closest key index to the requested key iteration
	// that is multiple of KeyCacheBase.
	keyIndex := (keyIter / conf.KeyCacheBase) * conf.KeyCacheBase

	// check if the key is cached, if not try the next closest key till we reach
	// the base key.
	for i := keyIndex; i < conf.KeyCacheMax; i = i - conf.KeyCacheBase {
		keyPath := path.Join(conf.KeyCachePath, fmt.Sprintf("key_%d", i))
		key, err := os.ReadFile(keyPath)
		if err != nil {
			continue
		}

		return key, i
	}

	return nil, 0
}

// computeVerficationKey computes the verification key for the given initial key
// and the key iteration. If the key is cached, it will use the cached key to
// compute the verification key.
func computeVerficationKey(initialKey []byte, keyIter uint64, conf secLogConfig) []byte {
	// check if the key is cached first, this is a performance optimization
	startingkey, KeyIndex := getClosestCachedKey(keyIter, conf)
	if startingkey != nil {
		// there is opurtunity to cache more intermidiate keys here,
		// but this will suffice for now.
		return common.EvolveKey(startingkey, keyIter-KeyIndex)
	}

	log.Printf("Cache miss detected. Key calculation is required, and log verification might take longer than expected.")

	// get the closest key and cache it first (same as above, we can cache all
	// the intermidate keys here, but this will suffice for now).
	keyIndex := (keyIter / conf.KeyCacheBase) * conf.KeyCacheBase
	interimKey := common.EvolveKey(initialKey, keyIndex)
	cacheKeyOnDisk(path.Join(conf.KeyCachePath, fmt.Sprintf("key_%d", keyIndex)), interimKey)

	// then compute and return the requested key
	return common.EvolveKey(interimKey, keyIter-keyIndex)
}

func newLogsProcessSecure(manager driver.DeviceManager, logsChannel chan []byte, u uuid.UUID, reader io.Reader) (int, error) {
	gr, err := gzip.NewReader(reader)
	if err != nil {
		return http.StatusBadRequest, fmt.Errorf("error gzip.NewReader: %v", err)
	}
	msg := &logs.LogBundle{}
	if err := json.Unmarshal([]byte(gr.Comment), msg); err != nil {
		return http.StatusBadRequest, fmt.Errorf("error parsing logbundle message from Comment: %v", err)
	}

	// verfiy the logs first, in order to do it we need to collect all the logs
	// from the gzip file as they appear and then verify all of them.
	verfiedLogs := true
	aggSig, keyIter, err := getLogVerficiationMetadata(gr.Comment)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("failed to get log verification metadata: %v", err)
	}
	collectedLogs := make([][]byte, 0)
	scanner := bufio.NewScanner(gr)
	for scanner.Scan() {
		if !json.Valid(scanner.Bytes()) {
			return http.StatusInternalServerError, fmt.Errorf("invalid log entry: %s", scanner.Text())
		}
		collectedLogs = append(collectedLogs, append([]byte(nil), scanner.Bytes()...))
	}

	// load the seclogconfig if not already loaded, it is needed to compute the
	// verification key.
	if logConfig == nil {
		logConfig = &secLogConfig{}
		err = loadSecLogConfig(manager.GetDevicePath(u), logConfig)
		if err != nil {
			return http.StatusInternalServerError, fmt.Errorf("failed to load seclogconfig: %v", err)
		}
	}

	// about to verify the logs and write them to disk, this is expensive operation,
	// launch go routine to avoid blocking the http response.
	go func() {
		// compute the batch verification key and verify the logs.
		verifKey := computeVerficationKey(sk0, keyIter, *logConfig)
		res := common.FssAggVer(verifKey, aggSig, collectedLogs)
		if !res {
			log.Printf("failed to verify the logs, consider the logs unprotected.\n")
			verfiedLogs = false
		} else {
			log.Printf("logs bundle verified.\n")
		}

		// about to write logs, acquire the writeLogsLock
		writeLogsLock.Lock()
		defer writeLogsLock.Unlock()

		for _, l := range collectedLogs {
			le := &logs.LogEntry{}
			if err := json.Unmarshal(l, le); err != nil {
				log.Printf("failed to unmarshal log entry: %v\n", err)
				continue
			}
			entry := &common.FullLogEntry{
				LogEntry:   le,
				Image:      msg.GetImage(),
				EveVersion: msg.GetEveVersion(),
			}
			var entryBytes []byte
			if entryBytes, err = entry.Json(); err != nil {
				log.Printf("failed to marshal log entry: %v\n", err)
				continue
			}
			select {
			case logsChannel <- entryBytes:
			default:
			}

			// if verfication was successful, tag the log entry as verified.
			if verfiedLogs {
				taggedEntry, err := tagVerfiedLogEntry(entryBytes)
				if err != nil {
					log.Printf("failed to tag verified log entry: %v\n", err)
				} else {
					entryBytes = taggedEntry
				}
			}

			err = manager.WriteLogs(u, entryBytes)
			if err != nil {
				log.Printf("failed to write logs message: %v\n", err)
				continue
			}
		}
	}()

	// send back a 201
	return http.StatusCreated, nil
}
