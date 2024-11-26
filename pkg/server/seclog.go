// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bufio"
	"bytes"
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
)

type secLogMetadata struct {
	AggSig  string `json:"aggSig"`
	KeyIter int    `json:"keyIter"`
}

type cachedSecLogKeys struct {
	Keys         map[uint64][]byte `json:"keys"`
	Uuid         string            `json:"uuid"`
	KeyCacheBase uint64            `json:"keyCacheBase"`
	KeyCacheMax  uint64            `json:"keyCacheMax"`
}

const (
	DefaultKeyCacheBase = uint64(1000)
	DefaultKeyCacheMax  = uint64(10000)
	cachedKeysFile      = "cachedseclogkeys.json"
)

var (
	writeLogsLock sync.Mutex
	// this is the initial key, shared between EVE and controller, in production
	// this should be securely shared between the two parties.
	sk0 = []byte{
		0x12, 0x34, 0x56, 0x78,
		0x9A, 0xBC, 0xDE, 0xF0,
		0x11, 0x22, 0x33, 0x44,
		0x55, 0x66, 0x77, 0x88,
	}
)

// getLogVerficiationMetadata extracts the metadata from the gzip comment
// and returns the aggregated signature and the key iteration of the log batch.
func getLogVerficiationMetadata(gwComment string) ([]byte, uint64, error) {
	var msg secLogMetadata
	err := json.Unmarshal([]byte(gwComment), &msg)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to unmarshal metadata: %s", err)
	}

	if msg.AggSig == "" {
		return nil, 0, fmt.Errorf("aggSig is empty")
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
func isProtectedLog(payload *bytes.Reader) bool {
	gr, err := gzip.NewReader(payload)
	if err != nil {
		return false
	}
	_, _, err = getLogVerficiationMetadata(gr.Comment)
	return err == nil
}

func saveDeviceCachedKeys(devicePath string, ckey cachedSecLogKeys) error {
	// on disk, in plain text, this is a security risk and should never be done in production code.
	return cacheKeysOnDisk(devicePath, ckey)
}

func loadDeviceCachedKeys(devicePath string, ckey *cachedSecLogKeys) error {
	return loadCachedKeysFromDisk(devicePath, ckey)
}

// cacheKeysOnDisk saves the key in plain text on disk.
func cacheKeysOnDisk(devicePath string, ckey cachedSecLogKeys) error {
	keysPath := path.Join(devicePath, cachedKeysFile)
	data, err := json.Marshal(ckey)
	if err != nil {
		return fmt.Errorf("failed to marshal keys: %s", err)
	}

	fd, err := os.Create(keysPath)
	if err != nil {
		return fmt.Errorf("failed to create key file: %s", err)
	}

	fd.Write(data)
	fd.Close()
	return nil
}

// loadSecLogKeys loads the cached keys from disk.
func loadCachedKeysFromDisk(devicePath string, ckey *cachedSecLogKeys) error {
	keysPath := path.Join(devicePath, cachedKeysFile)
	fd, err := os.Open(keysPath)
	if err != nil {
		return fmt.Errorf("failed to open key file: %v", err)
	}

	decoder := json.NewDecoder(fd)
	err = decoder.Decode(ckey)
	if err != nil {
		return fmt.Errorf("failed to decode key file: %v", err)
	}

	return nil
}

// cacheSecLogKeys precomputes the keys and caches them.
// This is a performance optimization.
func cacheSecLogKeys(initialKey []byte, devicePath string, ckey *cachedSecLogKeys) error {
	ckey.Keys = make(map[uint64][]byte)
	for i := ckey.KeyCacheBase; i <= ckey.KeyCacheMax; i += ckey.KeyCacheBase {
		if i == ckey.KeyCacheBase {
			ckey.Keys[i] = evolveKey(initialKey, ckey.KeyCacheBase)
		} else {
			startingkey, KeyIndex := getClosestCachedKey(i, *ckey)
			ckey.Keys[i] = evolveKey(startingkey, i-KeyIndex)
		}
	}

	err := saveDeviceCachedKeys(devicePath, *ckey)
	if err != nil {
		return fmt.Errorf("failed to save the key cache: %v", err)
	}

	return nil
}

// growCachedSecLogKeys doubles the cached keys and saves them.
func growCachedSecLogKeys(devicePath string, ckey *cachedSecLogKeys) error {
	startingKey := ckey.Keys[ckey.KeyCacheMax]
	startingIndex := ckey.KeyCacheMax + ckey.KeyCacheBase
	ckey.KeyCacheMax = ckey.KeyCacheMax * 2

	for i := startingIndex; i <= ckey.KeyCacheMax; i += ckey.KeyCacheBase {
		if i == startingIndex {
			ckey.Keys[i] = evolveKey(startingKey, ckey.KeyCacheBase)
		} else {
			startingkey, KeyIndex := getClosestCachedKey(i, *ckey)
			ckey.Keys[i] = evolveKey(startingkey, i-KeyIndex)
		}
	}

	err := saveDeviceCachedKeys(devicePath, *ckey)
	if err != nil {
		return fmt.Errorf("failed to save key cache: %v", err)
	}

	return nil
}

// getClosestCachedKey returns the closest cached key to the requested key iteration.
func getClosestCachedKey(keyIter uint64, ckey cachedSecLogKeys) ([]byte, uint64) {
	if keyIter < ckey.KeyCacheBase {
		return nil, 0
	}

	// keyIndex is the closest key index to the requested key iteration
	// that is multiple of KeyCacheBase.
	keyIndex := (keyIter / ckey.KeyCacheBase) * ckey.KeyCacheBase
	for i := keyIndex; i <= ckey.KeyCacheMax; i = i - ckey.KeyCacheBase {
		if _, ok := ckey.Keys[i]; !ok {
			continue
		}

		return ckey.Keys[i], i
	}

	return nil, 0
}

// computeVerficationKey computes the verification key for the given initial key
// and the key iteration. If a close key is cached, it will use the cached key to
// compute the verification key and speed up the process.
func computeVerficationKey(initialKey []byte, keyIter uint64, devicePath string, ckey cachedSecLogKeys) []byte {
	// check if close key is cached first
	startingkey, KeyIndex := getClosestCachedKey(keyIter, ckey)
	if startingkey != nil {
		return evolveKey(startingkey, keyIter-KeyIndex)
	}

	// key iteration is bigger the max cached key, double the cache.
	if keyIter > ckey.KeyCacheMax {
		log.Printf("hit the max cached key (%d > %d), growing the cache...\n", keyIter, ckey.KeyCacheMax)
		err := growCachedSecLogKeys(devicePath, &ckey)
		if err != nil {
			fmt.Printf("failed to grow the cache, this might slow down the log verification.\n")
		}

		// try again to get the key from the cache
		startingkey, KeyIndex = getClosestCachedKey(keyIter, ckey)
		if startingkey != nil {
			return evolveKey(startingkey, keyIter-KeyIndex)
		}
	}

	// less than the cache base, compute the key from the initial key,
	// this is the slow path (dependig on the cach and key iteration).
	return evolveKey(initialKey, keyIter)
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

func newLogsProcessSecure(manager driver.DeviceManager, logsChannel chan []byte, u uuid.UUID, reader io.Reader) (int, error) {
	gr, err := gzip.NewReader(reader)
	if err != nil {
		return http.StatusBadRequest, fmt.Errorf("error gzip.NewReader: %v", err)
	}
	msg := &logs.LogBundle{}
	if err := json.Unmarshal([]byte(gr.Comment), msg); err != nil {
		return http.StatusBadRequest, fmt.Errorf("error parsing logbundle message from Comment: %v", err)
	}

	// to verfiy the logs we need to collect all the logs from the gzip file as
	// they appear and then verify all of them.
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

	// about to verify the logs and write them to disk, this is expensive operation,
	// launch go routine to avoid blocking the http response.
	go func() {
		ckeys := cachedSecLogKeys{}
		ckeys.Uuid = u.String()
		// load the cached keys for this device, surely we can keep these in memory,
		// but that might grow unbounded and we might run out of memory.
		devicePath := manager.GetDevicePath(u)
		err = loadDeviceCachedKeys(devicePath, &ckeys)
		if err != nil {
			log.Printf("error while reading cached keys, lets cache some keys, it is worth the time.\n")

			ckeys.KeyCacheBase = DefaultKeyCacheBase
			ckeys.KeyCacheMax = DefaultKeyCacheMax
			cacheSecLogKeys(sk0, devicePath, &ckeys)
		}

		// compute the batch verification key and verify the logs.
		verifKey := computeVerficationKey(sk0, keyIter, devicePath, ckeys)
		verfiedLogs := fssAggVer(verifKey, aggSig, collectedLogs)
		if !verfiedLogs {
			log.Printf("failed to verify the logs, consider the logs untrustworthy!!!\n")
		} else {
			log.Printf("logs bundle:\n\tverified\n\tKeyIter: %d\n", keyIter)
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
