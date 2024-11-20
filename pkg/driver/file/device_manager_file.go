// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package file

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/lf-edge/adam/pkg/driver/common"
	ax "github.com/lf-edge/adam/pkg/x509"
	eveuuid "github.com/lf-edge/eve-api/go/eveuuid"
	"github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve-api/go/metrics"
	uuid "github.com/satori/go.uuid"
	"google.golang.org/protobuf/proto"
)

var witeLock = sync.Mutex{}

const (
	deviceCertFilename        = "device-certificate.pem"
	deviceOnboardCertFilename = "onboard-certificate.pem"
	deviceOnboardedFilename   = "onboarded"
	deviceConfigFilename      = "config.json"
	deviceAttestCertsFilename = "certs.json"
	deviceStorageKeysFilename = "storage-keys.json"
	deviceSerialFilename      = "serial.txt"
	deviceOptionsFilename     = "options.json"
	globalOptionsFilename     = "global-options.json"
	logDir                    = "logs"
	metricsDir                = "metrics"
	infoDir                   = "info"
	deviceDir                 = "device"
	requestsDir               = "requests"
	flowMessageDir            = "flow_message"
	MB                        = common.MB
	maxLogSizeFile            = 100 * MB
	maxInfoSizeFile           = 100 * MB
	maxMetricSizeFile         = 100 * MB
	maxRequestsSizeFile       = 100 * MB
	maxAppLogsSizeFile        = 100 * MB
	maxFlowMessageSizeFile    = 100 * MB
	fileSplit                 = 10
)

type ManagedFile struct {
	dir         string
	file        *os.File
	maxSize     int64
	currentSize int64
	totalSize   int64
}

// DeviceManager implementation of DeviceManager interface with a directory as the backing store
type DeviceManager struct {
	databasePath       string
	maxLogSize         int
	maxInfoSize        int
	maxMetricSize      int
	maxRequestsSize    int
	maxFlowMessageSize int
	maxAppLogsSize     int
	devices            map[uuid.UUID]common.DeviceStorage
}

func (m *ManagedFile) Get(index int) ([]byte, error) {
	return nil, errors.New("unsupported")
}

func (m *ManagedFile) Write(b []byte) (int, error) {
	if m.file == nil {
		f, err := openTimestampFile(m.dir)
		if err != nil {
			return 0, fmt.Errorf("failed to open file: %v", err)
		}
		m.file = f
	}
	written, err := m.file.Write(append(b, '\n'))
	if err != nil {
		return 0, fmt.Errorf("failed to write log: %v", err)
	}
	m.file.Sync()
	m.currentSize += int64(written)
	m.totalSize += int64(written)

	// do we need to open a new file?
	if m.currentSize > m.maxSize/fileSplit {
		m.file.Close()
		f, err := openTimestampFile(m.dir)
		if err != nil {
			return 0, fmt.Errorf("failed top open file: %v", err)
		}
		// use the new log file pointer and reset the size
		m.file = f
		m.currentSize = 0
	}

	if m.totalSize > m.maxSize {
		// get all of the files from the directory
		fi, err := os.ReadDir(m.dir)
		if err != nil {
			return written, fmt.Errorf("could not read directory %s: %v", m.dir, err)
		}
		// sort the file names
		sort.Slice(fi, func(i int, j int) bool {
			return fi[i].Name() < fi[j].Name()
		})
		for _, f := range fi {
			if m.totalSize < m.maxSize {
				break
			}
			filename := path.Join(m.dir, f.Name())
			fileInfo, err := os.Stat(filename)
			if err != nil {
				return written, fmt.Errorf("could not get file info for %s: %v", filename, err)
			}
			size := fileInfo.Size()
			if err := os.Remove(filename); err != nil {
				return written, fmt.Errorf("failed to remove %s: %v", filename, err)
			}
			m.totalSize -= size
		}
	}

	return written, nil
}

func (m *ManagedFile) Reader() (common.ChunkReader, error) {
	r := &DirReader{
		Path: m.dir,
	}
	return r, nil
}

// Name return name
func (d *DeviceManager) Name() string {
	return "file"
}

// Database return database path
func (d *DeviceManager) Database() string {
	return d.databasePath
}

// MaxLogSize return the default maximum log size in bytes for this device manager
func (d *DeviceManager) MaxLogSize() int {
	return maxLogSizeFile
}

// MaxInfoSize return the default maximum info size in bytes for this device manager
func (d *DeviceManager) MaxInfoSize() int {
	return maxInfoSizeFile
}

// MaxMetricSize return the maximum metrics size in bytes for this device manager
func (d *DeviceManager) MaxMetricSize() int {
	return maxMetricSizeFile
}

// MaxRequestsSize return the maximum request logs size in bytes for this device manager
func (d *DeviceManager) MaxRequestsSize() int {
	return maxRequestsSizeFile
}

// MaxAppLogsSize return the maximum app logs size in bytes for this device manager
func (d *DeviceManager) MaxAppLogsSize() int {
	return maxAppLogsSizeFile
}

// MaxFlowMessageSize return the maximum FlowMessage logs size in bytes for this device manager
func (d *DeviceManager) MaxFlowMessageSize() int {
	return maxFlowMessageSizeFile
}

// Init check if a URL is valid and initialize
func (d *DeviceManager) Init(s string, sizes common.MaxSizes) (bool, error) {
	witeLock.Lock()
	defer witeLock.Unlock()

	// parse the URL
	// we accept the following:
	// - scheme = file
	// - invalid URL (everything is path)
	URL, err := url.Parse(s)
	if err != nil {
		return false, err
	}
	if URL.Scheme != "file" && URL.Scheme != "" {
		return false, nil
	}
	fi, err := os.Stat(s)
	if err == nil && !fi.IsDir() {
		return false, fmt.Errorf("database path %s exists and is not a directory", s)
	}
	// we use MkdirAll, since we are willing to continue if the directory already exists; we only error if we cannot make it
	err = os.MkdirAll(s, 0755)
	if err != nil {
		return false, fmt.Errorf("could not create database path %s: %v", s, err)
	}
	d.databasePath = s

	// ensure everything exists
	err = d.initializeDB()
	if err != nil {
		return false, err
	}

	if sizes.MaxLogSize == 0 {
		d.maxLogSize = maxLogSizeFile
	} else {
		d.maxLogSize = sizes.MaxLogSize
	}
	if sizes.MaxInfoSize == 0 {
		d.maxInfoSize = maxInfoSizeFile
	} else {
		d.maxInfoSize = sizes.MaxInfoSize
	}
	if sizes.MaxMetricSize == 0 {
		d.maxMetricSize = maxMetricSizeFile
	} else {
		d.maxMetricSize = sizes.MaxMetricSize
	}
	if sizes.MaxRequestsSize == 0 {
		d.maxRequestsSize = maxRequestsSizeFile
	} else {
		d.maxRequestsSize = sizes.MaxRequestsSize
	}
	if sizes.MaxAppLogsSize == 0 {
		d.maxAppLogsSize = maxAppLogsSizeFile
	} else {
		d.maxAppLogsSize = sizes.MaxAppLogsSize
	}
	if sizes.MaxFlowMessageSize == 0 {
		d.maxFlowMessageSize = maxFlowMessageSizeFile
	} else {
		d.maxFlowMessageSize = sizes.MaxFlowMessageSize
	}

	err = d.refreshCache()
	if err != nil {
		return false, fmt.Errorf("unable to load cache filesystem: %v", err)
	}

	return true, nil
}

// SetCacheTimeout set the timeout for refreshing the cache, unused in memory
func (d *DeviceManager) SetCacheTimeout(timeout int) {
	// unused
}

// FindDevicebyCert see if a particular certificate is a valid registered device certificate
func (d *DeviceManager) FindDevicebyCert(cert *x509.Certificate) (*uuid.UUID, error) {
	for _, dev := range d.devices {
		if dev.DeviceCert != nil && bytes.Equal(dev.DeviceCert.Raw, cert.Raw) {
			return &dev.UUID, nil
		}
	}

	return nil, fmt.Errorf("device not found")
}

// FindDevicebyCertHash see if a particular certificate hash is a valid registered device certificate
func (d *DeviceManager) FindDevicebyCertHash(hash []byte) (*uuid.UUID, error) {
	if hash == nil {
		return nil, fmt.Errorf("invalid empty hash")
	}

	for _, dev := range d.devices {
		if dev.DeviceCert != nil {
			s := sha256.Sum256(dev.DeviceCert.Raw)
			if bytes.Equal(hash, s[:]) {
				return &dev.UUID, nil
			}
		}
	}

	return nil, fmt.Errorf("device not found")
}

// DeviceRemove remove a device
func (d *DeviceManager) DeviceRemove(u *uuid.UUID) error {
	witeLock.Lock()
	defer witeLock.Unlock()

	_, _, _, _, err := d.DeviceGet(u)
	if err != nil {
		return err
	}

	// remove the directory
	devicePath := d.GetDevicePath(*u)
	err = os.RemoveAll(devicePath)
	if err != nil {
		return fmt.Errorf("unable to remove the device directory: %v", err)
	}

	// refresh the cache
	err = d.refreshCache()
	if err != nil {
		return fmt.Errorf("unable to refresh certs from filesystem: %v", err)
	}

	return nil
}

// DeviceClear remove all devices
func (d *DeviceManager) DeviceClear() error {
	witeLock.Lock()
	defer witeLock.Unlock()

	// remove the directory and clear the cache
	devicePath := path.Join(d.databasePath, deviceDir)
	candidates, err := os.ReadDir(devicePath)
	if err != nil {
		return fmt.Errorf("unable to read device certificates at %s: %v", devicePath, err)
	}

	// remove each directory
	for _, fi := range candidates {
		// we only are interested in directories
		if !fi.IsDir() {
			continue
		}
		name := fi.Name()
		f := path.Join(devicePath, name)
		err = os.RemoveAll(f)
		if err != nil {
			return fmt.Errorf("unable to remove the device directory: %v", err)
		}
	}

	// refresh the cache
	err = d.refreshCache()
	if err != nil {
		return fmt.Errorf("unable to refresh certs from filesystem: %v", err)
	}

	return nil
}

// DeviceGet get an individual device by UUID
func (d *DeviceManager) DeviceGet(u *uuid.UUID) (*x509.Certificate, *x509.Certificate, string, bool, error) {
	if u == nil {
		return nil, nil, "", false, fmt.Errorf("empty UUID")
	}

	dev, ok := d.devices[*u]
	if !ok {
		return nil, nil, "", false, fmt.Errorf("device not found: %s", u)
	}

	return dev.DeviceCert, dev.OnboardCert, dev.Serial, dev.Onboarded, nil
}

// DeviceList list all of the known UUIDs for devices
func (d *DeviceManager) DeviceList() ([]*uuid.UUID, error) {
	ids := make([]uuid.UUID, 0, len(d.devices))
	for u := range d.devices {
		ids = append(ids, u)
	}
	pids := make([]*uuid.UUID, 0, len(ids))
	for i := range ids {
		pids = append(pids, &ids[i])
	}
	return pids, nil
}

// initDevice initialize all structures for one device
func (d *DeviceManager) initDeviceDirs(dev *common.DeviceStorage) error {
	// create filesystem tree and subdirs for the new device
	devicePath := d.GetDevicePath(dev.UUID)
	err := os.MkdirAll(devicePath, 0755)
	if err != nil {
		return fmt.Errorf("error creating new device tree %s: %v", devicePath, err)
	}

	// create the necessary directories for data uploads
	for _, p := range []string{logDir, metricsDir, infoDir, requestsDir} {
		cur := path.Join(devicePath, p)
		err = os.MkdirAll(cur, 0755)
		if err != nil {
			return fmt.Errorf("error creating new device sub-path %s: %v", cur, err)
		}
	}

	return nil
}

// initDevice initialize all structures for one device
func (d *DeviceManager) initDevice(dev *common.DeviceStorage) {
	// create filesystem tree and subdirs for the new device
	devicePath := d.GetDevicePath(dev.UUID)
	dev.Logs = &ManagedFile{
		dir:     path.Join(devicePath, logDir),
		maxSize: int64(d.maxLogSize),
	}
	dev.Info = &ManagedFile{
		dir:     path.Join(devicePath, infoDir),
		maxSize: int64(d.maxInfoSize),
	}
	dev.Metrics = &ManagedFile{
		dir:     path.Join(devicePath, metricsDir),
		maxSize: int64(d.maxMetricSize),
	}
	dev.Requests = &ManagedFile{
		dir:     path.Join(devicePath, requestsDir),
		maxSize: int64(d.maxRequestsSize),
	}
	dev.FlowMessage = &ManagedFile{
		dir:     path.Join(devicePath, flowMessageDir),
		maxSize: int64(d.maxFlowMessageSize),
	}
	dev.AppLogs = map[uuid.UUID]common.BigData{}
}

// DeviceRegister register a new device
func (d *DeviceManager) DeviceRegister(unew uuid.UUID, cert, onboard *x509.Certificate, serial string, conf []byte) error {
	witeLock.Lock()
	defer witeLock.Unlock()

	if onboard == nil || cert == nil || serial == "" {
		return fmt.Errorf("invalid parameters")
	}
	// check if it already exists with the same certs
	for _, dev := range d.devices {
		if dev.Serial == serial && dev.DeviceCert != nil && dev.OnboardCert != nil &&
			bytes.Equal(dev.DeviceCert.Raw, cert.Raw) && bytes.Equal(dev.OnboardCert.Raw, onboard.Raw) {
			return fmt.Errorf("device already exists: %s", dev.UUID)
		}
	}

	device := common.DeviceStorage{}
	device.UUID = unew
	d.initDevice(&device)
	if err := d.initDeviceDirs(&device); err != nil {
		return fmt.Errorf("unable to initialize device structure for device %s: %v", unew, err)
	}
	devicePath := d.GetDevicePath(unew)

	// save the device certificate
	certPath := path.Join(devicePath, deviceCertFilename)
	err := ax.WriteCert(cert.Raw, certPath, true)
	if err != nil {
		return fmt.Errorf("error saving device certificate to %s: %v", certPath, err)
	}

	// save the onboard certificate and serial
	certPath = path.Join(devicePath, deviceOnboardCertFilename)
	err = ax.WriteCert(onboard.Raw, certPath, true)
	if err != nil {
		return fmt.Errorf("error saving device onboard certificate to %s: %v", certPath, err)
	}

	// save the serial
	serialPath := path.Join(devicePath, deviceSerialFilename)
	err = os.WriteFile(serialPath, []byte(serial), 0644)
	if err != nil {
		return fmt.Errorf("error saving device serial to %s: %v", serialPath, err)
	}

	// save the base configuration
	err = d.writeDeviceFile(unew, "", deviceConfigFilename, conf)
	if err != nil {
		return fmt.Errorf("error saving device config to %s: %v", deviceConfigFilename, err)
	}

	// refresh the cache
	err = d.refreshCache()
	if err != nil {
		return fmt.Errorf("unable to refresh certs from filesystem: %v", err)
	}

	return nil
}

// OnboardDevice onboards a existing device
func (d *DeviceManager) OnboardDevice(deviceCert *x509.Certificate, onboardCert *x509.Certificate, serial string) error {
	witeLock.Lock()
	defer witeLock.Unlock()

	uid := uuid.Nil
	for _, dev := range d.devices {
		// check if the device is already onboarded
		if dev.Onboarded {
			return fmt.Errorf("device already onboarded: %s", dev.UUID)
		}
		// check if the onboard certificate matches
		if !bytes.Equal(dev.OnboardCert.Raw, onboardCert.Raw) {
			continue
		}
		// check if the serial matches
		if dev.Serial != serial {
			continue
		}

		uid = dev.UUID
		break
	}
	if uid == uuid.Nil {
		return fmt.Errorf("device not found")
	}

	devicePath := d.GetDevicePath(uid)
	// save the onboarded file
	onboardedPath := path.Join(devicePath, deviceOnboardedFilename)
	err := os.WriteFile(onboardedPath, []byte{}, 0644)
	if err != nil {
		return fmt.Errorf("error saving onboarded file to %s: %v", onboardedPath, err)
	}

	// update the device cert in file
	certPath := path.Join(devicePath, deviceCertFilename)
	err = ax.WriteCert(deviceCert.Raw, certPath, true)
	if err != nil {
		return fmt.Errorf("error saving device certificate to %s: %v", certPath, err)
	}

	// refresh the cache
	err = d.refreshCache()
	if err != nil {
		return fmt.Errorf("unable to refresh certs from filesystem: %v", err)
	}

	return nil
}

// WriteRequest record a request
func (d *DeviceManager) WriteRequest(u uuid.UUID, bj []byte) error {
	if bj == nil || len(bj) < 1 {
		return nil
	}

	// check that the device actually exists
	if !d.deviceExists(u) {
		return fmt.Errorf("unregistered device UUID: %s", u)
	}

	dev := d.devices[u]
	return dev.AddRequest(bj)
}

// WriteInfo write an info message
func (d *DeviceManager) WriteInfo(u uuid.UUID, b []byte) error {
	if b == nil || len(b) < 1 {
		return nil
	}

	// check that the device actually exists
	if !d.deviceExists(u) {
		return fmt.Errorf("unregistered device UUID: %s", u)
	}

	var i info.ZInfoMsg
	err := proto.Unmarshal(b, &i)
	if err != nil {
		return fmt.Errorf("unable to unmarshal info: %v", err)
	}
	bj, err := json.MarshalIndent(i, "", "  ")
	if err != nil {
		return fmt.Errorf("unable to marshal info: %v", err)
	}

	dev := d.devices[u]
	return dev.AddInfo(bj)
}

// WriteLogs write a message of logs
func (d *DeviceManager) WriteLogs(u uuid.UUID, b []byte) error {
	if b == nil || len(b) < 1 {
		return nil
	}

	// check that the device actually exists
	if !d.deviceExists(u) {
		return fmt.Errorf("unregistered device UUID: %s", u)
	}

	dev := d.devices[u]
	return dev.AddLogs(b)
}

// appExists return if an app has been created
func (d *DeviceManager) appExists(u, instanceID uuid.UUID) bool {
	_, err := os.Stat(d.GetAppPath(u, instanceID))
	if err != nil {
		return false
	}
	if _, ok := d.devices[u]; !ok {
		return false
	}
	return true
}

// WriteAppInstanceLogs write a message of AppInstanceLogBundle
func (d *DeviceManager) WriteAppInstanceLogs(instanceID uuid.UUID, deviceID uuid.UUID, b []byte) error {
	// make sure it is not nil
	if b == nil || len(b) < 1 {
		return nil
	}
	// get the uuid
	// check that the device actually exists
	if !d.deviceExists(deviceID) {
		return fmt.Errorf("unregistered device UUID: %s", deviceID)
	}
	if !d.appExists(deviceID, instanceID) {
		d.devices[deviceID].AppLogs[instanceID] = &ManagedFile{
			dir:     d.GetAppPath(deviceID, instanceID),
			maxSize: int64(d.maxAppLogsSize),
		}
	}
	dev := d.devices[deviceID]
	return dev.AddAppLog(instanceID, b)
}

// WriteMetrics write a metrics message
func (d *DeviceManager) WriteMetrics(u uuid.UUID, b []byte) error {
	// make sure it is not nil
	if b == nil || len(b) < 1 {
		return nil
	}
	// check that the device actually exists
	if !d.deviceExists(u) {
		return fmt.Errorf("unregistered device UUID: %s", u)
	}

	var m metrics.ZMetricMsg
	err := proto.Unmarshal(b, &m)
	if err != nil {
		return fmt.Errorf("unable to unmarshal metrics: %v", err)
	}
	bj, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("unable to marshal metrics: %v", err)
	}

	dev := d.devices[u]
	return dev.AddMetrics(bj)
}

// WriteCerts write an attestation certs information
func (d *DeviceManager) WriteAttestCerts(u uuid.UUID, b []byte) error {
	witeLock.Lock()
	defer witeLock.Unlock()

	if b == nil || len(b) < 1 {
		return nil
	}

	// look up the device by uuid
	_, ok := d.devices[u]
	if !ok {
		return fmt.Errorf("unregistered device UUID %s", u.String())
	}
	if len(b) < 1 {
		return fmt.Errorf("empty configuration")
	}

	err := d.writeDeviceFile(u, "", deviceAttestCertsFilename, b)
	if err != nil {
		return fmt.Errorf("error saving attestation to %s: %v", deviceAttestCertsFilename, err)
	}

	err = d.refreshCache()
	if err != nil {
		return fmt.Errorf("unable to refresh certs from filesystem: %v", err)
	}

	return nil
}

// GetCerts retrieve the attest certs for a particular device
func (d *DeviceManager) GetCerts(u uuid.UUID) ([]byte, error) {
	// read the config from disk
	fullAttestPath := path.Join(d.GetDevicePath(u), deviceAttestCertsFilename)
	b, err := os.ReadFile(fullAttestPath)
	if err != nil {
		return nil, fmt.Errorf("could not read certificates from %s: %v", fullAttestPath, err)
	}

	return b, nil
}

// WriteStorageKeys write storage keys information
func (d *DeviceManager) WriteStorageKeys(u uuid.UUID, b []byte) error {
	witeLock.Lock()
	defer witeLock.Unlock()

	// look up the device by uuid
	_, ok := d.devices[u]
	if !ok {
		return fmt.Errorf("unregistered device UUID %s", u.String())
	}
	if b == nil || len(b) < 1 {
		return fmt.Errorf("empty configuration")
	}
	err := d.writeDeviceFile(u, "", deviceStorageKeysFilename, b)
	if err != nil {
		return fmt.Errorf("error saving storage keys to %s: %v", deviceStorageKeysFilename, err)
	}

	// refresh cache from filesystem, if needed - includes checking if necessary based on timer
	err = d.refreshCache()
	if err != nil {
		return fmt.Errorf("unable to refresh cache from filesystem: %v", err)
	}
	return nil
}

// GetStorageKeys retrieve storage keys for a particular device
func (d *DeviceManager) GetStorageKeys(u uuid.UUID) ([]byte, error) {
	// read storage keys from disk
	fullStorageKeysPath := path.Join(d.GetDevicePath(u), deviceStorageKeysFilename)
	b, err := os.ReadFile(fullStorageKeysPath)
	if err != nil {
		return nil, fmt.Errorf("could not read storage keys from %s: %v", fullStorageKeysPath, err)
	}

	return b, nil
}

// GetConfig retrieve the config for a particular device
func (d *DeviceManager) GetConfig(u uuid.UUID) ([]byte, error) {
	witeLock.Lock()
	defer witeLock.Unlock()

	// read the config from disk
	fullConfigPath := path.Join(d.GetDevicePath(u), deviceConfigFilename)
	b, err := os.ReadFile(fullConfigPath)
	if err != nil {
		return nil, fmt.Errorf("could not read config from %s: %v", fullConfigPath, err)
	}

	return b, nil
}

// SetConfig set the config for a particular device
func (d *DeviceManager) SetConfig(u uuid.UUID, b []byte) error {
	witeLock.Lock()
	defer witeLock.Unlock()

	// look up the device by uuid
	_, ok := d.devices[u]
	if !ok {
		return fmt.Errorf("unregistered device UUID %s", u.String())
	}
	if len(b) < 1 {
		return fmt.Errorf("empty configuration")
	}
	// save the base configuration
	err := d.writeDeviceFile(u, "", deviceConfigFilename, b)
	if err != nil {
		return fmt.Errorf("error saving device config to %s: %v", deviceConfigFilename, err)
	}

	err = d.refreshCache()
	if err != nil {
		return fmt.Errorf("unable to refresh certs from filesystem: %v", err)
	}
	return nil
}

// refreshCache refresh cache from disk
func (d *DeviceManager) refreshCache() error {
	d.devices = make(map[uuid.UUID]common.DeviceStorage)
	// scan the device path for each dir which is the UUID
	//   and in each one, if a cert exists with the appropriate name, load it
	devicePath := path.Join(d.databasePath, deviceDir)
	candidates, err := os.ReadDir(devicePath)
	if err != nil {
		return fmt.Errorf("unable to read devices at %s: %v", devicePath, err)
	}
	// check each directory to see if it is a valid device directory
	for _, fi := range candidates {
		// we only are interested in directories
		if !fi.IsDir() {
			continue
		}
		name := fi.Name()
		// convert the path name to a UUID
		u, err := uuid.FromString(name)
		if err != nil {
			return fmt.Errorf("unable to convert device uuid from directory name %s: %v", name, err)
		}

		device := common.DeviceStorage{}
		device.UUID = u
		d.initDevice(&device)
		if err := d.initDeviceDirs(&device); err != nil {
			return fmt.Errorf("unable to initialize device structure for device %s: %v", u, err)
		}

		// get the device path
		devicePath := d.GetDevicePath(u)

		// load the device certificate
		f := path.Join(devicePath, deviceCertFilename)
		_, err = os.Stat(f)
		if err != nil {
			return fmt.Errorf("unable to list device certificate file %s: %v", f, err)
		}
		b, err := os.ReadFile(f)
		if err != nil {
			return fmt.Errorf("unable to read device certificate file %s: %v", f, err)
		}
		certPem, _ := pem.Decode(b)
		cert, err := x509.ParseCertificate(certPem.Bytes)
		if err != nil {
			return fmt.Errorf("unable to convert data from file %s to device certificate: %v", f, err)
		}
		device.DeviceCert = cert

		// load the device onboarding certificate
		f = path.Join(devicePath, deviceOnboardCertFilename)
		_, err = os.Stat(f)
		if err != nil {
			return fmt.Errorf("unable to list device onboard certificate file %s: %v", f, err)
		}
		b, err = os.ReadFile(f)
		if err != nil {
			return fmt.Errorf("unable to read device onboard certificate file %s: %v", f, err)
		}
		certPem, _ = pem.Decode(b)
		cert, err = x509.ParseCertificate(certPem.Bytes)
		if err != nil {
			return fmt.Errorf("unable to convert data from file %s to device onboard certificate: %v", f, err)
		}
		device.OnboardCert = cert

		// and the serial
		f = path.Join(devicePath, deviceSerialFilename)
		_, err = os.Stat(f)
		if err != nil {
			return fmt.Errorf("unable to list device serial file %s: %v", f, err)
		}
		b, err = os.ReadFile(f)
		if err != nil {
			return fmt.Errorf("unable to read device serial file %s: %v", f, err)
		}
		device.Serial = string(b)

		// read the onboarded file
		f = path.Join(devicePath, deviceOnboardedFilename)
		_, err = os.Stat(f)
		if err != nil {
			if os.IsNotExist(err) {
				device.Onboarded = false
			} else {
				return fmt.Errorf("unable to list onboarded file %s: %v", f, err)
			}
		} else {
			device.Onboarded = true
		}

		d.devices[u] = device
	}

	return nil
}

// initialize dirs, in case they do not exist
func (d *DeviceManager) initializeDB() error {
	pdir := path.Join(d.databasePath, deviceDir)
	err := os.MkdirAll(pdir, 0755)
	if err != nil {
		return fmt.Errorf("unable to initialize database path %s: %v", pdir, err)
	}
	return nil
}

// GetDevicePath get the path for a given device
func (d *DeviceManager) GetDevicePath(u uuid.UUID) string {
	return GetDevicePath(d.databasePath, u)
}

// getDevicePath get the path for a given device
func (d *DeviceManager) GetAppPath(u, instanceID uuid.UUID) string {
	return filepath.Join(GetDevicePath(d.databasePath, u), instanceID.String())
}

func openTimestampFile(filename string) (*os.File, error) {
	// open a new one
	fullPath := path.Join(filename, time.Now().Format("2006-01-02T15:04:05.111"))
	return os.Create(fullPath)
}

// writeDeviceFile write json to a named file in the given directory
func (d *DeviceManager) writeDeviceFile(u uuid.UUID, dir, filename string, b []byte) error {
	fullPath := path.Join(d.GetDevicePath(u), dir, filename)
	f, err := os.Create(fullPath)
	if err != nil {
		return fmt.Errorf("failed to open file %s: %v", fullPath, err)
	}
	defer f.Close()
	if _, err := f.Write(b); err != nil {
		return fmt.Errorf("error writing to file: %v", err)
	}

	return nil
}

// deviceExists return if a device has been created
func (d *DeviceManager) deviceExists(u uuid.UUID) bool {
	_, err := os.Stat(d.GetDevicePath(u))
	if err != nil {
		return false
	}
	if _, ok := d.devices[u]; !ok {
		return false
	}
	return true
}

// GetDevicePath get the path for a given device
func GetDevicePath(databasePath string, u uuid.UUID) string {
	return path.Join(databasePath, deviceDir, u.String())
}

// GetLogsReader get the logs for a given uuid
func (d *DeviceManager) GetLogsReader(u uuid.UUID) (common.ChunkReader, error) {
	// check that the device actually exists
	if !d.deviceExists(u) {
		return nil, fmt.Errorf("unregistered device UUID: %s", u)
	}
	return d.devices[u].Logs.Reader()
}

// GetInfoReader get the info for a given uuid
func (d *DeviceManager) GetInfoReader(u uuid.UUID) (common.ChunkReader, error) {
	// check that the device actually exists
	if !d.deviceExists(u) {
		return nil, fmt.Errorf("unregistered device UUID: %s", u)
	}
	return d.devices[u].Info.Reader()
}

// GetRequestsReader get the requests for a given uuid
func (d *DeviceManager) GetRequestsReader(u uuid.UUID) (common.ChunkReader, error) {
	// check that the device actually exists
	if !d.deviceExists(u) {
		return nil, fmt.Errorf("unregistered device UUID: %s", u)
	}
	return d.devices[u].Requests.Reader()
}

// WriteFlowMessage write FlowMessage
func (d *DeviceManager) WriteFlowMessage(u uuid.UUID, b []byte) error {
	// make sure it is not nil
	if len(b) < 1 {
		return nil
	}
	// check that the device actually exists
	if !d.deviceExists(u) {
		return fmt.Errorf("unregistered device UUID: %s", u)
	}
	dev := d.devices[u]
	return dev.AddFlowRecord(b)
}

// GetUUID get UuidResponse for device by uuid
func (d *DeviceManager) GetUUID(u uuid.UUID) ([]byte, error) {
	// check that the device actually exists
	if !d.deviceExists(u) {
		return nil, fmt.Errorf("unregistered device UUID: %s", u)
	}
	ur := &eveuuid.UuidResponse{Uuid: u.String()}
	return proto.Marshal(ur)
}

func (d *DeviceManager) SetDeviceOptions(u uuid.UUID, b []byte) error {
	witeLock.Lock()
	defer witeLock.Unlock()

	if len(b) < 1 {
		return fmt.Errorf("empty options")
	}
	if !d.deviceExists(u) {
		return fmt.Errorf("unregistered device UUID: %s", u)
	}
	// save the device options
	err := d.writeDeviceFile(u, "", deviceOptionsFilename, b)
	if err != nil {
		return fmt.Errorf("error saving options to %s: %v", deviceOptionsFilename, err)
	}

	err = d.refreshCache()
	if err != nil {
		return fmt.Errorf("unable to refresh certs from filesystem: %v", err)
	}

	return nil
}

func (d *DeviceManager) GetDeviceOptions(u uuid.UUID) ([]byte, error) {
	if !d.deviceExists(u) {
		return nil, fmt.Errorf("unregistered device UUID: %s", u)
	}
	// read options from disk
	fullOptionsPath := path.Join(d.GetDevicePath(u), deviceOptionsFilename)
	b, err := os.ReadFile(fullOptionsPath)
	if err != nil {
		// if error another than not exists than return
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("could not read options from %s: %v", fullOptionsPath, err)
		}
		// if is not exists, try to create default options
		cfg := common.CreateBaseDeviceOptions(u)
		err = d.SetDeviceOptions(u, cfg)
		if err != nil {
			return nil, fmt.Errorf("cannot set default options for %s: %s", u, err)
		}
		return cfg, nil
	}
	return b, nil
}

func (d *DeviceManager) SetGlobalOptions(b []byte) error {
	witeLock.Lock()
	defer witeLock.Unlock()

	err := os.WriteFile(filepath.Join(d.databasePath, globalOptionsFilename), b, 0666)
	if err != nil {
		return fmt.Errorf("error saving global options to %s: %v", globalOptionsFilename, err)
	}

	err = d.refreshCache()
	if err != nil {
		return fmt.Errorf("unable to refresh certs from filesystem: %v", err)
	}

	return nil
}

func (d *DeviceManager) GetGlobalOptions() ([]byte, error) {
	return os.ReadFile(filepath.Join(d.databasePath, globalOptionsFilename))
}
