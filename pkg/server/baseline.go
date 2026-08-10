// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// This file decides which baseline a device's attested boot applies to, and what
// to do with the answer.
//
// It does not judge event logs or PCR values. Whether a log is a truthful account
// of a signed boot, and whether a boot is the published image running on this
// device, are answered by evepcr.VerifyBaselineCandidate and
// evepcr.VerifyUpdatedBoot. Where the files live is in tpm_eventlog.go; where the
// published images come from is in pcr_predict.go.

package server

import (
	"log"

	"github.com/lf-edge/adam/pkg/driver"
	"github.com/lf-edge/eve-api/go/attest"
	uuid "github.com/satori/go.uuid"
	evepcr "github.com/zededa/evepcr"
)

// baselineOutcome is what one attested event log meant for the device baseline.
type baselineOutcome int

const (
	// baselineNoEvidence: the log was missing, unreadable, or was not a truthful
	// account of the signed boot, so it says nothing about the device.
	baselineNoEvidence baselineOutcome = iota
	// baselineEstablished: the device had no baseline and an operator had asked
	// for this boot to become it.
	baselineEstablished
	// baselineUnchanged: the log is the trusted baseline, bit for bit.
	baselineUnchanged
	// baselineMoved: the log differed from the baseline and matched the values
	// predicted for the image the device reports, so the baseline moved to it.
	baselineMoved
	// baselineUnexplained: the log differed from the baseline and no prediction
	// accounts for it. The baseline was left alone.
	baselineUnexplained
)

func (o baselineOutcome) String() string {
	switch o {
	case baselineEstablished:
		return "baseline established"
	case baselineUnchanged:
		return "baseline unchanged"
	case baselineMoved:
		return "baseline moved"
	case baselineUnexplained:
		return "change unexplained"
	}
	return "no evidence"
}

// vouchesForDevice reports whether this outcome is grounds to accept the device.
//
// A device part-way through an update fails the PCR template check, which is the
// case prediction exists to resolve, so this is what lets a predicted update
// through without the template being widened.
func (o baselineOutcome) vouchesForDevice() bool {
	switch o {
	case baselineEstablished, baselineUnchanged, baselineMoved:
		return true
	}
	return false
}

// evidence spells out why this outcome does or does not speak for the device,
// phrased to drop into a log line.
func (o baselineOutcome) evidence() string {
	switch o {
	case baselineEstablished:
		return "its event log accounts for the quote it signed and is now its trusted baseline"
	case baselineUnchanged:
		return "its event log accounts for the quote it signed and is its trusted baseline"
	case baselineMoved:
		return "its event log matches the PCR values predicted for the version it reports"
	case baselineUnexplained:
		return "its event log changed and no prediction explains the new values"
	}
	return "its event log could not be checked"
}

// reconcileEventLogBaseline records the event log carried by a validated quote
// and works out what it means for the device's trusted baseline.
//
// The caller must have verified the quote's signature against the device's key.
// nonce is the nonce this controller issued. templateRejected is this controller's PCR template check having
// rejected the device, which blocks first-use trust only.
//
// Nothing here fails attestation on its own; the caller decides that from the
// outcome.
func reconcileEventLogBaseline(manager driver.DeviceManager, deviceDir string, u uuid.UUID,
	quote *attest.ZAttestQuote, nonce []byte, templateRejected error, storageURL string) baselineOutcome {

	rawLog, err := evepcr.DecompressEventLog(quote.GetTpmBinaryEventLog())
	if err != nil {
		log.Printf("device %s: %s", u, err)
		return baselineNoEvidence
	}

	// Kept whatever is decided below, because a refused log is the only record of
	// why it was refused.
	if err := storeIncomingEventLog(deviceDir, rawLog, quote.GetPcrValues()); err != nil {
		log.Printf("device %s: recording incoming event log failed: %s", u, err)
	}

	baseline, err := loadTrustedBaseline(deviceDir)
	if err != nil {
		log.Printf("device %s: reading event log state failed: %s", u, err)
		return baselineNoEvidence
	}

	switch {
	case baseline == nil:
		return establishRequestedBaseline(deviceDir, u, rawLog, quote, nonce, templateRejected)
	case baseline.isLog(rawLog):
		log.Printf("device %s: event log is the trusted baseline", u)
		return baselineUnchanged
	default:
		return moveBaselineOnPredictedChange(manager, deviceDir, u, rawLog, quote, nonce, baseline, storageURL)
	}
}

// establishRequestedBaseline promotes a log to the device's trusted baseline, but
// only when an operator has asked for it.
//
// Trusting whatever a device reports first is tempting and wrong. The boot after
// onboarding is not the boot the device will keep repeating: onboarding writes
// device certificates, sets up the vault and moves the partition state, so PCR 14
// and the gptprio bits in PCR 5 are still in flight. Baselining that boot pins
// values the device will never produce again.
//
// So the controller waits to be told. An operator reboots the device, sees it come
// up clean, and marks it trusted; the next log that accounts for its own quote
// becomes the baseline.
func establishRequestedBaseline(deviceDir string, u uuid.UUID, rawLog []byte,
	quote *attest.ZAttestQuote, nonce []byte, templateRejected error) baselineOutcome {

	requested, err := baselineRequested(deviceDir)
	if err != nil {
		log.Printf("device %s: reading the trust request failed: %s", u, err)
		return baselineNoEvidence
	}
	if !requested {
		log.Printf("device %s: no trusted baseline yet; waiting for an operator to trust a boot", u)
		return baselineNoEvidence
	}

	verdict, err := evepcr.VerifyBaselineCandidate(quote, nonce)
	if err != nil {
		log.Printf("device %s: cannot judge the event log: %s", u, err)
		return baselineNoEvidence
	}
	if !verdict.OK {
		log.Printf("device %s: refusing to trust this log, %s", u, verdict.Reason)
		return baselineNoEvidence
	}
	if templateRejected != nil {
		log.Printf("device %s: trust was requested but the PCR template did not match, refusing this log: %s",
			u, templateRejected)
		return baselineNoEvidence
	}

	// The request is consumed before the baseline is written, not after. Two
	// attestations arriving together would otherwise both find it armed and both
	// establish a baseline. Consuming first means a failure here costs an operator
	// one more command, instead of costing the device two baselines.
	if err := clearBaselineRequest(deviceDir); err != nil {
		log.Printf("device %s: could not consume the trust request, not trusting this log: %s", u, err)
		return baselineNoEvidence
	}
	if err := writeEventLogBaseline(deviceDir, rawLog, quote.GetPcrValues(), "", eveVersionFromQuote(quote)); err != nil {
		log.Printf("device %s: establishing event log baseline failed, the trust request has been used up: %s", u, err)
		return baselineNoEvidence
	}
	log.Printf("device %s: %s, and is now the trusted baseline (%d bytes)", u, verdict.Reason, len(rawLog))
	return baselineEstablished
}

// moveBaselineOnPredictedChange handles a device whose log no longer matches its
// trusted baseline, which is what an OS update looks like from this side.
//
// The baseline only moves if the new log is what the published image would produce
// on this device. Nothing the device sent is an input to that prediction.
func moveBaselineOnPredictedChange(manager driver.DeviceManager, deviceDir string, u uuid.UUID,
	rawLog []byte, quote *attest.ZAttestQuote, nonce []byte, baseline *tpmEventLogState,
	storageURL string) baselineOutcome {

	version := eveVersionFromQuote(quote)
	if version == "" {
		log.Printf("device %s: event log changed but the quote carries no EVE version, baseline left alone", u)
		return baselineUnexplained
	}
	if storageURL == "" {
		log.Printf("device %s: event log changed but no storage service is configured, baseline left alone", u)
		return baselineUnexplained
	}

	// Only the version this controller asked the device to run. Any other version
	// with a published reference measurement would otherwise be accepted,
	// including an older one, which is a downgrade to a genuinely signed but
	// superseded image.
	if want := targetedVersion(deviceDir); want != "" && want != version {
		log.Printf("device %s: reports %s but was sent %s, baseline left alone", u, version, want)
		return baselineUnexplained
	}

	rootfsHash, referenceLog, measureConfigLog, err := referenceForVersion(storageURL, version)
	if err != nil {
		log.Printf("device %s: %s cannot be predicted: %s, baseline left alone", u, version, err)
		return baselineUnexplained
	}

	// PCR 14 needs the device's fixed /config origin stamp. The device reports it
	// as the basename of its /config origin file, which is set at install and
	// never changes. A device that does not report it cannot have PCR 14 predicted
	// with substitution; the verdict below then rests on the other PCRs.
	installOrigin := quote.GetInstallVersion()
	if installOrigin == "" {
		log.Printf("device %s: quote carries no install version; PCR 14 origin cannot be substituted", u)
	}

	baselineLog, err := readBaselineEventLog(deviceDir, baseline)
	if err != nil {
		log.Printf("device %s: reading trusted baseline %s failed: %s", u, baseline.BaselineFile, err)
		return baselineUnexplained
	}

	verdict, err := evepcr.VerifyUpdatedBoot(baselineLog, referenceLog, rootfsHash, measureConfigLog,
		installOrigin, quote, nonce)
	if err != nil {
		log.Printf("device %s: cannot judge the change to %s: %s", u, version, err)
		return baselineUnexplained
	}
	if !verdict.OK {
		log.Printf("device %s: rejecting the change to %s, %s", u, version, verdict.Reason)
		return baselineUnexplained
	}

	// The origin stamp does not change on an update, so the install version is
	// carried forward rather than replaced with the version just booted.
	if err := writeEventLogBaseline(deviceDir, rawLog, quote.GetPcrValues(), baseline.BaselineFile, baseline.Version); err != nil {
		log.Printf("device %s: moving the baseline failed: %s", u, err)
		return baselineUnexplained
	}

	// Moving the PCR template to this version is deliberately not done here. The
	// caller runs its template check after this returns, and a template written now
	// would be one built from the very quote that check is about, so the check would
	// pass on its own output and the prediction would never be seen to carry the
	// device. The caller moves it once its own check has run.

	log.Printf("device %s: prediction for %s used the reference measurement (%d bytes) and the published rootfs hash",
		u, version, len(referenceLog))
	log.Printf("device %s: change to %s matches prediction, baseline moved (previous %s kept): %s",
		u, version, baseline.BaselineFile, verdict.Reason)
	return baselineMoved
}
