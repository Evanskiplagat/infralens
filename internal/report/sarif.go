package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"sort"
	"strings"
	"time"

	"infralens/internal/findings"
)

const (
	sarifSchema  = "https://json.schemastore.org/sarif-2.1.0.json"
	sarifVersion = "2.1.0"
	toolName     = "InfraLens"
	toolInfoURI  = "https://github.com/Evanskiplagat/infralens"
)

// The types below model the subset of SARIF 2.1.0 that InfraLens emits.
// Field names follow the specification exactly.

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool        sarifTool      `json:"tool"`
	Results     []sarifResult  `json:"results"`
	Invocations []invocation   `json:"invocations,omitempty"`
	Properties  map[string]any `json:"properties,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name,omitempty"`
	ShortDescription *sarifText     `json:"shortDescription,omitempty"`
	FullDescription  *sarifText     `json:"fullDescription,omitempty"`
	Help             *sarifHelp     `json:"help,omitempty"`
	HelpURI          string         `json:"helpUri,omitempty"`
	DefaultConfig    *sarifConfig   `json:"defaultConfiguration,omitempty"`
	Properties       map[string]any `json:"properties,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifHelp struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown,omitempty"`
}

type sarifConfig struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Suppressions        []sarifSuppress   `json:"suppressions,omitempty"`
	Properties          map[string]any    `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical  `json:"physicalLocation"`
	LogicalLocations []sarifLogical `json:"logicalLocations"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           sarifRegion   `json:"region"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

type sarifLogical struct {
	Name               string `json:"name"`
	FullyQualifiedName string `json:"fullyQualifiedName"`
	Kind               string `json:"kind"`
}

type sarifSuppress struct {
	Kind          string `json:"kind"`
	Justification string `json:"justification"`
}

type invocation struct {
	ExecutionSuccessful bool   `json:"executionSuccessful"`
	EndTimeUTC          string `json:"endTimeUtc,omitempty"`
}

// sarifLevel maps InfraLens severities onto SARIF's three result levels.
func sarifLevel(s findings.Severity) string {
	switch s {
	case findings.SeverityCritical, findings.SeverityHigh:
		return "error"
	case findings.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

// securitySeverity is the CVSS-like 0-10 score GitHub code scanning reads
// from the "security-severity" property to bucket alerts into
// critical/high/medium/low.
func securitySeverity(s findings.Severity) string {
	switch s {
	case findings.SeverityCritical:
		return "9.5"
	case findings.SeverityHigh:
		return "8.0"
	case findings.SeverityMedium:
		return "5.5"
	case findings.SeverityLow:
		return "3.0"
	default:
		return "0.5"
	}
}

// fingerprint identifies a finding across scans by what it is about (the rule
// and the resource), not by wording or severity, so a platform can track the
// same alert as descriptions improve.
func fingerprint(f findings.Finding) string {
	sum := sha256.Sum256([]byte(f.RuleID + "\x00" + f.ResourceID))
	return hex.EncodeToString(sum[:16])
}

// artifactURI builds a stable, repository-relative virtual path for a cloud
// resource. SARIF results need a file location, but AWS resources are not
// files, so consumers that insist on one see "aws/<account>/<kind>/<id>".
func artifactURI(accountID, resourceID string) string {
	account := accountID
	if account == "" {
		account = "unknown-account"
	}
	return "aws/" + account + "/" + strings.ReplaceAll(resourceID, " ", "_")
}

// WriteSARIF writes the report as a SARIF 2.1.0 log with one run. Suppressed
// findings are included with a SARIF suppression carrying the waiver's
// justification, so viewers can hide them while keeping an audit trail.
func WriteSARIF(w io.Writer, in Input) error {
	idx := in.ruleIndex()

	// Every rule that appears in the results must appear in the driver's
	// rule list, ordered so ruleIndex is stable.
	used := map[string]bool{}
	for _, f := range in.Findings {
		used[f.RuleID] = true
	}
	for _, s := range in.Suppressed {
		used[s.RuleID] = true
	}
	ids := make([]string, 0, len(used))
	for id := range used {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	position := make(map[string]int, len(ids))
	rules := make([]sarifRule, 0, len(ids))
	for i, id := range ids {
		position[id] = i
		rules = append(rules, buildRule(id, idx))
	}

	results := make([]sarifResult, 0, len(in.Findings)+len(in.Suppressed))
	for _, f := range in.Findings {
		results = append(results, buildResult(in.Meta, f, position[f.RuleID], nil))
	}
	for _, s := range in.Suppressed {
		results = append(results, buildResult(in.Meta, s.Finding, position[s.RuleID], &s.Reason))
	}

	end := in.Meta.GeneratedAt
	run := sarifRun{
		Tool: sarifTool{Driver: sarifDriver{
			Name:           toolName,
			Version:        in.Meta.ToolVersion,
			InformationURI: toolInfoURI,
			Rules:          rules,
		}},
		Results: results,
		Invocations: []invocation{{
			ExecutionSuccessful: in.Meta.Status != "failed",
			EndTimeUTC:          formatTime(end),
		}},
		Properties: map[string]any{
			"scanId":    in.Meta.ScanID,
			"accountId": in.Meta.AccountID,
			"regions":   in.Meta.Regions,
			"status":    in.Meta.Status,
		},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(sarifLog{Schema: sarifSchema, Version: sarifVersion, Runs: []sarifRun{run}})
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func buildRule(id string, idx map[string]findings.RuleInfo) sarifRule {
	info, ok := idx[id]
	if !ok {
		return sarifRule{ID: id, Name: id, ShortDescription: &sarifText{Text: id}}
	}
	help := info.Remediation
	markdown := "**Remediation:** " + info.Remediation
	if len(info.References) > 0 {
		markdown += "\n\n" + "References:\n"
		for _, ref := range info.References {
			markdown += "- " + ref + "\n"
		}
		help += " See " + strings.Join(info.References, ", ") + "."
	}
	rule := sarifRule{
		ID:               id,
		Name:             id,
		ShortDescription: &sarifText{Text: info.Title},
		FullDescription:  &sarifText{Text: info.Description},
		Help:             &sarifHelp{Text: help, Markdown: markdown},
		DefaultConfig:    &sarifConfig{Level: sarifLevel(info.DefaultSeverity)},
		Properties: map[string]any{
			"tags":              append([]string{"security", "aws"}, info.Tags...),
			"security-severity": securitySeverity(info.DefaultSeverity),
		},
	}
	if len(info.References) > 0 {
		rule.HelpURI = info.References[0]
	}
	return rule
}

func buildResult(meta Meta, f findings.Finding, ruleIndex int, suppressedReason *string) sarifResult {
	message := f.Title
	if f.Description != "" {
		message += ": " + f.Description
	}
	res := sarifResult{
		RuleID:    f.RuleID,
		RuleIndex: ruleIndex,
		Level:     sarifLevel(f.Severity),
		Message:   sarifText{Text: message},
		Locations: []sarifLocation{{
			PhysicalLocation: sarifPhysical{
				ArtifactLocation: sarifArtifact{URI: artifactURI(meta.AccountID, f.ResourceID)},
				Region:           sarifRegion{StartLine: 1},
			},
			LogicalLocations: []sarifLogical{{
				Name:               f.ResourceID,
				FullyQualifiedName: f.ResourceID,
				Kind:               "resource",
			}},
		}},
		PartialFingerprints: map[string]string{"infralens/v1": fingerprint(f)},
		Properties: map[string]any{
			"severity":          string(f.Severity),
			"resourceId":        f.ResourceID,
			"security-severity": securitySeverity(f.Severity),
		},
	}
	if suppressedReason != nil {
		res.Suppressions = []sarifSuppress{{Kind: "external", Justification: *suppressedReason}}
	}
	return res
}
