package main

import gate "vpp.local/vpp-egress-gate"

// Gate's reading of its own configuration, under the names this package uses.
const defaultListDir = gate.DefaultListDir

var (
	listFiles         = gate.ListFiles
	parsePrefixStrict = gate.ParsePrefixStrict
	readJSONObject    = gate.ReadJSONObject
	prefixString      = gate.PrefixString
	prefixesOverlap   = gate.PrefixesOverlap
	asInt             = gate.AsInt
	parseHostPort     = gate.ParseHostPort
	checkDomain       = gate.CheckDomain
	summarizeRange    = gate.SummarizeRange
	linkedJSON        = gate.LinkedJSON
	NewPrefixIndex    = gate.NewPrefixIndex
	// Replaced by tests, which have no device journal.
	generatedIPv6 = gate.GeneratedIPv6
)
