# Decision table for command_method.rego: one valid input, then one fact changed per row; each row must produce
# exactly the violations it names. Run with `opa test core/src/main/resources/opa core/src/test/opa` (scripts/build-opa-wasm.sh does).
package command.method_test

import data.command.method

base := {
	"proposer": {"principal": "agent", "grants": ["propose_command"]},
	"approver": {"principal": "operator", "grants": ["approve_command"]},
	"distinctKeys": true,
	"window": {"notBefore": 1000, "notAfter": 1900},
	"now": 1000,
	"headMatch": true,
	"evidence": {"usable": true},
	"target": {"group": "Bifrost:Line1", "edge": "heimdall-edge", "device": "Line1/Mixer1"},
	"method": "nsu=urn:bifrost:opcua:sim;s=Line1/Mixer1.SetTemperature",
	"inputs": [{"name": "targetTemperature", "type": "Double", "value": 42.0}],
}

arg(v) := [{"name": "targetTemperature", "type": "Double", "value": v}]

rows := [
	{"name": "valid", "patch": {}, "want": set()},
	{"name": "lower bound", "patch": {"inputs": arg(0)}, "want": set()},
	{"name": "upper bound", "patch": {"inputs": arg(100)}, "want": set()},
	{"name": "last second of the window", "patch": {"now": 1899}, "want": set()},
	{"name": "both grants among others", "patch": {"proposer": {"grants": ["activate", "propose_command"]}, "approver": {"grants": ["approve", "approve_command"]}}, "want": set()},
	{"name": "same principal", "patch": {"approver": {"principal": "agent"}}, "want": {"principal"}},
	{"name": "empty principal", "patch": {"proposer": {"principal": ""}}, "want": {"principal"}},
	{"name": "principal not a string", "patch": {"approver": {"principal": 7}}, "want": {"principal"}},
	{"name": "proposer lacks propose_command", "patch": {"proposer": {"grants": ["activate"]}}, "want": {"grant.propose"}},
	{"name": "approver holds approve, not approve_command", "patch": {"approver": {"grants": ["approve"]}}, "want": {"grant.approve"}},
	{"name": "grants swapped", "patch": {"proposer": {"grants": ["approve_command"]}, "approver": {"grants": ["propose_command"]}}, "want": {"grant.propose", "grant.approve"}},
	{"name": "one key", "patch": {"distinctKeys": false}, "want": {"distinct-keys"}},
	{"name": "distinctKeys not a boolean", "patch": {"distinctKeys": "true"}, "want": {"distinct-keys"}},
	{"name": "before notBefore", "patch": {"now": 999}, "want": {"window"}},
	{"name": "at notAfter", "patch": {"now": 1900}, "want": {"window"}},
	{"name": "span 901 seconds", "patch": {"window": {"notAfter": 1901}}, "want": {"window"}},
	{"name": "time as a string", "patch": {"now": "1000"}, "want": {"window"}},
	{"name": "head moved", "patch": {"headMatch": false}, "want": {"head"}},
	{"name": "evidence unusable", "patch": {"evidence": {"usable": false}}, "want": {"evidence"}},
	{"name": "unknown method", "patch": {"method": "nsu=urn:bifrost:opcua:sim;s=Line1/Mixer1.Vent"}, "want": {"method", "argument"}},
	{"name": "namespace index instead of URI", "patch": {"method": "ns=2;s=Line1/Mixer1.SetTemperature"}, "want": {"method", "argument"}},
	{"name": "below min", "patch": {"inputs": arg(-0.5)}, "want": {"argument"}},
	{"name": "above max", "patch": {"inputs": arg(100.000001)}, "want": {"argument"}},
	{"name": "value as a string", "patch": {"inputs": arg("42")}, "want": {"argument"}},
	{"name": "wrong input name", "patch": {"inputs": [{"name": "rpm", "type": "Double", "value": 42}]}, "want": {"argument"}},
	{"name": "wrong input type", "patch": {"inputs": [{"name": "targetTemperature", "type": "Float", "value": 42}]}, "want": {"argument"}},
	{"name": "two inputs", "patch": {"inputs": [{"name": "targetTemperature", "type": "Double", "value": 42}, {"name": "targetTemperature", "type": "Double", "value": 43}]}, "want": {"argument"}},
]

test_rows if {
	every row in rows {
		got := method.violations with input as object.union(base, row.patch)
		got == row.want
	}
}

test_allow_only_without_violations if {
	method.decision.allow with input as base
	not method.decision.allow with input as object.union(base, {"headMatch": false})
}

# Every check fails closed on an empty input.
test_empty_input if {
	method.violations with input as {} == {"principal", "grant.propose", "grant.approve", "distinct-keys", "window", "head", "evidence", "method", "argument"}
	not method.decision.allow with input as {}
}
