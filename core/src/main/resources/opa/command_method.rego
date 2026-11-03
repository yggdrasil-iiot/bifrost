# The OPA half of Heimdall's check on a governed Method call (op=method). CommandAuthorizer runs first; this
# policy sees what the Java rules cannot: two principals and their command grants, whether their signatures
# resolved to distinct keys, the validity window against the edge clock, whether the proposal's subjects are the
# head this edge serves, the evidence verdict, and per-method argument bounds. Every input fact is one Heimdall
# verified itself; a missing or mistyped fact is a violation, so the policy fails closed.
#
# The Method table is input, not data: Heimdall builds input.methods per call from the command binding it resolved
# in the pinned release (the input's name and type) and the command-policy rule that admitted the call (the bounds),
# never from the proposal. A Method without an entry, or an entry of the wrong shape, is a violation.
#
# Times are Unix epoch seconds. The decision lists every violation, not only the first.
package command.method

# Methods admitted for this call, by expanded NodeId, with the one input each takes and its inclusive bounds.
methods := input.methods

max_window := 900

violations contains "principal" if not principals_ok

violations contains "grant.propose" if not proposer_granted

violations contains "grant.approve" if not approver_granted

violations contains "distinct-keys" if not input.distinctKeys == true

violations contains "window" if not window_ok

violations contains "head" if not input.headMatch == true

violations contains "evidence" if not input.evidence.usable == true

violations contains "method" if not method_known

violations contains "argument" if not argument_ok

# Written as a rule: `not methods[input.method]` with input.method undefined is itself undefined, not true.
method_known if {
	is_string(input.method)
	methods[input.method]
}

principals_ok if {
	is_string(input.proposer.principal)
	is_string(input.approver.principal)
	input.proposer.principal != ""
	input.approver.principal != ""
	input.proposer.principal != input.approver.principal
}

proposer_granted if "propose_command" in input.proposer.grants

approver_granted if "approve_command" in input.approver.grants

window_ok if {
	is_number(input.window.notBefore)
	is_number(input.window.notAfter)
	is_number(input.now)
	input.window.notBefore <= input.now
	input.now < input.window.notAfter
	input.window.notAfter - input.window.notBefore <= max_window
}

argument_ok if {
	m := methods[input.method]
	is_string(m.input)
	is_string(m.type)
	is_number(m.min)
	is_number(m.max)
	count(input.inputs) == 1
	arg := input.inputs[0]
	arg.name == m.input
	arg.type == m.type
	is_number(arg.value)
	arg.value >= m.min
	arg.value <= m.max
}

default allow := false

allow if count(violations) == 0

decision := {"allow": allow, "violations": violations}
