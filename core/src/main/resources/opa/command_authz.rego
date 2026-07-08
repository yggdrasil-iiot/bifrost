package acl.command_authz
import future.keywords.if

default allow := false

# high-rpm setpoint requires day-shift AND Execute (context-conditional)
allow if {
	input.command == "write"
	input.target.group == "line1"
	input.value > 1000
	input.value <= 3000
	input.context.hour >= 6
	input.context.hour < 22
	input.context.state == "Execute"
}
# subsumption: normal-range write (<=1000) allowed regardless of context
allow if {
	input.command == "write"
	input.target.group == "line1"
	input.value >= 0
	input.value <= 1000
}
# SafeHold only from Execute
allow if {
	input.command == "SafeHold"
	input.context.state == "Execute"
}

default matched_rule_id := "none"
matched_rule_id := "rpm-high-day-execute" if { allow; input.command == "write"; input.value > 1000 }
matched_rule_id := "rpm-normal"           if { allow; input.command == "write"; input.value <= 1000 }
matched_rule_id := "safehold-execute"     if { allow; input.command == "SafeHold" }

reason := "allow" if { allow }
default deny_reason := "no-matching-rule (deny-by-default)"
deny_reason := "high-rpm restricted to day-shift(06-22) & Execute" if { input.command == "write"; input.value > 1000 }
deny_reason := "SafeHold requires state=Execute" if { input.command == "SafeHold" }
reason := deny_reason if { not allow }

decision := {"allow": allow, "reason": reason, "rule": matched_rule_id}
