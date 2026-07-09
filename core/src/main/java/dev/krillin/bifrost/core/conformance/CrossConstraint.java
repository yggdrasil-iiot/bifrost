package dev.krillin.bifrost.core.conformance;
/** One conditional-bound rule: if <ifMember> <ifOp> <ifValue> then require <thenMember> <thenOp> <thenValue>.
 *  ops: "lt","le","gt","ge","eq". A small CLOSED algebra element. */
public record CrossConstraint(String id, String ifMember, String ifOp, double ifValue,
                              String thenMember, String thenOp, double thenValue) {}
