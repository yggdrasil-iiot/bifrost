package dev.krillin.bifrost.core.conformance;
/** Links a governed member to its OPC-UA nodes. opcNodeId = the WRITE/setpoint node matched against an
 *  incoming command (nullable for read-only siblings never commanded). readNodeId = the live INSTANCE node
 *  whose current value is read for cross-member rules (nullable if the member is never a cross-member sibling).
 *  The two namespaces differ (setpoint vs instance), so both are explicit — no string-concat convention. */
public record NodeBinding(String opcNodeId, String readNodeId, String member) {}
