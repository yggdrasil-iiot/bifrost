package dev.krillin.bifrost.core.schema;

import java.util.List;

/**
 * UDT data contract (the unit of source of truth in the registry). Protocol-independent.
 * AAS-aligned — a definition ≈ AAS {@code Submodel} (its members ≈ AAS {@code Property}s).
 * {@code conformsTo} is a reserved pointer to an enterprise submodel-template this definition
 * conforms to; null on this track.
 */
public record UdtDefinition(String templateRef, SemVer version,
                            List<Member> members, List<Param> params,
                            String conformsTo) {}
