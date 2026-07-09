package dev.krillin.bifrost.core.schema;

import java.util.List;

/**
 * ISA-88 master recipe: a {@link GeneralSpec} bound to a specific site's equipment. Equipment-dependent —
 * it names the {@code site}, the {@code equipmentRef}/{@code equipmentVersion} it targets, and carries
 * concrete {@link Setpoint}s addressed to that equipment's members.
 */
public record MasterSpec(String specRef, String version, String site,
                         String equipmentRef, String equipmentVersion, List<Setpoint> setpoints) {}
