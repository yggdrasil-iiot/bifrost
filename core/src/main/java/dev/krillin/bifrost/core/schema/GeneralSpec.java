package dev.krillin.bifrost.core.schema;

import java.util.List;

/**
 * ISA-88 general recipe: a product-domain, equipment-independent spec. Carries equipment-independent
 * {@link SetpointIntent}s keyed by logical name; bound to a site's equipment it becomes a
 * {@link MasterSpec} (master recipe).
 */
public record GeneralSpec(String specRef, String version, String productDomain,
                          List<SetpointIntent> setpointIntents) {}
