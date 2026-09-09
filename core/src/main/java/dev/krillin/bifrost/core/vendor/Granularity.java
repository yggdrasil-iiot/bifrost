package dev.krillin.bifrost.core.vendor;

/**
 * The unit at which a vendor product can be reconciled -- and, more to the point, CORRECTED.
 *
 * <p>This is a property of the product's API, <b>not of any particular export file</b>. The same
 * JSON could come from a product with a per-object write API or from one whose only ingest path is
 * a whole entity blob, so declaring it on the SOURCE rather than inferring it from the data is what
 * keeps the distinction honest.
 *
 * <p>It exists because two booleans would not carry it. {@code canRead}/{@code canWrite} report
 * Kepware, Ignition and ThingWorx as equally supported and hide the only difference that changes
 * how this is operated -- which is the difference an operator plans around.
 */
public enum Granularity {

    /**
     * Kepware and Ignition: a correction touches one object, so divergence is actionable per member
     * and can be worked incrementally.
     */
    PER_OBJECT,

    /**
     * ThingWorx: there is no per-object write, so a correction re-imports an entity set. The
     * <i>finding</i> is still per member once the export is parsed -- what is coarse is the fetch
     * and the fix, which is why {@code ReconciliationVerdict} carries this separately from the
     * findings rather than degrading them to match.
     */
    WHOLE_SET
}
