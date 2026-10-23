package com.victor.reconloop;

/**
 * The specific mechanism by which an active finding was confirmed.
 *
 * <p>Carried as structured data on {@link ActiveTestEngine.ActiveFinding} so the Nuclei PoC builder can
 * decide — from an enum, not a substring of the human-readable evidence — whether a finding is reproducible
 * by an in-band matcher and which matcher reproduces it. Classes with a single confirmation mechanism, and
 * classes whose PoC is not keyed on the vector, do not carry one (their {@code Confirmation} is null).
 *
 * <p>Gating on this instead of parsing the display prose is what keeps the two sides from silently
 * desyncing: rewording a finding's evidence can no longer change which PoCs are emitted.
 */
enum ConfirmationVector {
    /** SQLi confirmed by a database error signature that appeared only after injection. In-band reproducible. */
    SQL_ERROR,
    /** SQLi confirmed by boolean-based blind differencing. Not reproduced by an in-band body matcher. */
    SQL_BOOLEAN,
    /** SQLi confirmed by time-based blind timing. Not reproduced by an in-band body matcher. */
    SQL_TIME,
    /** NoSQLi confirmed by a datastore error signature that appeared only after injection. In-band reproducible. */
    NOSQL_ERROR,
    /** SSTI confirmed via the Jinja2/Twig {@code {{...}}} family — reproduced by the {@code {{7*777}}} payload. */
    SSTI_BRACE,
    /** SSTI confirmed via a non-{@code {{...}}} family ({@code ${...}}/{@code #{...}}/{@code <%=%>}/nested {@code ${{...}}}) — not reproduced by {@code {{7*777}}}. */
    SSTI_OTHER
}
