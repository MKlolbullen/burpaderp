package com.victor.reconloop;

/**
 * The single source of truth for the database/datastore error-signature regexes and the stable evidence
 * markers that distinguish one confirmation vector from another.
 *
 * <p>These are referenced by two sides that must agree:
 * <ul>
 *   <li>{@link ActiveTestEngine} compiles {@link #SQL_ERROR_REGEX}/{@link #NOSQL_ERROR_REGEX} to confirm a
 *       finding in-band, and authors its evidence prose from the marker constants; and</li>
 *   <li>{@link NucleiTemplateBuilder} emits those same regexes as the matcher of the runnable PoC and gates
 *       on those same markers to decide which confirmations a PoC can faithfully reproduce.</li>
 * </ul>
 *
 * <p>Keeping one copy is the point. A second, hand-maintained copy on the PoC side drifts: it had already
 * narrowed to a subset of the engine's signatures, so a finding confirmed on an omitted signature produced
 * a "runnable PoC" whose matcher could never match — a PoC that fails to reproduce the finding it is
 * attached to. Sourcing both sides here closes that gap by construction, and makes a reworded marker a
 * single-edit, compile-checked change rather than an independent string that silently desyncs.
 *
 * <p>Both regexes carry an inline {@code (?i)} flag so they are case-insensitive wherever used — Java's
 * {@link java.util.regex.Pattern} and Nuclei's RE2 engine both honour it — rather than relying on a
 * compile-time flag that the Nuclei side cannot see. Every construct used here (inline flags, {@code \\b},
 * {@code \\d{n}}, alternation, escaped literals) is supported by both engines.
 */
final class DetectionSignatures {

    private DetectionSignatures() {}

    /** Error-based SQL injection driver/parser signatures (MySQL/MariaDB/PostgreSQL/MSSQL/Oracle/SQLite/.NET). */
    static final String SQL_ERROR_REGEX = "(?i)"
            + "sql syntax|unclosed quotation mark|quoted string not properly terminated|"
            + "mysql_fetch|mysqli|you have an error in your sql syntax|warning: mysql|"
            + "valid mysql result|check the manual that corresponds to your (mysql|mariadb) server|"
            + "ora-\\d{5}|pg_query\\(\\)|postgresql.*error|sqlstate\\[|sqlite3?\\.(operationalerror|error)|"
            + "microsoft ole db provider for odbc drivers|incorrect syntax near|"
            + "unterminated quoted string|System\\.Data\\.SqlClient\\.SqlException";

    /** Error-based NoSQL (Mongo-style) driver/parser signatures. */
    static final String NOSQL_ERROR_REGEX = "(?i)"
            + "mongoerror|mongonetworkerror|mongoserverror|mongoose|bsonerror|\\bbson\\b|"
            + "e11000 duplicate key|cast to objectid failed|casterror|"
            + "\\$where|\\$regex|unterminated string|couchdberror|"
            + "unexpected token .* in json|error parsing (bson|json)";

    /**
     * The marker the engine writes into the evidence of an <em>error-based</em> SQLi confirmation. A PoC
     * reproduces error-based SQLi with an error-signature body matcher; boolean- and time-based blind
     * confirmations do not carry this marker, so the PoC side can tell which it may reproduce.
     */
    static final String SQL_ERROR_EVIDENCE = "database error signature";

    /**
     * The template-engine family label the engine writes for a Jinja2/Twig {@code {{...}}} confirmation —
     * the only family the fixed {@code {{7*777}}} PoC payload reproduces. Gating on the whole label (not a
     * bare {@code "{{"} substring) excludes the nested {@code ${{...}}} family, whose label also contains
     * {@code {{} but whose engine would not evaluate the plain {@code {{...}}} payload.
     */
    static final String SSTI_JINJA_FAMILY = "Jinja2/Twig-style {{...}}";
}
