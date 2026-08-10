package com.syntrace.common;

/**
 * MODULE 6 - single source of truth for cross-cutting literals.
 *
 * <p>Anything referenced by more than one layer (headers, API prefixes, classification
 * markings, default page sizes) lives here so the values cannot drift apart.</p>
 */
public final class AppConstants {

    private AppConstants() {
    }

    /** Root prefix of every REST endpoint. */
    public static final String API_PREFIX = "/api";

    /** Product name printed on every exported artefact. */
    public static final String PRODUCT_NAME = "SynTrace AI";

    /** Tagline printed under the logo in reports. */
    public static final String PRODUCT_TAGLINE = "Offline Security Investigation Platform";

    /** Handling marking stamped on generated reports. */
    public static final String DEFAULT_CLASSIFICATION = "RESTRICTED - INTERNAL INVESTIGATION USE ONLY";

    /** Authorization header name. */
    public static final String HEADER_AUTHORIZATION = "Authorization";

    /** Bearer scheme prefix, including the trailing space. */
    public static final String BEARER_PREFIX = "Bearer ";

    /** Correlation identifier propagated into the MDC for every request. */
    public static final String HEADER_REQUEST_ID = "X-Request-Id";

    /** MDC key holding the request identifier. */
    public static final String MDC_REQUEST_ID = "requestId";

    /** MDC key holding the acting username. */
    public static final String MDC_USER = "user";

    /** Default page size for paged endpoints. */
    public static final int DEFAULT_PAGE_SIZE = 20;

    /** Hard ceiling on page size so a client cannot request the whole database. */
    public static final int MAX_PAGE_SIZE = 200;

    /** Role names, mirrored from {@code RoleName} for use in SpEL expressions. */
    public static final String ROLE_ADMIN = "ADMIN";
    public static final String ROLE_ANALYST = "ANALYST";
    public static final String ROLE_VIEWER = "VIEWER";

    /** Sub-directory of the storage root used for transient working files. */
    public static final String TEMP_DIRECTORY = "tmp";

    /** Sub-directory of the storage root where generated reports are written. */
    public static final String REPORT_DIRECTORY = "reports";

    /** Maximum characters of raw evidence quoted into a report or chat answer. */
    public static final int EVIDENCE_SNIPPET_LIMIT = 400;
}
