package com.victor.reconloop;

import java.util.Objects;

/**
 * Structured provenance attached to active findings.
 *
 * <p>The human-readable finding evidence still describes what the target returned. This record
 * captures how Recon Hound produced and judged that evidence so the result can be audited and
 * reproduced without reverse-engineering UI prose.
 */
record FindingEvidence(
        String runId,
        String probeId,
        String detectorVersion,
        String mutation,
        String confidenceRationale,
        String reproductionRecipe
) {
    FindingEvidence {
        runId = clean(runId);
        probeId = clean(probeId);
        detectorVersion = clean(detectorVersion);
        mutation = clean(mutation);
        confidenceRationale = clean(confidenceRationale);
        reproductionRecipe = clean(reproductionRecipe);
    }

    static FindingEvidence empty() {
        return new FindingEvidence("", "", "", "", "", "");
    }

    static FindingEvidence active(ScanRun run, String probeId, String detectorVersion,
                                  String mutation, VerificationState state,
                                  String testClass, String parameter, String url,
                                  String responseEvidence) {
        String rationale = rationale(state, responseEvidence);
        String recipe = reproductionRecipe(testClass, parameter, url, mutation, responseEvidence);
        return new FindingEvidence(
                run == null ? "" : run.id().toString(),
                probeId,
                detectorVersion,
                mutation,
                rationale,
                recipe);
    }

    boolean present() {
        return !runId.isBlank() || !probeId.isBlank() || !detectorVersion.isBlank()
                || !mutation.isBlank() || !confidenceRationale.isBlank()
                || !reproductionRecipe.isBlank();
    }

    private static String rationale(VerificationState state, String evidence) {
        VerificationState actual = state == null ? VerificationState.SIGNAL : state;
        String basis = clean(evidence);
        return switch (actual) {
            case SIGNAL -> "Observed a probe/result signal but not enough evidence to reproduce the vulnerability."
                    + suffix(basis);
            case CANDIDATE -> "Observed behavior consistent with the vulnerability, but independent reproduction or direct proof is still missing."
                    + suffix(basis);
            case REPRODUCED -> "The expected vulnerability-specific behavior was reproduced or baseline-differenced deterministically."
                    + suffix(basis);
            case CONFIRMED -> "Direct target behavior or correlated out-of-band evidence confirms the tested vulnerability condition."
                    + suffix(basis);
            case EXPLOITABLE -> "The vulnerability condition was confirmed and an end-impact exploit path was demonstrated."
                    + suffix(basis);
            case REJECTED -> "Follow-up evidence rejected the original candidate."
                    + suffix(basis);
        };
    }

    private static String reproductionRecipe(String testClass, String parameter, String url,
                                             String mutation, String evidence) {
        StringBuilder recipe = new StringBuilder("Replay the captured request");
        if (url != null && !url.isBlank()) recipe.append(" to ").append(url);
        if (parameter != null && !parameter.isBlank()) {
            recipe.append(", targeting ").append(parameter);
        }
        if (mutation != null && !mutation.isBlank()) {
            recipe.append(", with mutation: ").append(mutation);
        }
        if (testClass != null && !testClass.isBlank()) {
            recipe.append(". Re-run the ").append(testClass).append(" verification");
        }
        if (evidence != null && !evidence.isBlank()) {
            recipe.append(" and confirm the same evidence condition: ").append(evidence);
        }
        return recipe.append('.').toString();
    }

    private static String suffix(String evidence) {
        return evidence.isBlank() ? "" : " Evidence: " + evidence;
    }

    private static String clean(String value) {
        return Objects.toString(value, "").strip();
    }
}
