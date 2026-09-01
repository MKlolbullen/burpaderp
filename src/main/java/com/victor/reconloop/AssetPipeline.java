package com.victor.reconloop;

import com.victor.reconloop.contracts.Asset;
import com.victor.reconloop.contracts.ContractResult;
import com.victor.reconloop.contracts.ContractValidator;
import com.victor.reconloop.contracts.ParamLocation;
import com.victor.reconloop.contracts.PayloadFamily;
import com.victor.reconloop.contracts.PayloadRouter;
import com.victor.reconloop.contracts.Quarantine;
import com.victor.reconloop.contracts.Rejected;
import com.victor.reconloop.contracts.VerificationState;

import java.util.Set;
import java.util.UUID;

/**
 * Adapter between Burp ingest paths and the typed contract validators.
 * Invalid assets are quarantined instead of entering Hosts / discovery / params.
 */
final class AssetPipeline {
    private final ContractValidator validator = new ContractValidator();
    private final Quarantine quarantine = new Quarantine();
    private final PayloadRouter router;
    private final ReconModel.QuarantineTableModel model;
    private volatile UUID runId = UUID.randomUUID();

    AssetPipeline(ReconModel.QuarantineTableModel model, boolean allowDestructive) {
        this.model = model;
        this.router = new PayloadRouter(allowDestructive);
    }

    UUID runId() {
        return runId;
    }

    void newRun() {
        runId = UUID.randomUUID();
        quarantine.clear();
        if (model != null) model.clear();
    }

    Quarantine quarantine() {
        return quarantine;
    }

    PayloadRouter router() {
        return router;
    }

    boolean acceptHost(String raw, boolean inScope, String source) {
        ContractResult<Asset.Hostname> result = validator.hostname(raw, inScope, source, 0);
        return accept(result);
    }

    boolean acceptIp(String raw, boolean inScope, String source) {
        ContractResult<Asset.IpOrCidr> result = validator.ipOrCidr(raw, inScope, source);
        return accept(result);
    }

    boolean acceptUrl(String raw, boolean inScope, String source) {
        return accept(validator.url(raw, inScope, source));
    }

    PayloadFamily familyFor(Set<String> profilerClasses) {
        if (profilerClasses == null || profilerClasses.isEmpty()) return PayloadFamily.GENERIC;
        for (String cls : profilerClasses) {
            PayloadFamily family = PayloadRouter.hintFromProfilerClass(cls);
            if (family != PayloadFamily.GENERIC) return family;
        }
        return PayloadFamily.GENERIC;
    }

    boolean corpusCategoryFits(String category, PayloadFamily hint) {
        PayloadFamily family = PayloadRouter.fromManifestCategory(category);
        Asset.ParameterizedUrl probe = new Asset.ParameterizedUrl(
                java.net.URI.create("https://scope.invalid/"),
                "param",
                ParamLocation.QUERY,
                hint,
                "profiler");
        return router.compatible(family, probe);
    }

    VerificationState defaultState() {
        return VerificationState.SIGNAL;
    }

    private boolean accept(ContractResult<?> result) {
        if (result == null) return false;
        if (result.accepted()) return true;
        absorb(result);
        return false;
    }

    private void absorb(ContractResult<?> result) {
        quarantine.absorb(result);
        Rejected rejected = result.rejected();
        if (rejected != null && model != null) {
            model.add(new ReconModel.QuarantineRow(
                    rejected.schema(), rejected.reason(), rejected.raw(), rejected.source()));
        }
    }
}
