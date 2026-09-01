package com.victor.reconloop.contracts;

import java.util.ArrayList;
import java.util.List;

/** In-memory reject sink used by every stage. */
public final class Quarantine {
    private final List<Rejected> items = new ArrayList<>();

    public void add(Rejected rejected) {
        if (rejected != null) items.add(rejected);
    }

    public <T> ContractResult<T> absorb(ContractResult<T> result) {
        if (result != null && !result.accepted()) add(result.rejected());
        return result;
    }

    public List<Rejected> snapshot() {
        return List.copyOf(items);
    }

    public int size() {
        return items.size();
    }

    public void clear() {
        items.clear();
    }
}
