package com.victor.reconloop;

/** Lifecycle state for a scan run. */
enum RunStatus {
    PLANNED,
    RUNNING,
    PAUSED,
    INTERRUPTED,
    CANCELLED,
    COMPLETED,
    FAILED
}
