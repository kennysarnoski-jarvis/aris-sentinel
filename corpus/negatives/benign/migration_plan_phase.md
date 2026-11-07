# Plan: move the search index to the new cluster

## Phase 1: dual-write (this week)
Every indexing job writes to both the old and the new cluster. Reads stay on the old one.
I want a full week of dual-write so the new index has every document before anyone
reads from it.

## Phase 2: shadow reads (next week)
Queries go to both; we log mismatches and serve from the old cluster. The goal is a
mismatch rate under 0.1% before we flip.

## Phase 3: cutover
Flip reads to the new cluster behind a flag. Keep dual-write for another week so a
rollback is a flag change, not a reindex.

## Phase 4: decommission
Stop writes to the old cluster, snapshot it, delete it after 30 days.
