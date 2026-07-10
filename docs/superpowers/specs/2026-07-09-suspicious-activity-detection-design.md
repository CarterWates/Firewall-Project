# Suspicious Activity Detection Design

## Goal

Detect repeated suspicious connection attempts from stored firewall events and produce safe temporary block recommendations without changing firewall state.

## Scope

Phase four adds a detection module, repository time-window query support, and a `detect scan` CLI command. It reports sources that exceed a configurable attempt threshold within a recent time window and renders a dry-run nftables rule recommendation for each source.

The milestone does not execute temporary block commands, schedule expiration, or persist block decisions.

## Architecture

- `detection.suspicious` groups events by source IP and returns suspicious sources.
- `detection.blocking` renders temporary block plans as text for operator review.
- `database.events` gains `list_since`.
- `cli.main` adds a `detect` command group with `scan`.

Detection consumes stored events instead of raw logs. This keeps parsing, persistence, and analysis separate.

## Safety

Temporary block plans are recommendations only. The CLI must clearly say no firewall commands were executed. Generated recommendations use documentation-friendly text and include an expiration timestamp in the comment for future rollback tooling.

## Testing

Tests cover threshold behavior, time-window filtering, deterministic ordering by event count, temporary block rule rendering, repository `list_since`, and CLI scan output.
