<!-- Sync Impact Report
Version change: none → 1.0.0
List of modified principles: All principles added (Context Over Volume, Modularity and Extensibility, Developer-First Interface, Safety and Ethics First, Performance Matters)
Added sections: Primary Goal, Implementation Guidelines
Removed sections: none
Templates requiring updates: none (new constitution)
Follow-up TODOs: RATIFICATION_DATE (original adoption date unknown), GUIDANCE_FILE (runtime guidance file not specified), SECTION_3_CONTENT (implementation guidelines not provided)
-->

# Argus Security Scanner Constitution

## Core Principles

### Context Over Volume
The scanner's primary strength will be its ability to choose the right payload for the right parameter. We prefer one accurate SQLi finding over 10,000 blind, noisy requests.

### Modularity and Extensibility
The architecture must be pluggable. Adding a new vulnerability detection module (e.g., for SSRF) should be straightforward and not require rewriting the core engine.

### Developer-First Interface
The tool should be easy to run and its output must be clear, actionable, and available in both human-readable (CLI) and machine-readable (JSON) formats.

### Safety and Ethics First
The tool is a weapon. It must be built and documented with a strong ethical framework. It will never default to a dangerous action and will include clear warnings against misuse.

### Performance Matters
While context is key, the tool should be reasonably performant and utilize concurrency to scan multiple endpoints or parameters simultaneously where appropriate.

## Primary Goal
To create an automated security tool that discovers common web vulnerabilities by understanding the application's context, leading to fewer, more accurate findings than a purely "dumb" fuzzer.

## Implementation Guidelines
TODO: Define specific development workflow, review process, and quality gates.

## Governance
Constitution supersedes all other practices; Amendments require documentation, approval, migration plan

All PRs/reviews must verify compliance; Complexity must be justified; Use TODO(GUIDANCE_FILE): runtime development guidance file not specified for runtime development guidance

**Version**: 1.0.0 | **Ratified**: TODO(RATIFICATION_DATE): Original adoption date unknown | **Last Amended**: 2025-10-04