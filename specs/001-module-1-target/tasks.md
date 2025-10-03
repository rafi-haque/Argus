# Tasks: Web Vulnerability Scanner

**Input**: Design documents from `/specs/001-module-1-target/`
**Prerequisites**: plan.md (required), research.md, data-model.md, contracts/

## Execution Flow (main)
```
1. Load plan.md from feature directory
   → If not found: ERROR "No implementation plan found"
   → Extract: tech stack, libraries, structure
2. Load optional design documents:
   → data-model.md: Extract entities → model tasks
   → contracts/: Each file → contract test task
   → research.md: Extract decisions → setup tasks
3. Generate tasks by category:
   → Setup: project init, dependencies, linting
   → Tests: contract tests, integration tests
   → Core: models, services, CLI commands
   → Integration: DB, middleware, logging
   → Polish: unit tests, performance, docs
4. Apply task rules:
   → Different files = mark [P] for parallel
   → Same file = sequential (no [P])
   → Tests before implementation (TDD)
5. Number tasks sequentially (T001, T002...)
6. Generate dependency graph
7. Create parallel execution examples
8. Validate task completeness:
   → All contracts have tests?
   → All entities have models?
   → All endpoints implemented?
9. Return: SUCCESS (tasks ready for execution)
```

## Format: `[ID] [P?] Description`
- **[P]**: Can run in parallel (different files, no dependencies)
- Include exact file paths in descriptions

## Path Conventions
- **Argus project**: `argus/`, `tests/` at repository root
- Adjust based on plan.md structure

## Phase 0: Foundation & Setup
- [x] T001 Create argus/ directory structure per implementation plan
- [ ] T002 Initialize Git repository in argus/
- [ ] T003 Set up Python virtual environment (.venv)
- [x] T004 Create requirements.txt with initial dependencies (requests, beautifulsoup4)
- [ ] T005 Install OWASP Juice Shop via Docker for testing (requires manual Docker installation)
- [x] T006 Write initial README.md with project goal and ethical disclaimer

## Phase 1: Tests First (TDD) ⚠️ MUST COMPLETE BEFORE Phase 1 Implementation
- [x] T007 [P] Create contract test for attack_module interface (tests/contract/test_attack_module.py)
- [x] T008 [P] Create contract test for crawler interface (tests/contract/test_crawler.py)
- [x] T009 [P] Create contract test for orchestrator interface (tests/contract/test_orchestrator.py)
- [x] T010 [P] Create contract test for reporting interface (tests/contract/test_reporting.py)
- [x] T011 [P] Create integration test for basic header check scenario (tests/integration/test_basic_scan.py)
- [x] T012 [P] Create integration test for site map discovery (tests/integration/test_crawler.py)
- [x] T013 [P] Create integration test for SQLi detection (tests/integration/test_sqli_detection.py)
- [x] T014 [P] Create integration test for XSS detection (tests/integration/test_xss_detection.py)
- [x] T015 [P] Create integration test for full scan workflow (tests/integration/test_full_scan.py)

## Phase 1: The Simplest End-to-End Flow
- [x] T016 Implement basic CLI with argparse (argus/main.py)
- [x] T017 Build Insecure Headers attack module (argus/modules/attack_modules/insecure_headers.py)
- [x] T018 Build rudimentary reporting engine (argus/modules/reporting.py)

## Phase 2: Basic Crawling & Orchestration
- [x] T019 [P] Implement Site Map data structure (argus/modules/crawler.py)
- [x] T020 Build passive crawler with requests and BeautifulSoup (argus/modules/crawler.py)
- [x] T021 Build basic Scanning Orchestrator (argus/modules/orchestrator.py)

## Phase 3: The First Real Attack Module (SQLi)
- [x] T022 Implement response diffing utility (argus/modules/attack_modules/sqli.py)
- [x] T023 Build Boolean-Based SQLi module (argus/modules/attack_modules/sqli.py)
- [x] T024 Integrate SQLi module into Orchestrator (argus/modules/orchestrator.py)

## Phase 4: Introducing Context and Headless Browsing
- [x] T025 Integrate Playwright for headless browsing (requirements.txt, argus/modules/crawler.py)
- [x] T026 Augment crawler with active crawling (argus/modules/crawler.py)
- [x] T027 Enhance Orchestrator with contextual rules (argus/modules/orchestrator.py)
- [x] T028 Build Reflected XSS module (argus/modules/attack_modules/xss.py)

## Phase 5: Advanced Detection & Reporting
- [x] T029 Implement Time-Based SQLi module (argus/modules/attack_modules/sqli.py)
- [x] T030 Implement DOM-Based XSS module (argus/modules/attack_modules/xss.py)
- [x] T031 Build JSON reporting engine (argus/modules/reporting.py)
- [x] T032 Refine CLI output to be clean and professional (argus/main.py)

## Phase 6: Polish & Documentation
- [x] **T033**: Add comprehensive unit tests for all modules (`tests/unit/`)
  - Priority: Medium
  - Dependencies: T016-T028
- [x] T034 [P] Add performance tests and optimizations (tests/performance/)
- [x] T035 Update README.md with usage instructions and examples (README.md)
- [x] T036 Add configuration management (argus/config/config.py)
- [x] T037 Implement logging and error handling (argus/modules/)

## Dependency Graph
- T001-T006: Setup tasks, no dependencies
- T007-T015: Test tasks [P], depend on T001 (structure)
- T016-T018: Phase 1 core, depend on T007-T011 (tests)
- T019-T021: Phase 2 core, depend on T016-T018
- T022-T024: Phase 3 core, depend on T019-T021
- T025-T028: Phase 4 core, depend on T022-T024
- T029-T032: Phase 5 core, depend on T025-T028
- T033-T037: Polish, depend on all core tasks

## Parallel Execution Examples
Run setup tasks sequentially, then tests in parallel:
```
/execute T001
/execute T002
...
/execute T007 T008 T009 T010 T011 T012 T013 T014 T015
```

Run model/entity tasks in parallel:
```
/execute T019 T020 T021
```

Run integration tests in parallel:
```
/execute T011 T012 T013 T014 T015
```

## Validation Checklist
- [x] All 4 contract files have corresponding tests (T007-T010)
- [x] All 3 entities have model implementations (implied in core tasks)
- [x] All 5 user stories have integration tests (T011-T015)
- [x] Dependencies respected (tests before implementation)
- [x] File paths specified for all tasks
- [x] Parallel opportunities identified