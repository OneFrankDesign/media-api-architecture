## Summary of Changes

Describe what changed and why.

## TDD Evidence (Failing Test First)

Link or paste the failing test evidence that existed before implementation.

## Implementation Delta

Describe exactly what was implemented to make the failing tests pass.

## Refactor Notes (Optional)

List any no-behavior-change refactors made after tests passed.

## Risk and Blast Radius

Describe user-visible and operational risk for this change.

## Test Evidence

List all validation steps and results:
- unit
- integration
- e2e (if required for this change)
- contract generation drift check

## Rollback Plan

Reference rollback command/runbook and target SHA strategy.

## Atomic Change Checklist

- [ ] PR scope is one behavior-focused change
- [ ] commit sequence follows test -> implementation -> optional refactor
- [ ] rollback steps are documented for this change
