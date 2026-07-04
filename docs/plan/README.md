# Plan Workflow

## Task States

```text
pending -> ready -> in-progress -> done
                      |
                      v
                    blocked
```

`pending` tasks have unfinished dependencies. `ready` tasks can start. `in-progress` tasks are actively being implemented. `done` tasks have passed verification and have been committed. `blocked` tasks need a design or implementation decision before work continues.

## Task File Contract

Every task file contains:

- YAML front matter with `id`, `scope`, `status`, and `depends-on`;
- `objective`: the smallest independently reviewable outcome;
- `context`: design docs that define the contract;
- `path`: files and directories the task may touch;
- `verification`: commands or smoke scenarios required before commit;
- `notes`: constraints and known exclusions.

## Execution Rules

- Start only `ready` tasks.
- Commit each completed task before beginning the next task.
- Use Conventional Commits.
- Stage only paths listed in the task.
- If a task changes public behavior, update the relevant design doc listed in `context`.
- Do not implement backlog items inside MVP/Phase 2 tasks.
- Performance viability gates may be promoted ahead of compatibility or build
  work when measured latency threatens product value. They must be represented
  by an explicit task, record before/after measurements, and stay focused on
  the diagnosed runtime bottleneck rather than reopening broad backend rewrites.

## Review Rules

Review checks:

- implementation matches the design docs;
- integration tasks replace stubs with real call paths;
- unsupported behavior returns intentional errors;
- tests cover the contract and important failure paths;
- task paths do not include unrelated changes.

Blocking findings must be fixed before a task is marked done.
