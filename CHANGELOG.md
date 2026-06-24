# Changelog

## Unreleased

### Improvements

- **Unrecognized rule names now warn**: OPA rules with names that lack a recognized prefix
  (`deny`, `violation`, `warn`, `stack_deny`, `stack_warn`) now emit a clear stderr warning
  explaining the rule won't be evaluated and how to rename it. Previously these were silently
  skipped. (#42)
- **`input.props` and `input.__props` aliases**: Resource properties are now also available
  under `input.props` and `input.__props`, aliasing the existing `input.properties` and
  `input.__properties`, to match the Node policy SDK convention. (#42)

## v1.1.0

### New Features

- **Kubernetes Admission Controller compatibility**: New `inputFormat: kubernetes-admission`
  setting in `PulumiPolicy.yaml` enables drop-in reuse of existing OPA Gatekeeper constraint
  template rules. Pulumi automatically wraps Kubernetes resources in the Gatekeeper
  AdmissionReview structure (`input.review.object`, `input.review.kind`, etc.) so `.rego`
  files work without modification. Non-Kubernetes resources are automatically skipped. (#35)

- **Gatekeeper `input.parameters` support**: Per-policy configuration properties are injected
  as `input.parameters` when using the `kubernetes-admission` input format, matching the
  Gatekeeper Constraint parameter convention. (#35)

- **Gatekeeper violation map format**: Rules returning `violation[{"msg": msg}]` (map values)
  are now handled alongside the existing string-based `deny[msg]` format. (#35)

### Improvements

- `PulumiPolicy.yaml` manifest is now parsed at load time, populating the policy pack
  description and validating the `inputFormat` field.
- Added new example: `examples/policy-kubernetes-gatekeeper/` demonstrating Gatekeeper-style
  policy reuse.

## v1.0.0

### Summary

First stable release. The OPA policy bridge now has full feature parity with the native
Python and TypeScript policy SDKs for all capabilities that apply to a Rego-based evaluator:
resource-level and stack-level policies, enforcement level control (mandatory/advisory/disabled),
policy configuration with schema validation, and OPA metadata annotations.

### Improvements

- Expanded test coverage for analyzer lifecycle methods (`Name`, `GetPluginInfo`, `Remediate`,
  `Cancel`, `Close`) and `loadPolicyPack` error paths (invalid Rego syntax, package name
  mismatches, empty directories). (#34)
- Tightened README: removed placeholder badges, redundant examples, and non-existent script
  references; reduced from ~1170 to ~815 lines. (#34)

### Known Limitations

- **Remediation is not supported.** The `Remediate()` method returns an empty response. OPA/Rego
  is a declarative evaluation engine and is not designed to produce mutated resource state. Use
  the native TypeScript or Python policy SDKs if you need auto-remediation.

## v0.2.0

### New Features

- **Resource metadata in OPA policies**: OPA policies now receive full resource metadata
  including type, URN, name, options (protect, ignoreChanges, customTimeouts, aliases),
  and provider information — not just resource properties. Collision-safe access is available
  via `input.__type`, `input.__urn`, `input.__name`, `input.__options`, `input.__provider`,
  and `input.properties.<key>`. (#24)

- **Stack-level policy support**: New `stack_deny` and `stack_warn` rule prefixes enable
  policies that evaluate the entire stack of resources at once via `AnalyzeStack()`. This
  enables cross-resource checks such as resource count limits, orphan detection, and
  relationship validation. (#25)

- **Policy configuration**: Users can pass custom properties and enforcement level overrides
  to OPA policy packs via `--policy-pack-config` JSON files. Custom config is available in
  Rego as `data.config.<policy_name>.<key>`. Enforcement levels can be overridden to
  advisory, mandatory, or disabled without modifying Rego source. Policy packs can include
  a `config-schema.json` for validation. (#27)

- **OPA annotation metadata extraction**: Policy metadata (title, description, message) is
  now extracted from OPA `METADATA` annotations on Rego rules, populating the previously
  empty Description, Message, and DisplayName fields. Pack-level DisplayName is extracted
  from package-scoped annotations. (#28)

### Improvements

- Use subtests and `t.Parallel()` across all test files for better organization and faster
  test execution. (#29)
- Provider info is always defined (empty map when nil) so policies can safely reference
  provider fields without guarding against undefined.
- Rich aliases: `options.aliases` exposes the full Alias struct; URN-only aliases moved to
  `options.aliasURNs`.
- Guard against panic when OPA rules return non-string values.
- Support for both Rego v0 and v1 syntax.
- Updated documentation and examples for all new features.

## v0.1.0

Initial release.
