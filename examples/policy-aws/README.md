## AWS Security Policy Pack

This example demonstrates several features of the Pulumi OPA Policy Bridge:

- **Resource-level policies** using `deny` and `warn` prefixes
- **Stack-level policies** using `stack_deny` to enforce cross-resource constraints
- **Policy configuration** with `config-schema.json` for the `deny_large_instances` rule
- **OPA annotations** (`# METADATA` blocks) for policy metadata

### Usage

```bash
# Run against your Pulumi project
pulumi preview --policy-pack /path/to/examples/policy-aws

# Override enforcement level for a rule
# (via Pulumi policy configuration)
pulumi preview --policy-pack /path/to/examples/policy-aws \
    --policy-pack-config policy-config.json
```

Example `policy-config.json`:
```json
{
    "deny_large_instances": {
        "properties": {
            "maxInstanceSize": "m5.xlarge"
        }
    },
    "warn_logging": {
        "enforcementLevel": "mandatory"
    }
}
```
