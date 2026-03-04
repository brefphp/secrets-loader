Automatically load secrets from SSM or Secrets Manager into environment variables when running with Bref.

It replaces (at runtime) the variables whose value starts with `bref-ssm:` or `bref-secret:`. For example, you could set such a variable in `serverless.yml` like this:

```yaml
provider:
    # ...
    environment:
        MY_PARAMETER: bref-ssm:/my-app/my-parameter
```

In AWS Lambda, the `MY_PARAMETER` would be automatically replaced and would contain the value stored at `/my-app/my-parameter` in AWS SSM Parameters.

This feature is shipped as a separate package so that all its code and dependencies are not installed by default for all Bref users. Install this package if you want to use the feature.

## Installation

```
composer require bref/secrets-loader
```

## Usage

Read the Bref documentation: https://bref.sh/docs/environment/variables.html#secrets

### SSM Parameter Store

```yaml
provider:
    environment:
        MY_PARAMETER: bref-ssm:/my-app/my-parameter
```

`MY_PARAMETER` is replaced at runtime with the value stored at `/my-app/my-parameter` in SSM.

### Secrets Manager

You can also use AWS Secrets Manager. Store all your env vars as a single JSON secret and load them in 1 API call:

```bash
aws secretsmanager create-secret \
  --name api/production \
  --secret-string '{"DB_PASSWORD":"secret123","API_KEY":"abc-xyz"}'
```

**Global import** — all JSON keys become env vars:

```yaml
provider:
    environment:
        BREF_SECRETS_MANAGER: api/${sls:stage}
    iam:
        role:
            statements:
                - Effect: Allow
                  Action: secretsmanager:GetSecretValue
                  Resource: arn:aws:secretsmanager:${aws:region}:${aws:accountId}:secret:api/${sls:stage}-*
```

> **Note:** The `-*` wildcard at the end of the ARN is required. Secrets Manager appends a random 6-character suffix to every secret ARN (e.g., `api/production-AbCdEf`). Without the wildcard, IAM will deny the request.

**Individual import** — load specific secrets per env var:

```yaml
provider:
    environment:
        # Plain string secret
        VENDOR_KEY: bref-secret:vendor/api-key
        # Extract a specific key from a JSON secret
        SPECIFIC_VAR: bref-secret:api/${sls:stage}:SPECIFIC_KEY
```

Multiple references to the same secret name are deduplicated into a single API call.

### Combining both backends

You can use both SSM and Secrets Manager together. If the same env var name is set by multiple sources, the more explicit source wins:

1. `bref-ssm:` overrides everything
2. `bref-secret:` overrides the global import
3. `BREF_SECRETS_MANAGER` global import sets the baseline

```yaml
provider:
    environment:
        BREF_SECRETS_MANAGER: api/${sls:stage}
        VENDOR_KEY: bref-secret:vendor/api-key
        MY_PARAMETER: bref-ssm:/my-app/my-parameter
```

### Important: `bref/bref` compatibility

The current version of `bref/bref` only triggers the secrets loader when it detects at least one `bref-ssm:` env var. If you're using Secrets Manager without any SSM parameters, the loader won't run and your env vars won't be set.

Until `bref/bref` is updated, keep at least one `bref-ssm:` variable in your configuration alongside `BREF_SECRETS_MANAGER` or `bref-secret:` vars.

### When to use Secrets Manager over SSM

SSM Parameter Store works well at low concurrency. Standard parameters are free below 40 TPS (shared across all `GetParameter*` APIs). But SSM's `GetParameters` batches at most 10 parameters per call. If you have 50 parameters, that's 5 API calls (5 TPS) per cold start — so only 8 simultaneous cold starts will hit the 40 TPS default limit. Beyond that, requests get throttled unless you enable higher throughput.

With higher throughput enabled, SSM charges $0.05 per 10,000 API interactions. Note that AWS counts each individual parameter returned as a separate interaction, not each API call. So those 5 batch calls returning 50 parameters count as 50 billable interactions per cold start.

Secrets Manager takes a different approach: you store all your variables in one JSON secret and fetch them in 1 API call per cold start. It costs $0.40/secret/month plus $0.05 per 10,000 API calls, and handles up to 10,000 TPS.

Here's how costs compare with 50 parameters at different cold start volumes (assuming 30 days):

```
                       SSM (free tier,    SSM (higher        Secrets Manager
Cold starts/day        ≤40 TPS)           throughput)        (1 JSON secret)
─────────────────────────────────────────────────────────────────────────────
100                    $0.00*             $0.75/mo           $0.42/mo
500                    $0.00*             $3.75/mo           $0.48/mo
1,000                  $0.00*             $7.50/mo           $0.55/mo
```

\* Free but limited to 40 TPS shared — cold start spikes will cause throttling errors.

In short: SSM is effectively free at low scale but breaks under concurrency pressure. Secrets Manager has a small fixed cost but stays cheap and reliable as you scale, because 1 API call beats 50 interactions every time.

Pricing as of March 2025 — see [SSM pricing](https://aws.amazon.com/systems-manager/pricing/) and [Secrets Manager pricing](https://aws.amazon.com/secrets-manager/pricing/) for current rates.
