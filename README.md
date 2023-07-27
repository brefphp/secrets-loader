Automatically load secrets from SSM into environment variables when running with Bref.

It replaces (at runtime) the variables whose value starts with `bref-ssm:`. For example, you could set such a variable in `serverless.yml` like this:

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

