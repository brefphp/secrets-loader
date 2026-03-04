<?php declare(strict_types=1);

namespace Bref\Secrets;

use AsyncAws\Core\Exception\Http\ClientException;
use AsyncAws\SecretsManager\Exception\ResourceNotFoundException;
use AsyncAws\SecretsManager\SecretsManagerClient;
use AsyncAws\Ssm\SsmClient;
use Closure;
use JsonException;
use RuntimeException;

class Secrets
{
    /** @var resource|null Override to capture log output in tests. */
    public static $outputStream = null;

    /**
     * Load secret environment variables from AWS Secrets Manager and/or SSM Parameter Store.
     *
     * Processing order (later phases override earlier ones for same key):
     * 1. BREF_SECRETS_MANAGER global import (all JSON keys become env vars)
     * 2. Individual bref-secret: prefix env vars
     * 3. Individual bref-ssm: prefix env vars (existing behavior)
     *
     * @param SsmClient|null $ssmClient To allow mocking in tests.
     * @param SecretsManagerClient|null $smClient To allow mocking in tests.
     * @throws JsonException
     */
    public static function loadSecretEnvironmentVariables(?SsmClient $ssmClient = null, ?SecretsManagerClient $smClient = null): void
    {
        /** @var array<string,string>|string|false $envVars */
        $envVars = getenv(local_only: true);
        if (! is_array($envVars)) {
            return;
        }

        // Secrets Manager (global import + individual bref-secret: vars)
        self::loadSecretsManager($smClient, $envVars);

        // SSM bref-ssm: prefix env vars
        self::loadSsmParameters($ssmClient, $envVars);
    }

    /**
     * Load env vars from AWS Secrets Manager.
     *
     * Collects all needed secret names from both BREF_SECRETS_MANAGER and bref-secret: env vars,
     * fetches them in a single cached batch, then sets env vars.
     *
     * @param array<string,string> $envVars
     */
    private static function loadSecretsManager(?SecretsManagerClient $smClient, array $envVars): void
    {
        $globalSecretName = $envVars['BREF_SECRETS_MANAGER'] ?? null;
        if ($globalSecretName === '') {
            $globalSecretName = null;
        }

        // Find individual bref-secret: env vars and group by secret name
        $envVarsToResolve = array_filter($envVars, function (string $value): bool {
            return str_starts_with($value, 'bref-secret:');
        });

        /** @var array<string, list<array{envVar: string, jsonKey: string|null}>> $secretNameToEnvVars */
        $secretNameToEnvVars = [];
        foreach ($envVarsToResolve as $envVar => $prefixedValue) {
            $withoutPrefix = substr($prefixedValue, strlen('bref-secret:'));
            // Parse: secret-name or secret-name:json-key
            // Secret names can contain / but not colons, so first colon is the separator
            $colonPos = strpos($withoutPrefix, ':');
            if ($colonPos !== false) {
                $secretName = substr($withoutPrefix, 0, $colonPos);
                $jsonKey = substr($withoutPrefix, $colonPos + 1);
            } else {
                $secretName = $withoutPrefix;
                $jsonKey = null;
            }
            $secretNameToEnvVars[$secretName][] = [
                'envVar' => $envVar,
                'jsonKey' => $jsonKey,
            ];
        }

        // Collect all unique secret names needed
        $allSecretNames = array_keys($secretNameToEnvVars);
        if ($globalSecretName !== null && ! in_array($globalSecretName, $allSecretNames, true)) {
            $allSecretNames[] = $globalSecretName;
        }

        if (empty($allSecretNames)) {
            return;
        }

        // Fetch all secrets in a single cached batch (1 API call per unique secret name)
        $actuallyCalledApi = false;
        $fetchedSecrets = self::readFromCacheOr(
            sys_get_temp_dir() . '/bref-secrets-manager.php',
            function () use ($smClient, $allSecretNames, &$actuallyCalledApi) {
                $actuallyCalledApi = true;
                $secrets = [];
                foreach ($allSecretNames as $secretName) {
                    $fetched = self::retrieveFromSecretsManager($smClient, $secretName);
                    $secrets = array_merge($secrets, $fetched);
                }
                return $secrets;
            }
        );

        // Global import: set all JSON keys as env vars
        if ($globalSecretName !== null) {
            $secretValue = $fetchedSecrets[$globalSecretName] ?? null;
            if ($secretValue !== null) {
                /** @var mixed $decoded */
                $decoded = json_decode($secretValue, true, 512, JSON_THROW_ON_ERROR);
                if (! is_array($decoded)) {
                    throw new RuntimeException(
                        "Secret '$globalSecretName' is not valid JSON. When using BREF_SECRETS_MANAGER or bref-secret: with a JSON key, the secret value must be a valid JSON object."
                    );
                }
                foreach ($decoded as $key => $value) {
                    if (! is_scalar($value) && $value !== null) {
                        throw new RuntimeException(
                            "Secret '$globalSecretName' contains non-scalar value for key '$key'. Only string, number, and boolean values are supported."
                        );
                    }
                    $stringValue = (string) $value;
                    $_SERVER[$key] = $_ENV[$key] = $stringValue;
                    putenv("$key=$stringValue");
                }
            }

            // Consume the BREF_SECRETS_MANAGER env var
            unset($_SERVER['BREF_SECRETS_MANAGER'], $_ENV['BREF_SECRETS_MANAGER']);
            putenv('BREF_SECRETS_MANAGER');
        }

        // Individual bref-secret: env vars override global import for the same key
        $individualEnvVarsSet = [];
        foreach ($secretNameToEnvVars as $secretName => $envVarMappings) {
            $secretValue = $fetchedSecrets[$secretName] ?? null;
            if ($secretValue === null) {
                continue;
            }

            foreach ($envVarMappings as $mapping) {
                $envVar = $mapping['envVar'];
                $jsonKey = $mapping['jsonKey'];

                if ($jsonKey !== null) {
                    $decoded = json_decode($secretValue, true, 512, JSON_THROW_ON_ERROR);
                    if (! is_array($decoded)) {
                        throw new RuntimeException(
                            "Secret '$secretName' is not valid JSON. When using bref-secret: with a JSON key, the secret value must be a valid JSON object."
                        );
                    }
                    if (! array_key_exists($jsonKey, $decoded)) {
                        throw new RuntimeException(
                            "Key '$jsonKey' not found in secret '$secretName'. Available keys: " . implode(', ', array_keys($decoded))
                        );
                    }
                    $value = (string) $decoded[$jsonKey];
                } else {
                    $value = $secretValue;
                }

                $_SERVER[$envVar] = $_ENV[$envVar] = $value;
                putenv("$envVar=$value");
                $individualEnvVarsSet[] = $envVar;
            }
        }

        // Log loaded env vars (only on actual API call, not from cache)
        if ($actuallyCalledApi) {
            $allEnvVarsSet = [];
            if ($globalSecretName !== null) {
                $secretValue = $fetchedSecrets[$globalSecretName] ?? null;
                if ($secretValue !== null) {
                    $decoded = json_decode($secretValue, true, 512, JSON_THROW_ON_ERROR);
                    if (is_array($decoded)) {
                        $allEnvVarsSet = array_keys($decoded);
                    }
                }
            }
            $allEnvVarsSet = array_unique(array_merge($allEnvVarsSet, $individualEnvVarsSet));
            if (! empty($allEnvVarsSet)) {
                $secretNameStr = implode("', '", $allSecretNames);
                self::writeLog("[Bref] Loaded environment variables from Secrets Manager secret '$secretNameStr': " . implode(', ', $allEnvVarsSet) . PHP_EOL);
            }
        }
    }

    /**
     * Load SSM parameters.
     *
     * @param array<string,string> $envVars
     */
    private static function loadSsmParameters(?SsmClient $ssmClient, array $envVars): void
    {
        // Only consider environment variables that start with "bref-ssm:"
        $envVarsToDecrypt = array_filter($envVars, function (string $value): bool {
            return str_starts_with($value, 'bref-ssm:');
        });
        if (empty($envVarsToDecrypt)) {
            return;
        }

        // Extract the SSM parameter names by removing the "bref-ssm:" prefix
        $ssmNames = array_map(function (string $value): string {
            return substr($value, strlen('bref-ssm:'));
        }, $envVarsToDecrypt);

        $actuallyCalledSsm = false;
        $parameters = self::readFromCacheOr(
            sys_get_temp_dir() . '/bref-ssm-parameters.php',
            function () use ($ssmClient, $ssmNames, &$actuallyCalledSsm) {
                $actuallyCalledSsm = true;
                return self::retrieveParametersFromSsm($ssmClient, array_values($ssmNames));
            }
        );

        foreach ($envVarsToDecrypt as $envVar => $prefixedSsmRefName) {
            $parameterName = substr($prefixedSsmRefName, strlen('bref-ssm:'));
            $parameterValue = $parameters[$parameterName];
            $_SERVER[$envVar] = $_ENV[$envVar] = $parameterValue;
            putenv("$envVar=$parameterValue");
        }

        // Only log once (when the cache was empty) else it might spam the logs in the function runtime
        // (where the process restarts on every invocation)
        if ($actuallyCalledSsm) {
            self::writeLog('[Bref] Loaded these environment variables from SSM: ' . implode(', ', array_keys($envVarsToDecrypt)) . PHP_EOL);
        }
    }

    /**
     * Write a log message to stderr (or to the override stream for testing).
     */
    private static function writeLog(string $message): void
    {
        $stream = self::$outputStream ?? fopen('php://stderr', 'ab');
        fwrite($stream, $message);
        if (self::$outputStream === null) {
            fclose($stream);
        }
    }

    /**
     * Read from a file cache, or resolve and write to cache.
     *
     * Why cache? On the function runtime the PHP process may restart on every
     * invocation (or on error), so we avoid calling AWS APIs every time.
     *
     * @param Closure(): array<string, string> $resolver
     * @return array<string, string>
     * @throws JsonException
     */
    private static function readFromCacheOr(string $cacheFile, Closure $resolver): array
    {
        if (is_file($cacheFile)) {
            $data = json_decode(file_get_contents($cacheFile), true, 512, JSON_THROW_ON_ERROR);
            if (is_array($data)) {
                return $data;
            }
        }

        $data = $resolver();

        file_put_contents($cacheFile, json_encode($data, JSON_THROW_ON_ERROR));

        return $data;
    }

    /**
     * Fetch a secret from AWS Secrets Manager.
     *
     * @return array<string, string> Map of secret name -> raw secret string value
     */
    private static function retrieveFromSecretsManager(?SecretsManagerClient $smClient, string $secretName): array
    {
        $sm = $smClient ?? new SecretsManagerClient([
            'region' => $_ENV['AWS_REGION'] ?? $_ENV['AWS_DEFAULT_REGION'],
        ]);

        try {
            $result = $sm->getSecretValue(['SecretId' => $secretName]);
            $secretString = $result->getSecretString();
        } catch (ResourceNotFoundException $e) {
            throw new RuntimeException(
                "Secret '$secretName' not found in AWS Secrets Manager. Check that the secret exists and the name is correct.",
                $e->getCode(),
                $e,
            );
        } catch (ClientException $e) {
            $message = $e->getMessage();
            // Check if this is actually a permissions error vs. other errors (e.g., throttling)
            if (str_contains($message, 'not authorized') || str_contains($message, 'AccessDenied') || str_contains($message, 'access denied')) {
                throw new RuntimeException(
                    "Bref was not able to retrieve secret '$secretName' from AWS Secrets Manager because of a permissions issue. Did you add `secretsmanager:GetSecretValue` to your IAM role? (docs: https://bref.sh/docs/environment/variables.html)\nFull exception message: {$e->getMessage()}",
                    $e->getCode(),
                    $e,
                );
            }
            throw $e;
        }

        if ($secretString === null) {
            throw new RuntimeException(
                "Secret '$secretName' does not contain a string value. Binary secrets are not supported."
            );
        }

        return [$secretName => $secretString];
    }

    /**
     * @param string[] $ssmNames
     * @return array<string, string> Map of parameter name -> value
     */
    private static function retrieveParametersFromSsm(?SsmClient $ssmClient, array $ssmNames): array
    {
        $ssm = $ssmClient ?? new SsmClient([
            'region' => $_ENV['AWS_REGION'] ?? $_ENV['AWS_DEFAULT_REGION'],
        ]);

        /** @var array<string, string> $parameters Map of parameter name -> value */
        $parameters = [];
        $parametersNotFound = [];

        // The API only accepts up to 10 parameters at a time, so we batch the calls
        foreach (array_chunk($ssmNames, 10) as $batchOfSsmNames) {
            try {
                $result = $ssm->getParameters([
                    'Names' => $batchOfSsmNames,
                    'WithDecryption' => true,
                ]);
                foreach ($result->getParameters() as $parameter) {
                    $parameters[$parameter->getName()] = $parameter->getValue();
                }
            } catch (RuntimeException $e) {
                if ($e->getCode() === 400) {
                    $message = $e->getMessage();
                    // Check if this is actually a permissions error vs. other 400 errors (e.g., throttling)
                    if (str_contains($message, 'not authorized') || str_contains($message, 'AccessDenied') || str_contains($message, 'access denied')) {
                        throw new RuntimeException(
                            "Bref was not able to resolve secrets contained in environment variables from SSM because of a permissions issue with the SSM API. Did you add IAM permissions in serverless.yml to allow Lambda to access SSM? (docs: https://bref.sh/docs/environment/variables.html#at-deployment-time).\nFull exception message: {$e->getMessage()}",
                            $e->getCode(),
                            $e,
                        );
                    }
                }
                throw $e;
            }
            $parametersNotFound = array_merge($parametersNotFound, $result->getInvalidParameters());
        }

        if (count($parametersNotFound) > 0) {
            throw new RuntimeException('The following SSM parameters could not be found: ' . implode(', ', $parametersNotFound));
        }

        return $parameters;
    }
}
