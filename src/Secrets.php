<?php declare(strict_types=1);

namespace Bref\Secrets;

use AsyncAws\SecretsManager\SecretsManagerClient;
use AsyncAws\Ssm\SsmClient;
use Closure;
use Exception;
use JsonException;
use RuntimeException;

class Secrets
{
    /**
     * Decrypt environment variables that are encrypted with AWS SSM.
     *
     * @param SsmClient|null $ssmClient To allow mocking in tests.
     * @param SecretsManagerClient|null $secretsManagerClient To allow mocking in tests.
     * @throws JsonException
     */
    public static function loadSecretEnvironmentVariables(?SsmClient $ssmClient = null, ?SecretsManagerClient $secretsManagerClient = null): void
    {
        /** @var array<string,string>|string|false $envVars */
        $envVars = getenv(local_only: true);
        if (! is_array($envVars)) {
            return;
        }

        // Only consider environment variables that start with "bref-ssm:" or "bref-secretsmanager:"
        $envVarsToDecrypt = array_filter($envVars, function (string $value): bool {
            return str_starts_with($value, 'bref-ssm:') || str_starts_with($value, 'bref-secretsmanager:');
        });
        if (empty($envVarsToDecrypt)) {
            return;
        }
 
        $ssmNames = [];
        $secretsManagerNames = [];

        // Extract the SSM and Secrets Manager parameter names by removing the prefixes
        foreach ($envVarsToDecrypt as $key => $envVar) {
            if (str_starts_with($envVar, 'bref-ssm:')) {
                $ssmNames[$key] = substr($envVar, strlen('bref-ssm:'));
            }
            if (str_starts_with($envVar, 'bref-secretsmanager:')) {
                $secretsManagerNames[$key] = substr($envVar, strlen('bref-secretsmanager:'));
            }
        }

        if (count($secretsManagerNames) > 0 && class_exists(SecretsManagerClient::class) === false) {
            throw new RuntimeException('In order to load secrets from SecretsManager you must install "async-aws/secrets-manager" package');
        }

        $actuallyCalledSsm = false;
        if (count($ssmNames) > 0) {
            $ssmParameters = self::readParametersFromCacheOr('ssm', function () use ($ssmClient, $ssmNames, &$actuallyCalledSsm) {
                $actuallyCalledSsm = true;
                return self::retrieveParametersFromSsm($ssmClient, array_values($ssmNames));
            });

            foreach ($ssmParameters as $parameterName => $parameterValue) {
                $envVar = array_search($parameterName, $ssmNames, true);
                $_SERVER[$envVar] = $_ENV[$envVar] = $parameterValue;
                putenv("$envVar=$parameterValue");
            }
        }

        $actuallyCalledSecretsManager = false;
        if (count($secretsManagerNames) > 0) {
            $secretsManagerParameters = self::readParametersFromCacheOr('secretsmanager', function () use ($secretsManagerClient, $secretsManagerNames, &$actuallyCalledSecretsManager) {
                $actuallyCalledSecretsManager = true;
                return self::retrieveParametersFromSecretsManager($secretsManagerClient, array_values($secretsManagerNames));
            });

            foreach ($secretsManagerParameters as $parameterName => $parameterValue) {
                $envVar = array_search($parameterName, $secretsManagerNames, true);
                $_SERVER[$envVar] = $_ENV[$envVar] = $parameterValue;
                putenv("$envVar=$parameterValue");
            }
        }

        // Only log once (when the cache was empty) else it might spam the logs in the function runtime
        // (where the process restarts on every invocation)
        if ($actuallyCalledSsm || $actuallyCalledSecretsManager) {
            $stderr = fopen('php://stderr', 'ab');
            fwrite($stderr, '[Bref] Loaded these environment variables from SSM/SecretsManager: ' . implode(', ', array_keys($envVarsToDecrypt)) . PHP_EOL);
        }
    }

    /**
     * Cache the parameters in a temp file.
     * Why? Because on the function runtime, the PHP process might
     * restart on every invocation (or on error), so we don't want to
     * call SSM/Secrets Manager every time.
     *
     * @param Closure(): array<string, string> $paramResolver
     * @return array<string, string> Map of parameter name -> value
     * @throws JsonException
     */
    private static function readParametersFromCacheOr(string $paramType, Closure $paramResolver): array
    {
        // Check in cache first
        $cacheFile = sprintf('%s/bref-%s-parameters.php', sys_get_temp_dir(), $paramType);
        if (is_file($cacheFile)) {
            $parameters = json_decode(file_get_contents($cacheFile), true, 512, JSON_THROW_ON_ERROR);
            if (is_array($parameters)) {
                return $parameters;
            }
        }

        // Not in cache yet: we resolve it
        $parameters = $paramResolver();

        // Using json_encode instead of var_export due to possible security issues
        file_put_contents($cacheFile, json_encode($parameters, JSON_THROW_ON_ERROR));

        return $parameters;
    }

    /**
     * @param string[] $secretIds
     * @return array<string, string> Map of parameter name -> value
     * @throws JsonException
     */
    private static function retrieveParametersFromSecretsManager(
        ?SecretsManagerClient $secretsManagerClient,
        array $secretIds
    ): array {
        if (! class_exists(SecretsManagerClient::class)) {
            throw new Exception('The "async-aws/secrets-manager" package is required to load secrets from Secrets Manager via the "bref-secretsmanager:xxx" syntax in environment variables. Please add it to your "require" section in composer.json.');
        }

        $secretsManager = $secretsManagerClient ?? new SecretsManagerClient([
            'region' => $_ENV['AWS_REGION'] ?? $_ENV['AWS_DEFAULT_REGION'],
        ]);

        /** @var array<string, string> $parameters Map of parameter name -> value */
        $parameters = [];
        $parametersNotFound = [];

        foreach ($secretIds as $secretId) {
            try {
                $result = $secretsManager->getSecretValue([
                    'SecretId' => $secretId,
                ]);
                $secretString = $result->getSecretString();

                $parameters[$secretId] = $secretString;
            } catch (RuntimeException $e) {
                $parametersNotFound[$secretId] = $e;
            }
        }

        if (count($parametersNotFound) > 0) {
            array_walk($parametersNotFound, function(&$value, $key) { 
                $message = $value->getMessage();
                $value = "$key ($message)"; 
            });

            throw new RuntimeException(
                'The following secrets from Secrets Manager could not be found: ' . implode(', ', $parametersNotFound) .'. Did you add IAM permissions in serverless.yml to allow Lambda to access Secrets Manager?',
            );
        }

        return $parameters;
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
                    // Extra descriptive error message for the most common error
                    throw new RuntimeException(
                        "Bref was not able to resolve secrets contained in environment variables from SSM because of a permissions issue with the SSM API. Did you add IAM permissions in serverless.yml to allow Lambda to access SSM? (docs: https://bref.sh/docs/environment/variables.html#at-deployment-time).\nFull exception message: {$e->getMessage()}",
                        $e->getCode(),
                        $e,
                    );
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
