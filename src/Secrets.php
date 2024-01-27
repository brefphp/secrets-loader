<?php declare(strict_types=1);

namespace Bref\Secrets;

use AsyncAws\Ssm\SsmClient;
use Closure;
use JsonException;
use RuntimeException;

class Secrets
{
    public const PARAMETER_STORE_VAR_NAME = 'BREF_PARAMETER_STORE';

    /**
     * Decrypt environment variables that are encrypted with AWS SSM.
     *
     * @param SsmClient|null $ssmClient To allow mocking in tests.
     * @throws JsonException
     */
    public static function loadSecretEnvironmentVariables(?SsmClient $ssmClient = null): void
    {
        /** @var array<string,string>|string|false $envVars */
        $envVars = getenv(local_only: true); // @phpstan-ignore-line PHPStan is wrong
        if (! is_array($envVars)) {
            return;
        }

        if (\array_key_exists(self::PARAMETER_STORE_VAR_NAME, $envVars)) {
            $parameterStoreName = $envVars[self::PARAMETER_STORE_VAR_NAME];
            $actuallyCalledSsm = self::readEnvFromCacheOrParameterStore($parameterStoreName, $ssmClient);
            if ($actuallyCalledSsm) {
                self::logToStderr('[Bref] Loaded environment variables from SSM parameter store ' . $parameterStoreName);
            }
        }

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
        $parameters = self::readParametersFromCacheOr(function () use ($ssmClient, $ssmNames, &$actuallyCalledSsm) {
            $actuallyCalledSsm = true;
            return self::retrieveParametersFromSsm($ssmClient, array_values($ssmNames));
        });

        foreach ($parameters as $parameterName => $parameterValue) {
            $envVar = array_search($parameterName, $ssmNames, true);
            self::setIniValue($parameterValue, $envVar);
        }

        // Only log once (when the cache was empty) else it might spam the logs in the function runtime
        // (where the process restarts on every invocation)
        if ($actuallyCalledSsm) {
            $message = '[Bref] Loaded these environment variables from SSM: ' . implode(', ', array_keys($envVarsToDecrypt));
            self::logToStderr($message);
        }
    }

    /**
     * Cache the parameters in a temp file.
     * Why? Because on the function runtime, the PHP process might
     * restart on every invocation (or on error), so we don't want to
     * call SSM every time.
     *
     * @param Closure(): array<string, string> $paramResolver
     * @return array<string, string> Map of parameter name -> value
     * @throws JsonException
     */
    private static function readParametersFromCacheOr(Closure $paramResolver): array
    {
        // Check in cache first
        $cacheFile = sys_get_temp_dir() . '/bref-ssm-parameters.php';
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

    /**
     * This method logs to stderr.
     *
     * It must only be used in a lambda environment since all error output will be logged.
     *
     * @param string $message The message to log
     */
    private static function logToStderr(string $message): void
    {
        file_put_contents('php://stderr', date('[c] ') . $message . PHP_EOL, FILE_APPEND);
    }

    private static function setIniValue(string $parameterValue, bool|int|string $envVar): void
    {
        $_SERVER[$envVar] = $_ENV[$envVar] = $parameterValue;
        putenv("$envVar=$parameterValue");
    }

    private static function readEnvFromCacheOrParameterStore(string $parameterStoreName, ?SsmClient $ssmClient): bool
    {
        $cacheFile = sys_get_temp_dir() . '/bref-ssm-parameters-store.ini';
        if (is_file($cacheFile)) {
            $values = parse_ini_file($cacheFile);
            if ($values === false) {
                throw new \RuntimeException('Error parsing data from parameter store');
            }
            $actuallyCalledSsm = false;
        } else {
            $values = self::readEnvFromParameterStore($parameterStoreName, $ssmClient);
            self::writeToIni($cacheFile, $values);
            $actuallyCalledSsm = true;
        }

        foreach ($values as $key => $value) {
            self::setIniValue($value, $key);
        }

        return $actuallyCalledSsm;
    }

    /**
     * @param string $parameterStoreName Name of the ssn variable that stores env var in ini format
     * @param SsmClient|null $ssmClient Client to use. If null it will be created, otherwise it's probably a mock for tests
     * @return array<string, string> Map of parameter name -> value
     */
    private static function readEnvFromParameterStore(string $parameterStoreName, ?SsmClient $ssmClient): array
    {
        // The ssm: prefix will allow to implement a secretsmanager: prefix in the future
        $cleanParameterStoreName = substr($parameterStoreName, strlen('ssm:'));

        $iniValues = self::retrieveParametersFromSsm($ssmClient, [$cleanParameterStoreName])[$cleanParameterStoreName];

        $values = parse_ini_string($iniValues);
        if ($values === false) {
            throw new \RuntimeException('Error parsing data from parameter store');
        }

        return $values;
    }

    /**
     * @param string $fileName Name of the file where to store values
     * @param array<string, string> $values Map of parameter name -> value
     */
    private static function writeToIni(string $fileName, array $values): void
    {
        $content = '';
        foreach ($values as $key => $value) {
            $content .= "$key = $value" . PHP_EOL;
        }

        file_put_contents($fileName, $content, FILE_APPEND) !== false;
    }
}
