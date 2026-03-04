<?php declare(strict_types=1);

namespace Bref\Secrets\Test;

use AsyncAws\Core\AwsError\AwsError;
use AsyncAws\Core\Exception\Http\ClientException;
use AsyncAws\Core\Test\ResultMockFactory;
use AsyncAws\SecretsManager\Exception\ResourceNotFoundException;
use AsyncAws\SecretsManager\Result\GetSecretValueResponse;
use AsyncAws\SecretsManager\SecretsManagerClient;
use AsyncAws\Ssm\Result\GetParametersResult;
use AsyncAws\Ssm\SsmClient;
use AsyncAws\Ssm\ValueObject\Parameter;
use Bref\Secrets\Secrets;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Symfony\Contracts\HttpClient\ResponseInterface;

class SecretsTest extends TestCase
{
    private array $resultParams = [
        'Name' => '/some/parameter',
        'Value' => 'foobar',
    ];

    public function setUp(): void
    {
        if (file_exists(sys_get_temp_dir() . '/bref-ssm-parameters.php')) {
            unlink(sys_get_temp_dir() . '/bref-ssm-parameters.php');
        }
        if (file_exists(sys_get_temp_dir() . '/bref-secrets-manager.php')) {
            unlink(sys_get_temp_dir() . '/bref-secrets-manager.php');
        }
    }

    public function tearDown(): void
    {
        // Clean up any env vars that may have been left behind (e.g. after expected exceptions)
        foreach (['SOME_VARIABLE', 'SOME_OTHER_VARIABLE', 'VAR1', 'VAR2', 'DB_PASSWORD', 'API_KEY', 'STRIPE_SECRET', 'BREF_SECRETS_MANAGER', 'VENDOR_KEY', 'SPECIFIC_VAR'] as $var) {
            putenv($var);
            unset($_SERVER[$var], $_ENV[$var]);
        }
        // Reset the output stream override
        Secrets::$outputStream = null;
    }

    public function test decrypts env variables(): void
    {
        putenv('SOME_VARIABLE=bref-ssm:/some/parameter');
        putenv('SOME_OTHER_VARIABLE=helloworld');

        // Sanity checks
        $this->assertSame('bref-ssm:/some/parameter', getenv('SOME_VARIABLE'));
        $this->assertSame('helloworld', getenv('SOME_OTHER_VARIABLE'));

        $ssmClient = $this->mockSsmClient([new Parameter($this->resultParams)]);
        Secrets::loadSecretEnvironmentVariables($ssmClient);

        $this->assertSame('foobar', getenv('SOME_VARIABLE'));
        $this->assertSame('foobar', $_SERVER['SOME_VARIABLE']);
        $this->assertSame('foobar', $_ENV['SOME_VARIABLE']);
        // Check that the other variable was not modified
        $this->assertSame('helloworld', getenv('SOME_OTHER_VARIABLE'));

        // Cleanup
        putenv('SOME_VARIABLE');
        putenv('SOME_OTHER_VARIABLE');
    }

    public function test caches parameters to call SSM only once(): void
    {
        putenv('SOME_VARIABLE=bref-ssm:/some/parameter');

        // Call twice, the mock will assert that SSM was only called once
        $ssmClient = $this->mockSsmClient([new Parameter($this->resultParams)]);
        Secrets::loadSecretEnvironmentVariables($ssmClient);
        Secrets::loadSecretEnvironmentVariables($ssmClient);

        $this->assertSame('foobar', getenv('SOME_VARIABLE'));

        // Cleanup
        putenv('SOME_VARIABLE');
    }

    public function test same ssm value can be assigned more than once(): void
    {
        putenv('VAR1=bref-ssm:/some/parameter');
        putenv('VAR2=bref-ssm:/some/parameter');

        // Sanity checks
        $this->assertSame('bref-ssm:/some/parameter', getenv('VAR1'));
        $this->assertSame('bref-ssm:/some/parameter', getenv('VAR2'));

        $ssmClient = $this->mockSsmClient([
            new Parameter($this->resultParams),
            new Parameter($this->resultParams),
        ]);
        Secrets::loadSecretEnvironmentVariables($ssmClient);

        $this->assertSame('foobar', getenv('VAR1'));
        $this->assertSame('foobar', getenv('VAR2'));

        // Cleanup
        putenv('VAR1');
        putenv('VAR2');
    }

    public function test throws a clear error message on missing permissions(): void
    {
        putenv('SOME_VARIABLE=bref-ssm:/app/test');

        $ssmClient = $this->getMockBuilder(SsmClient::class)
            ->disableOriginalConstructor()
            ->getMock();
        $result = ResultMockFactory::createFailing(GetParametersResult::class, 400, 'User: arn:aws:sts::123456:assumed-role/app-dev-us-east-1-lambdaRole/app-dev-hello is not authorized to perform: ssm:GetParameters on resource: arn:aws:ssm:us-east-1:123456:parameter/app/test because no identity-based policy allows the ssm:GetParameters action');
        $ssmClient->method('getParameters')
            ->willReturn($result);

        $expected = preg_quote("Bref was not able to resolve secrets contained in environment variables from SSM because of a permissions issue with the SSM API. Did you add IAM permissions in serverless.yml to allow Lambda to access SSM? (docs: https://bref.sh/docs/environment/variables.html#at-deployment-time).\nFull exception message:", '/');
        $this->expectExceptionMessageMatches("/$expected .+/");
        Secrets::loadSecretEnvironmentVariables($ssmClient);

        // Cleanup
        putenv('SOME_VARIABLE');
    }

    public function test ssm throttling error is not labeled as permissions issue(): void
    {
        putenv('SOME_VARIABLE=bref-ssm:/app/test');

        $ssmClient = $this->getMockBuilder(SsmClient::class)
            ->disableOriginalConstructor()
            ->getMock();
        $result = ResultMockFactory::createFailing(GetParametersResult::class, 400, 'Rate exceeded');
        $ssmClient->method('getParameters')
            ->willReturn($result);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageMatches('/Rate exceeded/');
        try {
            Secrets::loadSecretEnvironmentVariables($ssmClient);
        } catch (RuntimeException $e) {
            $this->assertStringNotContainsString('permissions issue', $e->getMessage());
            throw $e;
        }
    }

    public function test secrets manager bulk import sets env vars from json secret(): void
    {
        putenv('BREF_SECRETS_MANAGER=api/production');

        $secretJson = json_encode([
            'DB_PASSWORD' => 'secret123',
            'API_KEY' => 'abc-xyz',
        ]);

        $smClient = $this->mockSecretsManagerClient('api/production', $secretJson);
        Secrets::loadSecretEnvironmentVariables(null, $smClient);

        $this->assertSame('secret123', getenv('DB_PASSWORD'));
        $this->assertSame('secret123', $_SERVER['DB_PASSWORD']);
        $this->assertSame('secret123', $_ENV['DB_PASSWORD']);
        $this->assertSame('abc-xyz', getenv('API_KEY'));
        $this->assertSame('abc-xyz', $_SERVER['API_KEY']);
        $this->assertSame('abc-xyz', $_ENV['API_KEY']);
        // BREF_SECRETS_MANAGER should be consumed (unset) after loading
        $this->assertFalse(getenv('BREF_SECRETS_MANAGER'));

        // Cleanup
        putenv('DB_PASSWORD');
        putenv('API_KEY');
        putenv('BREF_SECRETS_MANAGER');
    }

    public function test bref secret prefix resolves plain string secret(): void
    {
        putenv('VENDOR_KEY=bref-secret:vendor/api-key');

        $smClient = $this->mockSecretsManagerClient('vendor/api-key', 'my-vendor-key-value');
        Secrets::loadSecretEnvironmentVariables(null, $smClient);

        $this->assertSame('my-vendor-key-value', getenv('VENDOR_KEY'));
        $this->assertSame('my-vendor-key-value', $_SERVER['VENDOR_KEY']);
        $this->assertSame('my-vendor-key-value', $_ENV['VENDOR_KEY']);
    }

    public function test bref secret prefix extracts json key(): void
    {
        putenv('SPECIFIC_VAR=bref-secret:api/production:DB_PASSWORD');

        $secretJson = json_encode(['DB_PASSWORD' => 'secret123', 'API_KEY' => 'abc-xyz']);
        $smClient = $this->mockSecretsManagerClient('api/production', $secretJson);
        Secrets::loadSecretEnvironmentVariables(null, $smClient);

        $this->assertSame('secret123', getenv('SPECIFIC_VAR'));
        $this->assertSame('secret123', $_SERVER['SPECIFIC_VAR']);
        $this->assertSame('secret123', $_ENV['SPECIFIC_VAR']);
    }

    public function test smart batching fetches same secret only once(): void
    {
        putenv('DB_PASSWORD=bref-secret:api/production:DB_PASSWORD');
        putenv('API_KEY=bref-secret:api/production:API_KEY');

        $secretJson = json_encode(['DB_PASSWORD' => 'secret123', 'API_KEY' => 'abc-xyz']);

        $smClient = $this->getMockBuilder(SecretsManagerClient::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['getSecretValue'])
            ->getMock();

        $result = ResultMockFactory::create(GetSecretValueResponse::class, [
            'SecretString' => $secretJson,
        ]);

        $smClient->expects($this->once())
            ->method('getSecretValue')
            ->with(['SecretId' => 'api/production'])
            ->willReturn($result);

        Secrets::loadSecretEnvironmentVariables(null, $smClient);

        $this->assertSame('secret123', getenv('DB_PASSWORD'));
        $this->assertSame('abc-xyz', getenv('API_KEY'));
    }

    public function test smart batching deduplicates global and individual refs(): void
    {
        putenv('BREF_SECRETS_MANAGER=api/production');
        putenv('STRIPE_SECRET=bref-secret:api/production:STRIPE_SECRET');

        $secretJson = json_encode([
            'DB_PASSWORD' => 'secret123',
            'API_KEY' => 'abc-xyz',
            'STRIPE_SECRET' => 'sk_live_override',
        ]);

        $smClient = $this->getMockBuilder(SecretsManagerClient::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['getSecretValue'])
            ->getMock();

        $result = ResultMockFactory::create(GetSecretValueResponse::class, [
            'SecretString' => $secretJson,
        ]);

        $smClient->expects($this->once())
            ->method('getSecretValue')
            ->with(['SecretId' => 'api/production'])
            ->willReturn($result);

        Secrets::loadSecretEnvironmentVariables(null, $smClient);

        $this->assertSame('secret123', getenv('DB_PASSWORD'));
        $this->assertSame('abc-xyz', getenv('API_KEY'));
        $this->assertSame('sk_live_override', getenv('STRIPE_SECRET'));
    }

    public function test individual bref secret overrides global import for same key(): void
    {
        putenv('BREF_SECRETS_MANAGER=api/production');
        putenv('DB_PASSWORD=bref-secret:override/db-password');

        $globalJson = json_encode([
            'DB_PASSWORD' => 'global-password',
            'API_KEY' => 'global-api-key',
        ]);

        $smClient = $this->getMockBuilder(SecretsManagerClient::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['getSecretValue'])
            ->getMock();

        $globalResult = ResultMockFactory::create(GetSecretValueResponse::class, [
            'SecretString' => $globalJson,
        ]);
        $overrideResult = ResultMockFactory::create(GetSecretValueResponse::class, [
            'SecretString' => 'individual-override-password',
        ]);

        $smClient->expects($this->exactly(2))
            ->method('getSecretValue')
            ->withConsecutive(
                [['SecretId' => 'override/db-password']],
                [['SecretId' => 'api/production']],
            )
            ->willReturnOnConsecutiveCalls($overrideResult, $globalResult);

        Secrets::loadSecretEnvironmentVariables(null, $smClient);

        $this->assertSame('individual-override-password', getenv('DB_PASSWORD'));
        $this->assertSame('global-api-key', getenv('API_KEY'));
    }

    public function test secrets manager caches to avoid repeat api calls(): void
    {
        putenv('BREF_SECRETS_MANAGER=api/production');

        $secretJson = json_encode(['DB_PASSWORD' => 'secret123']);

        $smClient = $this->mockSecretsManagerClient('api/production', $secretJson);

        Secrets::loadSecretEnvironmentVariables(null, $smClient);
        $this->assertSame('secret123', getenv('DB_PASSWORD'));

        // Re-set the env var for the second call (it gets consumed)
        putenv('BREF_SECRETS_MANAGER=api/production');

        Secrets::loadSecretEnvironmentVariables(null, $smClient);
        $this->assertSame('secret123', getenv('DB_PASSWORD'));
    }

    public function test error secret not found(): void
    {
        putenv('DB_PASSWORD=bref-secret:nonexistent/secret');

        $smClient = $this->getMockBuilder(SecretsManagerClient::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['getSecretValue'])
            ->getMock();

        $smClient->method('getSecretValue')
            ->willThrowException($this->createResourceNotFoundException('nonexistent/secret'));

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage("Secret 'nonexistent/secret' not found in AWS Secrets Manager. Check that the secret exists and the name is correct.");
        Secrets::loadSecretEnvironmentVariables(null, $smClient);
    }

    public function test error invalid json in global import(): void
    {
        putenv('BREF_SECRETS_MANAGER=api/production');

        $smClient = $this->mockSecretsManagerClient('api/production', 'not-valid-json{{{');

        $this->expectException(\JsonException::class);
        Secrets::loadSecretEnvironmentVariables(null, $smClient);
    }

    public function test error non object json in global import(): void
    {
        putenv('BREF_SECRETS_MANAGER=api/production');

        $smClient = $this->mockSecretsManagerClient('api/production', '"just a string"');

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage("Secret 'api/production' is not valid JSON");
        Secrets::loadSecretEnvironmentVariables(null, $smClient);
    }

    public function test error nested json values in global import(): void
    {
        putenv('BREF_SECRETS_MANAGER=api/production');

        $secretJson = json_encode(['DB_PASSWORD' => 'secret123', 'CONFIG' => ['nested' => true]]);
        $smClient = $this->mockSecretsManagerClient('api/production', $secretJson);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage("Secret 'api/production' contains non-scalar value for key 'CONFIG'");
        Secrets::loadSecretEnvironmentVariables(null, $smClient);
    }

    public function test error json key not found(): void
    {
        putenv('DB_PASSWORD=bref-secret:api/production:NONEXISTENT_KEY');

        $secretJson = json_encode(['DB_HOST' => 'localhost', 'DB_USER' => 'admin']);
        $smClient = $this->mockSecretsManagerClient('api/production', $secretJson);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage("Key 'NONEXISTENT_KEY' not found in secret 'api/production'. Available keys: DB_HOST, DB_USER");
        Secrets::loadSecretEnvironmentVariables(null, $smClient);
    }

    public function test error sm throttling is not labeled as permissions(): void
    {
        putenv('DB_PASSWORD=bref-secret:api/production');

        $smClient = $this->getMockBuilder(SecretsManagerClient::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['getSecretValue'])
            ->getMock();

        $smClient->method('getSecretValue')
            ->willThrowException($this->createClientException(400, 'ThrottlingException', 'Rate exceeded'));

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageMatches('/Rate exceeded/');
        try {
            Secrets::loadSecretEnvironmentVariables(null, $smClient);
        } catch (RuntimeException $e) {
            $this->assertStringNotContainsString('permissions issue', $e->getMessage());
            throw $e;
        }
    }

    public function test error permission denied(): void
    {
        putenv('DB_PASSWORD=bref-secret:api/production');

        $smClient = $this->getMockBuilder(SecretsManagerClient::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['getSecretValue'])
            ->getMock();

        $smClient->method('getSecretValue')
            ->willThrowException($this->createClientException(400, 'AccessDeniedException', 'User: arn:aws:sts::123456:assumed-role/app-dev is not authorized to perform: secretsmanager:GetSecretValue'));

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage("Bref was not able to retrieve secret 'api/production' from AWS Secrets Manager because of a permissions issue. Did you add `secretsmanager:GetSecretValue` to your IAM role?");
        Secrets::loadSecretEnvironmentVariables(null, $smClient);
    }

    public function test secrets manager logs loaded env vars to stderr(): void
    {
        putenv('BREF_SECRETS_MANAGER=api/production');

        $secretJson = json_encode([
            'DB_PASSWORD' => 'secret123',
            'API_KEY' => 'abc-xyz',
        ]);

        $smClient = $this->mockSecretsManagerClient('api/production', $secretJson);

        $capturedOutput = fopen('php://memory', 'r+b');
        Secrets::$outputStream = $capturedOutput;
        try {
            Secrets::loadSecretEnvironmentVariables(null, $smClient);
        } finally {
            Secrets::$outputStream = null;
        }

        rewind($capturedOutput);
        $output = stream_get_contents($capturedOutput);
        fclose($capturedOutput);

        $this->assertStringContainsString("[Bref] Loaded environment variables from Secrets Manager secret 'api/production': ", $output);
        $this->assertStringContainsString('DB_PASSWORD', $output);
        $this->assertStringContainsString('API_KEY', $output);
    }

    public function test secrets manager does not log when using cache(): void
    {
        putenv('BREF_SECRETS_MANAGER=api/production');

        $secretJson = json_encode(['DB_PASSWORD' => 'secret123']);
        $smClient = $this->mockSecretsManagerClient('api/production', $secretJson);

        // First call — triggers API + logging
        Secrets::loadSecretEnvironmentVariables(null, $smClient);

        // Re-set env var (consumed after first call)
        putenv('BREF_SECRETS_MANAGER=api/production');

        // Second call — should use cache, no logging
        $capturedOutput = fopen('php://memory', 'r+b');
        Secrets::$outputStream = $capturedOutput;
        try {
            Secrets::loadSecretEnvironmentVariables(null, $smClient);
        } finally {
            Secrets::$outputStream = null;
        }

        rewind($capturedOutput);
        $output = stream_get_contents($capturedOutput);
        fclose($capturedOutput);

        $this->assertEmpty($output, 'No logging should occur when reading from cache');
    }

    public function test coexistence ssm and secrets manager and global import(): void
    {
        // Global import: sets DB_PASSWORD and API_KEY from Secrets Manager
        putenv('BREF_SECRETS_MANAGER=api/production');
        // Individual bref-secret: overrides DB_PASSWORD (higher priority than global)
        putenv('DB_PASSWORD=bref-secret:override/db-password');
        // bref-ssm: sets LEGACY_PARAM from SSM (highest priority of all)
        putenv('LEGACY_PARAM=bref-ssm:/old/ssm/parameter');

        $globalJson = json_encode([
            'DB_PASSWORD' => 'global-password',
            'API_KEY' => 'global-api-key',
        ]);

        $smClient = $this->getMockBuilder(SecretsManagerClient::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['getSecretValue'])
            ->getMock();

        $globalResult = ResultMockFactory::create(GetSecretValueResponse::class, [
            'SecretString' => $globalJson,
        ]);
        $overrideResult = ResultMockFactory::create(GetSecretValueResponse::class, [
            'SecretString' => 'individual-db-password',
        ]);

        $smClient->expects($this->exactly(2))
            ->method('getSecretValue')
            ->withConsecutive(
                [['SecretId' => 'override/db-password']],
                [['SecretId' => 'api/production']],
            )
            ->willReturnOnConsecutiveCalls($overrideResult, $globalResult);

        $ssmClient = $this->mockSsmClient([
            new Parameter([
                'Name' => '/old/ssm/parameter',
                'Value' => 'ssm-legacy-value',
            ]),
        ]);

        Secrets::loadSecretEnvironmentVariables($ssmClient, $smClient);

        // API_KEY from global import
        $this->assertSame('global-api-key', getenv('API_KEY'));
        // DB_PASSWORD from individual bref-secret: (overrides global)
        $this->assertSame('individual-db-password', getenv('DB_PASSWORD'));
        // LEGACY_PARAM from SSM
        $this->assertSame('ssm-legacy-value', getenv('LEGACY_PARAM'));
        // BREF_SECRETS_MANAGER consumed
        $this->assertFalse(getenv('BREF_SECRETS_MANAGER'));

        // Cleanup
        putenv('LEGACY_PARAM');
    }

    /**
     * @param array<Parameter> $resultParameters
     */
    private function mockSsmClient(array $resultParameters): SsmClient
    {
        $ssmClient = $this->getMockBuilder(SsmClient::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['getParameters'])
            ->getMock();

        $result = ResultMockFactory::create(GetParametersResult::class, [
            'Parameters' => $resultParameters,
        ]);

        $expectedNames = [];
        foreach ($resultParameters as $resultParameter) {
            $expectedNames[] = $resultParameter->getName();
        }
        $ssmClient->expects($this->once())
            ->method('getParameters')
            ->with([
                'Names' => $expectedNames,
                'WithDecryption' => true,
            ])
            ->willReturn($result);

        return $ssmClient;
    }

    /**
     * Creates a mock SecretsManagerClient that expects one getSecretValue call.
     */
    private function mockSecretsManagerClient(string $expectedSecretId, string $secretString): SecretsManagerClient
    {
        $smClient = $this->getMockBuilder(SecretsManagerClient::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['getSecretValue'])
            ->getMock();

        $result = ResultMockFactory::create(GetSecretValueResponse::class, [
            'SecretString' => $secretString,
        ]);

        $smClient->expects($this->once())
            ->method('getSecretValue')
            ->with(['SecretId' => $expectedSecretId])
            ->willReturn($result);

        return $smClient;
    }

    /**
     * Creates a ResourceNotFoundException for testing.
     */
    private function createResourceNotFoundException(string $secretName): ResourceNotFoundException
    {
        $response = $this->createMock(ResponseInterface::class);
        $response->method('getInfo')->willReturnCallback(function (?string $type) {
            if ($type === 'http_code') return 404;
            if ($type === 'url') return 'https://secretsmanager.us-east-1.amazonaws.com';
            return null;
        });
        $response->method('getHeaders')->willReturn([]);
        $response->method('getContent')->willReturn('');

        $awsError = new AwsError('ResourceNotFoundException', "Secrets Manager can't find the specified secret: $secretName", null, null);
        return new ResourceNotFoundException($response, $awsError);
    }

    /**
     * Creates a ClientException for testing (e.g., permission denied).
     */
    private function createClientException(int $httpCode, string $awsCode, string $message): ClientException
    {
        $response = $this->createMock(ResponseInterface::class);
        $response->method('getInfo')->willReturnCallback(function (?string $type) use ($httpCode) {
            if ($type === 'http_code') return $httpCode;
            if ($type === 'url') return 'https://secretsmanager.us-east-1.amazonaws.com';
            return null;
        });
        $response->method('getHeaders')->willReturn([]);
        $response->method('getContent')->willReturn('');

        $awsError = new AwsError($awsCode, $message, null, null);
        return new ClientException($response, $awsError);
    }
}
