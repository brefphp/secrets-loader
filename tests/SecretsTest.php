<?php declare(strict_types=1);

namespace Bref\Secrets\Test;

use AsyncAws\Core\Test\ResultMockFactory;
use AsyncAws\Ssm\Result\GetParametersResult;
use AsyncAws\Ssm\SsmClient;
use AsyncAws\Ssm\ValueObject\Parameter;
use Bref\Secrets\Secrets;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;

class SecretsTest extends TestCase
{
    /** @var array{Name: string, Value: string} */
    private array $resultParams = [
        'Name' => '/some/parameter',
        'Value' => 'foobar',
    ];

    public function setUp(): void
    {
        if (file_exists(sys_get_temp_dir() . '/bref-ssm-parameters.php')) {
            unlink(sys_get_temp_dir() . '/bref-ssm-parameters.php');
        }
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

    public function test sends the batches of parameters in parallel(): void
    {
        // 11 parameters: two batches, as the API takes up to 10 at a time
        $names = [];
        for ($i = 1; $i <= 11; $i++) {
            $names[] = "/some/parameter-$i";
            putenv("VAR_$i=bref-ssm:/some/parameter-$i");
        }

        $events = [];
        $httpClient = new MockHttpClient(function (string $method, string $url, array $options) use (&$events): MockResponse {
            $batch = json_decode($options['body'], true)['Names'];
            $events[] = 'request';
            $body = (function () use (&$events, $batch) {
                $events[] = 'read';
                yield json_encode([
                    'Parameters' => array_map(fn (string $name) => ['Name' => $name, 'Value' => "value of $name"], $batch),
                    'InvalidParameters' => [],
                ]);
            })();

            return new MockResponse($body, ['http_code' => 200, 'response_headers' => ['content-type' => 'application/x-amz-json-1.1']]);
        });
        $ssmClient = new SsmClient(['region' => 'us-east-1', 'accessKeyId' => 'key', 'accessKeySecret' => 'secret'], null, $httpClient);

        Secrets::loadSecretEnvironmentVariables($ssmClient);

        // Both requests are sent before either response is read
        $this->assertSame(['request', 'request', 'read', 'read'], $events);
        foreach ($names as $i => $name) {
            $this->assertSame("value of $name", getenv('VAR_' . ($i + 1)));
            putenv('VAR_' . ($i + 1));
        }
    }

    public function test throws a clear error message when every batch fails(): void
    {
        for ($i = 1; $i <= 11; $i++) {
            putenv("VAR_$i=bref-ssm:/app/test-$i");
        }

        $ssmClient = $this->getMockBuilder(SsmClient::class)
            ->disableOriginalConstructor()
            ->getMock();
        // Both batches are sent, and both fail
        $ssmClient->expects($this->exactly(2))
            ->method('getParameters')
            ->willReturnCallback(fn () => ResultMockFactory::createFailing(GetParametersResult::class, 400, 'User: arn:aws:sts::123456:assumed-role/app-dev-us-east-1-lambdaRole/app-dev-hello is not authorized to perform: ssm:GetParameters'));

        $expected = preg_quote('Bref was not able to resolve secrets contained in environment variables from SSM because of a permissions issue with the SSM API.', '/');
        $this->expectExceptionMessageMatches("/^$expected/");
        try {
            Secrets::loadSecretEnvironmentVariables($ssmClient);
        } finally {
            for ($i = 1; $i <= 11; $i++) {
                putenv("VAR_$i");
            }
        }
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
}
