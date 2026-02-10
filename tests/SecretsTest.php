<?php declare(strict_types=1);

namespace Bref\Secrets\Test;

use AsyncAws\Core\Test\ResultMockFactory;
use AsyncAws\Ssm\Result\GetParametersResult;
use AsyncAws\Ssm\SsmClient;
use AsyncAws\Ssm\ValueObject\Parameter;
use Bref\Secrets\Secrets;
use PHPUnit\Framework\TestCase;

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
