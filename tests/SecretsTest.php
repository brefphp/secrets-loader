<?php declare(strict_types=1);

namespace Bref\Secrets\Test;

use AsyncAws\Core\Test\ResultMockFactory;
use AsyncAws\SecretsManager\Result\GetSecretValueResponse;
use AsyncAws\SecretsManager\SecretsManagerClient;
use AsyncAws\Ssm\Result\GetParametersResult;
use AsyncAws\Ssm\SsmClient;
use AsyncAws\Ssm\ValueObject\Parameter;
use Bref\Secrets\Secrets;
use PHPUnit\Framework\TestCase;

class SecretsTest extends TestCase
{
    public function setUp(): void
    {
        if (file_exists(sys_get_temp_dir() . '/bref-ssm-parameters.php')) {
            unlink(sys_get_temp_dir() . '/bref-ssm-parameters.php');
        }
        if (file_exists(sys_get_temp_dir() . '/bref-secretsmanager-parameters.php')) {
            unlink(sys_get_temp_dir() . '/bref-secretsmanager-parameters.php');
        }
    }

    public function test decrypts env variables(): void
    {
        putenv('SOME_VARIABLE=bref-ssm:/some/parameter');
        putenv('SOME_OTHER_VARIABLE=helloworld');

        // Sanity checks
        $this->assertSame('bref-ssm:/some/parameter', getenv('SOME_VARIABLE'));
        $this->assertSame('helloworld', getenv('SOME_OTHER_VARIABLE'));

        Secrets::loadSecretEnvironmentVariables($this->mockSsmClient());

        $this->assertSame('foobar', getenv('SOME_VARIABLE'));
        $this->assertSame('foobar', $_SERVER['SOME_VARIABLE']);
        $this->assertSame('foobar', $_ENV['SOME_VARIABLE']);
        // Check that the other variable was not modified
        $this->assertSame('helloworld', getenv('SOME_OTHER_VARIABLE'));
    }

    public function test decrypts env variables from secretsmanager(): void
    {
        putenv('SOME_VARIABLE=bref-secretsmanager:/some/parameter');
        putenv('SOME_OTHER_VARIABLE=helloworld');

        // Sanity checks
        $this->assertSame('bref-secretsmanager:/some/parameter', getenv('SOME_VARIABLE'));
        $this->assertSame('helloworld', getenv('SOME_OTHER_VARIABLE'));

        Secrets::loadSecretEnvironmentVariables(null, $this->mockSecretsManagerClient());

        $this->assertSame('foobar_1', getenv('SOME_VARIABLE_1'));
        $this->assertSame('foobar_1', $_SERVER['SOME_VARIABLE_1']);
        $this->assertSame('foobar_1', $_ENV['SOME_VARIABLE_1']);
        $this->assertSame('foobar_2', getenv('SOME_VARIABLE_2'));
        $this->assertSame('foobar_2', $_SERVER['SOME_VARIABLE_2']);
        $this->assertSame('foobar_2', $_ENV['SOME_VARIABLE_2']);
        // Check that the other variable was not modified
        $this->assertSame('helloworld', getenv('SOME_OTHER_VARIABLE'));
    }

    public function test decrypts env variables from both ssm and secretsmanager(): void
    {
        putenv('SOME_VARIABLE=bref-ssm:/some/parameter');
        putenv('SOME_VARIABLE_1=bref-secretsmanager:/some/parameter');
        putenv('SOME_OTHER_VARIABLE=helloworld');

        // Sanity checks
        $this->assertSame('bref-ssm:/some/parameter', getenv('SOME_VARIABLE'));
        $this->assertSame('bref-secretsmanager:/some/parameter', getenv('SOME_VARIABLE_1'));
        $this->assertSame('helloworld', getenv('SOME_OTHER_VARIABLE'));

        Secrets::loadSecretEnvironmentVariables($this->mockSsmClient(), $this->mockSecretsManagerClient());

        // Check value from ssm
        $this->assertSame('foobar', getenv('SOME_VARIABLE'));
        $this->assertSame('foobar', $_SERVER['SOME_VARIABLE']);
        $this->assertSame('foobar', $_ENV['SOME_VARIABLE']);
        // Check value from secretsmanager
        $this->assertSame('foobar_1', getenv('SOME_VARIABLE_1'));
        $this->assertSame('foobar_1', $_SERVER['SOME_VARIABLE_1']);
        $this->assertSame('foobar_1', $_ENV['SOME_VARIABLE_1']);
        $this->assertSame('foobar_2', getenv('SOME_VARIABLE_2'));
        $this->assertSame('foobar_2', $_SERVER['SOME_VARIABLE_2']);
        $this->assertSame('foobar_2', $_ENV['SOME_VARIABLE_2']);
        // Check that the other variable was not modified
        $this->assertSame('helloworld', getenv('SOME_OTHER_VARIABLE'));
    }

    public function test env variables from secretsmanager overrides ssm(): void
    {
        putenv('SOME_VARIABLE=bref-ssm:/some/parameter');
        putenv('SOME_VARIABLE_1=bref-secretsmanager:/some/parameter');
        putenv('SOME_OTHER_VARIABLE=helloworld');

        // Sanity checks
        $this->assertSame('bref-ssm:/some/parameter', getenv('SOME_VARIABLE'));
        $this->assertSame('bref-secretsmanager:/some/parameter', getenv('SOME_VARIABLE_1'));
        $this->assertSame('helloworld', getenv('SOME_OTHER_VARIABLE'));

        Secrets::loadSecretEnvironmentVariables(
            $this->mockSsmClient(),
            $this->mockSecretsManagerClient('{"SOME_VARIABLE":"foobar_from_secretsmanager"}')
        );

        // Check value from ssm
        $this->assertSame('foobar_from_secretsmanager', getenv('SOME_VARIABLE'));
        $this->assertSame('foobar_from_secretsmanager', $_SERVER['SOME_VARIABLE']);
        $this->assertSame('foobar_from_secretsmanager', $_ENV['SOME_VARIABLE']);
        // Check that the other variable was not modified
        $this->assertSame('helloworld', getenv('SOME_OTHER_VARIABLE'));
    }

    public function test caches parameters to call SSM only once(): void
    {
        putenv('SOME_VARIABLE=bref-ssm:/some/parameter');

        // Call twice, the mock will assert that SSM was only called once
        $ssmClient = $this->mockSsmClient();
        Secrets::loadSecretEnvironmentVariables($ssmClient);
        Secrets::loadSecretEnvironmentVariables($ssmClient);

        $this->assertSame('foobar', getenv('SOME_VARIABLE'));
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
    }

    private function mockSecretsManagerClient(?string $secretString = null): SecretsManagerClient
    {
        $secretsManagerClient = $this->getMockBuilder(SecretsManagerClient::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['getSecretValue'])
            ->getMock();

        $result = ResultMockFactory::create(GetSecretValueResponse::class, [
            'SecretString' => $secretString ?? '{"SOME_VARIABLE_1":"foobar_1","SOME_VARIABLE_2":"foobar_2"}',
        ]);

        $secretsManagerClient->expects($this->once())
            ->method('getSecretValue')
            ->with([
                'SecretId' => '/some/parameter',
            ])
            ->willReturn($result);

        return $secretsManagerClient;
    }

    private function mockSsmClient(): SsmClient
    {
        $ssmClient = $this->getMockBuilder(SsmClient::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['getParameters'])
            ->getMock();

        $result = ResultMockFactory::create(GetParametersResult::class, [
            'Parameters' => [
                new Parameter([
                    'Name' => '/some/parameter',
                    'Value' => 'foobar',
                ]),
            ],
        ]);

        $ssmClient->expects($this->once())
            ->method('getParameters')
            ->with([
                'Names' => ['/some/parameter'],
                'WithDecryption' => true,
            ])
            ->willReturn($result);

        return $ssmClient;
    }
}
