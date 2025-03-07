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

    const envToReset = [
        'SOME_VARIABLE',
        'SOME_OTHER_VARIABLE',
        'APP_ENV',
        'BREF_ENV',
        'BREF_ENV_PATH',
        'LAMBDA_TASK_ROOT'
    ];

    const envFilesToCleanup = [
        '.env',
        '.env.foobar'
    ];

    public static function tearDownAfterClass(): void
    {
        self::cleanupFiles();
        parent::tearDownAfterClass();

    }

    public function setUp(): void
    {

        self::cleanupFiles();

        // reset env
        array_map(function ($env) {
            putenv($env);
            unset($_ENV[$env], $_SERVER[$env]);
        }, self::envToReset);
    }

    protected static function cleanupFiles()
    {
        if (file_exists(sys_get_temp_dir() . '/bref-ssm-parameters.php')) {
            unlink(sys_get_temp_dir() . '/bref-ssm-parameters.php');
        }

        // cleanup dotenv files
        array_map(function ($envFile){

            if (file_exists(getcwd() .'/'. $envFile)) {
                unlink(getcwd()  .'/'.  $envFile);
            }

            if (file_exists(__DIR__ . '/env/' . $envFile)) {
                unlink(__DIR__ . '/env/' . $envFile);
            }
        }, self::envFilesToCleanup);

        if(file_exists(__DIR__ . '/env')) {
            rmdir(__DIR__ . '/env');
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

    /**
     * @testWith [null, null]
     *           ["BREF_ENV_PATH", null]
     *           ["LAMBDA_TASK_ROOT", null]
     *           [null, "BREF_ENV"]
     *           [null, "APP_ENV"]
     *           ["BREF_ENV_PATH", "BREF_ENV"]
     *           ["LAMBDA_TASK_ROOT", "APP_ENV"]
     */
    public function testLoadsSecretsFromDotenv(?string $envPath, ?string $envKey): void
    {

        if ($envPath) {
            putenv("$envPath=" . __DIR__ . '/env');
            mkdir( __DIR__ . '/env');
        }
        $envPath = $envPath ? __DIR__ . '/env' : getcwd();
        copy(__DIR__ . '/fixtures/.env', "$envPath/.env");

        if($envKey) {
            putenv("$envKey=foobar");
        }

        putenv('SOME_VARIABLE');
        putenv('SOME_OTHER_VARIABLE=helloworld');

        // Sanity checks
        $this->assertFalse(getenv('SOME_VARIABLE'));
        $this->assertSame('helloworld', getenv('SOME_OTHER_VARIABLE'));

        Secrets::loadSecretEnvironmentVariables($this->mockSsmClient());

        $this->assertSame('foobar', getenv('SOME_VARIABLE'));
        $this->assertSame('foobar', $_SERVER['SOME_VARIABLE']);
        $this->assertSame('foobar', $_ENV['SOME_VARIABLE']);
        // Check that the other variable was not modified
        $this->assertSame('helloworld', getenv('SOME_OTHER_VARIABLE'));
    }

    /**
     * @testWith [null, "BREF_ENV"]
     *           [null, "APP_ENV"]
     *           ["BREF_ENV_PATH", "BREF_ENV"]
     *           ["BREF_ENV_PATH", "APP_ENV"]
     *           ["LAMBDA_TASK_ROOT", "BREF_ENV"]
     *           ["LAMBDA_TASK_ROOT", "APP_ENV"]
     */
    public function testLoadsSecretsFromDotenvForSpecificEnv(?string $envPath, string $envKey): void
    {
        if ($envPath) {
            putenv("$envPath=" . __DIR__ . '/env');
            mkdir( __DIR__ . '/env');
        }

        $envPath = $envPath ? __DIR__ . '/env' : getcwd();
        copy(__DIR__ . '/fixtures/.env', "$envPath/.env.foobar");
        putenv('SOME_VARIABLE');
        putenv("$envKey=foobar");
        putenv('SOME_OTHER_VARIABLE=helloworld');

        // Sanity checks
        $this->assertFalse(getenv('SOME_VARIABLE'));
        $this->assertSame('foobar', getenv($envKey));
        $this->assertSame('helloworld', getenv('SOME_OTHER_VARIABLE'));

        Secrets::loadSecretEnvironmentVariables($this->mockSsmClient());

        $this->assertSame('foobar', getenv('SOME_VARIABLE'));
        $this->assertSame('foobar', $_SERVER['SOME_VARIABLE']);
        $this->assertSame('foobar', $_ENV['SOME_VARIABLE']);
        // Check that the other variable was not modified
        $this->assertSame('helloworld', getenv('SOME_OTHER_VARIABLE'));
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
