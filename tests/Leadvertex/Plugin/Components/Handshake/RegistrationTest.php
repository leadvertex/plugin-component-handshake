<?php


namespace Leadvertex\Plugin\Components\Handshake;


use DateTimeImmutable;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\ValidationData;
use Leadvertex\Plugin\Components\Db\Components\Connector;
use Leadvertex\Plugin\Components\Guzzle\Guzzle;
use Leadvertex\Plugin\Components\Handshake\Exceptions\HandshakeException;
use Medoo\Medoo;
use PHPUnit\Framework\TestCase;

class RegistrationTest extends TestCase
{

    private static $mock;

    public static function setUpBeforeClass(): void
    {
        parent::setUpBeforeClass();
        $_ENV['LV_PLUGIN_SELF_URL'] = 'https://plugin.example.com/excel/';
        $_ENV['LV_PLUGIN_COMPONENT_HANDSHAKE_SCHEME'] = 'https';
        $_ENV['LV_PLUGIN_COMPONENT_HANDSHAKE_HOSTNAME'] = 'leadvertex.com';
        $_ENV['LV_PLUGIN_SELF_TYPE'] = 'macros';

        Connector::init(
            new Medoo([
                'database_type' => 'sqlite',
                'database_file' => ''
            ]),
            1
        );

        self::$mock = new MockHandler();
        $handlerStack = HandlerStack::create(self::$mock);
        Guzzle::getInstance(['handler' => $handlerStack, 'http_errors' => false]);
    }

    protected function setUp(): void
    {
        parent::setUp();
        self::$mock->reset();
    }

    public function testRequestJWTClaims()
    {
        $lvt = "TestToken";
        self::$mock->append( new Response(200, [], json_encode(['confirmed' => true])));

        $token = (new Builder())->issuedBy('https://backend.leadvertex.com/')
            ->permittedFor($_ENV['LV_PLUGIN_SELF_URL'])
            ->expiresAt((new DateTimeImmutable())->getTimestamp())
            ->withClaim('plugin', ['model' => 'macros', 'id' => '1'])
            ->withClaim('lvt', $lvt)
            ->withClaim('endpoint', '/companies/1/CRM/plugin/register')
            ->getToken();

        new Registration(
            $token
        );

        $testRequest = json_decode(self::$mock->getLastRequest()->getBody()->getContents(), true);
        $data = (new Parser())->parse($testRequest['registration']);

        $this->assertEquals($token->getClaim('iss'), $data->getClaim('iss'));
        $this->assertEquals($token->getClaim('aud'), $data->getClaim('aud'));
        $this->assertEquals($token->getClaim('exp'), $data->getClaim('exp'));
        $this->assertEquals($token->getClaim('plugin')['model'], $data->getClaim('plugin')->model);
        $this->assertEquals($token->getClaim('plugin')['id'], $data->getClaim('plugin')->id);
        $this->assertEquals($token->getClaim('lvt'), $data->getClaim('lvt'));
        $this->assertEquals($token->getClaim('endpoint'), $data->getClaim('endpoint'));
    }

    public function testValidateRequestJWT()
    {
        $lvt = "TestToken";
        self::$mock->append( new Response(200, [], json_encode(['confirmed' => true])));

        $token = (new Builder())->issuedBy('https://backend.leadvertex.com/')
            ->permittedFor($_ENV['LV_PLUGIN_SELF_URL'])
            ->expiresAt((new DateTimeImmutable())->getTimestamp())
            ->withClaim('plugin', ['model' => 'macros', 'id' => '1'])
            ->withClaim('lvt', $lvt)
            ->withClaim('endpoint', '/companies/1/CRM/plugin/register')
            ->getToken();

        new Registration(
            $token
        );


        $testRequest = json_decode(self::$mock->getLastRequest()->getBody()->getContents(), true);
        $data = (new Parser())->parse($testRequest['registration']);

        $validationData = new ValidationData();
        $validationData->setIssuer($data->getClaim('iss'));
        $validationData->setAudience($data->getClaim('aud'));
        $this->assertTrue($token->validate($validationData));
    }

    public function testVerifySignedRequestJWT()
    {
        $lvt = "TestToken";
        self::$mock->append( new Response(200, [], json_encode(['confirmed' => true])));

        $token = (new Builder())->issuedBy('https://backend.leadvertex.com/')
            ->permittedFor($_ENV['LV_PLUGIN_SELF_URL'])
            ->expiresAt((new DateTimeImmutable())->getTimestamp())
            ->withClaim('plugin', ['model' => 'macros', 'id' => '1'])
            ->withClaim('lvt', $lvt)
            ->withClaim('endpoint', '/companies/1/CRM/plugin/register')
            ->getToken();

        $testReg = new Registration(
            $token
        );

        $signed = $testReg->getSignedToken('test');
        $this->assertEquals($signed->getClaim('iss'), $_ENV['LV_PLUGIN_SELF_URL']);
        $this->assertEquals($signed->getClaim('jwt'), 'test');
        $this->assertTrue($signed->verify(new Sha256(), $testReg->getLVT()));
    }

    public function testSelfUrlAudience()
    {
        $incorrectUrl = 'https://incorrect.com';
        $this->expectException(HandshakeException::class);
        $this->expectExceptionCode(1);

        $token = (new Builder())->issuedBy('https://backend.leadvertex.com/')
            ->permittedFor($incorrectUrl)
            ->expiresAt((new DateTimeImmutable())->getTimestamp())
            ->withClaim('plugin', ['model' => 'macros', 'id' => '1'])
            ->withClaim('lvt', 'test')
            ->withClaim('endpoint', '/companies/1/CRM/plugin/register')
            ->getToken();

        new Registration(
            $token
        );
    }

    public function testHttpIssuer()
    {
        $this->expectException(HandshakeException::class);
        $this->expectExceptionCode(2);

        $token = (new Builder())->issuedBy('http://backend.leadvertex.com/')
            ->permittedFor($_ENV['LV_PLUGIN_SELF_URL'])
            ->expiresAt((new DateTimeImmutable())->getTimestamp())
            ->withClaim('plugin', ['model' => 'macros', 'id' => '1'])
            ->withClaim('lvt', 'test')
            ->withClaim('endpoint', '/companies/1/CRM/plugin/register')
            ->getToken();

        new Registration(
            $token
        );
    }

    public function testNotLeadVertexSubDomain()
    {
        $this->expectException(HandshakeException::class);
        $this->expectExceptionCode(3);

        $token = (new Builder())->issuedBy('https://backend.justvertex.com/')
            ->permittedFor($_ENV['LV_PLUGIN_SELF_URL'])
            ->expiresAt((new DateTimeImmutable())->getTimestamp())
            ->withClaim('plugin', ['model' => 'macros', 'id' => '1'])
            ->withClaim('lvt', 'test')
            ->withClaim('endpoint', '/companies/1/CRM/plugin/register')
            ->getToken();

        new Registration(
            $token
        );
    }

    public function testNot200Response()
    {
        self::$mock->append(new Response(400, [], json_encode(['confirmed' => true])));

        $this->expectException(HandshakeException::class);
        $this->expectExceptionCode(4);

        $token = (new Builder())->issuedBy('https://backend.leadvertex.com/')
            ->permittedFor($_ENV['LV_PLUGIN_SELF_URL'])
            ->expiresAt((new DateTimeImmutable())->getTimestamp())
            ->withClaim('plugin', ['model' => 'macros', 'id' => '1'])
            ->withClaim('lvt', 'test')
            ->withClaim('endpoint', '/companies/1/CRM/plugin/register')
            ->getToken();

        new Registration(
            $token
        );
    }

    public function testInvalidResponseBody()
    {
        self::$mock->append(new Response(200, [], json_encode(['someData' => 'value'])));


        $this->expectException(HandshakeException::class);
        $this->expectExceptionCode(5);

        $token = (new Builder())->issuedBy('https://backend.leadvertex.com/')
            ->permittedFor($_ENV['LV_PLUGIN_SELF_URL'])
            ->expiresAt((new DateTimeImmutable())->getTimestamp())
            ->withClaim('plugin', ['model' => 'macros', 'id' => '1'])
            ->withClaim('lvt', 'test')
            ->withClaim('endpoint', '/companies/1/CRM/plugin/register')
            ->getToken();

        new Registration(
            $token
        );
    }

    public function testResponseNotConfirmed()
    {
        self::$mock->append(new Response(200, [], json_encode(['confirmed' => false])));

        $this->expectException(HandshakeException::class);
        $this->expectExceptionCode(6);

        $token = (new Builder())->issuedBy('https://backend.leadvertex.com/')
            ->permittedFor($_ENV['LV_PLUGIN_SELF_URL'])
            ->expiresAt((new DateTimeImmutable())->getTimestamp())
            ->withClaim('plugin', ['model' => 'macros', 'id' => '1'])
            ->withClaim('lvt', 'test')
            ->withClaim('endpoint', '/companies/1/CRM/plugin/register')
            ->getToken();

        new Registration(
            $token
        );
    }
}