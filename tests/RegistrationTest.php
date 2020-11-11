<?php
namespace Leadvertex\Plugin\Components\Registration;


use DateTimeImmutable;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\ValidationData;
use Leadvertex\Plugin\Components\Db\Components\Connector;
use Leadvertex\Plugin\Components\Guzzle\Guzzle;
use Leadvertex\Plugin\Components\Registration\Exceptions\PluginRegistrationException;
use PHPUnit\Framework\TestCase;

class RegistrationTest extends TestCase
{

    private static $mock;

    /**
     * @var Token
     */
    private $token;

    /**
     * @var Registration
     */
    private $registration;

    public static function setUpBeforeClass(): void
    {
        parent::setUpBeforeClass();
        $_ENV['LV_PLUGIN_SELF_URI'] = 'https://plugin.example.com/excel/';
        $_ENV['LV_PLUGIN_COMPONENT_REGISTRATION_SCHEME'] = 'https';
        $_ENV['LV_PLUGIN_COMPONENT_REGISTRATION_HOSTNAME'] = 'leadvertex.com';
        $_ENV['LV_PLUGIN_SELF_TYPE'] = 'MACROS';

        Connector::setCompanyId(1);

        self::$mock = new MockHandler();
        $handlerStack = HandlerStack::create(self::$mock);
        Guzzle::getInstance(['handler' => $handlerStack, 'http_errors' => false]);
    }

    protected function setUp(): void
    {
        parent::setUp();
        self::$mock->reset();
    }

    private function standardRegistration()
    {
        $lvt = "TestToken";
        self::$mock->append( new Response(200, [], json_encode(['confirmed' => true])));

        $this->token = (new Builder())->issuedBy('https://backend.leadvertex.com/')
            ->permittedFor($_ENV['LV_PLUGIN_SELF_URI'])
            ->expiresAt((new DateTimeImmutable())->getTimestamp())
            ->withClaim('cid', '1')
            ->withClaim('plugin', ['alias' => 'macros', 'id' => '1'])
            ->withClaim('LVPT', $lvt)
            ->getToken();

        $this->token = $this->convertToken($this->token);

        $this->registration = new Registration($this->token);
    }

    public function testRequestJWTClaims()
    {
        $this->standardRegistration();

        $testRequest = json_decode(self::$mock->getLastRequest()->getBody()->getContents(), true);
        $token = (new Parser())->parse($testRequest['registration']);

        $this->assertEquals($this->token->getClaim('iss'), $token->getClaim('iss'));
        $this->assertEquals($this->token->getClaim('aud'), $token->getClaim('aud'));
        $this->assertEquals($this->token->getClaim('exp'), $token->getClaim('exp'));

        $this->assertEquals($this->token->getClaim('plugin')->alias, $token->getClaim('plugin')->alias);
        $this->assertEquals($this->token->getClaim('plugin')->alias, $this->registration->getFeature());

        $this->assertEquals($this->token->getClaim('plugin')->id, $token->getClaim('plugin')->id);
        $this->assertEquals($this->token->getClaim('plugin')->id, $this->registration->getCompanyId());

        $this->assertEquals($this->token->getClaim('cid'), $token->getClaim('cid'));

        $this->assertEquals($this->token->getClaim('LVPT'), $token->getClaim('LVPT'));
    }

    public function testValidateRequestJWT()
    {
        $this->standardRegistration();

        $testRequest = json_decode(self::$mock->getLastRequest()->getBody()->getContents(), true);
        $data = (new Parser())->parse($testRequest['registration']);

        $validationData = new ValidationData();
        $validationData->setIssuer($data->getClaim('iss'));
        $validationData->setAudience($data->getClaim('aud'));
        $this->assertTrue($this->token->validate($validationData));
    }

    public function testSelfUriAudience()
    {
        $incorrectUri = 'https://incorrect.com';
        $this->expectException(PluginRegistrationException::class);
        $this->expectExceptionCode(1);

        $token = (new Builder())->issuedBy('https://backend.leadvertex.com/')
            ->permittedFor($incorrectUri)
            ->expiresAt((new DateTimeImmutable())->getTimestamp())
            ->withClaim('plugin', ['alias' => 'macros', 'id' => '1'])
            ->withClaim('LVPT', 'test')
            ->getToken();

        $token = $this->convertToken($token);

        //Trying to register plugin
        new Registration($token);
    }

    public function testHttpIssuer()
    {
        $this->expectException(PluginRegistrationException::class);
        $this->expectExceptionCode(2);

        $token = (new Builder())->issuedBy('http://backend.leadvertex.com/')
            ->permittedFor($_ENV['LV_PLUGIN_SELF_URI'])
            ->expiresAt((new DateTimeImmutable())->getTimestamp())
            ->withClaim('plugin', ['alias' => 'macros', 'id' => '1'])
            ->withClaim('LVPT', 'test')
            ->getToken();

        $token = $this->convertToken($token);

        //Trying to register plugin
        new Registration($token);
    }

    public function testNotLeadVertexSubDomain()
    {
        $this->expectException(PluginRegistrationException::class);
        $this->expectExceptionCode(3);

        $token = (new Builder())->issuedBy('https://backend.justvertex.com/')
            ->permittedFor($_ENV['LV_PLUGIN_SELF_URI'])
            ->expiresAt((new DateTimeImmutable())->getTimestamp())
            ->withClaim('plugin', ['alias' => 'macros', 'id' => '1'])
            ->withClaim('LVPT', 'test')
            ->getToken();

        $token = $this->convertToken($token);

        //Trying to register plugin
        new Registration($token);
    }

    public function testNot200Response()
    {
        self::$mock->append(new Response(400, [], json_encode(['confirmed' => true])));

        $this->expectException(PluginRegistrationException::class);
        $this->expectExceptionCode(4);

        $token = (new Builder())->issuedBy('https://backend.leadvertex.com/')
            ->permittedFor($_ENV['LV_PLUGIN_SELF_URI'])
            ->expiresAt((new DateTimeImmutable())->getTimestamp())
            ->withClaim('plugin', ['alias' => 'macros', 'id' => '1'])
            ->withClaim('cid', '1')
            ->withClaim('LVPT', 'test')
            ->getToken();

        $token = $this->convertToken($token);

        //Trying to register plugin
        new Registration($token);
    }

    public function testInvalidResponseBody()
    {
        self::$mock->append(new Response(200, [], json_encode(['someData' => 'value'])));


        $this->expectException(PluginRegistrationException::class);
        $this->expectExceptionCode(5);

        $token = (new Builder())->issuedBy('https://backend.leadvertex.com/')
            ->permittedFor($_ENV['LV_PLUGIN_SELF_URI'])
            ->expiresAt((new DateTimeImmutable())->getTimestamp())
            ->withClaim('plugin', ['alias' => 'macros', 'id' => '1'])
            ->withClaim('cid', '1')
            ->withClaim('LVPT', 'test')
            ->getToken();

        $token = $this->convertToken($token);

        //Trying to register plugin
        new Registration($token);
    }

    public function testResponseNotConfirmed()
    {
        self::$mock->append(new Response(200, [], json_encode(['confirmed' => false])));

        $this->expectException(PluginRegistrationException::class);
        $this->expectExceptionCode(6);

        $token = (new Builder())->issuedBy('https://backend.leadvertex.com/')
            ->permittedFor($_ENV['LV_PLUGIN_SELF_URI'])
            ->expiresAt((new DateTimeImmutable())->getTimestamp())
            ->withClaim('plugin', ['alias' => 'macros', 'id' => '1'])
            ->withClaim('cid', '1')
            ->withClaim('LVPT', 'test')
            ->getToken();

        $token = $this->convertToken($token);

        //Trying to register plugin
        new Registration($token);
    }

    private function convertToken(Token $token): Token
    {
        return (new Parser())->parse((string) $token);
    }

}