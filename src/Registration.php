<?php
/**
 * Created for plugin-component-handshake
 * Datetime: 10.02.2020 18:03
 * @author Timur Kasumov aka XAKEPEHOK
 */

namespace Leadvertex\Plugin\Components\Handshake;


use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Token;
use Leadvertex\Plugin\Components\Db\Model;
use Leadvertex\Plugin\Components\Guzzle\Guzzle;
use Leadvertex\Plugin\Components\Handshake\Exceptions\HandshakeException;
use League\Uri\UriString;

class Registration extends Model
{

    /**
     * Registration constructor.
     * @param Token $token
     * @throws HandshakeException
     */
    public function __construct(Token $token)
    {
        parent::__construct(
            $token->getClaim('plugin')['id'],
            $token->getClaim('plugin')['model']
        );

        $this->setTag_1($token->getClaim('lvt'));
        $this->register($token);
    }


    public function getLVT(): string
    {
        return $this->getTag_1();
    }

    public function getSignedToken(string $jwt): Token
    {
        return (new Builder())
            ->issuedBy($_ENV['LV_PLUGIN_SELF_URI'])
            ->withClaim('jwt', $jwt)
            ->getToken(new Sha256(), new Key($this->getLVT()));
    }

    /**
     * @param Token $token
     * @throws HandshakeException
     */
    private function register(Token $token)
    {
        $selfUri = $_ENV['LV_PLUGIN_SELF_URI'];
        if ($selfUri !== $token->getClaim('aud')) {
            throw new HandshakeException("Audience mismatched '{$token->getClaim('aud')}'", 1);
        }

        $endpoint = UriString::parse($token->getClaim('iss'));

        $scheme = $_ENV['LV_PLUGIN_COMPONENT_HANDSHAKE_SCHEME'] ?? 'https';
        if ($endpoint['scheme'] !== $scheme) {
            throw new HandshakeException("Issuer scheme is not '{$scheme}}'", 2);
        }

        $hostname = $_ENV['LV_PLUGIN_COMPONENT_HANDSHAKE_HOSTNAME'] ?? 'leadvertex.com';
        if (!preg_match('~(^|\.)' . preg_quote($hostname) . '$~ui', $endpoint['host'])) {
            throw new HandshakeException("Issuer hostname is not '{$hostname}'", 3);
        }

        $endpoint['path'] = null;
        $endpoint['query'] = null;
        $endpoint['fragment'] = null;

        $endpoint = UriString::build($endpoint) . '/' . ltrim($token->getClaim('endpoint'), '/');

        $guzzle = Guzzle::getInstance();
        $response = $guzzle->patch($endpoint, [
            'json' => [
                'allow_redirects' => false,
                'registration' => (string) $token,
            ]
        ]);

        if ($response->getStatusCode() != 200) {
            throw new HandshakeException("LV respond with non-200 code: '{$response->getStatusCode()}'", 4);
        }

        $body = json_decode($response->getBody()->getContents(), true);

        if (!isset($body['confirmed'])) {
            throw new HandshakeException("Invalid LV response", 5);
        }

        if ($body['confirmed'] !== true) {
            throw new HandshakeException("LV did not confirm your request", 6);
        }
    }

}