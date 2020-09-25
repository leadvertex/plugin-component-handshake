<?php
/**
 * Created for plugin-component-registration
 * Datetime: 10.02.2020 18:03
 * @author Timur Kasumov aka XAKEPEHOK
 */

namespace Leadvertex\Plugin\Components\Registration;


use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer\Hmac\Sha512;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Token;
use Leadvertex\Plugin\Components\Db\Model;
use Leadvertex\Plugin\Components\Guzzle\Guzzle;
use Leadvertex\Plugin\Components\Registration\Exceptions\PluginRegistrationException;
use League\Uri\UriString;

class Registration extends Model
{

    /**
     * Registration constructor.
     * @param Token $token
     * @throws PluginRegistrationException
     */
    public function __construct(Token $token)
    {
        parent::__construct(
            $token->getClaim('plugin')->id,
            $token->getClaim('plugin')->alias
        );

        $this->setTag_1($token->getClaim('LVPT'));
        $this->register($token);
    }


    public function getLVPT(): string
    {
        return $this->getTag_1();
    }

    public function getSignedToken(string $jwt): Token
    {
        return (new Builder())
            ->issuedBy($_ENV['LV_PLUGIN_SELF_URI'])
            ->withClaim('jwt', $jwt)
            ->withClaim('type', 'macrosPlugin')
            ->getToken(new Sha512(), new Key($this->getLVPT()));
    }

    /**
     * @param Token $token
     * @throws PluginRegistrationException
     */
    private function register(Token $token)
    {
        $selfUri = $_ENV['LV_PLUGIN_SELF_URI'];
        if ($selfUri !== $token->getClaim('aud')) {
            throw new PluginRegistrationException("Audience mismatched '{$token->getClaim('aud')}'", 1);
        }

        $endpoint = UriString::parse($token->getClaim('iss'));

        $scheme = $_ENV['LV_PLUGIN_COMPONENT_REGISTRATION_SCHEME'] ?? 'https';
        if ($endpoint['scheme'] !== $scheme) {
            throw new PluginRegistrationException("Issuer scheme is not '{$scheme}'", 2);
        }

        $hostname = $_ENV['LV_PLUGIN_COMPONENT_REGISTRATION_HOSTNAME'] ?? 'leadvertex.com';
        if (!preg_match('~(^|\.)' . preg_quote($hostname) . '$~ui', $endpoint['host'])) {
            throw new PluginRegistrationException("Issuer hostname is not '{$hostname}'", 3);
        }

        $endpoint['path'] = null;
        $endpoint['query'] = null;
        $endpoint['fragment'] = null;

        $companyId = $token->getClaim('cid');
        $endpoint = UriString::build($endpoint) . "/companies/{$companyId}/CRM/plugin/register";

        $guzzle = Guzzle::getInstance();
        $response = $guzzle->put($endpoint, [
            'allow_redirects' => false,
            'json' => [
                'registration' => (string) $token,
            ]
        ]);

        if ($response->getStatusCode() != 200) {
            throw new PluginRegistrationException("LV respond with non-200 code: '{$response->getStatusCode()}'", 4);
        }

        $body = json_decode($response->getBody()->getContents(), true);

        if (!isset($body['confirmed'])) {
            throw new PluginRegistrationException("Invalid LV response", 5);
        }

        if ($body['confirmed'] !== true) {
            throw new PluginRegistrationException("LV did not confirm your request", 6);
        }
    }

}