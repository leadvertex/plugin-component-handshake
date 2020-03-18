# LeadVertex handshake plugin component
`Leadvertex\Plugin\Components\Handshake\Registration` - component that is designed for easy
registration of the plugin on LeadVertex. It uses [lcobucci\jwt]("https://github.com/lcobucci/jwt/tree/3.3" "lcobucci\jwt") component.

## Installation
```shell script
composer require leadvertex/plugin-component-handshake
```

## Usage
Registration of the plugin starts with sending a registration URI for your plugin to LeadVertex.
The request containing a `JWT` token would be sent to that uri.

These are steps to get your registration:
- The plugin accepts the `JWT` token in its constructor.
- When creating the plugin, it checks the token passed to the `JWT` - whether it was issued by the domain
specified in the environment variable `LV_PLUGIN_COMPONENT_HANDSHAKE_HOSTNAME`
and whether its scheme really matches the one specified in the environment variable `LV_PLUGIN_COMPONENT_HANDSHAKE_SCHEME`.
Also it checks received plugin URI - it must match with current URI, specified in the environment variable `LV_PLUGIN_SELF_URI`.
- After all data is checked, plugin sends this token to LeadVertex. If LeadVertex confirms that token is valid - registration is complete.
Now in your application you can be sure that this `Registration` really came from LeadVertex, and LeadVertex, in turn,
can be sure that it received the correct answer from the valid plugin. Make sure, that you `save()` this registration for further usage.

Now you can start work with this plugin using signed `JWT` token.

## Examples
First of all, you need to configure some environment variables for plugin to work:
```php
$_ENV['LV_PLUGIN_COMPONENT_HANDSHAKE_SCHEME'] = 'https'; // HTTP connection scheme. 'https' is set for example.
$_ENV['LV_PLUGIN_COMPONENT_HANDSHAKE_HOSTNAME'] = 'leadvertex.com'; // Connection hostname. 'leadvertex.com' is set for example.
$_ENV['LV_PLUGIN_SELF_URI'] = 'https://your.plugin.com/LeadVertexPlugin'; // URI to your plugin
```

You need to receive signed `JWT` token in LeadVertex request, which would be sent to your URI with `application/json` header.
```php
// Get JWT as json
$jwt = file_get_contents('php://input');
```

Then you need to parse `JWT` token like this:
```php
$token = (new Parser())->parse($jwt); // Parses from a string
```

In this parsed `JWT` token you need to validate 2 fields:
- `aud` MUST be your plugin current URI.
- `iss` MUST be a subdomain of leadvertex.com. HTTP scheme dor this URI MUST be a `https`.

If this fields are successfully validated, you can finalize registration process by sending this `JWT` token to LeadVertex.
With usage of `Registration` class you can simply do this:
```php
$registration = new Registration($token);
```
When creating the `Registration` class, all conditions for the `iss` and `aud` fields are checked and a URI is formed for the subsequent token sending.\
The rule for generating the URI is combining a `$jwt['iss']` and `$jwt['endpoint']` together.

If registration process was completed successfully, make sure, that you used `$registration->save()` to save registration for further usage.
More information about this method you can get from [plugin-component-db](https://github.com/leadvertex/plugin-component-db "plugin-component-db") documentation.\
If the registration process was failed an instance of `HandshakeException` will be thrown with an error message.

When your plugin receives `JWT` in LeadVertex request it needs to load saved registration and get signed token from it with `getSignedToken()` method:
```php
$signedToken = $registration->getSignedToken($jwt);
``` 

Also you can use `getLVT()` method on loaded registration model to get raw unencrypted token value:
```php
$rawToken = $registration->getLVT();
```

Now you can start to work with you newly registered plugin and receive requests with `$signedToken`.