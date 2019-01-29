<?php

namespace SocialiteProviders\Azure;

use SocialiteProviders\Manager\OAuth2\AbstractProvider;
use SocialiteProviders\Manager\OAuth2\User;
use Laravel\Socialite\Two\InvalidStateException;

class Provider extends AbstractProvider
{
    /**
     * Unique Provider Identifier.
     */
    const IDENTIFIER = 'AZURE';

    /**
     * The base Azure Graph URL.
     *
     * @var string
     */
    protected $graphUrl = 'https://graph.windows.net/myorganization/me';

    /**
     * The Graph API version for the request.
     *
     * @var string
     */
    protected $version = '1.5';

    /**
     * {@inheritdoc}
     */
    protected function getAuthUrl($state)
    {
        return $this->buildAuthUrlFromBase(
                        'https://login.microsoftonline.com/' . ($this->config['tenant'] ?: 'common') . '/oauth2/authorize', $state
        );
    }

    protected function getLogoutUrl($redirectBack)
    {
        return 'https://login.microsoftonline.com/' . ($this->config['tenant'] ?: 'common') . '/oauth2/logout' . '?' . http_build_query(['post_logout_redirect_uri' => $redirectBack], '', '&', $this->encodingType);
    }

    /**
     * {@inheritdoc}
     */
    protected function getTokenUrl()
    {
        return 'https://login.microsoftonline.com/common/oauth2/token';
    }

    public function getAccessToken($code)
    {
        $response = $this->getHttpClient()->post($this->getTokenUrl(), [
            'form_params' => $this->getTokenFields($code),
        ]);

        $this->credentialsResponseBody = json_decode($response->getBody(), true);

        return $this->parseAccessToken($response->getBody());
    }

    public function logout($redirectBack = null)
    {
        return dd($this->getLogoutUrl($redirectBack));
    }

    /**
     * @return \SocialiteProviders\Manager\OAuth2\User
     */
    public function user()
    {
        if ($this->hasInvalidState()) {
            throw new InvalidStateException();
        }

        $response = $this->getAccessTokenResponse($this->getCode());

        $token = $this->parseAccessToken($response);
        $userObject = $this->getUserByToken($token);
        $groupsObject = $this->getUserMemberOfByToken($token);

        $userObject['memberOf'] = $groupsObject;

        $user = $this->mapUserToObject($userObject);

        $this->credentialsResponseBody = $response;

        if ($user instanceof User) {
            $user->setAccessTokenResponseBody($this->credentialsResponseBody);
        }

        return $user->setToken($token)
                        ->setRefreshToken($this->parseRefreshToken($response))
                        ->setExpiresIn($this->parseExpiresIn($response));
    }

    /**
     * {@inheritdoc}
     */
    protected function getUserByToken($token)
    {
        $response = $this->getHttpClient()->get($this->graphUrl, [
            'query' => [
                'api-version' => $this->version,
            ],
            'headers' => [
                'Accept' => 'application/json',
                'Authorization' => 'Bearer ' . $token,
            ],
        ]);

        return json_decode($response->getBody(), true);
    }

    /**
     * {@inheritdoc}
     */
    protected function getUserMemberOfByToken($token)
    {
        $response = $this->getHttpClient()->get($this->graphUrl . '/memberOf', [
            'query' => [
                'api-version' => $this->version,
            ],
            'headers' => [
                'Accept' => 'application/json',
                'Authorization' => 'Bearer ' . $token,
            ],
        ]);

        return json_decode($response->getBody(), true);
    }

    /**
     * {@inheritdoc}
     */
    protected function mapUserToObject(array $user)
    {
        return (new User())->setRaw($user)->map([
                    'id' => $user['objectId'], 'nickname' => null, 'name' => $user['displayName'],
                    'email' => $user['userPrincipalName'], 'avatar' => null,
        ]);
    }

    /**
     * {@inheritdoc}
     */
    protected function getTokenFields($code)
    {
        return array_merge(parent::getTokenFields($code), [
            'grant_type' => 'authorization_code',
            'resource' => 'https://graph.windows.net',
        ]);
    }

    /**
     * Add the additional configuration key 'tenant' to enable the branded sign-in experience.
     *
     * @return array
     */
    public static function additionalConfigKeys()
    {
        return ['tenant'];
    }
}