<?php

namespace SocialiteProviders\Azure;

use Carbon\Carbon;
use Illuminate\Support\Arr;
use Illuminate\Support\Str;
use GuzzleHttp\ClientInterface;
use Illuminate\Support\Facades\Crypt;
use SocialiteProviders\Manager\OAuth2\User;
use Laravel\Socialite\Two\InvalidStateException;
use SocialiteProviders\Manager\OAuth2\AbstractProvider;
use Illuminate\Support\Facades\Session;
use Illuminate\Support\Facades\Log;

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
     * The name of the session var where we keep the token
     *
     * @var string
     */
    protected $session_token = 'azure_token';

    /**
     * OAuth2 response from getting a token or refreshing a token
     *
     * @var string
     */
    protected $token_response;

    /**
     * Azure User profile
     *
     * @var mixed
     */
    protected $azure_user;

    /**
     * how many minutes left on a token lifetime before we refresh
     * the OAuth token will be refreshed if lifetime left is
     * this value or less (in minutes)
     *
     * @var int
     */
    protected $token_refresh_threshold = 10;

    /**
     * timezone we expect token exipry to be in
     * makes comparisons correct
     *
     * @var string
     */
    protected $token_timezone = 'UTC';

    /**
     * prevent multiple reads from session
     *
     * @var bool
     */
    protected $session_loaded = false;

    /**
     * {@inheritdoc}
     */
    protected function getAuthUrl($state)
    {
        return $this->buildAuthUrlFromBase('https://login.microsoftonline.com/' . ($this->config['tenant'] ?: 'common') . '/oauth2/authorize', $state);
    }

    /**
     * @param $redirectBack
     *
     * @return string
     */
    public function getLogoutUrl($redirectBack)
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

    /**
     * Get an access token from the OAuth code
     *
     * @param $code
     *
     * @return string
     */
    public function getAccessToken($code)
    {
        $this->debug('getAccessToken');
        $postKey = (version_compare(ClientInterface::VERSION, '6') === 1) ? 'form_params' : 'body';

        $response = $this->getHttpClient()->post($this->getTokenUrl(), [
            $postKey => $this->getTokenFields($code),
        ]);

        $this->credentialsResponseBody = json_decode($response->getBody(), true);

        return $this->parseAccessToken($response->getBody());
    }

    /**
     * Logout of Azure
     *
     * @param null $redirectBack
     *
     * @return string
     */
    public function logout($redirectBack = null)
    {
        $this->debug('logout');
        return $this->getLogoutUrl($redirectBack);
    }

    /**
     * @return \SocialiteProviders\Manager\OAuth2\User
     */
    public function user()
    {
        if ($this->hasInvalidState()) {
            throw new InvalidStateException();
        }

        $this->token_response = $this->getAccessTokenResponse($this->getCode());

        return $this->getUserProfileFromReponse();
    }

    /**
     * Force a refresh of the token an user info
     */
    public function refreshToken($force = false)
    {
        $this->debug('refreshToken');
        if ($this->shouldTokenBeRefreshed()) {
            $this->debug('refreshToken.refresh');
            $this->token_response = $this->getRefreshTokenResponse();

            return $this->getUserProfileFromReponse();
        } else if ($force) {
            $this->debug('refreshToken.force');
            return $this->getUserProfileFromReponse();
        }

        return $this->azure_user;
    }

    /**
     * Check if we should refresh the token
     * Only if...
     * - Token has > $this->token_timezone left until expiry
     * - Token not expired
     */
    protected function shouldTokenBeRefreshed()
    {
        // if token expired then force re-auth
        if ($this->hasTokenExpired()) {
            $this->debug('shouldTokenBeRefreshed token has expired');
            return true;
        }

        // if token coming to end of life then reresh it
        return $this->isTokenUnderThreshold();
    }

    /**
     * get the timestamp of when the token expires
     */
    protected function parseExpiresOn()
    {
        return Arr::get($this->token_response, 'expires_on');
    }

    /**
     * Check if the OAuth token has expired
     */
    public function hasTokenExpired()
    {
        $this->debug('hasTokenExpired');
        $this->getTokenFromSession();

        $now = Carbon::now($this->token_timezone);
        $expiry = Carbon::createFromTimestamp($this->parseExpiresOn(), $this->token_timezone);
        // token expired
        if ($expiry->lessThan($now)) {
            $this->debug('hasTokenExpired lessThan now');
            return true;
        }

        return false;
    }

    /**
     * Check if the OAuth token is coming to end of life
     */
    public function isTokenUnderThreshold()
    {
        $this->debug('isTokenUnderThreshold');
        $this->getTokenFromSession();

        // get expiry and current time
        $now = Carbon::now($this->token_timezone);
        $expiry = Carbon::createFromTimestamp($this->parseExpiresOn(), $this->token_timezone);

        // get the diff between the teo
        $diffInMinutes = $expiry->diffInMinutes($now);

        // token expired
        if ($now->lessThan($expiry) && $diffInMinutes <= $this->token_refresh_threshold) {
            $this->debug('isTokenUnderThreshold true');
            return true;
        }

        return false;
    }

    /**
     * Get the user profile and group membership
     *
     * We have a token response body from either a getToken or a RefreshToken call
     */
    public function getUserProfileFromReponse()
    {
        $token = $this->parseAccessToken($this->token_response);
        $userObject = $this->getUserByToken($token);
        $groupsObject = $this->getUserMemberGroupsByToken($token, $userObject['objectId']);

        $userObject['memberOf'] = $groupsObject;

        $user = $this->mapUserToObject($userObject);

        $this->credentialsResponseBody = $this->token_response;

        if ($user instanceof User) {
            $user->setAccessTokenResponseBody($this->credentialsResponseBody);
        }

        $user->setToken($token)
                ->setRefreshToken($this->parseRefreshToken($this->token_response))
                ->setExpiresIn($this->parseExpiresIn($this->token_response));
        $this->saveToSession($user);

        return $user;
    }

    /**
     * Get the refresh token response for the given access token.
     *
     * @param  string $refreshToken
     *
     * @return array
     */
    public function getRefreshTokenResponse()
    {
        $this->getTokenFromSession();

        if ($this->token_response['refresh_token']) {
            $postKey = (version_compare(ClientInterface::VERSION, '6') === 1) ? 'form_params' : 'body';

            $response = $this->getHttpClient()->post($this->getTokenUrl(), [
                'headers' => ['Accept' => 'application/json'],
                $postKey => $this->getRefreshTokenFields(),
            ]);

            return json_decode($response->getBody(), true);
        }
    }

    /**
     * Get the POST fields for the token request.
     *
     * @param  string $code
     *
     * @return array
     */
    protected function getRefreshTokenFields()
    {
        return [
            'client_id' => $this->clientId,
            'grant_type' => 'refresh_token',
            'refresh_token' => $this->token_response['refresh_token'],
            'client_secret' => $this->clientSecret,
            'redirect_uri' => $this->redirectUrl,
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function getUserByToken($token)
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
     * Get a transative list of groups the current user is a member of
     *
     * @param $token
     * @param $userId
     *
     * @return mixed
     */
    public function getUserMemberGroupsByToken($token, $userId)
    {
        $response = $this->getHttpClient()->post($this->graphUrl . "/getMemberGroups", [
            'body' => json_encode([
                'securityEnabledOnly' => true
            ]),
            'query' => [
                'api-version' => $this->version,
            ],
            'headers' => [
                'Accept' => 'application/json',
                'Content-Type' => 'application/json',
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
                    'id' => $user['objectId'],
                    'nickname' => null,
                    'name' => $user['displayName'],
                    'email' => $user['mail'],
                    'avatar' => null,
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

    /**
     * Save encrypted Azure user to session
     */
    public function saveToSession($user)
    {
        $this->debug('saveToSession', ['expiresIn' => $user->expiresIn]);
        Session::put($this->session_token, $user);
        Session::save();

        return $this;
    }

    /**
     * Get and decyrpt Azure user from session
     *
     * Auto set the Token response info from the session
     */
    public function getFromSession()
    {
        if ($this->session_loaded && $this->azure_user) {
            $this->debug('getFromSession session loaded');
            return $this->azure_user;
        } else {
            $decrypted = Session::get($this->session_token);
            $this->debug('getFromSession session decrypted', ['expiresIn', $decrypted->expiresIn]);
            if (isset($decrypted->accessTokenResponseBody)) {
                $this->azure_user = $decrypted;
                $this->credentialsResponseBody = $this->token_response = $decrypted->accessTokenResponseBody;
                $this->debug('getFromSession session decrypted set', ['expiresIn', $this->azure_user->expiresIn]);

                return $decrypted;
            }
        }

        $this->debug('getFromSession failed');
        return false;
    }

    /**
     * Get and decyrpt Azure user from session
     *
     * Auto set the Token response info from the session
     */
    public function getTokenFromSession()
    {
        $this->debug('getTokenFromSession');
        if ($this->getFromSession()) {
            return $this->token_response;
        }

        return false;
    }

    private function debug($msg, $context = [])
    {
        Log::info('Azure: ' . $msg, $context);
    }
}