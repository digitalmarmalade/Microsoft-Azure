<?php

namespace SocialiteProviders\Azure;

use Carbon\Carbon;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Session;
use Laravel\Socialite\Two\InvalidStateException;
use SocialiteProviders\Manager\OAuth2\User;

class Provider extends AzureProvider
{
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
     * Logout of Azure
     *
     * @param  null  $redirectBack
     *
     * @return string
     */
    public function logout($redirectBack = null)
    {
        return $this->getLogoutUrl($redirectBack);
    }

    /**
     * @param $redirectBack
     *
     * @return string
     */
    public function getLogoutUrl($redirectBack)
    {
        return 'https://login.microsoftonline.com/'.($this->config['tenant'] ?: 'common').'/oauth2/logout'.'?'.http_build_query(['post_logout_redirect_uri' => $redirectBack],
                '', '&', $this->encodingType);
    }

    protected function mapUserToObject(array $user)
    {
        return (new User())->setRaw($user)->map([
            'id'    => $user['objectId'], 'nickname' => null, 'name' => $user['displayName'],
            'email' => $user['mail'], 'avatar' => null,
        ]);
    }

    /**
     * @return User
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
     * Get a transative list of groups the current user is a member of
     *
     * @param $token
     * @param $userId
     *
     * @return mixed
     */
    public function getUserMemberGroupsByToken($token, $userId)
    {
        $response = $this->getHttpClient()->post($this->graphUrl."/getMemberGroups", [
            'body' => json_encode([
                'securityEnabledOnly' => true
            ]),
            'query' => [
                'api-version' => $this->version,
            ],
            'headers' => [
                'Accept' => 'application/json',
                'Content-Type' => 'application/json',
                'Authorization' => 'Bearer '.$token,
            ],
        ]);

        return json_decode($response->getBody(), true);
    }

    /**
     * Save encrypted Azure user to session
     */
    public function saveToSession($user)
    {
        Session::put($this->session_token, $user);
        Session::save();

        return $this;
    }

    /**
     * Force a refresh of the token an user info
     */
    public function refreshToken($force = false)
    {
        if ($this->shouldTokenBeRefreshed()) {
            $this->token_response = $this->getRefreshTokenResponse();

            return $this->getUserProfileFromReponse();
        } else {
            if ($force) {
                return $this->getUserProfileFromReponse();
            }
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
            return true;
        }

        // if token coming to end of life then reresh it
        return $this->isTokenUnderThreshold();
    }

    /**
     * Check if the OAuth token has expired
     */
    public function hasTokenExpired()
    {
        $this->getTokenFromSession();

        $now = Carbon::now($this->token_timezone);
        $expiry = Carbon::createFromTimestamp($this->parseExpiresOn(), $this->token_timezone);
        // token expired
        if ($expiry->lessThan($now)) {
            return true;
        }

        return false;
    }

    /**
     * Get and decyrpt Azure user from session
     *
     * Auto set the Token response info from the session
     */
    public function getTokenFromSession()
    {
        if ($this->getFromSession()) {
            return $this->token_response;
        }

        return false;
    }

    /**
     * Get and decyrpt Azure user from session
     *
     * Auto set the Token response info from the session
     */
    public function getFromSession()
    {
        if ($this->session_loaded && $this->azure_user) {
            return $this->azure_user;
        } else {
            $decrypted = Session::get($this->session_token);
            if (isset($decrypted->accessTokenResponseBody)) {
                $this->azure_user = $decrypted;
                $this->credentialsResponseBody = $this->token_response = $decrypted->accessTokenResponseBody;

                return $decrypted;
            }
        }

        return false;
    }

    /**
     * get the timestamp of when the token expires
     */
    protected function parseExpiresOn()
    {
        return Arr::get($this->token_response, 'expires_on');
    }

    /**
     * Check if the OAuth token is coming to end of life
     */
    public function isTokenUnderThreshold()
    {
        $this->getTokenFromSession();

        // get expiry and current time
        $now = Carbon::now($this->token_timezone);
        $expiry = Carbon::createFromTimestamp($this->parseExpiresOn(), $this->token_timezone);

        // get the diff between the teo
        $diffInMinutes = $expiry->diffInMinutes($now);

        // token expired
        if ($now->lessThan($expiry) && $diffInMinutes <= $this->token_refresh_threshold) {
            return true;
        }

        return false;
    }

    /**
     * Get the refresh token response for the given access token.
     *
     * @param  string  $refreshToken
     *
     * @return array
     */
    public function getRefreshTokenResponse()
    {
        $this->getTokenFromSession();

        if ($this->token_response['refresh_token']) {
            $response = $this->getHttpClient()->post($this->getTokenUrl(), [
                'headers' => ['Accept' => 'application/json'],
                'form_params' => $this->getRefreshTokenFields(),
            ]);
            return json_decode($response->getBody(), true);
        }
    }

    /**
     * Get the POST fields for the token request.
     *
     * @param  string  $code
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
}