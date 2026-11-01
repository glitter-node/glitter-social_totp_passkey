<?php

namespace Glitter\SocialTOTPPasskey\Providers;

use GuzzleHttp\RequestOptions;
use Illuminate\Support\Arr;
use Glitter\SocialTotpPasskey\Vendor\SocialiteProviders\Manager\OAuth2\AbstractProvider;
use Glitter\SocialTotpPasskey\Vendor\SocialiteProviders\Manager\OAuth2\User;

class NaverProvider extends AbstractProvider
{
    protected function getAuthUrl($state)
    {
        return $this->buildAuthUrlFromBase('https://nid.naver.com/oauth2.0/authorize', $state);
    }

    protected function getTokenUrl()
    {
        return 'https://nid.naver.com/oauth2.0/token';
    }

    protected function getTokenFields($code)
    {
        return [
            'grant_type' => 'authorization_code',
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
            'code' => $code,
            'state' => (string) $this->request->input('state'),
        ];
    }

    public function getAccessTokenResponse($code)
    {
        if (! is_string($code) || $code === '') {
            throw new \RuntimeException('naver_token_request_failed');
        }

        try {
            $response = parent::getAccessTokenResponse($code);
        } catch (\Throwable) {
            throw new \RuntimeException('naver_token_request_failed');
        }

        if (! is_array($response) || ! is_string(Arr::get($response, 'access_token')) || Arr::get($response, 'access_token') === '') {
            throw new \RuntimeException('naver_token_response_invalid');
        }

        return $response;
    }

    protected function getUserByToken($token)
    {
        try {
            $response = $this->getHttpClient()->get('https://openapi.naver.com/v1/nid/me', [
                RequestOptions::HEADERS => [
                    'Accept' => 'application/json',
                    'Authorization' => 'Bearer '.$token,
                ],
            ]);
        } catch (\Throwable) {
            throw new \RuntimeException('naver_profile_request_failed');
        }

        $payload = json_decode((string) $response->getBody(), true);

        if (! is_array($payload) || (string) Arr::get($payload, 'resultcode') !== '00') {
            throw new \RuntimeException('naver_profile_response_invalid');
        }

        $profile = Arr::get($payload, 'response');
        $id = is_array($profile) ? ($profile['id'] ?? null) : null;

        if (! is_array($profile) || ! is_string($id) || trim($id) === '') {
            throw new \RuntimeException('naver_profile_response_invalid');
        }

        return $payload;
    }

    protected function mapUserToObject(array $user)
    {
        $profile = Arr::get($user, 'response');

        if (! is_array($profile) || ! is_string($profile['id'] ?? null) || trim($profile['id']) === '') {
            throw new \RuntimeException('naver_profile_response_invalid');
        }

        $email = is_string($profile['email'] ?? null) ? trim($profile['email']) : '';
        $email = filter_var($email, FILTER_VALIDATE_EMAIL) ? $email : null;
        $nickname = is_string($profile['nickname'] ?? null) ? $profile['nickname'] : null;
        $name = is_string($profile['name'] ?? null) ? $profile['name'] : null;
        $avatar = is_string($profile['profile_image'] ?? null) ? $profile['profile_image'] : null;

        return (new User())->setRaw($user)->map([
            'id' => $profile['id'],
            'nickname' => $nickname,
            'name' => $name ?: $nickname,
            'email' => $email,
            'avatar' => $avatar,
        ]);
    }
}
