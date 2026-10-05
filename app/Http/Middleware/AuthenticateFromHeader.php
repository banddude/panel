<?php

namespace Pterodactyl\Http\Middleware;

use Illuminate\Http\Request;
use Pterodactyl\Models\User;
use Illuminate\Auth\AuthManager;
use Pterodactyl\Events\Auth\DirectLogin;
use Symfony\Component\HttpFoundation\IpUtils;
use Pterodactyl\Services\Users\UserCreationService;
use Symfony\Component\HttpKernel\Exception\HttpException;
use Pterodactyl\Contracts\Repository\UserRepositoryInterface;
use Pterodactyl\Exceptions\Repository\RecordNotFoundException;

class AuthenticateFromHeader
{
    private const SESSION_KEY = 'auth_header_user_id';

    public function __construct(
        private AuthManager $auth,
        private UserRepositoryInterface $repository,
        private UserCreationService $creationService,
    ) {
    }

    public function handle(Request $request, \Closure $next): mixed
    {
        if (!config('auth.header.enabled')) {
            return $next($request);
        }

        $username = mb_strtolower(trim((string) $request->headers->get((string) config('auth.header.username_header'))));
        $email = mb_strtolower(trim((string) $request->headers->get((string) config('auth.header.email_header'))));

        if ($username === '' && $email === '') {
            $this->logoutHeaderSession($request);

            return $next($request);
        }

        if ($username === '' || $email === '') {
            throw new HttpException(400, 'Both remote authentication headers must be provided.');
        }

        if (!$this->isTrustedProxy($request)) {
            throw new HttpException(403, 'Remote authentication headers were not provided by a trusted proxy.');
        }

        $user = $this->resolveUser($username, $email);

        if (!$user && !config('auth.header.auto_create')) {
            throw new HttpException(403, 'No local account exists for the authenticated remote user.');
        }

        if (!$user) {
            $user = $this->creationService->handle([
                'username' => $username,
                'email' => $email,
                'name_first' => $username,
                'name_last' => 'User',
            ]);
        }

        $guard = $this->auth->guard();
        $currentUser = $guard->user();

        if ($currentUser instanceof User && $currentUser->id === $user->id) {
            $request->session()->put(self::SESSION_KEY, $user->id);

            return $next($request);
        }

        $request->session()->remove('auth_confirmation_token');
        $request->session()->regenerate();

        $guard->login($user);
        $request->session()->put(self::SESSION_KEY, $user->id);
        event(new DirectLogin($user, false));

        return $next($request);
    }

    private function logoutHeaderSession(Request $request): void
    {
        if (!$request->hasSession() || !$request->session()->has(self::SESSION_KEY)) {
            return;
        }

        $this->auth->guard()->logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();
    }

    private function resolveUser(string $username, string $email): ?User
    {
        $byEmail = $this->findUser(['email' => $email]);
        $byUsername = $this->findUser(['username' => $username]);

        if ($byEmail && $byUsername && $byEmail->id !== $byUsername->id) {
            throw new HttpException(409, 'The remote username and email belong to different local accounts.');
        }

        $user = $byEmail ?? $byUsername;
        if (!$user) {
            return null;
        }

        if (mb_strtolower($user->username) !== $username || mb_strtolower($user->email) !== $email) {
            throw new HttpException(409, 'The remote identity does not match the local account.');
        }

        return $user;
    }

    private function findUser(array $fields): ?User
    {
        try {
            $user = $this->repository->findFirstWhere($fields);
        } catch (RecordNotFoundException) {
            return null;
        }

        return $user instanceof User ? $user : null;
    }

    private function isTrustedProxy(Request $request): bool
    {
        $remoteAddress = $request->server->get('REMOTE_ADDR');
        $trustedProxies = config('trustedproxy.proxies', []);

        if (!$remoteAddress || in_array($trustedProxies, ['*', '**'], true)) {
            return false;
        }

        $trustedProxies = array_values(array_filter(array_map(
            static fn ($proxy) => is_string($proxy) ? trim($proxy) : '',
            is_array($trustedProxies) ? $trustedProxies : [$trustedProxies],
        )));

        if ($trustedProxies === [] || in_array('*', $trustedProxies, true) || in_array('**', $trustedProxies, true)) {
            return false;
        }

        return IpUtils::checkIp($remoteAddress, $trustedProxies);
    }
}
