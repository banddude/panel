<?php

namespace Pterodactyl\Tests\Unit\Http\Middleware;

use Mockery as m;
use Mockery\MockInterface;
use Illuminate\Http\Request;
use Pterodactyl\Models\User;
use Pterodactyl\Tests\TestCase;
use Illuminate\Auth\AuthManager;
use Illuminate\Support\Facades\Event;
use Pterodactyl\Events\Auth\DirectLogin;
use Illuminate\Contracts\Session\Session;
use Illuminate\Contracts\Auth\StatefulGuard;
use Pterodactyl\Services\Users\UserCreationService;
use Pterodactyl\Http\Middleware\AuthenticateFromHeader;
use Symfony\Component\HttpKernel\Exception\HttpException;
use Pterodactyl\Contracts\Repository\UserRepositoryInterface;
use Pterodactyl\Exceptions\Repository\RecordNotFoundException;

class AuthenticateFromHeaderTest extends TestCase
{
    private MockInterface $auth;
    private MockInterface $guard;
    private MockInterface $repository;
    private MockInterface $creationService;

    public function setUp(): void
    {
        parent::setUp();

        $this->auth = m::mock(AuthManager::class);
        $this->guard = m::mock(StatefulGuard::class);
        $this->repository = m::mock(UserRepositoryInterface::class);
        $this->creationService = m::mock(UserCreationService::class);

        config([
            'auth.header.enabled' => true,
            'auth.header.auto_create' => false,
            'auth.header.username_header' => 'X-Auth-Username',
            'auth.header.email_header' => 'X-Auth-Email',
            'trustedproxy.proxies' => ['10.0.0.2'],
        ]);

        Event::fake([DirectLogin::class]);
    }

    public function testDisabledHeaderAuthenticationIsSkipped(): void
    {
        config(['auth.header.enabled' => false]);

        $response = $this->middleware()->handle($this->request(), fn (Request $request) => 'next');

        $this->assertSame('next', $response);
    }

    public function testRequestWithoutRemoteHeadersUsesNormalAuthenticationFlow(): void
    {
        $response = $this->middleware()->handle($this->request(), fn (Request $request) => 'next');

        $this->assertSame('next', $response);
    }

    public function testIncompleteRemoteIdentityIsRejected(): void
    {
        try {
            $this->middleware()->handle($this->request('alice'), fn (Request $request) => 'next');
            $this->fail('Expected an HTTP exception for incomplete remote identity headers.');
        } catch (HttpException $exception) {
            $this->assertSame(400, $exception->getStatusCode());
        }
    }

    public function testHeadersFromUntrustedAddressAreRejected(): void
    {
        try {
            $this->middleware()->handle(
                $this->request('alice', 'alice@example.com', '203.0.113.10'),
                fn (Request $request) => 'next',
            );
            $this->fail('Expected an HTTP exception for untrusted remote headers.');
        } catch (HttpException $exception) {
            $this->assertSame(403, $exception->getStatusCode());
        }
    }

    public function testWildcardTrustedProxyConfigurationIsRejectedForHeaderAuthentication(): void
    {
        config(['trustedproxy.proxies' => '*']);

        try {
            $this->middleware()->handle(
                $this->request('alice', 'alice@example.com'),
                fn (Request $request) => 'next',
            );
            $this->fail('Expected an HTTP exception for wildcard proxy trust.');
        } catch (HttpException $exception) {
            $this->assertSame(403, $exception->getStatusCode());
        }
    }

    public function testExistingUserIsLoggedInFromTrustedHeaders(): void
    {
        $user = $this->user(1, 'alice', 'alice@example.com');
        $session = $this->sessionExpectingLogin(1);

        $this->expectIdentityLookup($user, $user);
        $this->auth->shouldReceive('guard')->once()->andReturn($this->guard);
        $this->guard->shouldReceive('user')->once()->andReturnNull();
        $this->guard->shouldReceive('login')->once()->with($user);

        $response = $this->middleware()->handle(
            $this->request('Alice', 'Alice@Example.com', '10.0.0.2', $session),
            fn (Request $request) => 'next',
        );

        $this->assertSame('next', $response);
        Event::assertDispatched(fn (DirectLogin $event) => $event->user === $user && !$event->remember);
    }

    public function testMatchingHeaderUserDoesNotRegenerateOrReloginEveryRequest(): void
    {
        $user = $this->user(1, 'alice', 'alice@example.com');
        $session = m::mock(Session::class);
        $session->shouldReceive('put')->once()->with('auth_header_user_id', 1);

        $this->expectIdentityLookup($user, $user);
        $this->auth->shouldReceive('guard')->once()->andReturn($this->guard);
        $this->guard->shouldReceive('user')->once()->andReturn($user);
        $this->guard->shouldNotReceive('login');

        $response = $this->middleware()->handle(
            $this->request('alice', 'alice@example.com', '10.0.0.2', $session),
            fn (Request $request) => 'next',
        );

        $this->assertSame('next', $response);
        Event::assertNotDispatched(DirectLogin::class);
    }

    public function testChangedHeaderIdentityRebindsExistingSession(): void
    {
        $oldUser = $this->user(1, 'alice', 'alice@example.com');
        $newUser = $this->user(2, 'bob', 'bob@example.com');
        $session = $this->sessionExpectingLogin(2);

        $this->expectIdentityLookup($newUser, $newUser, 'bob', 'bob@example.com');
        $this->auth->shouldReceive('guard')->once()->andReturn($this->guard);
        $this->guard->shouldReceive('user')->once()->andReturn($oldUser);
        $this->guard->shouldReceive('login')->once()->with($newUser);

        $response = $this->middleware()->handle(
            $this->request('bob', 'bob@example.com', '10.0.0.2', $session),
            fn (Request $request) => 'next',
        );

        $this->assertSame('next', $response);
        Event::assertDispatched(fn (DirectLogin $event) => $event->user === $newUser);
    }

    public function testHeaderAuthenticatedSessionIsLoggedOutWhenHeadersDisappear(): void
    {
        $session = m::mock(Session::class);
        $session->shouldReceive('has')->once()->with('auth_header_user_id')->andReturnTrue();
        $session->shouldReceive('invalidate')->once();
        $session->shouldReceive('regenerateToken')->once();

        $this->auth->shouldReceive('guard')->once()->andReturn($this->guard);
        $this->guard->shouldReceive('logout')->once();

        $response = $this->middleware()->handle(
            $this->request(session: $session),
            fn (Request $request) => 'next',
        );

        $this->assertSame('next', $response);
    }

    public function testTrustedRemoteUserCanBeCreatedWhenEnabled(): void
    {
        config(['auth.header.auto_create' => true]);

        $user = $this->user(1, 'alice', 'alice@example.com');
        $session = $this->sessionExpectingLogin(1);

        $this->expectIdentityLookup(null, null);
        $this->creationService->shouldReceive('handle')->once()->with([
            'username' => 'alice',
            'email' => 'alice@example.com',
            'name_first' => 'alice',
            'name_last' => 'User',
        ])->andReturn($user);
        $this->auth->shouldReceive('guard')->once()->andReturn($this->guard);
        $this->guard->shouldReceive('user')->once()->andReturnNull();
        $this->guard->shouldReceive('login')->once()->with($user);

        $response = $this->middleware()->handle(
            $this->request('alice', 'alice@example.com', '10.0.0.2', $session),
            fn (Request $request) => 'next',
        );

        $this->assertSame('next', $response);
    }

    public function testUnknownRemoteUserIsRejectedWhenAutoCreateIsDisabled(): void
    {
        $this->expectIdentityLookup(null, null);

        try {
            $this->middleware()->handle(
                $this->request('alice', 'alice@example.com'),
                fn (Request $request) => 'next',
            );
            $this->fail('Expected an HTTP exception for an unknown remote user.');
        } catch (HttpException $exception) {
            $this->assertSame(403, $exception->getStatusCode());
        }
    }

    public function testUsernameAndEmailCollisionIsRejected(): void
    {
        $emailUser = $this->user(1, 'alice', 'alice@example.com');
        $usernameUser = $this->user(2, 'bob', 'bob@example.com');

        $this->expectIdentityLookup($emailUser, $usernameUser, 'bob', 'alice@example.com');

        try {
            $this->middleware()->handle(
                $this->request('bob', 'alice@example.com'),
                fn (Request $request) => 'next',
            );
            $this->fail('Expected an HTTP exception for conflicting local identities.');
        } catch (HttpException $exception) {
            $this->assertSame(409, $exception->getStatusCode());
        }
    }

    public function testCustomHeaderNamesAreSupported(): void
    {
        config([
            'auth.header.username_header' => 'Remote-User',
            'auth.header.email_header' => 'Remote-Email',
        ]);

        $user = $this->user(1, 'alice', 'alice@example.com');
        $session = $this->sessionExpectingLogin(1);
        $request = $this->request(remoteAddress: '10.0.0.2', session: $session);
        $request->headers->set('Remote-User', 'alice');
        $request->headers->set('Remote-Email', 'alice@example.com');

        $this->expectIdentityLookup($user, $user);
        $this->auth->shouldReceive('guard')->once()->andReturn($this->guard);
        $this->guard->shouldReceive('user')->once()->andReturnNull();
        $this->guard->shouldReceive('login')->once()->with($user);

        $response = $this->middleware()->handle($request, fn (Request $request) => 'next');

        $this->assertSame('next', $response);
    }

    private function middleware(): AuthenticateFromHeader
    {
        return new AuthenticateFromHeader($this->auth, $this->repository, $this->creationService);
    }

    private function request(
        ?string $username = null,
        ?string $email = null,
        string $remoteAddress = '10.0.0.2',
        ?Session $session = null,
    ): Request {
        $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => $remoteAddress]);

        if ($username !== null) {
            $request->headers->set('X-Auth-Username', $username);
        }

        if ($email !== null) {
            $request->headers->set('X-Auth-Email', $email);
        }

        if ($session) {
            $request->setLaravelSession($session);
        }

        return $request;
    }

    private function user(int $id, string $username, string $email): User
    {
        $user = User::factory()->make(['username' => $username, 'email' => $email]);
        $user->id = $id;

        return $user;
    }

    private function expectIdentityLookup(
        ?User $byEmail,
        ?User $byUsername,
        string $username = 'alice',
        string $email = 'alice@example.com',
    ): void {
        $emailExpectation = $this->repository->shouldReceive('findFirstWhere')->once()->with(['email' => $email]);
        $usernameExpectation = $this->repository->shouldReceive('findFirstWhere')->once()->with(['username' => $username]);

        $byEmail ? $emailExpectation->andReturn($byEmail) : $emailExpectation->andThrow(new RecordNotFoundException());
        $byUsername ? $usernameExpectation->andReturn($byUsername) : $usernameExpectation->andThrow(new RecordNotFoundException());
    }

    private function sessionExpectingLogin(int $userId): MockInterface
    {
        $session = m::mock(Session::class);
        $session->shouldReceive('remove')->once()->with('auth_confirmation_token');
        $session->shouldReceive('regenerate')->once();
        $session->shouldReceive('put')->once()->with('auth_header_user_id', $userId);

        return $session;
    }
}
