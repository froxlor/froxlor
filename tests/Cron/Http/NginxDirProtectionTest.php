<?php

use Froxlor\Cron\Http\Nginx;
use PHPUnit\Framework\TestCase;

/**
 * @covers \Froxlor\Cron\Http\Nginx
 */
class NginxDirProtectionTest extends TestCase
{
	private function call(string $name, ...$args)
	{
		$nginx = $this->getMockBuilder(Nginx::class)->disableOriginalConstructor()->onlyMethods([])->getMock();
		$method = new ReflectionMethod(Nginx::class, $name);
		if (PHP_VERSION_ID < 80100) {
			$method->setAccessible(true);
		}
		return $method->invoke($nginx, ...$args);
	}

	private function single(string $path, string $authname = 'realm'): array
	{
		return ['path' => $path, 'authname' => $authname, 'usrf' => '/etc/nginx/htpasswd/1-' . md5($path) . '.htpasswd'];
	}

	public function testDocumentrootIsProtectedOnServerLevelWithoutAcmeChallenges()
	{
		$auth = $this->call('getServerAuthBasic', $this->single('/'));

		$this->assertStringContainsString('set $froxlor_auth_realm "realm";', $auth);
		$this->assertStringContainsString('auth_basic            $froxlor_auth_realm;', $auth);
		$this->assertStringContainsString('auth_basic_user_file', $auth);
		$this->assertStringNotContainsString('location', $auth);
		$this->assertMatchesRegularExpression('#\[A-Za-z0-9_-\]\+\$\) \{#', $auth);
	}

	public function testChildLocationInheritsClosestProtectedParent()
	{
		$htpasswds = [$this->single('/'), $this->single('/a/', 'outer'), $this->single('/a/b/', 'inner')];

		$auth = $this->call('getInheritedAuthBasic', '/a/b/c/', $htpasswds);

		$this->assertStringContainsString('auth_basic            "inner";', $auth);
		$this->assertStringContainsString(md5('/a/b/'), $auth);
	}

	public function testChildLocationWithOwnProtectionGetsNoDuplicateDirectives()
	{
		$this->assertSame('', $this->call('getInheritedAuthBasic', '/a/b/', [$this->single('/a/'), $this->single('/a/b/')]));
	}

	public function testUnprotectedAndSimilarlyNamedPathsAreNotAffected()
	{
		// the documentroot is inherited via server-level, /ab/ is not below /a/
		$this->assertSame('', $this->call('getInheritedAuthBasic', '/ab/', [$this->single('/'), $this->single('/a/')]));
		$this->assertSame('', $this->call('getInheritedAuthBasic', '/other/', []));
	}

	public function testMergeIntoBlockWithNestedLocationEndsUpInOuterBlock()
	{
		$merged = $this->call('mergeVhostCustom', "location ^~ /a {\nindex a;\nlocation ~ b {\nc;\n}\n}", "location ^~ /a {\nadd_header x y;\n}");

		$this->assertMatchesRegularExpression('/c;\s*\}\s*add_header x y;\s*\}/', $merged);
	}
}
