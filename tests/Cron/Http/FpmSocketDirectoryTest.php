<?php

use Froxlor\Cron\Http\Php\Fpm;
use Froxlor\Settings;
use PHPUnit\Framework\TestCase;

/**
 * @covers \Froxlor\Cron\Http\Php\Fpm
 */
class FpmSocketDirectoryTest extends TestCase
{
	private function fpm(array $config = [], array $domain = []): Fpm
	{
		$reflection = new ReflectionClass(Fpm::class);
		$fpm = $reflection->newInstanceWithoutConstructor();
		foreach (['fpm_cfg' => $config, 'domain' => array_merge([
			'fpm_config_id' => 4,
			'loginname' => 'customer',
			'domain' => 'Example.org',
			'id' => 17,
			'guid' => 10007
		], $domain)] as $name => $value) {
			$property = $reflection->getProperty($name);
			if (PHP_VERSION_ID < 80100) {
				$property->setAccessible(true);
			}
			$property->setValue($fpm, $value);
		}
		return $fpm;
	}

	public function testDaemonDirectoryOverridesGlobalDirectory()
	{
		$this->assertSame('/run/PHP56/4-customer-example.org-php-fpm.socket',
			$this->fpm(['socket_dir' => '/run/PHP56'])->getSocketFile(false));
	}

	public function testEmptyDirectoryUsesGlobalSetting()
	{
		$expected = rtrim(Settings::Get('phpfpm.fastcgi_ipcdir'), '/') . '/4-customer-example.org-php-fpm.socket';
		$this->assertSame($expected, $this->fpm(['socket_dir' => ''])->getSocketFile(false));
		$this->assertSame($expected, $this->fpm()->getSocketFile(false));
	}

	public function testLongDomainUsesDomainIdWithinDaemonDirectory()
	{
		$this->assertSame('/run/php56/4-customer-17-php-fpm.socket',
			$this->fpm(['socket_dir' => '/run/php56'], ['domain' => str_repeat('a', 100) . '.org'])->getSocketFile(false));
	}

	public function testLongLoginUsesNumericCustomerId()
	{
		$this->assertSame('/run/php56/4-10007-17-php-fpm.socket',
			$this->fpm(['socket_dir' => '/run/php56'], ['loginname' => str_repeat('a', 100)])->getSocketFile(false));
	}

	public function testUnusableSocketPathIsRejected()
	{
		$this->expectException(InvalidArgumentException::class);
		$this->fpm(['socket_dir' => '/run/' . str_repeat('a', 100)])->getSocketFile(false);
	}

	public function testDummyPoolUsesDaemonDirectory()
	{
		$directory = sys_get_temp_dir() . '/fpm-dummy-' . uniqid();
		mkdir($directory);
		try {
			Fpm::createDummyPool($directory, '/run/php56');
			$this->assertStringContainsString('listen = /run/php56/' . md5($directory) . '-fpm.sock', file_get_contents($directory . '/dummy.conf'));
		} finally {
			unlink($directory . '/dummy.conf');
			rmdir($directory);
		}
	}
}
