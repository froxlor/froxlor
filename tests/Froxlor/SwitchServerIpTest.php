<?php

use Froxlor\Cli\SwitchServerIp;
use PHPUnit\Framework\TestCase;

/**
 * @covers \Froxlor\Cli\SwitchServerIp
 */
class SwitchServerIpTest extends TestCase
{
	private function replace(string $list, string $old, string $new): string
	{
		$method = new ReflectionMethod(SwitchServerIp::class, 'replaceInList');
		if (PHP_VERSION_ID < 80100) {
			$method->setAccessible(true);
		}
		return $method->invoke(null, $list, $old, $new);
	}

	public function testOnlyCompleteEntriesAreReplaced()
	{
		$this->assertSame('10.0.0.2,10.0.0.10,110.0.0.1', $this->replace('10.0.0.1,10.0.0.10,110.0.0.1', '10.0.0.1', '10.0.0.2'));
	}

	public function testWhitespaceAroundEntriesIsKept()
	{
		$this->assertSame('localhost, 192.168.1.5 ,::1', $this->replace('localhost, 192.168.1.4 ,::1', '192.168.1.4', '192.168.1.5'));
	}

	public function testIpv6EntriesAreNotPartiallyReplaced()
	{
		$this->assertSame('2001:db8::10,2001:db8::2', $this->replace('2001:db8::10,2001:db8::1', '2001:db8::1', '2001:db8::2'));
	}

	public function testListWithoutMatchStaysUnchanged()
	{
		$this->assertSame('', $this->replace('', '10.0.0.1', '10.0.0.2'));
		$this->assertSame('10.0.0.10', $this->replace('10.0.0.10', '10.0.0.1', '10.0.0.2'));
	}
}
