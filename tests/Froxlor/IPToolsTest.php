<?php

use PHPUnit\Framework\TestCase;

use Froxlor\System\IPTools;

/**
 *
 * @covers \Froxlor\System\IPTools
 */
class IPToolsTest extends TestCase
{
	public function testValidateIPv6()
	{
		$result = IPTools::is_ipv6('1.1.1.1/4');
		$this->assertFalse($result);
		$result = IPTools::is_ipv6('1.1.1.1');
		$this->assertFalse($result);
		$result = IPTools::is_ipv6('::ffff:10.20.30.40');
		$this->assertEquals('::ffff:10.20.30.40', $result);
		$result = IPTools::is_ipv6('2620:0:2d0:200::7/32');
		$this->assertFalse($result);
		$result = IPTools::is_ipv6('2620:0:2d0:200::7');
		$this->assertEquals('2620:0:2d0:200::7', $result);
	}

	public function testValidateIPinRange()
	{
		$result = IPTools::ip_in_range([0=>'82.149.225.46',1=>24], '123.213.132.1');
		$this->assertFalse($result);
		$result = IPTools::ip_in_range([0=>'82.149.225.46',1=>24], '2620:0:2d0:200::7');
		$this->assertFalse($result);
		$result = IPTools::ip_in_range([0=>'82.149.225.46',1=>24], '82.149.225.152');
		$this->assertTrue($result);
		$result = IPTools::ip_in_range([0=>'2620:0:2d0:200::1',1=>116], '2620:0:2d0:200::fff1');
		$this->assertFalse($result);
		$result = IPTools::ip_in_range([0=>'2620:0:2d0:200::1',1=>64], '2620:0:2d0:200::fff1');
		$this->assertTrue($result);
	}

	/**
	 * regression test / defense-in-depth: an out-of-range netmask must never be
	 * treated as a wildcard match. Previously, a garbage netmask (e.g. one that
	 * slipped through Validate::validate_ip2()'s now-fixed length-check bug) made
	 * pow(2, 32 - $netmask) underflow, collapsing the effective netmask to 0 and
	 * matching every address; the IPv6 path threw an uncaught gmp error instead of
	 * failing closed.
	 */
	public function testValidateIPinRangeRejectsOutOfRangeNetmask()
	{
		$result = IPTools::ip_in_range([0 => '1.2.3.4', 1 => 12345], '203.0.113.99');
		$this->assertFalse($result);
		$result = IPTools::ip_in_range([0 => '1.2.3.4', 1 => 0], '203.0.113.99');
		$this->assertFalse($result);
		$result = IPTools::ip_in_range([0 => '1.2.3.4', 1 => -1], '203.0.113.99');
		$this->assertFalse($result);
		$result = IPTools::ip_in_range([0 => '2001:db8::1', 1 => 99999], 'fe80::dead:beef');
		$this->assertFalse($result);
		$result = IPTools::ip_in_range([0 => '2001:db8::1', 1 => 0], 'fe80::dead:beef');
		$this->assertFalse($result);
	}
}
