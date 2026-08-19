<?php
use PHPUnit\Framework\TestCase;

use Froxlor\Validate\Validate;

/**
 *
 * @covers \Froxlor\Validate\Validate
 * @covers \Froxlor\UI\Response
 * @covers \Froxlor\FroxlorLogger
 * @covers \Froxlor\Idna\IdnaWrapper
 */
class ValidateTest extends TestCase
{

	public function testValidate()
	{
		$teststr = Validate::validate("user input", "test-field", '', '', [], true);
		$this->assertEquals("user input", $teststr);
	}

	public function testValidateStrInEmptyDefault()
	{
		$teststr = Validate::validate("user input", "test-field", '', '', [
			"user test",
			"user input",
			"user bla"
		], true);
		$this->assertEquals("user input", $teststr);
	}

	public function testValidateEmptyDefaultNoArray()
	{
		$teststr = Validate::validate("user input", "test-field", '', '', "user input", true);
		$this->assertEquals("user input", $teststr);
	}

	public function testValidateRemoveNotAllowedChar()
	{
		$teststr = Validate::validate("user " . PHP_EOL . "input", "test-field", '', '', [], true);
		$this->assertEquals("user input", $teststr);
	}

	public function testValidateStringFormatError()
	{
		$this->expectException("Exception");
		$this->expectExceptionCode(400);
		Validate::validate("user input", "test-field", '/^[A-Z]+$/i', '', [], true);
	}

	public function testValidateIp()
	{
		$result = Validate::validate_ip2("12.34.56.78", false, 'invalidip', false, false, false, false, true);
		$this->assertEquals("12.34.56.78", $result);
	}

	public function testValidateIpPrivNotAllowed()
	{
		$this->expectException("Exception");
		$this->expectExceptionCode(400);
		Validate::validate_ip2("10.0.0.1", false, 'invalidip', false, false, false, false, true);
	}

	public function testValidateIpPrivNotAllowedBool()
	{
		$result = Validate::validate_ip2("10.0.0.1", true, 'invalidip', false, false, false, false, true);
		$this->assertFalse($result);
	}

	public function testValidateIpCidrNotAllowed()
	{
		$this->expectException("Exception");
		$this->expectExceptionCode(400);
		Validate::validate_ip2("12.34.56.78/24", false, 'invalidip', false, false, false, false, true);
	}

	public function testValidateIpCidrNotAllowedBool()
	{
		$result = Validate::validate_ip2("12.34.56.78/24", true, 'invalidip', false, false, false, false, true);
		$this->assertFalse($result);
	}

	public function testValidateIpCidr()
	{
		$result = Validate::validate_ip2("12.34.56.78/24", false, 'invalidip', false, false, true, false, true);
		$this->assertEquals("12.34.56.78/24", $result);
	}

    public function testValidateIpv6Disallowed()
    {
        $this->expectException("Exception");
        $this->expectExceptionCode(400);
        Validate::validate_ip2("2620:0:2d0:200::7/32", false, 'invalidip', false, false, true, true, true);
    }

	public function testValidateIpLocalhostAllowed()
	{
		$result = Validate::validate_ip2("127.0.0.1/32", false, 'invalidip', true, false, true, false, true);
		$this->assertEquals("127.0.0.1/32", $result);
	}

    public function testValidateCidrNoationToNetmaskNotationIPv4()
    {
        $result = Validate::validate_ip2("1.1.1.1/4", false, 'invalidip', true, false, true, true, true);
        $this->assertEquals("1.1.1.1/240.0.0.0", $result);
        $result = Validate::validate_ip2("8.8.8.8/18", false, 'invalidip', true, false, true, true, true);
        $this->assertEquals("8.8.8.8/255.255.192.0", $result);
        $result = Validate::validate_ip2("8.8.8.8/1", false, 'invalidip', true, false, true, true, true);
        $this->assertEquals("8.8.8.8/128.0.0.0", $result);
    }

	public function testValidateIpLocalhostAllowedWrongIp()
	{
		$this->expectException("Exception");
		$this->expectExceptionCode(400);
		Validate::validate_ip2("127.0.0.2", false, 'invalidip', true, false, false, false, true);
	}

	public function testValidateUrl()
	{
		$result = Validate::validateUrl("https://froxlor.org/");
		$this->assertTrue($result);
		$result = Validate::validateUrl("https://froxlor.org/", true);
		$this->assertTrue($result);
		$result = Validate::validateUrl("http://forum.froxlor.org/");
		$this->assertTrue($result);
		$result = Validate::validateUrl("https://api.froxlor.org/doc/0.10.0/index.php");
		$this->assertTrue($result);
		$result = Validate::validateUrl("https://api.froxlor.org/doc/0.10.0/index.php", true);
		$this->assertTrue($result);
		$result = Validate::validateUrl("#froxlor");
		$this->assertFalse($result);
		$result = Validate::validateUrl("https://82.149.225.211/");
		$this->assertTrue($result);
		$result = Validate::validateUrl("https://82.149.225.211/", true);
		$this->assertTrue($result);
		$result = Validate::validateUrl("https://82.149.225.300");
		$this->assertFalse($result);
		$result = Validate::validateUrl("82.149.225.211:443");
		$this->assertTrue($result);
		$result = Validate::validateUrl("172.16.0.1:8080");
		$this->assertFalse($result);
		$result = Validate::validateUrl("172.16.0.1:8080", true);
		$this->assertTrue($result);
		$result = Validate::validateUrl("https://xn--frxlr-kuac.de/", true);
		$this->assertTrue($result);
		$result = Validate::validateUrl("https://2a10:ec2::193:107:51:5/test");
		$this->assertFalse($result);
		$result = Validate::validateUrl("https://[2a10:ec2::193:107:51:5]");
		$this->assertTrue($result);
	}

	/**
	 * regression test: parse_url() rewrites raw control characters in path/query/fragment
	 * to '_' before the per-component regex ever sees them, so a check that only inspects
	 * $parts[...] (the already-masked value) never catches a raw CRLF - only the
	 * percent-encoded form. validateUrl() must reject the raw bytes on the full, unparsed
	 * $url string before parse_url() runs.
	 */
	public function testValidateUrlRejectsRawControlCharacters()
	{
		$LF = "\n";
		$CR = "\r";
		$TAB = "\t";

		// raw CRLF in the path, as used to inject e.g. an Include directive into a
		// generated vhost config (GHSA-c3p2 bypass)
		$result = Validate::validateUrl("http://example.com/a" . $LF . "Include" . $TAB . "evil.conf", true);
		$this->assertFalse($result);

		$result = Validate::validateUrl("http://example.com/a" . $CR . $LF . "b", true);
		$this->assertFalse($result);

		// control: the percent-encoded form was already correctly rejected before this fix
		// and must remain rejected
		$result = Validate::validateUrl("http://example.com/a%0ab", true);
		$this->assertFalse($result);

		// a plain, unremarkable URL must still be accepted
		$result = Validate::validateUrl("http://example.com/a/b?x=1", true);
		$this->assertTrue($result);
	}

	/**
	 * regression test: the per-component symlink/CRLF checks originally only covered
	 * path/query/fragment, leaving the URL's userinfo (user:pass@host) unchecked -
	 * raw or percent-encoded CRLF there must be rejected the same way.
	 */
	public function testValidateUrlRejectsControlCharactersInUserinfo()
	{
		$LF = "\n";

		$result = Validate::validateUrl("http://evil" . $LF . "Include:secret@example.com/", true);
		$this->assertFalse($result);

		$result = Validate::validateUrl("http://user:evil%0dpass@example.com/", true);
		$this->assertFalse($result);

		// a plain userinfo-bearing URL must still be accepted
		$result = Validate::validateUrl("http://user:pass@example.com/", true);
		$this->assertTrue($result);
	}

	public function testValidateDomain()
	{
		$result = Validate::validateDomain('froxlor.org');
		$this->assertEquals('froxlor.org', $result);
		$result = Validate::validateDomain('_dmarc.froxlor.org');
		$this->assertFalse($result);
		$result = Validate::validateDomain('_dmarc.froxlor.org', true);
		$this->assertEquals('_dmarc.froxlor.org', $result);
		$result = Validate::validateDomain('test._dmarc.froxlor.org', true);
		$this->assertEquals('test._dmarc.froxlor.org', $result);
		$result = Validate::validateDomain('0815');
		$this->assertFalse($result);
		$result = Validate::validateDomain('abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz.abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz');
		$this->assertFalse($result);
	}

	public function testValidateHostname()
	{
		$result = Validate::validateLocalHostname('localhost');
		$this->assertEquals('localhost', $result);
		$result = Validate::validateLocalHostname('froxlor-srv02');
		$this->assertEquals('froxlor-srv02', $result);
		$result = Validate::validateLocalHostname('froxlor_org');
		$this->assertFalse($result);
		$result = Validate::validateLocalHostname('froxlor.org');
		$this->assertFalse($result);
		$result = Validate::validateLocalHostname('a--------------------------------------------------------------');
		$this->assertEquals('a--------------------------------------------------------------', $result);
		$result = Validate::validateLocalHostname('-hostname');
		$this->assertFalse($result);
		$result = Validate::validateLocalHostname('a-----------------------------------------------------------------');
		$this->assertFalse($result);
	}

	public function testValidateEmail()
	{
		$result = Validate::validateEmail('team@froxlor.org');
		$this->assertEquals('team@froxlor.org', $result);
		$result = Validate::validateEmail('team.froxlor.org');
		$this->assertFalse($result);
	}

	public function testValidateUsername()
	{
		$result = Validate::validateUsername('web123sql2');
		$this->assertTrue($result);
		$mysql_max = \Froxlor\Database\Database::getSqlUsernameLength() - strlen(\Froxlor\Settings::Get('customer.mysqlprefix'));
		$result = Validate::validateUsername('web123sql2', true, $mysql_max);
		$this->assertTrue($result);
		// too long
		$result = Validate::validateUsername('myperfectsuperduperwebuserwhosnameisenormouslylongandprettyandshouldinnowaybeaccepted123sql2', true, $mysql_max);
		$this->assertFalse($result);
		// not unix-conform
		$result = Validate::validateUsername('web123-sql2', true, $mysql_max);
		$this->assertFalse($result);
		// non-unix-conform
		$result = Validate::validateUsername('web123-sql2', false, $mysql_max);
		$this->assertTrue($result);
		$result = Validate::validateUsername('web123--sql2', false, $mysql_max);
		$this->assertFalse($result);
		$result = Validate::validateUsername('-web123sql2', false, $mysql_max);
		$this->assertFalse($result);
		$result = Validate::validateUsername('web123sql2-', false, $mysql_max);
		$this->assertFalse($result);
	}

	public function testValidateSqlInterval()
	{
		$result = Validate::validateSqlInterval('60 HOUR');
		$this->assertTrue($result);
		$result = Validate::validateSqlInterval('2 MONTH');
		$this->assertTrue($result);
		$result = Validate::validateSqlInterval();
		$this->assertFalse($result);
		$result = Validate::validateSqlInterval('2 QUARTER');
		$this->assertFalse($result);
		$result = Validate::validateSqlInterval('1DAY');
		$this->assertFalse($result);
	}
}
