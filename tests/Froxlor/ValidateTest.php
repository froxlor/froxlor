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

	/**
	 * regression test: preg_match('/[0-9]+/', ...) only requires a digit to appear
	 * somewhere in the first part, not that the whole part is numeric, so a value like
	 * "abc123 DAY" or "1;DROP DAY" incorrectly passed. The check must be anchored.
	 */
	public function testValidateSqlIntervalRejectsNonNumericPrefix()
	{
		$result = Validate::validateSqlInterval('abc123 DAY');
		$this->assertFalse($result);
		$result = Validate::validateSqlInterval('1;DROP DAY');
		$this->assertFalse($result);
		$result = Validate::validateSqlInterval('1abc DAY');
		$this->assertFalse($result);
	}

	/**
	 * regression test: the strlen($ip_cidr[1]) <= 3 guard made the CIDR-suffix range
	 * check a no-op for any suffix longer than 3 characters, so a garbage value like
	 * "/12345" slipped through unvalidated instead of being rejected.
	 */
	public function testValidateIpCidrRejectsOutOfRangeSuffix()
	{
		$result = Validate::validate_ip2("1.2.3.4/12345", true, 'invalidip', false, false, true, false, true);
		$this->assertFalse($result);
		$result = Validate::validate_ip2("1.2.3.4/999", true, 'invalidip', false, false, true, false, true);
		$this->assertFalse($result);
		$result = Validate::validate_ip2("1.2.3.4/33", true, 'invalidip', false, false, true, false, true);
		$this->assertFalse($result);
		// legitimate suffixes must still validate
		$result = Validate::validate_ip2("1.2.3.4/32", true, 'invalidip', false, false, true, false, true);
		$this->assertEquals("1.2.3.4/32", $result);
	}

	public function testValidateBase64Image()
	{
		// 1x1 red PNG
		$png = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAADElEQVQImWP4z8AAAAMBAQCc479ZAAAAAElFTkSuQmCC';
		$result = Validate::validateBase64Image($png);
		$this->assertNotFalse($result);

		$result = Validate::validateBase64Image(base64_encode('this is not an image'));
		$this->assertFalse($result);

		$result = Validate::validateBase64Image('');
		$this->assertFalse($result);
	}

	public function testValidateDnsLoc()
	{
		$result = Validate::validateDnsLoc('52 22 23.000 N 4 53 32.000 E -2.00m 0.00m 10000.00m 10.00m');
		$this->assertNotFalse($result);
		// latitude degrees out of range
		$result = Validate::validateDnsLoc('92 22 23.000 N 4 53 32.000 E -2.00m');
		$this->assertFalse($result);
		// malformed input
		$result = Validate::validateDnsLoc('not a loc record');
		$this->assertFalse($result);
	}

	public function testValidateDnsRp()
	{
		$result = Validate::validateDnsRp('admin.froxlor.org. text.froxlor.org.');
		$this->assertEquals('admin.froxlor.org. text.froxlor.org.', $result);
		$result = Validate::validateDnsRp('admin.froxlor.org.');
		$this->assertFalse($result);
		$result = Validate::validateDnsRp('not_a_domain text.froxlor.org.');
		$this->assertFalse($result);
	}

	public function testValidateDnsSshfp()
	{
		$sha1 = str_repeat('a', 40);
		$sha256 = str_repeat('a', 64);
		$result = Validate::validateDnsSshfp("1 1 $sha1");
		$this->assertEquals("1 1 $sha1", $result);
		$result = Validate::validateDnsSshfp("4 2 $sha256");
		$this->assertEquals("4 2 $sha256", $result);
		// invalid algorithm
		$result = Validate::validateDnsSshfp("99 1 $sha1");
		$this->assertFalse($result);
		// wrong fingerprint length for type
		$result = Validate::validateDnsSshfp("1 1 $sha256");
		$this->assertFalse($result);
		// non-hex fingerprint
		$result = Validate::validateDnsSshfp("1 1 " . str_repeat('z', 40));
		$this->assertFalse($result);
	}

	public function testValidateDnsTlsa()
	{
		$sha256 = str_repeat('a', 64);
		$sha512 = str_repeat('a', 128);
		$result = Validate::validateDnsTlsa("3 1 1 $sha256");
		$this->assertEquals("3 1 1 $sha256", $result);
		$result = Validate::validateDnsTlsa("3 1 2 $sha512");
		$this->assertEquals("3 1 2 $sha512", $result);
		// invalid usage
		$result = Validate::validateDnsTlsa("9 1 1 $sha256");
		$this->assertFalse($result);
		// wrong data length for matching type
		$result = Validate::validateDnsTlsa("3 1 1 " . str_repeat('a', 10));
		$this->assertFalse($result);
	}

	public function testValidateDnsNaptr()
	{
		$result = Validate::validateDnsNaptr('100 10 "U" "E2U+sip" "!^.*$!sip:info@example.com!" .');
		$this->assertTrue($result);
		// order/preference out of range
		$result = Validate::validateDnsNaptr('999999 10 "U" "E2U+sip" "!^.*$!sip:info@example.com!" .');
		$this->assertFalse($result);
		// malformed (missing quotes)
		$result = Validate::validateDnsNaptr('100 10 U E2U+sip regexp .');
		$this->assertFalse($result);
	}
}
