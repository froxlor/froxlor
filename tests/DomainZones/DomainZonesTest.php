<?php
use PHPUnit\Framework\TestCase;

use Froxlor\Settings;
use Froxlor\Api\Commands\Admins;
use Froxlor\Api\Commands\Customers;
use Froxlor\Api\Commands\DomainZones;
use Froxlor\Api\Commands\Domains;
use Froxlor\Api\Commands\SubDomains;

/**
 *
 * @covers \Froxlor\Api\ApiCommand
 * @covers \Froxlor\Api\ApiParameter
 * @covers \Froxlor\Api\Commands\SubDomains
 * @covers \Froxlor\Api\Commands\DomainZones
 */
class DomainZonesTest extends TestCase
{

	public function testCustomerDomainZonesGet()
	{
		global $admin_userdata;

		Settings::Set('system.dnsenabled', 1, true);
		Settings::Set('system.mxservers', 'mx.hostname.tld', true);

		// get customer
		$json_result = Customers::getLocal($admin_userdata, array(
			'loginname' => 'test1'
		))->get();
		$customer_userdata = json_decode($json_result, true)['data'];

		$data = [
			'domainname' => 'test2.local'
		];
		$json_result = DomainZones::getLocal($customer_userdata, $data)->get();
		$result = json_decode($json_result, true)['data'];
		$this->assertTrue(count($result) > 1);
		$this->assertEquals('$ORIGIN test2.local.', $result[1]);
		$resstr = preg_replace('/\s+/', '', $result[count($result)-2]);
		$against = preg_replace('/\s+/', '', '@ 604800  IN      MX      10      mx.hostname.tld.');
		$this->assertEquals($against, $resstr);
	}

	/**
	 *
	 * @depends testCustomerDomainZonesGet
	 */
	public function testCustomerDomainZonesGetNoSubdomains()
	{
		global $admin_userdata;

		// get customer
		$json_result = Customers::getLocal($admin_userdata, array(
			'loginname' => 'test1'
		))->get();
		$customer_userdata = json_decode($json_result, true)['data'];

		$data = [
			'domainname' => 'mysub2.test2.local'
		];
		$this->expectExceptionCode(406);
		$this->expectExceptionMessage("DNS zones can only be generated for the main domain, not for subdomains");
		DomainZones::getLocal($customer_userdata, $data)->get();
	}

	/**
	 *
	 * @depends testCustomerDomainZonesGet
	 */
	public function testCustomerDomainZonesGetWithDMARC()
	{
		global $admin_userdata;

		Settings::Set('dmarc.use_dmarc', 1, true);

		// get customer
		$json_result = Customers::getLocal($admin_userdata, array(
			'loginname' => 'test1'
		))->get();
		$customer_userdata = json_decode($json_result, true)['data'];

		$data = [
			'domainname' => 'test2.local'
		];
		$json_result = DomainZones::getLocal($customer_userdata, $data)->get();
		$result = json_decode($json_result, true)['data'];
		$this->assertTrue(count($result) > 1);
		$foundCnt = 0;
		$foundStr = '';
		foreach ($result as $entry) {
			if (substr($entry, 0, 7) == '_dmarc	') {
				$foundCnt++;
				$foundStr = $entry;
			}
		}
		$this->assertEquals(1, $foundCnt);
		$resstr = preg_replace('/\s+/', '', $foundStr);
		$against = preg_replace('/\s+/', '', '_dmarc	604800	IN	TXT	v=DMARC1;p=none;');
		$this->assertEquals($against, $resstr);
	}

	/**
	 *
	 * @depends testCustomerDomainZonesGetWithDMARC
	 */
	public function testCustomerDomainZonesGetWithDMARCSubdomain()
	{
		global $admin_userdata;

		// enable isemaildomain for subdomain
		$json_result = Admins::getLocal($admin_userdata, array(
			'loginname' => 'reseller'
		))->get();
		$reseller_userdata = json_decode($json_result, true)['data'];
		$reseller_userdata['adminsession'] = 1;
		$data = [
			'domainname' => 'mysub2.test2.local',
			'isemaildomain' => 1,
			'customerid' => 1
		];
		$json_result = SubDomains::getLocal($reseller_userdata, $data)->update();

		// get customer
		$json_result = Customers::getLocal($admin_userdata, array(
			'loginname' => 'test1'
		))->get();
		$customer_userdata = json_decode($json_result, true)['data'];

		$data = [
			'domainname' => 'test2.local'
		];
		$json_result = DomainZones::getLocal($customer_userdata, $data)->get();
		$result = json_decode($json_result, true)['data'];
		$foundCnt = 0;
		$foundStr = '';
		$this->assertTrue(count($result) > 1);
		foreach ($result as $entry) {
			if (substr($entry, 0, 14) == '_dmarc.mysub2	') {
				$foundCnt++;
				$foundStr = $entry;
			}
		}
		$this->assertEquals(1, $foundCnt);
		$resstr = preg_replace('/\s+/', '', $foundStr);
		$against = preg_replace('/\s+/', '', '_dmarc.mysub2	604800	IN	TXT	v=DMARC1;p=none;');
		$this->assertEquals($against, $resstr);
	}

	public function testAdminDomainZonesUpdate()
	{
		global $admin_userdata;
		$this->expectExceptionCode(303);
		DomainZones::getLocal($admin_userdata)->update();
	}

	/**
	 *
	 * @depends testCustomerDomainZonesGet
	 */
	public function testCustomerDomainZonesAddA()
	{
		global $admin_userdata;

		// get customer
		$json_result = Customers::getLocal($admin_userdata, array(
			'loginname' => 'test1'
		))->get();
		$customer_userdata = json_decode($json_result, true)['data'];

		$data = [
			'domainname' => 'test2.local',
			'record' => 'www2',
			'type' => 'A',
			'content' => '127.0.0.1'
		];
		$json_result = DomainZones::getLocal($customer_userdata, $data)->add();
		$result = json_decode($json_result, true)['data'];
		$this->assertTrue(count($result) > 1);
		$found = false;
		foreach ($result as $entry) {
			if (substr($entry, 0, 4) == 'www2') {
				$found = true;
				break;
			}
		}
		$this->assertTrue($found);
		$this->assertEquals('www2	18000	IN	A	127.0.0.1', $entry);
	}

	/**
	 *
	 * @depends testCustomerDomainZonesAddA
	 */
	public function testAdminDomainZonesListing()
	{
		global $admin_userdata;

		$data = [
			'domainname' => 'test2.local',
			'record' => 'www2',
			'type' => 'A',
			'content' => '127.0.0.1'
		];
		$json_result = DomainZones::getLocal($admin_userdata, $data)->listing();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals(1, $result['count']);
		$this->assertEquals('www2', $result['list'][0]['record']);

		$json_result = DomainZones::getLocal($admin_userdata, $data)->listingCount();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals(1, $result);
	}

	/**
	 *
	 * @depends testCustomerDomainZonesAddA
	 */
	public function testCustomerDomainZonesAddAInvalid()
	{
		global $admin_userdata;

		// get customer
		$json_result = Customers::getLocal($admin_userdata, array(
			'loginname' => 'test1'
		))->get();
		$customer_userdata = json_decode($json_result, true)['data'];

		$data = [
			'domainname' => 'test2.local',
			'record' => 'www3',
			'type' => 'A',
			'content' => 'a.b.c.d',
			'ttl' => - 1
		];
		$this->expectExceptionMessage("No valid IP address for A-record given");
		DomainZones::getLocal($customer_userdata, $data)->add();
	}

	/**
	 *
	 * @depends testCustomerDomainZonesAddA
	 */
	public function testCustomerDomainZonesAddADuplicate()
	{
		global $admin_userdata;

		// get customer
		$json_result = Customers::getLocal($admin_userdata, array(
			'loginname' => 'test1'
		))->get();
		$customer_userdata = json_decode($json_result, true)['data'];

		$data = [
			'domainname' => 'test2.local',
			'record' => 'www2',
			'type' => 'A',
			'content' => '127.0.0.1',
			'ttl' => - 1
		];
		$this->expectExceptionMessage("Record already exists");
		DomainZones::getLocal($customer_userdata, $data)->add();
	}

	/**
	 *
	 * @depends testCustomerDomainZonesGet
	 */
	public function testCustomerDomainZonesAddAAAA()
	{
		global $admin_userdata;

		// get customer
		$json_result = Customers::getLocal($admin_userdata, array(
			'loginname' => 'test1'
		))->get();
		$customer_userdata = json_decode($json_result, true)['data'];

		$data = [
			'domainname' => 'test2.local',
			'record' => 'www3',
			'type' => 'AAAA',
			'content' => '::1'
		];
		$json_result = DomainZones::getLocal($customer_userdata, $data)->add();
		$result = json_decode($json_result, true)['data'];
		$this->assertTrue(count($result) > 1);
		$found = false;
		foreach ($result as $entry) {
			if (substr($entry, 0, 4) == 'www3') {
				$found = true;
				break;
			}
		}
		$this->assertTrue($found);
		$this->assertEquals('www3	18000	IN	AAAA	::1', $entry);
	}

	/**
	 *
	 * @depends testCustomerDomainZonesAddA
	 */
	public function testCustomerDomainZonesAddAAAAInvalid()
	{
		global $admin_userdata;

		// get customer
		$json_result = Customers::getLocal($admin_userdata, array(
			'loginname' => 'test1'
		))->get();
		$customer_userdata = json_decode($json_result, true)['data'];

		$data = [
			'domainname' => 'test2.local',
			'record' => 'www4',
			'type' => 'AAAA',
			'content' => 'z:z123.123',
			'ttl' => - 1
		];
		$this->expectExceptionMessage("No valid IP address for AAAA-record given");
		DomainZones::getLocal($customer_userdata, $data)->add();
	}

	public function testAdminDomainZonesAddMX()
	{
		global $admin_userdata;

		$data = [
			'domainname' => 'test2.local',
			'record' => '',
			'type' => 'MX',
			'prio' => 10,
			'content' => 'mail.example.com.'
		];
		$json_result = DomainZones::getLocal($admin_userdata, $data)->add();
		$result = json_decode($json_result, true)['data'];
		$this->assertTrue(count($result) > 1);
		$found = false;
		foreach ($result as $entry) {
			if (substr($entry, strlen('mail.example.com.') * - 1) == 'mail.example.com.') {
				$found = true;
				break;
			}
		}
		$this->assertTrue($found);
		$this->assertEquals('@	18000	IN	MX	10	mail.example.com.', $entry);
	}

	/**
	 *
	 * @depends testAdminDomainZonesAddMX
	 */
	public function testAdminDomainZonesAddMXNoPrio()
	{
		global $admin_userdata;

		$data = [
			'domainname' => 'test2.local',
			'record' => '',
			'type' => 'MX',
			'content' => 'mail.example.com.'
		];
		$this->expectExceptionMessage("Invalid MX priority given");
		DomainZones::getLocal($admin_userdata, $data)->add();
	}

	/**
	 *
	 * @depends testAdminDomainZonesAddMX
	 */
	public function testAdminDomainZonesAddMXInvalid()
	{
		global $admin_userdata;

		$data = [
			'domainname' => 'test2.local',
			'record' => '',
			'type' => 'MX',
			'prio' => 20,
			'content' => 'localhost'
		];
		$this->expectExceptionMessage("The MX content value must be a valid domain-name");
		DomainZones::getLocal($admin_userdata, $data)->add();
	}

	public function testAdminDomainZonesAddCAAIssue()
	{
		global $admin_userdata;

		$content = '0 issue "letsencrypt.org"';
		$data = [
			'domainname' => 'test2.local',
			'record' => '@',
			'type' => 'CAA',
			'content' => $content
		];
		$json_result = DomainZones::getLocal($admin_userdata, $data)->add();
		$result = json_decode($json_result, true)['data'];
		$this->assertTrue(count($result) > 1);
		$found = false;
		foreach ($result as $entry) {
			if (substr($entry, - strlen($content)) == $content) {
				$found = true;
				break;
			}
		}
		$this->assertTrue($found);
		$this->assertEquals('@	18000	IN	CAA	0 issue "letsencrypt.org"', $entry);
	}

	public function testAdminDomainZonesAddCAAIssueWithParameters()
	{
		global $admin_userdata;

		$content = '0 issue "letsencrypt.org; account=230123"';
		$data = [
			'domainname' => 'test2.local',
			'record' => '@',
			'type' => 'CAA',
			'content' => $content
		];
		$json_result = DomainZones::getLocal($admin_userdata, $data)->add();
		$result = json_decode($json_result, true)['data'];
		$this->assertTrue(count($result) > 1);
		$found = false;
		foreach ($result as $entry) {
			if (substr($entry, strlen($content) * - 1) == $content) {
				$found = true;
				break;
			}
		}
		$this->assertTrue($found);
		$this->assertEquals('@	18000	IN	CAA	' . $content, $entry);
	}

	public function testAdminDomainZonesAddCAAIssueWithTwoParameters()
	{
		global $admin_userdata;

		$content = '0 issue "letsencrypt.org; account=230123 policy=ev"';
		$data = [
			'domainname' => 'test2.local',
			'record' => '@',
			'type' => 'CAA',
			'content' => $content
		];
		$json_result = DomainZones::getLocal($admin_userdata, $data)->add();
		$result = json_decode($json_result, true)['data'];
		$this->assertTrue(count($result) > 1);
		$found = false;
		foreach ($result as $entry) {
			if (substr($entry, strlen($content) * - 1) == $content) {
				$found = true;
				break;
			}
		}
		$this->assertTrue($found);
		$this->assertEquals('@	18000	IN	CAA	' . $content, $entry);
	}

	public function testAdminDomainZonesAddCAAInvalidIssueValue()
	{
		global $admin_userdata;

		$content = '0 issue ""letsencrypt.org"';
		$data = [
			'domainname' => 'test2.local',
			'record' => '@',
			'type' => 'CAA',
			'content' => $content
		];
		$this->expectExceptionMessage("DNS content invalid");
		DomainZones::getLocal($admin_userdata, $data)->add();
	}

	public function testAdminDomainZonesAddCAAInvalidIssueDomain()
	{
		global $admin_userdata;

		$content = '0 issue "no-valid-domain"';
		$data = [
			'domainname' => 'test2.local',
			'record' => '@',
			'type' => 'CAA',
			'content' => $content
		];
		$this->expectExceptionMessage("DNS content invalid");
		DomainZones::getLocal($admin_userdata, $data)->add();
	}

	public function testAdminDomainZonesAddCAAInvalidIssueTld()
	{
		global $admin_userdata;

		$content = '0 issue "no-valid-domai.n"';
		$data = [
			'domainname' => 'test2.local',
			'record' => '@',
			'type' => 'CAA',
			'content' => $content
		];
		$this->expectExceptionMessage("DNS content invalid");
		DomainZones::getLocal($admin_userdata, $data)->add();
	}

	public function testAdminDomainZonesAddCAAIssueWild()
	{
		global $admin_userdata;

		$content = '0 issuewild "letsencrypt.org"';
		$data = [
			'domainname' => 'test2.local',
			'record' => '@',
			'type' => 'CAA',
			'content' => $content
		];
		$json_result = DomainZones::getLocal($admin_userdata, $data)->add();
		$result = json_decode($json_result, true)['data'];
		$this->assertTrue(count($result) > 1);
		$found = false;
		foreach ($result as $entry) {
			if (substr($entry, strlen($content) * - 1) == $content) {
				$found = true;
				break;
			}
		}
		$this->assertTrue($found);
		$this->assertEquals('@	18000	IN	CAA	' . $content, $entry);
	}

	public function testAdminDomainZonesAddCAAIssueWildWithParameters()
	{
		global $admin_userdata;

		$content = '0 issuewild "letsencrypt.org; account=230123"';
		$data = [
			'domainname' => 'test2.local',
			'record' => '@',
			'type' => 'CAA',
			'content' => $content
		];
		$json_result = DomainZones::getLocal($admin_userdata, $data)->add();
		$result = json_decode($json_result, true)['data'];
		$this->assertTrue(count($result) > 1);
		$found = false;
		foreach ($result as $entry) {
			if (substr($entry, strlen($content) * - 1) == $content) {
				$found = true;
				break;
			}
		}
		$this->assertTrue($found);
		$this->assertEquals('@	18000	IN	CAA	' . $content, $entry);
	}

	public function testAdminDomainZonesAddCAAIssueWildWithTwoParameters()
	{
		global $admin_userdata;

		$content = '0 issuewild "letsencrypt.org; account=230123 policy=ev"';
		$data = [
			'domainname' => 'test2.local',
			'record' => '@',
			'type' => 'CAA',
			'content' => $content
		];
		$json_result = DomainZones::getLocal($admin_userdata, $data)->add();
		$result = json_decode($json_result, true)['data'];
		$this->assertTrue(count($result) > 1);
		$found = false;
		foreach ($result as $entry) {
			if (substr($entry, strlen($content) * - 1) == $content) {
				$found = true;
				break;
			}
		}
		$this->assertTrue($found);
		$this->assertEquals('@	18000	IN	CAA	' . $content, $entry);
	}

	public function testAdminDomainZonesAddCAAInvalidIssueWildValue()
	{
		global $admin_userdata;

		$content = '0 issuewild ""letsencrypt.org"';
		$data = [
			'domainname' => 'test2.local',
			'record' => '@',
			'type' => 'CAA',
			'content' => $content
		];
		$this->expectExceptionMessage("DNS content invalid");
		DomainZones::getLocal($admin_userdata, $data)->add();
	}

	public function testAdminDomainZonesAddCAAInvalidIssueWildDomain()
	{
		global $admin_userdata;

		$content = '0 issuewild "no-valid-domain"';
		$data = [
			'domainname' => 'test2.local',
			'record' => '@',
			'type' => 'CAA',
			'content' => $content
		];
		$this->expectExceptionMessage("DNS content invalid");
		DomainZones::getLocal($admin_userdata, $data)->add();
	}

	public function testAdminDomainZonesAddCAAInvalidIssueWildTld()
	{
		global $admin_userdata;

		$content = '0 issuewild "no-valid-domai.n"';
		$data = [
			'domainname' => 'test2.local',
			'record' => '@',
			'type' => 'CAA',
			'content' => $content
		];
		$this->expectExceptionMessage("DNS content invalid");
		DomainZones::getLocal($admin_userdata, $data)->add();
	}

	public function testAdminDomainZonesAddCAAIodefMail()
	{
		global $admin_userdata;

		$content = '0 iodef "mailto:security@example.com"';
		$data = [
			'domainname' => 'test2.local',
			'record' => '@',
			'type' => 'CAA',
			'content' => $content
		];
		$json_result = DomainZones::getLocal($admin_userdata, $data)->add();
		$result = json_decode($json_result, true)['data'];
		$this->assertTrue(count($result) > 1);
		$found = false;
		foreach ($result as $entry) {
			if (substr($entry, strlen($content) * - 1) == $content) {
				$found = true;
				break;
			}
		}
		$this->assertTrue($found);
		$this->assertEquals('@	18000	IN	CAA	' . $content, $entry);
	}

	public function testAdminDomainZonesAddCAAIodefMailInvalid()
	{
		global $admin_userdata;

		$content = '0 iodef "mailtosecurity@example.com"';
		$data = [
			'domainname' => 'test2.local',
			'record' => '@',
			'type' => 'CAA',
			'content' => $content
		];
		$this->expectExceptionMessage("DNS content invalid");
		DomainZones::getLocal($admin_userdata, $data)->add();
	}

	public function testAdminDomainZonesAddCAAIodefHttp()
	{
		global $admin_userdata;

		$content = '0 iodef "http://iodef.example.com/"';
		$data = [
			'domainname' => 'test2.local',
			'record' => '@',
			'type' => 'CAA',
			'content' => $content
		];
		$json_result = DomainZones::getLocal($admin_userdata, $data)->add();
		$result = json_decode($json_result, true)['data'];
		$this->assertTrue(count($result) > 1);
		$found = false;
		foreach ($result as $entry) {
			if (substr($entry, strlen($content) * - 1) == $content) {
				$found = true;
				break;
			}
		}
		$this->assertTrue($found);
		$this->assertEquals('@	18000	IN	CAA	' . $content, $entry);
	}

	public function testAdminDomainZonesAddCAAIodefHttpInvalid()
	{
		global $admin_userdata;

		$content = '0 iodef "http:/iodef.example.com/"';
		$data = [
			'domainname' => 'test2.local',
			'record' => '@',
			'type' => 'CAA',
			'content' => $content
		];
		$this->expectExceptionMessage("DNS content invalid");
		DomainZones::getLocal($admin_userdata, $data)->add();
	}

	public function testAdminDomainZonesAddCAAIodefHttps()
	{
		global $admin_userdata;

		$content = '0 iodef "https://iodef.example.com/"';
		$data = [
			'domainname' => 'test2.local',
			'record' => '@',
			'type' => 'CAA',
			'content' => $content
		];
		$json_result = DomainZones::getLocal($admin_userdata, $data)->add();
		$result = json_decode($json_result, true)['data'];
		$this->assertTrue(count($result) > 1);
		$found = false;
		foreach ($result as $entry) {
			if (substr($entry, strlen($content) * - 1) == $content) {
				$found = true;
				break;
			}
		}
		$this->assertTrue($found);
		$this->assertEquals('@	18000	IN	CAA	' . $content, $entry);
	}

	public function testAdminDomainZonesAddCAAIodefHttpsInvalid()
	{
		global $admin_userdata;

		$content = '0 iodef "https:/iodef.example.com/"';
		$data = [
			'domainname' => 'test2.local',
			'record' => '@',
			'type' => 'CAA',
			'content' => $content
		];
		$this->expectExceptionMessage("DNS content invalid");
		DomainZones::getLocal($admin_userdata, $data)->add();
	}

	public function testAdminDomainZonesAddCname()
	{
		global $admin_userdata;

		$data = [
			'domainname' => 'test2.local',
			'record' => 'db',
			'type' => 'CNAME',
			'content' => 'db.example.com.'
		];
		$json_result = DomainZones::getLocal($admin_userdata, $data)->add();
		$result = json_decode($json_result, true)['data'];
		$this->assertTrue(count($result) > 1);
		$found = false;
		foreach ($result as $entry) {
			if (substr($entry, strlen('db.example.com.') * - 1) == 'db.example.com.') {
				$found = true;
				break;
			}
		}
		$this->assertTrue($found);
		$this->assertEquals('db	18000	IN	CNAME	db.example.com.', $entry);
	}

	public function testAdminDomainZonesAddCnameLocal()
	{
		global $admin_userdata;

		$data = [
			'domainname' => 'test2.local',
			'record' => 'db2',
			'type' => 'CNAME',
			'content' => 'db3'
		];
		$json_result = DomainZones::getLocal($admin_userdata, $data)->add();
		$result = json_decode($json_result, true)['data'];
		$this->assertTrue(count($result) > 1);
		$found = false;
		foreach ($result as $entry) {
			if (substr($entry, strlen('db3.test2.local.') * - 1) == 'db3.test2.local.') {
				$found = true;
				break;
			}
		}
		$this->assertTrue($found);
		$this->assertEquals('db2	18000	IN	CNAME	db3.test2.local.', $entry);
	}

	/**
	 *
	 * @depends testAdminDomainZonesAddCname
	 */
	public function testAdminDomainZonesAddCnameInvalid()
	{
		global $admin_userdata;

		$data = [
			'domainname' => 'test2.local',
			'record' => '',
			'type' => 'CNAME',
			'content' => 'localhost.'
		];
		$this->expectExceptionMessage("Invalid domain-name for CNAME record");
		DomainZones::getLocal($admin_userdata, $data)->add();
	}

	/**
	 *
	 * @depends testAdminDomainZonesAddCname
	 */
	public function testAdminDomainZonesAddCnameInvalidWwwAlias()
	{
		global $admin_userdata;

		// set domain to www-alias
		$data = [
			'domainname' => 'test2.local',
			'selectserveralias' => '1'
		];
		Domains::getLocal($admin_userdata, $data)->update();

		$data = [
			'domainname' => 'test2.local',
			'record' => 'www',
			'type' => 'CNAME',
			'content' => 'testing.local'
		];
		$this->expectExceptionMessage('Cannot set CNAME record for "www" as domain is set to generate a www-alias. Please change settings to either "No alias" or "Wildcard alias"');
		DomainZones::getLocal($admin_userdata, $data)->add();
	}

	/**
	 *
	 * @depends testAdminDomainZonesAddCname
	 */
	public function testAdminDomainZonesAddForExistingCname()
	{
		global $admin_userdata;

		// set domain to www-alias
		$data = [
			'domainname' => 'test2.local',
			'selectserveralias' => '1'
		];
		Domains::getLocal($admin_userdata, $data)->update();

		foreach ([
			'A' => '127.0.0.1',
			'AAAA' => '::1',
			'MX' => 'mail.example.com.',
			'NS' => 'ns.example.com.'
		] as $type => $val) {
			$data = [
				'domainname' => 'test2.local',
				'record' => 'db',
				'type' => $type,
				'content' => $val
			];
			$this->expectExceptionMessage('There already exists a CNAME record with the same record-name. It can not be used for another type.');
			DomainZones::getLocal($admin_userdata, $data)->add();
		}
	}

	/**
	 *
	 * @depends testAdminDomainZonesAddCname
	 */
	public function testAdminDomainZonesAddCnameUnderscore()
	{
		global $admin_userdata;

		$data = [
			'domainname' => 'test2.local',
			'record' => 'dkimtest',
			'type' => 'CNAME',
			'content' => 'test._domainkey.myhost.tld.'
		];
		$json_result = DomainZones::getLocal($admin_userdata, $data)->add();
		$result = json_decode($json_result, true)['data'];
		$this->assertTrue(count($result) > 1);
		$found = false;
		foreach ($result as $entry) {
			if (substr($entry, strlen('test._domainkey.myhost.tld.') * - 1) == 'test._domainkey.myhost.tld.') {
				$found = true;
				break;
			}
		}
		$this->assertTrue($found);
		$this->assertEquals('dkimtest	18000	IN	CNAME	test._domainkey.myhost.tld.', $entry);
	}

	public function testAdminDomainZonesAddNS()
	{
		global $admin_userdata;

		$data = [
			'domainname' => 'test2.local',
			'record' => '',
			'type' => 'NS',
			'content' => 'ns.example.com.'
		];
		$json_result = DomainZones::getLocal($admin_userdata, $data)->add();
		$result = json_decode($json_result, true)['data'];
		$this->assertTrue(count($result) > 1);
		$found = false;
		foreach ($result as $entry) {
			if (substr($entry, strlen('ns.example.com.') * - 1) == 'ns.example.com.') {
				$found = true;
				break;
			}
		}
		$this->assertTrue($found);
		$this->assertEquals('@	18000	IN	NS	ns.example.com.', $entry);
	}

	public function testAdminDomainZonesAddNsInvalid()
	{
		global $admin_userdata;

		$data = [
			'domainname' => 'test2.local',
			'record' => '',
			'type' => 'NS',
			'content' => 'localhost.'
		];
		$this->expectExceptionMessage("Invalid domain-name for NS record");
		DomainZones::getLocal($admin_userdata, $data)->add();
	}

	public function testAdminDomainZonesAddTXT()
	{
		global $admin_userdata;

		$data = [
			'domainname' => 'test2.local',
			'record' => '_test1',
			'type' => 'TXT',
			'content' => 'aw yeah'
		];
		$json_result = DomainZones::getLocal($admin_userdata, $data)->add();
		$result = json_decode($json_result, true)['data'];
		$this->assertTrue(count($result) > 1);
		$found = false;
		foreach ($result as $entry) {
			if (substr($entry, 0, 6) == '_test1') {
				$found = true;
				break;
			}
		}
		$this->assertTrue($found);
		$this->assertEquals('_test1	18000	IN	TXT	aw yeah', $entry);
	}

	/**
	 *
	 * @depends testCustomerDomainZonesGetWithDMARC
	 */
	public function testAdminDomainZonesAddTXTCustomDMARC()
	{
		global $admin_userdata;

		$data = [
			'domainname' => 'test2.local',
			'record' => '_dmarc',
			'type' => 'TXT',
			'content' => 'v=DMARC1;p=none;overwrite=TRUE'
		];
		$json_result = DomainZones::getLocal($admin_userdata, $data)->add();
		$result = json_decode($json_result, true)['data'];
		$this->assertTrue(count($result) > 1);
		$foundCnt = 0;
		$foundStr = '';
		foreach ($result as $entry) {
			if (substr($entry, 0, 7) == '_dmarc	') {
				$foundCnt++;
				$foundStr = $entry;
			}
		}
		$this->assertEquals(1, $foundCnt);
		$resstr = preg_replace('/\s+/', '', $foundStr);
		$against = preg_replace('/\s+/', '', '_dmarc	18000	IN	TXT	v=DMARC1;p=none;overwrite=TRUE');
		$this->assertEquals($against, $resstr);
	}

	/**
	 *
	 * @depends testCustomerDomainZonesGetWithDMARCSubdomain
	 */
	public function testAdminDomainZonesAddTXTCustomDMARCSubdomain()
	{
		global $admin_userdata;

		$data = [
			'domainname' => 'test2.local',
			'record' => '_dmarc.mysub2',
			'type' => 'TXT',
			'content' => 'v=DMARC1;p=none;overwrite=TRUE'
		];
		$json_result = DomainZones::getLocal($admin_userdata, $data)->add();
		$result = json_decode($json_result, true)['data'];
		$this->assertTrue(count($result) > 1);
		$foundCnt = 0;
		$foundStr = '';
		foreach ($result as $entry) {
			if (substr($entry, 0, 14) == '_dmarc.mysub2	') {
				$foundCnt++;
				$foundStr = $entry;
			}
		}
		$this->assertEquals(1, $foundCnt);
		$resstr = preg_replace('/\s+/', '', $foundStr);
		$against = preg_replace('/\s+/', '', '_dmarc.mysub2	18000	IN	TXT	v=DMARC1;p=none;overwrite=TRUE');
		$this->assertEquals($against, $resstr);
	}

	public function testAdminDomainZonesAddSRV()
	{
		global $admin_userdata;

		$data = [
			'domainname' => 'test2.local',
			'record' => '_test2',
			'type' => 'SRV',
			'prio' => 50,
			'content' => '2 1 srv.example.com.'
		];
		$json_result = DomainZones::getLocal($admin_userdata, $data)->add();
		$result = json_decode($json_result, true)['data'];
		$this->assertTrue(count($result) > 1);
		$found = false;
		foreach ($result as $entry) {
			if (substr($entry, 0, 6) == '_test2') {
				$found = true;
				break;
			}
		}
		$this->assertTrue($found);
		$this->assertEquals('_test2	18000	IN	SRV	50	2 1 srv.example.com.', $entry);
	}

	public function testAdminDomainZonesAddSrvInvalid()
	{
		global $admin_userdata;

		$data = [
			'domainname' => 'test2.local',
			'record' => '_test2',
			'type' => 'SRV',
			'prio' => 50,
			'content' => 'srv.example.com.'
		];
		$this->expectExceptionMessage("Invalid SRV content, must contain of fields weight, port and target, e.g.: 5 5060 sipserver.example.com.");
		DomainZones::getLocal($admin_userdata, $data)->add();
	}

	public function testCustomerDomainZonesDelete()
	{
		global $admin_userdata;

		// get customer
		$json_result = Customers::getLocal($admin_userdata, array(
			'loginname' => 'test1'
		))->get();
		$customer_userdata = json_decode($json_result, true)['data'];

		$data = [
			'domainname' => 'test2.local',
			'entry_id' => 1
		];
		$json_result = DomainZones::getLocal($customer_userdata, $data)->delete();
		$result = json_decode($json_result, true);
		$this->assertTrue($result['data']);
//		$this->assertEquals(200, http_response_code());
	}

	public function testCustomerDomainZonesDeleteUnmodified()
	{
		global $admin_userdata;

		// get customer
		$json_result = Customers::getLocal($admin_userdata, array(
			'loginname' => 'test1'
		))->get();
		$customer_userdata = json_decode($json_result, true)['data'];

		$data = [
			'domainname' => 'test2.local',
			'entry_id' => 1337
		];
		$json_result = DomainZones::getLocal($customer_userdata, $data)->delete();
		$result = json_decode($json_result, true);
		$this->assertTrue($result['data']);
		//$this->assertEquals(304, http_response_code());
	}
}
