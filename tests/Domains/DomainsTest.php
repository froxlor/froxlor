<?php
use PHPUnit\Framework\TestCase;

use Froxlor\Settings;
use Froxlor\Api\Commands\Admins;
use Froxlor\Api\Commands\Customers;
use Froxlor\Api\Commands\Domains;
use Froxlor\Api\Commands\SubDomains;
use Froxlor\Database\Database;

/**
 *
 * @covers \Froxlor\Api\ApiCommand
 * @covers \Froxlor\Api\ApiParameter
 * @covers \Froxlor\Api\Commands\Domains
 * @covers \Froxlor\Api\Commands\SubDomains
 */
class DomainsTest extends TestCase
{

	public function testAdminDomainsAdd()
	{
		global $admin_userdata;
		// get customer
		$json_result = Customers::getLocal($admin_userdata, array(
			'loginname' => 'test1'
		))->get();

		$customer_userdata = json_decode($json_result, true)['data'];
		$data = [
			'domain' => 'TEST.local',
			'customerid' => $customer_userdata['customerid'],
			'override_tls' => 1,
			'ssl_protocols' => array(
				'TLSv1.2',
				'TLSv1.3'
			),
			'description' => 'awesome domain'
		];
		$json_result = Domains::getLocal($admin_userdata, $data)->add();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals($customer_userdata['documentroot'] . 'test.local/', $result['documentroot']);
		$this->assertTrue(in_array('TLSv1.3', explode(",", $result['ssl_protocols'])));
		$this->assertEquals('0', $result['isemaildomain']);
		$this->assertEquals('awesome domain', $result['description']);
	}

	/**
	 *
	 * @depends testAdminDomainsAdd
	 */
	public function testAdminDomainsList()
	{
		global $admin_userdata;
		$json_result = Domains::getLocal($admin_userdata)->listing();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals(1, $result['count']);
		$this->assertEquals('test.local', $result['list'][0]['domain']);
		$this->assertEquals(2, count($result['list'][0]['ipsandports']));
		$this->assertEquals("82.149.225.56", $result['list'][0]['ipsandports'][1]['ip']);

		$json_result = Domains::getLocal($admin_userdata)->listingCount();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals(1, $result);

		$json_result = Domains::getLocal($admin_userdata, [
			'with_ips' => false
		])->listing();
		$result = json_decode($json_result, true)['data'];
		$this->assertEmpty($result['list'][0]['ipsandports']);
	}

	/**
	 *
	 * @depends testAdminDomainsAdd
	 */
	public function testResellerDomainsList()
	{
		global $admin_userdata;
		// get reseller
		$json_result = Admins::getLocal($admin_userdata, array(
			'loginname' => 'reseller'
		))->get();
		$reseller_userdata = json_decode($json_result, true)['data'];
		$reseller_userdata['adminsession'] = 1;
		$json_result = Domains::getLocal($reseller_userdata)->listing();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals(0, $result['count']);

		$json_result = Domains::getLocal($reseller_userdata)->listingCount();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals(0, $result);
	}

	public function testResellerDomainsAddWithCanEditPhpSettingsDefaultIp()
	{
		global $admin_userdata;
		// get reseller
		$json_result = Admins::getLocal($admin_userdata, array(
			'loginname' => 'reseller'
		))->get();
		$reseller_userdata = json_decode($json_result, true)['data'];
		$reseller_userdata['adminsession'] = 1;
		$reseller_userdata['caneditphpsettings'] = 1;
		$data = [
			'domain' => 'test2.local',
			'customerid' => 1,
			'isbinddomain' => 1
		];
		// the reseller is not allowed to use the default ip/port
		$this->expectExceptionMessage("The ip/port combination you have chosen doesn't exist.");
		Domains::getLocal($reseller_userdata, $data)->add();
	}

	public function testResellerDomainsAddWithCanEditPhpSettingsAllowedIp()
	{
		global $admin_userdata;
		// first, allow reseller access to ip #4
		Admins::getLocal($admin_userdata, array(
			'loginname' => 'reseller',
			'ipaddress' => 4
		))->update();
		// get reseller
		$json_result = Admins::getLocal($admin_userdata, array(
			'loginname' => 'reseller'
		))->get();
		$reseller_userdata = json_decode($json_result, true)['data'];
		$reseller_userdata['adminsession'] = 1;
		$data = [
			'domain' => 'test2.local',
			'customerid' => 1,
			'ipandport' => 4,
			'isemaildomain' => 1,
			'subcanemaildomain' => 2
		];
		$json_result = Domains::getLocal($reseller_userdata, $data)->add();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals('test2.local', $result['domain']);
		$this->assertEquals(2, $result['subcanemaildomain']);
	}

	public function testResellerDomainsAddWithAbsolutePathNoChangeServerSettings()
	{
		global $admin_userdata;
		// get reseller
		$json_result = Admins::getLocal($admin_userdata, array(
			'loginname' => 'reseller'
		))->get();
		$reseller_userdata = json_decode($json_result, true)['data'];
		$reseller_userdata['adminsession'] = 1;
		$data = [
			'domain' => 'test3.local',
			'customerid' => 1,
			'documentroot' => '/some/absolute/directory/the_reseller/cannot/set/',
			'ipandport' => 4
		];
		$this->expectExceptionMessage("The user does not have the permission to specify directories outside the customers home-directory. Please specify a relative path (no leading /).");
		$json_result = Domains::getLocal($reseller_userdata, $data)->add();
	}

	/**
	 *
	 * @depends testAdminDomainsAdd
	 */
	public function testResellerDomainsUpdate()
	{
		global $admin_userdata;
		// get reseller
		$json_result = Admins::getLocal($admin_userdata, array(
			'loginname' => 'reseller'
		))->get();
		$reseller_userdata = json_decode($json_result, true)['data'];
		$reseller_userdata['adminsession'] = 1;
		$data = [
			'domainname' => 'test2.local',
			'ssl_protocols' => 'TLSv1',
			'documentroot' => '/var/customers/webs/test1/sub/'
		];
		$json_result = Domains::getLocal($reseller_userdata, $data)->update();
		$result = json_decode($json_result, true)['data'];
		$this->assertEmpty($result['ssl_protocols']);
		$this->assertEquals('test2.local', $result['domain']);
		$this->assertEquals('/var/customers/webs/test1/sub/', $result['documentroot']);
	}

	/**
	 *
	 * @depends testResellerDomainsUpdate
	 */
	public function testResellerDomainsUpdateAboslutePathNotAllowed()
	{
		global $admin_userdata;
		// get reseller
		$json_result = Admins::getLocal($admin_userdata, array(
			'loginname' => 'reseller'
		))->get();
		$reseller_userdata = json_decode($json_result, true)['data'];
		$reseller_userdata['adminsession'] = 1;
		$data = [
			'domainname' => 'test2.local',
			'documentroot' => '/some/other/dir'
		];
		$this->expectExceptionMessage("The user does not have the permission to specify directories outside the customers home-directory. Please specify a relative path (no leading /).");
		$json_result = Domains::getLocal($reseller_userdata, $data)->update();
	}

	public function testAdminDomainsAddSysHostname()
	{
		global $admin_userdata;
		$data = [
			'domain' => 'dev.froxlor.org',
			'customerid' => 1
		];
		$this->expectExceptionMessage('The server-hostname cannot be used as customer-domain.');
		Domains::getLocal($admin_userdata, $data)->add();
	}

	public function testAdminDomainsAddNoPunycode()
	{
		global $admin_userdata;
		$data = [
			'domain' => 'xn--asdasd.tld',
			'customerid' => 1
		];
		$this->expectExceptionMessage('You must not specify punycode (IDNA). The domain will automatically be converted');
		Domains::getLocal($admin_userdata, $data)->add();
	}

	public function testAdminDomainsAddInvalidDomain()
	{
		global $admin_userdata;
		$data = [
			'domain' => 'dom?*ain.tld',
			'customerid' => 1
		];
		$this->expectExceptionMessage("Wrong Input in Field 'Domain'");
		Domains::getLocal($admin_userdata, $data)->add();
	}

	/**
	 *
	 * @depends testAdminDomainsAdd
	 */
	public function testAdminDomainsUpdate()
	{
		global $admin_userdata;
		// get customer
		$json_result = Customers::getLocal($admin_userdata, array(
			'loginname' => 'test1'
		))->get();
		$customer_userdata = json_decode($json_result, true)['data'];
		$data = [
			'domainname' => 'test.local',
			'email_only' => 1,
			'override_tls' => 0,
			'documentroot' => 'web',
			'description' => 'changed desc'
		];
		$json_result = Domains::getLocal($admin_userdata, $data)->update();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals(1, $result['email_only']);
		$this->assertFalse(in_array('TLSv1.3', explode(",", $result['ssl_protocols'])));
		$this->assertEquals('test.local', $result['domain']);
		$this->assertEquals($customer_userdata['documentroot'] . 'web/', $result['documentroot']);
		$this->assertEquals('changed desc', $result['description']);
	}

	/**
	 *
	 * @depends testAdminDomainsAdd
	 */
	public function testAdminDomainsUpdateAbsolutePath()
	{
		global $admin_userdata;
		$data = [
			'domainname' => 'test.local',
			'documentroot' => '/web'
		];
		$json_result = Domains::getLocal($admin_userdata, $data)->update();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals('/web/', $result['documentroot']);
	}

	/**
	 *
	 * @depends testAdminDomainsAdd
	 */
	public function testAdminDomainsUpdateIssue756()
	{
		global $admin_userdata;
		$data = [
			'domainname' => 'test.local',
			'ssl_redirect' => 1
		];
		$json_result = Domains::getLocal($admin_userdata, $data)->update();
		$result = json_decode($json_result, true)['data'];

		// get ssl ip/port for domain which should still exist
		$sel_stmt = Database::prepare("
			SELECT COUNT(*) as numips
			FROM `" . TABLE_DOMAINTOIP . "` di
			LEFT JOIN `" . TABLE_PANEL_IPSANDPORTS . "` i ON i.id = di.id_ipandports
			LEFT JOIN `" . TABLE_PANEL_DOMAINS . "` d ON d.id = di.id_domain
			WHERE d.id = :did AND i.ssl = 1
		");
		$result_ips = Database::pexecute_first($sel_stmt, [
			'did' => $result['id']
		], true, true);
		$this->assertEquals(1, $result_ips['numips']);

		// test clearing
		$data = [
			'domainname' => 'test.local',
			'ssl_ipandport' => array()
		];
		$json_result = Domains::getLocal($admin_userdata, $data)->update();
		$result = json_decode($json_result, true)['data'];

		// get ssl ip/port for domain which should still exist
		$result_ips = Database::pexecute_first($sel_stmt, [
			'did' => $result['id']
		], true, true);
		$this->assertEquals(1, $result_ips['numips']);

		$data = [
			'domainname' => 'test.local',
			'remove_ssl_ipandport' => 1
		];
		$json_result = Domains::getLocal($admin_userdata, $data)->update();
		$result = json_decode($json_result, true)['data'];

		// get ssl ip/port for domain which should still exist
		$result_ips = Database::pexecute_first($sel_stmt, [
			'did' => $result['id']
		], true, true);
		$this->assertEquals(0, $result_ips['numips']);
	}

	/**
	 *
	 * @depends testAdminDomainsUpdate
	 */
	public function testAdminDomainsMoveButUnknownCustomer()
	{
		global $admin_userdata;
		// get customer
		$json_result = Customers::getLocal($admin_userdata, array(
			'loginname' => 'test1'
		))->get();
		$customer_userdata = json_decode($json_result, true)['data'];
		$data = [
			'domainname' => 'test.local',
			'customerid' => $customer_userdata['customerid'] + 1
		];
		Settings::Set('panel.allow_domain_change_customer', 1);
		$this->expectExceptionMessage("Customer with id #2 could not be found");
		Domains::getLocal($admin_userdata, $data)->update();
	}

	public function testAdminDomainsMove()
	{
		global $admin_userdata;
		// add new customer
		$data = [
			'new_loginname' => 'test3',
			'email' => 'test3@froxlor.org',
			'firstname' => 'Test',
			'name' => 'Testman',
			'customernumber' => 1339,
			'new_customer_password' => 'h0lYmo1y'
		];
		$json_result = Customers::getLocal($admin_userdata, $data)->add();
		$customer_userdata = json_decode($json_result, true)['data'];

		$data = [
			'domainname' => 'test.local',
			'customerid' => $customer_userdata['customerid']
		];
		$json_result = Domains::getLocal($admin_userdata, $data)->update();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals($customer_userdata['customerid'], $result['customerid']);
		$this->assertEquals($customer_userdata['documentroot'] . 'test.local/', $result['documentroot']);
	}

	/**
	 *
	 * @depends testAdminDomainsMove
	 */
	public function testAdminDomainsDuplicate()
	{
		global $admin_userdata;
		$data = [
			'domainname' => 'test.local',
			'domain' => 'test.duplicate.local',
			'description' => 'duplicated domain'
		];
		$json_result = Domains::getLocal($admin_userdata, $data)->duplicate();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals('/var/customers/webs/test3/test.duplicate.local/', $result['documentroot']);
		$this->assertEquals(1, $result['email_only']);
		$this->assertEquals('test.duplicate.local', $result['domain']);
		$this->assertEquals('duplicated domain', $result['description']);
	}

	/**
	 *
	 * @depends testAdminDomainsDuplicate
	 */
	public function testAdminDomainsDelete()
	{
		global $admin_userdata;
		$data = [
			'domainname' => 'test.local',
			'delete_mainsubdomains' => 1
		];
		$json_result = Domains::getLocal($admin_userdata, $data)->delete();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals('test.local', $result['domain']);

		// remove customer again
		$json_result = Customers::getLocal($admin_userdata, array(
			'loginname' => 'test3'
		))->delete();
	}

	public function testCustomerDomainsList()
	{
		global $admin_userdata;
		// get customer
		$json_result = Customers::getLocal($admin_userdata, array(
			'id' => 1
		))->get();
		$customer_userdata = json_decode($json_result, true)['data'];

		$this->expectExceptionCode(403);
		$this->expectExceptionMessage("Not allowed to execute given command.");
		$json_result = Domains::getLocal($customer_userdata)->listing();

		$this->expectExceptionCode(403);
		$this->expectExceptionMessage("Not allowed to execute given command.");
		$json_result = Domains::getLocal($customer_userdata)->listingCount();
	}

	public function testAdminIdnDomainsAdd()
	{
		global $admin_userdata;
		// get customer
		$json_result = Customers::getLocal($admin_userdata, array(
			'loginname' => 'test1'
		))->get();
		$customer_userdata = json_decode($json_result, true)['data'];
		$data = [
			'domain' => 'täst.local',
			'customerid' => $customer_userdata['customerid']
		];
		$json_result = Domains::getLocal($admin_userdata, $data)->add();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals($customer_userdata['documentroot'] . 'xn--tst-qla.local/', $result['documentroot']);
		$this->assertEquals('xn--tst-qla.local', $result['domain']);
		$this->assertEquals('täst.local', $result['domain_ace']);

		Domains::getLocal($admin_userdata, [
			'domainname' => 'täst.local'
		])->delete();
	}

	/**
	 *
	 * @refs https://github.com/Froxlor/Froxlor/issues/899
	 */
	public function testAdminIdn2DomainsAdd()
	{
		global $admin_userdata;
		// get customer
		$json_result = Customers::getLocal($admin_userdata, array(
			'loginname' => 'test1'
		))->get();
		$customer_userdata = json_decode($json_result, true)['data'];
		$data = [
			'domain' => 'उदाहरण.भारत',
			'customerid' => $customer_userdata['customerid']
		];
		$json_result = Domains::getLocal($admin_userdata, $data)->add();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals($customer_userdata['documentroot'] . 'xn--p1b6ci4b4b3a.xn--h2brj9c/', $result['documentroot']);
		$this->assertEquals('xn--p1b6ci4b4b3a.xn--h2brj9c', $result['domain']);
		$this->assertEquals('उदाहरण.भारत', $result['domain_ace']);

		Domains::getLocal($admin_userdata, [
			'domainname' => 'उदाहरण.भारत'
		])->delete();
	}

	public function testAdminDomainsAddDnsLetsEncryptFail()
	{
		global $admin_userdata;
		// get customer
		$json_result = Customers::getLocal($admin_userdata, array(
			'loginname' => 'test1'
		))->get();
		Settings::Set('system.le_domain_dnscheck', 1);
		$customer_userdata = json_decode($json_result, true)['data'];
		$data = [
			'domain' => 'no-dns.local',
			'customerid' => $customer_userdata['customerid'],
			'letsencrypt' => 1,
			'description' => 'no dns domain'
		];

		$this->expectExceptionCode(400);
		$this->expectExceptionMessage('The domains DNS does not include any of the chosen IP addresses. Let\'s Encrypt certificate generation not possible.');
		Domains::getLocal($admin_userdata, $data)->add();
	}

	/**
	 * regression test: Domains::get()/listing() and SubDomains::get()/listing() used
	 * to return the raw panel_domains row (wildcard `d`.* SELECT), which includes
	 * dkim_privkey - the domain's DKIM mail-signing private key. An admin/reseller
	 * with the delegated customers_see_all flag could pull another tenant's key this
	 * way. Response payloads must never include it, regardless of caller/command.
	 */
	public function testDomainsResponseHidesDkimPrivkey()
	{
		global $admin_userdata;
		// get customer
		$json_result = Customers::getLocal($admin_userdata, array(
			'loginname' => 'test1'
		))->get();
		$customer_userdata = json_decode($json_result, true)['data'];

		$data = [
			'domain' => 'dkimtest.local',
			'customerid' => $customer_userdata['customerid']
		];
		$json_result = Domains::getLocal($admin_userdata, $data)->add();
		$result = json_decode($json_result, true)['data'];
		$domain_id = $result['id'];

		// simulate a populated DKIM key as Rspamd::writeDkimConfigs() would store it
		$upd_stmt = Database::prepare("UPDATE `" . TABLE_PANEL_DOMAINS . "` SET `dkim` = '1', `dkim_privkey` = :privkey WHERE `id` = :id");
		Database::pexecute($upd_stmt, [
			'privkey' => "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----",
			'id' => $domain_id
		]);

		$json_result = Domains::getLocal($admin_userdata, [
			'id' => $domain_id
		])->get();
		$result = json_decode($json_result, true)['data'];
		$this->assertArrayNotHasKey('dkim_privkey', $result);

		$json_result = Domains::getLocal($admin_userdata)->listing();
		$result = json_decode($json_result, true)['data'];
		$found = false;
		foreach ($result['list'] as $row) {
			if ($row['id'] == $domain_id) {
				$found = true;
				$this->assertArrayNotHasKey('dkim_privkey', $row);
			}
		}
		$this->assertTrue($found);

		$json_result = SubDomains::getLocal($admin_userdata, [
			'id' => $domain_id
		])->get();
		$result = json_decode($json_result, true)['data'];
		$this->assertArrayNotHasKey('dkim_privkey', $result);

		$json_result = SubDomains::getLocal($admin_userdata)->listing();
		$result = json_decode($json_result, true)['data'];
		$found = false;
		foreach ($result['list'] as $row) {
			if ($row['id'] == $domain_id) {
				$found = true;
				$this->assertArrayNotHasKey('dkim_privkey', $row);
			}
		}
		$this->assertTrue($found);

		// cleanup
		Domains::getLocal($admin_userdata, [
			'id' => $domain_id
		])->delete();
	}
}
