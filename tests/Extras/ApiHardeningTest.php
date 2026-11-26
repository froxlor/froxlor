<?php

use Froxlor\Api\Commands\Admins;
use Froxlor\Api\Commands\Customers;
use Froxlor\Api\Commands\Domains;
use Froxlor\Api\Commands\EmailForwarders;
use Froxlor\Api\Commands\Emails;
use Froxlor\Api\Commands\Ftps;
use Froxlor\Api\Commands\SubDomains;
use Froxlor\Database\Database;
use Froxlor\Settings;
use PHPUnit\Framework\TestCase;

/**
 * permission- and consistency-checks which have to be enforced by the API itself
 * (and not only by the web-interface or by a sibling command)
 *
 * @covers \Froxlor\Api\ApiCommand
 * @covers \Froxlor\Api\Commands\Admins
 * @covers \Froxlor\Api\Commands\Domains
 * @covers \Froxlor\Api\Commands\SubDomains
 * @covers \Froxlor\Api\Commands\Emails
 * @covers \Froxlor\Api\Commands\EmailForwarders
 * @covers \Froxlor\Api\Commands\Ftps
 */
class ApiHardeningTest extends TestCase
{

	private static $custA = [];
	private static $custB = [];
	private static $custR = [];
	private static $reseller = [];

	public static function setUpBeforeClass(): void
	{
		global $admin_userdata;

		$json_result = Admins::getLocal($admin_userdata, [
			'new_loginname' => 'hrdres',
			'email' => 'hrdres@froxlor.org',
			'name' => 'Hardening Reseller',
			'admin_password' => 'h0lYmo1y-hrdres',
			'diskspace_ul' => 1,
			'traffic_ul' => 1,
			'customers_ul' => 1,
			'domains_ul' => 1,
			'subdomains_ul' => 1,
			'emails_ul' => 1,
			'email_accounts_ul' => 1,
			'email_forwarders_ul' => 1,
			'ftps_ul' => 1,
			'mysqls_ul' => 1,
			'sendpassword' => 0,
			'custom_notes' => 'internal note about this reseller',
			'custom_notes_show' => 0
		])->add();
		self::$reseller = json_decode($json_result, true)['data'];
		self::$reseller['adminsession'] = 1;

		self::$custA = self::addCustomer($admin_userdata, 'hrda');
		self::$custB = self::addCustomer($admin_userdata, 'hrdb');
		self::$custR = self::addCustomer(self::$reseller, 'hrdr');

		self::addDomain('hrd-a.local', (int)self::$custA['customerid'], 1);
		self::addDomain('hrd-b.local', (int)self::$custB['customerid'], 0);

		Emails::getLocal($admin_userdata, [
			'customerid' => self::$custA['customerid'],
			'email_part' => 'info',
			'domain' => 'hrd-a.local'
		])->add();
	}

	public static function tearDownAfterClass(): void
	{
		global $admin_userdata;
		foreach (['hrda', 'hrdb', 'hrdr'] as $loginname) {
			try {
				Customers::getLocal($admin_userdata, ['loginname' => $loginname])->delete();
			} catch (Exception $e) {
				// ignore - best-effort cleanup
			}
		}
		try {
			Admins::getLocal($admin_userdata, ['loginname' => 'hrdres'])->delete();
		} catch (Exception $e) {
			// ignore - best-effort cleanup
		}
	}

	private static function addCustomer(array $userdata, string $loginname): array
	{
		$json_result = Customers::getLocal($userdata, [
			'new_loginname' => $loginname,
			'email' => $loginname . '@froxlor.org',
			'firstname' => 'Test',
			'name' => 'Hardening',
			'new_customer_password' => 'h0lYmo1y-' . $loginname,
			'subdomains' => -1,
			'emails' => -1,
			'email_accounts' => -1,
			'email_forwarders' => -1,
			'ftps' => -1,
			'diskspace_ul' => 1,
			'traffic_ul' => 1,
			'createstdsubdomain' => 0
		])->add();
		return json_decode($json_result, true)['data'];
	}

	private static function getCustomer(string $loginname): array
	{
		global $admin_userdata;
		$json_result = Customers::getLocal($admin_userdata, ['loginname' => $loginname])->get();
		return json_decode($json_result, true)['data'];
	}

	private static function addDomain(string $domain, int $customerid, int $isemaildomain): array
	{
		global $admin_userdata;
		$json_result = Domains::getLocal($admin_userdata, [
			'domain' => $domain,
			'customerid' => $customerid,
			'isemaildomain' => $isemaildomain,
			'subcanemaildomain' => 0,
			'caneditdomain' => 1
		])->add();
		return json_decode($json_result, true)['data'];
	}

	public function testResellerCannotAddDomainBelowDomainOfOtherAdmin()
	{
		$this->expectExceptionMessage('shop.hrd-a.local cannot be added, as it is located below a domain which does not belong to you.');
		Domains::getLocal(self::$reseller, [
			'domain' => 'shop.hrd-a.local',
			'customerid' => self::$custR['customerid']
		])->add();
	}

	public function testResellerCannotAddDomainDeepBelowDomainOfOtherAdmin()
	{
		$this->expectExceptionMessage('located below a domain which does not belong to you.');
		Domains::getLocal(self::$reseller, [
			'domain' => 'a.b.c.hrd-a.local',
			'customerid' => self::$custR['customerid']
		])->add();
	}

	public function testResellerCanAddDomainsBelowOwnDomain()
	{
		// a similar name is not a parent
		$json_result = Domains::getLocal(self::$reseller, [
			'domain' => 'nothrd-a.local',
			'customerid' => self::$custR['customerid']
		])->add();
		$this->assertEquals('nothrd-a.local', json_decode($json_result, true)['data']['domain']);

		$json_result = Domains::getLocal(self::$reseller, [
			'domain' => 'shop.nothrd-a.local',
			'customerid' => self::$custR['customerid']
		])->add();
		$this->assertEquals('shop.nothrd-a.local', json_decode($json_result, true)['data']['domain']);
	}

	public function testAdminCanAddDomainBelowDomainOfOtherCustomer()
	{
		global $admin_userdata;

		$json_result = Domains::getLocal($admin_userdata, [
			'domain' => 'forb.hrd-a.local',
			'customerid' => self::$custB['customerid']
		])->add();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals('forb.hrd-a.local', $result['domain']);
		$this->assertEquals(self::$custB['customerid'], $result['customerid']);
	}

	public function testAdminEmailsAddDomainOfOtherCustomer()
	{
		global $admin_userdata;

		$this->expectExceptionMessage("The main-domain hrd-a.local does not exist.");
		Emails::getLocal($admin_userdata, [
			'customerid' => self::$custB['customerid'],
			'email_part' => 'foreign',
			'domain' => 'hrd-a.local'
		])->add();
	}

	public function testAdminEmailsDeleteForOtherCustomer()
	{
		global $admin_userdata;

		$before = self::getCustomer('hrdb');
		try {
			Emails::getLocal($admin_userdata, [
				'customerid' => self::$custB['customerid'],
				'emailaddr' => 'info@hrd-a.local'
			])->delete();
			$this->fail('address of another customer was deleted');
		} catch (Exception $e) {
			$this->assertEquals(406, $e->getCode());
			$this->assertEquals('The requested entity does not belong to the given customer', $e->getMessage());
		}
		$after = self::getCustomer('hrdb');
		$this->assertEquals($before['emails_used'], $after['emails_used']);

		// still there
		$json_result = Emails::getLocal($admin_userdata, ['emailaddr' => 'info@hrd-a.local'])->get();
		$this->assertEquals('info@hrd-a.local', json_decode($json_result, true)['data']['email_full']);
	}

	public function testAdminEmailForwardersAddForOtherCustomer()
	{
		global $admin_userdata;

		$before = self::getCustomer('hrdb');
		try {
			EmailForwarders::getLocal($admin_userdata, [
				'customerid' => self::$custB['customerid'],
				'emailaddr' => 'info@hrd-a.local',
				'destination' => 'somewhere@froxlor.org'
			])->add();
			$this->fail('forwarder was booked to another customer');
		} catch (Exception $e) {
			$this->assertEquals(406, $e->getCode());
		}
		$after = self::getCustomer('hrdb');
		$this->assertEquals($before['email_forwarders_used'], $after['email_forwarders_used']);

		// the owner works as before
		$json_result = EmailForwarders::getLocal($admin_userdata, [
			'customerid' => self::$custA['customerid'],
			'emailaddr' => 'info@hrd-a.local',
			'destination' => 'somewhere@froxlor.org'
		])->add();
		$this->assertStringContainsString('somewhere@froxlor.org', json_decode($json_result, true)['data']['destination']);
	}

	public function testCustomerCannotEnableEmailOnMainDomain()
	{
		$json_result = SubDomains::getLocal(self::getCustomer('hrdb'), [
			'domainname' => 'hrd-b.local',
			'isemaildomain' => 1
		])->update();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals(0, $result['isemaildomain']);
	}

	public function testCustomerCannotDisableEmailOnMainDomain()
	{
		$json_result = SubDomains::getLocal(self::getCustomer('hrda'), [
			'domainname' => 'hrd-a.local',
			'isemaildomain' => 0
		])->update();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals(1, $result['isemaildomain']);
	}

	public function testDomainsUpdateInvalidOpenbasedirPath()
	{
		global $admin_userdata;

		$json_result = Domains::getLocal($admin_userdata, [
			'domainname' => 'hrd-b.local',
			'openbasedir_path' => 7
		])->update();
		$this->assertEquals(0, json_decode($json_result, true)['data']['openbasedir_path']);

		$json_result = Domains::getLocal($admin_userdata, [
			'domainname' => 'hrd-b.local',
			'openbasedir_path' => 2
		])->update();
		$this->assertEquals(2, json_decode($json_result, true)['data']['openbasedir_path']);
	}

	public function testDomainsUpdateMoveToOtherCustomerNotAllowed()
	{
		global $admin_userdata;

		Settings::Set('panel.allow_domain_change_customer', '0', true);
		try {
			$json_result = Domains::getLocal($admin_userdata, [
				'domainname' => 'hrd-b.local',
				'customerid' => self::$custA['customerid']
			])->update();
			$result = json_decode($json_result, true)['data'];
		} finally {
			Settings::Set('panel.allow_domain_change_customer', '1', true);
		}
		$this->assertEquals(self::$custB['customerid'], $result['customerid']);
	}

	public function testDomainsUpdateMoveToOtherCustomerAllowed()
	{
		global $admin_userdata;

		$json_result = Domains::getLocal($admin_userdata, [
			'domainname' => 'forb.hrd-a.local',
			'customerid' => self::$custA['customerid']
		])->update();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals(self::$custA['customerid'], $result['customerid']);
	}

	public function testCustomerFtpsAddIgnoresAdminOnlyParameters()
	{
		$customer = self::getCustomer('hrda');
		$json_result = Ftps::getLocal($customer, [
			'ftp_password' => 'h4xXx0r!Test',
			'path' => '/',
			'sendinfomail' => 0,
			'is_defaultuser' => 1,
			'additional_members' => ['hrdb']
		])->add();
		$result = json_decode($json_result, true)['data'];

		// counted as regular ftp-user
		$after = self::getCustomer('hrda');
		$this->assertEquals($customer['ftps_used'] + 1, $after['ftps_used']);

		// no foreign member in the customers group
		$stmt = Database::prepare("SELECT `members` FROM `" . TABLE_FTP_GROUPS . "` WHERE `customerid` = :cid");
		Database::pexecute($stmt, ['cid' => $customer['customerid']]);
		while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
			$this->assertNotContains('hrdb', explode(',', $row['members']));
		}

		Ftps::getLocal($customer, ['id' => $result['id']])->delete();
	}

	public function testResellerCannotReadHiddenNotesAboutItself()
	{
		$json_result = Admins::getLocal(self::$reseller, ['loginname' => 'hrdres'])->get();
		$result = json_decode($json_result, true)['data'];
		$this->assertSame('', $result['custom_notes']);
	}

	public function testResellerCannotChangeNotesAboutItself()
	{
		global $admin_userdata;

		Admins::getLocal(self::$reseller, [
			'loginname' => 'hrdres',
			'custom_notes' => 'changed by myself',
			'custom_notes_show' => 1
		])->update();

		$json_result = Admins::getLocal($admin_userdata, ['loginname' => 'hrdres'])->get();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals('internal note about this reseller', $result['custom_notes']);
		$this->assertEquals(0, $result['custom_notes_show']);
	}

	public function testAdminCanChangeNotesOfReseller()
	{
		global $admin_userdata;

		Admins::getLocal($admin_userdata, [
			'loginname' => 'hrdres',
			'custom_notes' => 'visible note',
			'custom_notes_show' => 1
		])->update();

		$json_result = Admins::getLocal(self::$reseller, ['loginname' => 'hrdres'])->get();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals('visible note', $result['custom_notes']);
	}
}
