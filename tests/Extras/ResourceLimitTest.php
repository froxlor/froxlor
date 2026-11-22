<?php

use Froxlor\Api\Commands\Customers;
use Froxlor\Api\Commands\Domains;
use Froxlor\Api\Commands\EmailAccounts;
use Froxlor\Api\Commands\EmailForwarders;
use Froxlor\Api\Commands\Emails;
use Froxlor\Api\Commands\Ftps;
use Froxlor\Api\Commands\Mysqls;
use Froxlor\Api\Commands\SubDomains;
use Froxlor\Database\Database;
use Froxlor\Settings;
use PHPUnit\Framework\TestCase;

/**
 * resource limits must hold for concurrent requests, which all pass the limit check based on
 * the customer data read at the beginning of the request (simulated by using outdated customer data)
 *
 * @covers \Froxlor\Api\Commands\Customers
 * @covers \Froxlor\Api\Commands\SubDomains
 * @covers \Froxlor\Api\Commands\Emails
 * @covers \Froxlor\Api\Commands\EmailAccounts
 * @covers \Froxlor\Api\Commands\EmailForwarders
 * @covers \Froxlor\Api\Commands\Ftps
 * @covers \Froxlor\Api\Commands\Mysqls
 */
class ResourceLimitTest extends TestCase
{

	private static $customer = [];

	public static function setUpBeforeClass(): void
	{
		global $admin_userdata;
		$json_result = Customers::getLocal($admin_userdata, [
			'new_loginname' => 'rltest',
			'email' => 'rltest@froxlor.org',
			'firstname' => 'Test',
			'name' => 'Limits',
			'new_customer_password' => 'h0lYmo1y-rltest',
			'subdomains' => 2,
			'emails' => 2,
			'email_accounts' => 2,
			'email_forwarders' => 2,
			'email_quota' => 100,
			'ftps' => 2,
			'mysqls' => 2,
			'diskspace_ul' => 1,
			'traffic_ul' => 1,
			'createstdsubdomain' => 0
		])->add();
		self::$customer = json_decode($json_result, true)['data'];
		Domains::getLocal($admin_userdata, [
			'domain' => 'rltest.local',
			'customerid' => self::$customer['customerid'],
			'isemaildomain' => 1
		])->add();
	}

	public static function tearDownAfterClass(): void
	{
		global $admin_userdata;
		Customers::getLocal($admin_userdata, ['loginname' => 'rltest'])->delete();
	}

	private static function getCustomer(): array
	{
		global $admin_userdata;
		$json_result = Customers::getLocal($admin_userdata, ['loginname' => 'rltest'])->get();
		return json_decode($json_result, true)['data'];
	}

	/**
	 * set the usage-counter in the database, the customer data of the running request is not changed
	 */
	private static function setUsed(string $resource, int $value)
	{
		Database::needRoot(false);
		$stmt = Database::prepare("UPDATE `" . TABLE_PANEL_CUSTOMERS . "` SET `" . $resource . "` = :val WHERE `customerid` = :cid");
		Database::pexecute($stmt, ['val' => $value, 'cid' => self::$customer['customerid']]);
	}

	private function assertLimitHolds(string $resource, int $limit, callable $add)
	{
		// customer data read before the other (concurrent) requests used up the resource
		$outdated = self::getCustomer();
		self::setUsed($resource, $limit);
		try {
			$add($outdated);
			$this->fail('resource limit of ' . $resource . ' has been exceeded');
		} catch (Exception $e) {
			$this->assertEquals('No more resources available', $e->getMessage());
		}
		$this->assertEquals($limit, (int)self::getCustomer()[$resource]);
	}

	public function testReserveUsage()
	{
		$cid = (int)self::$customer['customerid'];
		self::setUsed('subdomains_used', 1);
		$this->assertTrue(Customers::reserveUsage($cid, ['subdomains_used' => 1]));
		$this->assertFalse(Customers::reserveUsage($cid, ['subdomains_used' => 1]));
		$this->assertEquals(2, (int)self::getCustomer()['subdomains_used']);
		// all or nothing
		self::setUsed('emails_used', 0);
		$this->assertFalse(Customers::reserveUsage($cid, ['emails_used' => 1, 'subdomains_used' => 1]));
		$this->assertEquals(0, (int)self::getCustomer()['emails_used']);
		// nothing to reserve
		$this->assertTrue(Customers::reserveUsage($cid, ['email_quota_used' => 0]));
		self::setUsed('subdomains_used', 0);
	}

	public function testSubDomainsLimit()
	{
		$this->assertLimitHolds('subdomains_used', 2, function ($customer) {
			SubDomains::getLocal($customer, ['subdomain' => 'race', 'domain' => 'rltest.local'])->add();
		});
		self::setUsed('subdomains_used', 0);
	}

	public function testEmailsLimit()
	{
		$this->assertLimitHolds('emails_used', 2, function ($customer) {
			Emails::getLocal($customer, ['email_part' => 'race', 'domain' => 'rltest.local'])->add();
		});
		self::setUsed('emails_used', 0);
	}

	public function testEmailAccountsAndForwardersLimit()
	{
		Emails::getLocal(self::getCustomer(), ['email_part' => 'info', 'domain' => 'rltest.local'])->add();
		$this->assertLimitHolds('email_accounts_used', 2, function ($customer) {
			EmailAccounts::getLocal($customer, ['emailaddr' => 'info@rltest.local', 'email_password' => 'h0lYmo1y-Acc0unt', 'email_quota' => 10, 'sendinfomail' => 0])->add();
		});
		self::setUsed('email_accounts_used', 0);
		$this->assertLimitHolds('email_forwarders_used', 2, function ($customer) {
			EmailForwarders::getLocal($customer, ['emailaddr' => 'info@rltest.local', 'destination' => 'race@froxlor.org'])->add();
		});
		self::setUsed('email_forwarders_used', 0);

		// quota
		if (Settings::Get('system.mail_quota_enabled') == '1') {
			$outdated = self::getCustomer();
			self::setUsed('email_quota_used', 95);
			try {
				EmailAccounts::getLocal($outdated, ['emailaddr' => 'info@rltest.local', 'email_password' => 'h0lYmo1y-Acc0unt', 'email_quota' => 10, 'sendinfomail' => 0])->add();
				$this->fail('email quota limit has been exceeded');
			} catch (Exception $e) {
				$this->assertStringContainsString('10', $e->getMessage());
			}
			$customer = self::getCustomer();
			$this->assertEquals(95, (int)$customer['email_quota_used']);
			$this->assertEquals(0, (int)$customer['email_accounts_used']);
			self::setUsed('email_quota_used', 0);
		}
	}

	public function testFtpsLimit()
	{
		$this->assertLimitHolds('ftps_used', 2, function ($customer) {
			Ftps::getLocal($customer, ['path' => '/', 'ftp_password' => 'h0lYmo1y-Ftp', 'sendinfomail' => 0])->add();
		});
		self::setUsed('ftps_used', 0);
	}

	public function testMysqlsLimit()
	{
		$this->assertLimitHolds('mysqls_used', 2, function ($customer) {
			Mysqls::getLocal($customer, ['mysql_password' => 'h0lYmo1y-Db'])->add();
		});
		self::setUsed('mysqls_used', 0);
	}
}
