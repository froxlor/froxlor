<?php

use Froxlor\Api\Commands\Customers;
use Froxlor\Api\Commands\Domains;
use Froxlor\Api\Commands\Emails;
use Froxlor\Api\Commands\SubDomains;
use Froxlor\Cron\TaskId;
use Froxlor\Database\Database;
use Froxlor\Domain\Domain;
use PHPUnit\Framework\TestCase;

/**
 * domain-names (and therefore email-addresses) must be unique among all customers,
 * a customer must not be able to claim a domain of another customer as subdomain
 *
 * @covers \Froxlor\Api\Commands\SubDomains
 * @covers \Froxlor\Api\Commands\Emails
 * @covers \Froxlor\Domain\Domain
 */
class SubDomainsCollisionTest extends TestCase
{

	private static $victim = [];
	private static $attacker = [];
	private static $victim_domain = [];

	public static function setUpBeforeClass(): void
	{
		self::$victim = self::addCustomer('sdcvictim');
		self::$attacker = self::addCustomer('sdcattacker');
		self::addDomain('sdc-parent.local', (int)self::$attacker['customerid']);
		self::$victim_domain = self::addDomain('shop.sdc-parent.local', (int)self::$victim['customerid']);
		Emails::getLocal(self::getCustomer('sdcvictim'), [
			'email_part' => 'info',
			'domain' => 'shop.sdc-parent.local'
		])->add();
	}

	public static function tearDownAfterClass(): void
	{
		global $admin_userdata;
		foreach (['sdcattacker', 'sdcvictim'] as $loginname) {
			Customers::getLocal($admin_userdata, ['loginname' => $loginname])->delete();
		}
	}

	private static function addCustomer(string $loginname): array
	{
		global $admin_userdata;
		$json_result = Customers::getLocal($admin_userdata, [
			'new_loginname' => $loginname,
			'email' => $loginname . '@froxlor.org',
			'firstname' => 'Test',
			'name' => 'Collision',
			'new_customer_password' => 'h0lYmo1y-' . $loginname,
			'subdomains' => -1,
			'emails' => -1,
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

	private static function addDomain(string $domain, int $customerid): array
	{
		global $admin_userdata;
		$json_result = Domains::getLocal($admin_userdata, [
			'domain' => $domain,
			'customerid' => $customerid,
			'isemaildomain' => 1,
			'subcanemaildomain' => 2
		])->add();
		return json_decode($json_result, true)['data'];
	}

	public function testCustomerCannotClaimDomainOfOtherCustomer()
	{
		$this->expectExceptionMessage('The domain shop.sdc-parent.local already exists.');
		SubDomains::getLocal(self::getCustomer('sdcattacker'), [
			'subdomain' => 'shop',
			'domain' => 'sdc-parent.local',
			'isemaildomain' => 1
		])->add();
	}

	public function testCustomerCannotAddSubdomainBelowDomainOfOtherCustomer()
	{
		$this->expectExceptionMessage('The subdomain www.shop.sdc-parent.local cannot be added, as it is located below a domain which does not belong to you.');
		SubDomains::getLocal(self::getCustomer('sdcattacker'), [
			'subdomain' => 'www.shop',
			'domain' => 'sdc-parent.local'
		])->add();
	}

	public function testCustomerCanAddOwnSubdomains()
	{
		$attacker = self::getCustomer('sdcattacker');
		$json_result = SubDomains::getLocal($attacker, [
			'subdomain' => 'other',
			'domain' => 'sdc-parent.local'
		])->add();
		$this->assertEquals('other.sdc-parent.local', json_decode($json_result, true)['data']['domain']);
		$json_result = SubDomains::getLocal($attacker, [
			'subdomain' => 'deep.other',
			'domain' => 'sdc-parent.local'
		])->add();
		$this->assertEquals('deep.other.sdc-parent.local', json_decode($json_result, true)['data']['domain']);
		// the victim may add subdomains below its own domain
		$json_result = SubDomains::getLocal(self::getCustomer('sdcvictim'), [
			'subdomain' => 'www',
			'domain' => 'shop.sdc-parent.local'
		])->add();
		$this->assertEquals('www.shop.sdc-parent.local', json_decode($json_result, true)['data']['domain']);
	}

	public function testExistingDuplicateDomain()
	{
		// simulate a duplicate created by a former version
		$json_result = SubDomains::getLocal(self::getCustomer('sdcattacker'), [
			'subdomain' => 'shopdup',
			'domain' => 'sdc-parent.local',
			'isemaildomain' => 1
		])->add();
		$dup = json_decode($json_result, true)['data'];
		Database::needRoot(false);
		$stmt = Database::prepare("UPDATE `" . TABLE_PANEL_DOMAINS . "` SET `domain` = 'shop.sdc-parent.local' WHERE `id` = :id");
		Database::pexecute($stmt, ['id' => $dup['id']]);
		$this->assertTrue(Domain::isDomainNameUsedElsewhere('shop.sdc-parent.local', (int)$dup['id']));

		// the address of the victim cannot be added to the duplicate
		try {
			Emails::getLocal(self::getCustomer('sdcattacker'), [
				'email_part' => 'info',
				'domain' => 'shop.sdc-parent.local'
			])->add();
			$this->fail('email-address of another customer has been added');
		} catch (Exception $e) {
			$this->assertEquals('The email-address info@shop.sdc-parent.local already exists.', $e->getMessage());
		}

		// deleting the duplicate must not remove certificate / dns-zone of the victim's domain
		$task_stmt = Database::prepare("SELECT COUNT(*) AS `cnt` FROM `" . TABLE_PANEL_TASKS . "` WHERE `type` IN (:ssl, :pdns) AND `data` LIKE :domain");
		$task_params = ['ssl' => TaskId::DELETE_DOMAIN_SSL, 'pdns' => TaskId::DELETE_DOMAIN_PDNS, 'domain' => '%shop.sdc-parent.local%'];
		$tasks_before = Database::pexecute_first($task_stmt, $task_params)['cnt'];
		SubDomains::getLocal(self::getCustomer('sdcattacker'), ['id' => $dup['id']])->delete();
		$this->assertEquals($tasks_before, Database::pexecute_first($task_stmt, $task_params)['cnt']);
		// only the victim's domain is left
		$this->assertFalse(Domain::isDomainNameUsedElsewhere('shop.sdc-parent.local', (int)self::$victim_domain['id']));
	}
}
