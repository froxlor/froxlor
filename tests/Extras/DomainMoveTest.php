<?php

use Froxlor\Api\Commands\Customers;
use Froxlor\Api\Commands\Domains;
use Froxlor\Api\Commands\EmailAccounts;
use Froxlor\Api\Commands\EmailForwarders;
use Froxlor\Api\Commands\Emails;
use Froxlor\Api\Commands\SubDomains;
use Froxlor\Database\Database;
use Froxlor\Settings;
use PHPUnit\Framework\TestCase;

/**
 * moving a domain to another customer must move everything that belongs
 * to its subdomains too and must not leave anything with the previous owner
 *
 * @covers \Froxlor\Api\Commands\Domains
 */
class DomainMoveTest extends TestCase
{

	private static $old = [];
	private static $new = [];

	public static function setUpBeforeClass(): void
	{
		global $admin_userdata;

		Settings::Set('panel.allow_domain_change_customer', '1', true);

		self::$old = self::addCustomer('mvold');
		self::$new = self::addCustomer('mvnew');

		foreach (['mv.local', 'mvkeep.local'] as $domain) {
			Domains::getLocal($admin_userdata, [
				'domain' => $domain,
				'customerid' => self::$old['customerid'],
				'isemaildomain' => 1,
				'subcanemaildomain' => 1,
				'caneditdomain' => 1
			])->add();
		}

		$old = self::getCustomer('mvold');
		$keep = json_decode(Domains::getLocal($admin_userdata, ['domainname' => 'mvkeep.local'])->get(), true)['data'];

		// certificate of the domain the previous owner keeps (includes its alias al.mv.local)
		$stmt = Database::prepare("
			INSERT INTO `" . TABLE_PANEL_DOMAIN_SSL_SETTINGS . "` SET
			`domainid` = :id, `ssl_cert_file` = 'cert', `ssl_key_file` = 'key', `validtodate` = '2099-01-01 00:00:00'
		");
		Database::pexecute($stmt, ['id' => $keep['id']]);

		// everything below is done by the (at that time rightful) owner of the domain
		SubDomains::getLocal($old, [
			'subdomain' => 'shop',
			'domain' => 'mv.local',
			'path' => 'shop',
			'isemaildomain' => 1
		])->add();
		SubDomains::getLocal($old, [
			'subdomain' => 'al',
			'domain' => 'mv.local',
			'alias' => $keep['id']
		])->add();

		Emails::getLocal($old, ['email_part' => 'ceo', 'domain' => 'shop.mv.local'])->add();
		EmailAccounts::getLocal($old, [
			'emailaddr' => 'ceo@shop.mv.local',
			'email_password' => 'h0lYmo1y-Mailpw#1',
			'sendinfomail' => 0
		])->add();
		EmailForwarders::getLocal($old, [
			'emailaddr' => 'ceo@shop.mv.local',
			'destination' => 'other@domain.tld'
		])->add();

		// an account the previous owner keeps, allowed to send as the domain which gets moved
		Emails::getLocal($old, ['email_part' => 'box', 'domain' => 'mvkeep.local'])->add();
		EmailAccounts::getLocal($old, [
			'emailaddr' => 'box@mvkeep.local',
			'email_password' => 'h0lYmo1y-Mailpw#2',
			'sendinfomail' => 0
		])->add();
		// (EmailSender.add validates against the session-user, which does not exist here)
		$stmt = Database::prepare("
			INSERT INTO `" . TABLE_MAIL_SENDER_ALIAS . "` SET `email` = 'box@mvkeep.local', `allowed_sender` = '@shop.mv.local'
		");
		Database::pexecute($stmt);
	}

	public static function tearDownAfterClass(): void
	{
		global $admin_userdata;
		foreach (['mvold', 'mvnew'] as $loginname) {
			try {
				Customers::getLocal($admin_userdata, ['loginname' => $loginname])->delete();
			} catch (Exception $e) {
				// ignore - best-effort cleanup
			}
		}
	}

	private static function addCustomer(string $loginname): array
	{
		global $admin_userdata;
		$json_result = Customers::getLocal($admin_userdata, [
			'new_loginname' => $loginname,
			'email' => $loginname . '@froxlor.org',
			'firstname' => 'Test',
			'name' => 'Move',
			'new_customer_password' => 'h0lYmo1y-' . $loginname,
			'subdomains' => -1,
			'emails' => -1,
			'email_accounts' => -1,
			'email_forwarders' => -1,
			'email_quota' => -1,
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

	public function testMoveDomainMovesEverythingOfItsSubdomains()
	{
		global $admin_userdata;

		$old_before = self::getCustomer('mvold');
		$new_before = self::getCustomer('mvnew');

		$sub = json_decode(SubDomains::getLocal($admin_userdata, ['domainname' => 'shop.mv.local'])->get(), true)['data'];
		$this->assertEquals($old_before['documentroot'] . 'shop/', $sub['documentroot']);

		Domains::getLocal($admin_userdata, [
			'domainname' => 'mv.local',
			'customerid' => $new_before['customerid']
		])->update();

		$old_after = self::getCustomer('mvold');
		$new_after = self::getCustomer('mvnew');

		// docroot of the subdomain must not point to the previous owner anymore
		$sub = json_decode(SubDomains::getLocal($admin_userdata, ['domainname' => 'shop.mv.local'])->get(), true)['data'];
		$this->assertEquals($new_before['customerid'], $sub['customerid']);
		$this->assertEquals($new_before['documentroot'] . 'shop/', $sub['documentroot']);

		// alias to a domain of the previous owner is gone
		$sub = json_decode(SubDomains::getLocal($admin_userdata, ['domainname' => 'al.mv.local'])->get(), true)['data'];
		$this->assertEmpty($sub['aliasdomain']);
		$this->assertStringStartsWith($new_before['documentroot'], $sub['documentroot']);
		// which triggers a renewal of the certificate that included the alias
		$stmt = Database::prepare("
			SELECT `s`.`validtodate` FROM `" . TABLE_PANEL_DOMAIN_SSL_SETTINGS . "` `s`
			JOIN `" . TABLE_PANEL_DOMAINS . "` `d` ON `d`.`id` = `s`.`domainid` WHERE `d`.`domain` = 'mvkeep.local'
		");
		$cert = Database::pexecute_first($stmt);
		$this->assertNotEmpty($cert);
		$this->assertNull($cert['validtodate']);

		// address, account and forwarder moved along
		$email = json_decode(Emails::getLocal($new_after, ['emailaddr' => 'ceo@shop.mv.local'])->get(), true)['data'];
		$this->assertEquals($new_before['customerid'], $email['customerid']);
		$stmt = Database::prepare("
			SELECT `customerid` FROM `" . TABLE_MAIL_USERS . "` WHERE `email` = 'ceo@shop.mv.local'
		");
		$account = Database::pexecute_first($stmt);
		$this->assertEquals($new_before['customerid'], $account['customerid']);

		// usage counters follow
		foreach (['subdomains_used' => 2, 'emails_used' => 1, 'email_accounts_used' => 1, 'email_forwarders_used' => 1] as $field => $diff) {
			$this->assertEquals($old_before[$field] - $diff, $old_after[$field], 'previous owner: ' . $field);
			$this->assertEquals($new_before[$field] + $diff, $new_after[$field], 'new owner: ' . $field);
		}

		// the previous owner may not send as the moved domain anymore
		$stmt = Database::prepare("
			SELECT COUNT(*) AS `cnt` FROM `" . TABLE_MAIL_SENDER_ALIAS . "` WHERE `email` = 'box@mvkeep.local'
		");
		$sender = Database::pexecute_first($stmt);
		$this->assertEquals(0, $sender['cnt']);

		// and has no access to the address at all
		$this->expectExceptionCode(404);
		Emails::getLocal($old_after, ['emailaddr' => 'ceo@shop.mv.local'])->get();
	}
}
