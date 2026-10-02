<?php
use PHPUnit\Framework\TestCase;

use Froxlor\Api\Commands\Customers;
use Froxlor\Api\Commands\Domains;
use Froxlor\Cron\Http\Apache;
use Froxlor\Cron\Http\WebserverBase;

/**
 * regression test: an admin with change_serversettings is allowed to point a domain's
 * documentroot at an absolute path outside the customer's home directory (see
 * Domains::add()/update(), gated on getUserDetail('change_serversettings')) - a trusted,
 * admin-only escape hatch. getWebroot()'s write-time containment revalidation (added to
 * defend against a customer swapping a homedir-relative path component for a symlink)
 * must not apply that same containment check to this admin-authorized case, or it
 * silently overwrites the admin's explicit documentroot with the customer home directory
 * on every cron run.
 *
 * @covers \Froxlor\Cron\Http\Apache
 * @covers \Froxlor\Cron\Http\WebserverBase
 */
class ApacheAdminDocumentrootTest extends TestCase
{
	public function testAdminSetDocumentrootOutsideCustomerHomeIsPreserved()
	{
		global $admin_userdata;
		$this->assertEquals('1', (string)$admin_userdata['change_serversettings']);

		$json_result = Customers::getLocal($admin_userdata, [
			'loginname' => 'test1'
		])->get();
		$customer_userdata = json_decode($json_result, true)['data'];

		$data = [
			'domain' => 'admindocroottest.local',
			'customerid' => $customer_userdata['customerid']
		];
		Domains::getLocal($admin_userdata, $data)->add();

		$outside_path = '/var/www/shared-admin-path';
		$json_result = Domains::getLocal($admin_userdata, [
			'domainname' => 'admindocroottest.local',
			'documentroot' => $outside_path
		])->update();
		$domain_data = json_decode($json_result, true)['data'];
		$this->assertEquals(rtrim($outside_path, '/') . '/', $domain_data['documentroot']);
		$this->assertStringStartsNotWith($customer_userdata['documentroot'], $domain_data['documentroot']);

		$domains = WebserverBase::getVhostsToCreate();
		$this->assertArrayHasKey('admindocroottest.local', $domains);
		$domain = $domains['admindocroottest.local'];

		$apache = new Apache();
		$method = new ReflectionMethod(Apache::class, 'getWebroot');
		$method->setAccessible(true);
		$webroot_text = $method->invoke($apache, $domain);

		// the admin-authorized out-of-bounds documentroot must survive write-time
		// revalidation unchanged, not get silently swapped for the customer home directory
		$this->assertStringContainsString('DocumentRoot "' . rtrim($outside_path, '/') . '"', $webroot_text);
		$this->assertStringNotContainsString($customer_userdata['documentroot'], $webroot_text);

		Domains::getLocal($admin_userdata, [
			'domainname' => 'admindocroottest.local'
		])->delete();
	}
}
