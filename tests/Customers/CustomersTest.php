<?php
use PHPUnit\Framework\TestCase;

use Froxlor\Settings;
use Froxlor\Database\Database;
use Froxlor\Api\Commands\Admins;
use Froxlor\Api\Commands\Customers;
use Froxlor\Api\Commands\SubDomains;
use Froxlor\Api\Commands\Ftps;

/**
 *
 * @covers \Froxlor\Api\ApiCommand
 * @covers \Froxlor\Api\ApiParameter
 * @covers \Froxlor\Api\Commands\Customers
 * @covers \Froxlor\Api\Commands\Admins
 */
class CustomersTest extends TestCase
{

	public function testAdminCustomersAdd()
	{
		global $admin_userdata;

		$data = [
			'new_loginname' => 'test1',
			'email' => 'team@froxlor.org',
			'firstname' => 'Test',
			'name' => 'Testman',
			'customernumber' => 1337,
			'diskspace' => 0,
			'diskspace_ul' => 1,
			'traffic' => - 1,
			'subdomains' => 15,
			'emails' => - 1,
			'email_accounts' => 15,
			'email_forwarders' => 15,
			'email_imap' => 1,
			'email_pop3' => 0,
			'ftps' => 15,
			'mysqls' => 15,
			'createstdsubdomain' => 1,
			'new_customer_password' => 'h0lYmo1y',
			'sendpassword' => TRAVIS_CI == 1 ? 0 : 1,
			'phpenabled' => 1,
			'dnsenabled' => 1,
			'store_defaultindex' => 1,
			'custom_notes' => 'secret',
			'custom_notes_show' => 0,
			'gender' => 5,
			'allowed_phpconfigs' => array(
				1
			)
		];

		$json_result = Customers::getLocal($admin_userdata, $data)->add();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals(1, $result['customerid']);
		$this->assertEquals('team@froxlor.org', $result['email']);
		$this->assertEquals(1337, $result['customernumber']);
		$this->assertEquals(15, $result['subdomains']);
		$this->assertEquals('secret', $result['custom_notes']);

		$stdsubdomain = $result['standardsubdomain'] ?? false;
		if (! $stdsubdomain) {
			$this->fail('No standardsubdomain where there should be one');
		} else {
			// validate that the std-subdomain has been added
			$json_result = SubDomains::getLocal($admin_userdata, array(
				'id' => $result['standardsubdomain']
			))->get();
			$result = json_decode($json_result, true)['data'];
			$this->assertEquals('test1.dev.froxlor.org', $result['domain']);
		}
	}

	public function testAdminCustomersAddEmptyMail()
	{
		global $admin_userdata;

		$data = [
			'new_loginname' => 'test2',
			'email' => ' ',
			'firstname' => 'Test2',
			'name' => 'Testman2'
		];

		$this->expectExceptionMessage('Requested parameter "email" is empty where it should not be for "Customers:add"');
		Customers::getLocal($admin_userdata, $data)->add();
	}

	public function testAdminCustomersAddInvalidMail()
	{
		global $admin_userdata;

		$data = [
			'new_loginname' => 'test2',
			'email' => 'test.froxlor.org',
			'firstname' => 'Test2',
			'name' => 'Testman2'
		];

		$this->expectExceptionMessage("Email-address test.froxlor.org contains invalid characters or is incomplete");
		Customers::getLocal($admin_userdata, $data)->add();
	}

	/**
	 *
	 * @depends testAdminCustomersAdd
	 */
	public function testAdminCustomersList()
	{
		global $admin_userdata;

		$json_result = Customers::getLocal($admin_userdata)->listing();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals(1, $result['count']);
		$this->assertFalse(isset($result['list'][0]['webspace_used']));

		$json_result = Customers::getLocal($admin_userdata, [
			'show_usages' => true
		])->listing();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals(1, $result['count']);
		$this->assertTrue(isset($result['list'][0]['webspace_used']));

		$json_result = Customers::getLocal($admin_userdata)->listingCount();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals(1, $result);
	}

	/**
	 *
	 * @depends testAdminCustomersAdd
	 */
	public function testResellerCustomersList()
	{
		global $admin_userdata;
		// get reseller
		$json_result = Admins::getLocal($admin_userdata, array(
			'loginname' => 'reseller'
		))->get();
		$reseller_userdata = json_decode($json_result, true)['data'];
		$reseller_userdata['adminsession'] = 1;
		$json_result = Customers::getLocal($reseller_userdata)->listing();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals(0, $result['count']);

		$json_result = Customers::getLocal($reseller_userdata)->listingCount();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals(0, $result);
	}

	/**
	 *
	 * @depends testAdminCustomersAdd
	 */
	public function testCustomerCustomersList()
	{
		global $admin_userdata;
		// get customer
		$json_result = Customers::getLocal($admin_userdata, array(
			'id' => 1
		))->get();
		$customer_userdata = json_decode($json_result, true)['data'];

		$this->expectExceptionCode(403);
		$this->expectExceptionMessage("Not allowed to execute given command.");
		$json_result = Customers::getLocal($customer_userdata)->listing();

		$this->expectExceptionCode(403);
		$this->expectExceptionMessage("Not allowed to execute given command.");
		$json_result = Customers::getLocal($customer_userdata)->listingCount();
	}

	/**
	 *
	 * @depends testAdminCustomersAdd
	 */
	public function testCustomerCustomersGet()
	{
		global $admin_userdata;
		// get customer
		$json_result = Customers::getLocal($admin_userdata, array(
			'id' => 1
		))->get();
		$customer_userdata = json_decode($json_result, true)['data'];

		$json_result = Customers::getLocal($customer_userdata, array(
			'id' => $customer_userdata['customerid']
		))->get();
		$result = json_decode($json_result, true)['data'];

		$this->assertEquals(1, $result['customerid']);
		$this->assertEquals('team@froxlor.org', $result['email']);
		$this->assertEquals(1337, $result['customernumber']);
		$this->assertEquals(15, $result['subdomains']);
		$this->assertEquals('Froxlor', $result['theme']);
		$this->assertEquals('', $result['custom_notes']);
	}

	/**
	 * regression test: Customers::get()/listing() used to return the raw
	 * panel_customers row (a wildcard SELECT), which includes
	 * leprivatekey - the customer's Let's Encrypt/ACME account private key.
	 * It is never rendered in any UI and only ever read directly from the
	 * database by the acme.sh cron, so it must never round-trip through the
	 * API, same as password/data_2fa.
	 *
	 * @depends testAdminCustomersAdd
	 */
	public function testCustomersResponseHidesLeprivatekey()
	{
		global $admin_userdata;

		$upd_stmt = Database::prepare("UPDATE `" . TABLE_PANEL_CUSTOMERS . "` SET `leprivatekey` = :key WHERE `customerid` = 1");
		Database::pexecute($upd_stmt, [
			'key' => "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----"
		]);

		$json_result = Customers::getLocal($admin_userdata, [
			'id' => 1
		])->get();
		$result = json_decode($json_result, true)['data'];
		$this->assertArrayNotHasKey('leprivatekey', $result);

		$json_result = Customers::getLocal($admin_userdata)->listing();
		$result = json_decode($json_result, true)['data'];
		$found = false;
		foreach ($result['list'] as $row) {
			if ($row['customerid'] == 1) {
				$found = true;
				$this->assertArrayNotHasKey('leprivatekey', $row);
			}
		}
		$this->assertTrue($found);
	}

	public function testAdminCustomersGetNotFound()
	{
		global $admin_userdata;
		$this->expectExceptionCode(404);
		$this->expectExceptionMessage("Customer with id #999 could not be found");
		Customers::getLocal($admin_userdata, array(
			'id' => 999
		))->get();
	}

	/**
	 *
	 * @depends testAdminCustomersAdd
	 */
	public function testCustomerCustomersGetForeign()
	{
		global $admin_userdata;
		// get customer
		$json_result = Customers::getLocal($admin_userdata, array(
			'id' => 1
		))->get();
		$customer_userdata = json_decode($json_result, true)['data'];

		$this->expectException(Exception::class);
		$this->expectExceptionCode(401);

		Customers::getLocal($customer_userdata, array(
			'id' => 2
		))->get();
	}

	/**
	 *
	 * @depends testAdminCustomersAdd
	 */
	public function testAdminCustomerUpdateDeactivate()
	{
		global $admin_userdata;
		// get customer
		Customers::getLocal($admin_userdata, array(
			'id' => 1,
			'deactivated' => 1
		))->update();

		// get customer and check results
		$json_result = Customers::getLocal($admin_userdata, array(
			'id' => 1
		))->get();
		$result = json_decode($json_result, true)['data'];

		$this->assertEquals(1, $result['customerid']);
		$this->assertEquals(1, $result['deactivated']);
		// standard-subdomains will be removed on deactivation
		$this->assertEquals(0, $result['standardsubdomain']);
	}

	/**
	 *
	 * @depends testAdminCustomerUpdateDeactivate
	 */
	public function testCustomerCustomersGetWhenDeactivated()
	{
		global $admin_userdata;
		// get customer
		$json_result = Customers::getLocal($admin_userdata, array(
			'id' => 1
		))->get();
		$customer_userdata = json_decode($json_result, true)['data'];

		$this->expectException(Exception::class);
		$this->expectExceptionCode(406);
		$this->expectExceptionMessage("Account suspended");

		Customers::getLocal($customer_userdata, array(
			'id' => $customer_userdata['customerid']
		))->get();
	}

	/**
	 *
	 * @depends testCustomerCustomersGetWhenDeactivated
	 */
	public function testCustomerCustomersUpdate()
	{
		global $admin_userdata;

		// reactivate customer
		// get customer
		Customers::getLocal($admin_userdata, array(
			'id' => 1,
			'deactivated' => 0
		))->update();

		// get customer
		$json_result = Customers::getLocal($admin_userdata, array(
			'id' => 1
		))->get();
		$customer_userdata = json_decode($json_result, true)['data'];

		Customers::getLocal($customer_userdata, array(
			'id' => $customer_userdata['customerid'],
			'def_language' => 'English',
			'theme' => 'Froxlor',
			'new_customer_password' => 'h0lYmo1y2'
		))->update();

		$json_result = Customers::getLocal($customer_userdata, array(
			'id' => $customer_userdata['customerid']
		))->get();
		$result = json_decode($json_result, true)['data'];

		$this->assertEquals('Froxlor', $result['theme']);
		$this->assertEquals('English', $result['def_language']);
	}

	/**
	 *
	 * @depends testAdminCustomersAdd
	 */
	public function testResellerCustomersAddAllocateMore()
	{
		global $admin_userdata;
		// get reseller
		$json_result = Admins::getLocal($admin_userdata, array(
			'loginname' => 'reseller'
		))->get();
		$reseller_userdata = json_decode($json_result, true)['data'];
		$reseller_userdata['adminsession'] = 1;

		$this->expectExceptionMessage("You cannot allocate more resources than you own for yourself.");
		// add new customer
		$data = [
			'new_loginname' => 'test2',
			'email' => 'test2@froxlor.org',
			'firstname' => 'Test',
			'name' => 'Testman',
			'customernumber' => 1338,
			'subdomains' => - 1,
			'new_customer_password' => 'h0lYmo1y'
		];
		Customers::getLocal($reseller_userdata, $data)->add();
	}

	public function testCustomerCustomersDelete()
	{
		global $admin_userdata;
		// get customer
		$json_result = Customers::getLocal($admin_userdata, array(
			'loginname' => 'test1'
		))->get();
		$customer_userdata = json_decode($json_result, true)['data'];
		$this->expectExceptionCode(403);
		$this->expectExceptionMessage("Not allowed to execute given command.");
		Customers::getLocal($customer_userdata, array(
			'loginname' => 'test1'
		))->delete();
	}

	public function testResellerCustomersDeleteNotOwned()
	{
		global $admin_userdata;
		// get reseller
		$json_result = Admins::getLocal($admin_userdata, array(
			'loginname' => 'reseller'
		))->get();
		$reseller_userdata = json_decode($json_result, true)['data'];
		$reseller_userdata['adminsession'] = 1;
		$this->expectExceptionCode(404);
		Customers::getLocal($reseller_userdata, array(
			'loginname' => 'test1'
		))->delete();
	}

	public function testAdminCustomersDelete()
	{
		global $admin_userdata;
		// add new customer
		$data = [
			'new_loginname' => 'test2',
			'email' => 'test2@froxlor.org',
			'firstname' => 'Test',
			'name' => 'Testman',
			'customernumber' => 1338,
			'new_customer_password' => 'h0lYmo1y'
		];
		Customers::getLocal($admin_userdata, $data)->add();
		$json_result = Customers::getLocal($admin_userdata, array(
			'loginname' => 'test2'
		))->delete();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals('test2', $result['loginname']);
	}

	public function testAdminCustomersUnlock()
	{
		global $admin_userdata;
		// update customer to have correct test-data
		Database::query("UPDATE `" . TABLE_PANEL_CUSTOMERS . "` SET `loginfail_count` = '5' WHERE `loginname` = 'test1'");
		$json_result = Customers::getLocal($admin_userdata, array(
			'loginname' => 'test1'
		))->unlock();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals(0, $result['loginfail_count']);
	}

	public function testAdminCustomersUnlockNotAllowed()
	{
		global $admin_userdata;
		$testadmin_userdata = $admin_userdata;
		$testadmin_userdata['adminsession'] = 0;

		$this->expectExceptionCode(403);
		$this->expectExceptionMessage("Not allowed to execute given command.");
		Customers::getLocal($testadmin_userdata, array(
			'loginname' => 'test1'
		))->unlock();
	}

	public function testAdminCustomersMoveNotAllowed()
	{
		global $admin_userdata;
		$testadmin_userdata = $admin_userdata;
		$testadmin_userdata['change_serversettings'] = 0;

		$this->expectExceptionCode(403);
		$this->expectExceptionMessage("Not allowed to execute given command.");
		Customers::getLocal($testadmin_userdata, array(
			'loginname' => 'test1',
			'adminid' => 1
		))->move();
	}

	public function testAdminCustomersMoveTargetIsSource()
	{
		global $admin_userdata;
		$this->expectExceptionCode(406);
		$this->expectExceptionMessage("Cannot move customer to the same admin/reseller as he currently is assigned to");
		Customers::getLocal($admin_userdata, array(
			'loginname' => 'test1',
			'adminid' => 1
		))->move();
	}

	public function testAdminCustomersMove()
	{
		global $admin_userdata;
		$json_result = Customers::getLocal($admin_userdata, array(
			'loginname' => 'test1',
			'adminid' => 2
		))->move();
		$result = json_decode($json_result, true)['data'];

		$this->assertEquals(2, $result['adminid']);
	}

	/**
	 *
	 * @depends testAdminCustomersMove
	 */
	public function testAdminCustomersAddLoginnameIsSystemaccount()
	{
		global $admin_userdata;

		$data = [
			'new_loginname' => 'web1',
			'email' => 'team@froxlor.org',
			'firstname' => 'Test',
			'name' => 'Testman',
			'customernumber' => 1338,
			'diskspace' => - 1,
			'traffic' => - 1,
			'subdomains' => 15,
			'emails' => - 1,
			'email_accounts' => 15,
			'email_forwarders' => 15,
			'email_imap' => 1,
			'email_pop3' => 0,
			'ftps' => 15,
			'mysqls' => 15,
			'createstdsubdomain' => 1,
			'new_customer_password' => 'h0lYmo1y',
			'sendpassword' => TRAVIS_CI == 1 ? 0 : 1,
			'phpenabled' => 1,
			'store_defaultindex' => 1,
			'custom_notes' => 'secret',
			'custom_notes_show' => 0,
			'gender' => 5,
			'allowed_phpconfigs' => array(
				1
			)
		];

		$this->expectExceptionMessage('You cannot create accounts that begin with "web", as this prefix is set to be used for the automatic account-naming. Please enter another account name.');
		Customers::getLocal($admin_userdata, $data)->add();
	}

	/**
	 *
	 * @depends testAdminCustomersAddLoginnameIsSystemaccount
	 */
	public function testAdminCustomersAddAutoLoginname()
	{
		global $admin_userdata;

		Settings::Set('system.lastaccountnumber', 0, true);

		$data = [
			'new_loginname' => '',
			'email' => 'team@froxlor.org',
			'firstname' => 'Test2',
			'name' => 'Testman2',
			'customernumber' => 1338,
			'sendpassword' => 0,
			'perlenabled' => 2,
			'dnsenabled' => 4,
			'createstdsubdomain' => 0
		];

		$json_result = Customers::getLocal($admin_userdata, $data)->add();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals('web1', $result['loginname']);
		$this->assertEquals(1338, $result['customernumber']);
	}

	/**
	 *
	 * @depends testAdminCustomersAddAutoLoginname
	 */
	public function testAdminCustomersAddLoginnameExists()
	{
		global $admin_userdata;

		$data = [
			'new_loginname' => 'test1',
			'email' => 'team@froxlor.org',
			'firstname' => 'Test2',
			'name' => 'Testman2',
			'customernumber' => 1339
		];

		$this->expectExceptionMessage('Loginname test1 already exists');
		Customers::getLocal($admin_userdata, $data)->add();
	}

	/**
	 *
	 * @depends testAdminCustomersAddLoginnameExists
	 */
	public function testAdminCustomersAddLoginnameInvalid()
	{
		global $admin_userdata;

		$data = [
			'new_loginname' => 'user-',
			'email' => 'team@froxlor.org',
			'firstname' => 'Test2',
			'name' => 'Testman2',
			'customernumber' => 1339
		];

		$this->expectExceptionMessage('Loginname "user-" contains illegal characters.');
		Customers::getLocal($admin_userdata, $data)->add();
	}

	/**
	 *
	 * @depends testAdminCustomersAddLoginnameExists
	 */
	public function testAdminCustomersAddLoginnameInvalid2()
	{
		global $admin_userdata;

		$loginname = str_repeat("x", \Froxlor\Database\Database::getSqlUsernameLength() + 1);
		$data = [
			'new_loginname' => $loginname,
			'email' => 'team@froxlor.org',
			'firstname' => 'Test2',
			'name' => 'Testman2',
			'customernumber' => 1339
		];

		$this->expectExceptionMessage('Loginname contains too many characters. Only ' . (\Froxlor\Database\Database::getSqlUsernameLength() - strlen(Settings::Get('customer.mysqlprefix'))) . ' characters are allowed.');
		Customers::getLocal($admin_userdata, $data)->add();
	}

	/**
	 *
	 * @depends testAdminCustomersAddAutoLoginname
	 */
	public function testResellerCustomersAddNoFtpValidateDefaultUserExists()
	{
		global $admin_userdata;
		// get reseller
		$json_result = Admins::getLocal($admin_userdata, array(
			'loginname' => 'reseller'
		))->get();
		$reseller_userdata = json_decode($json_result, true)['data'];
		$reseller_userdata['adminsession'] = 1;

		// set available ftp resources to 0 to validate that when the customer
		// is added the default ftp user for the customer is created too regardless of
		// available resource of the reseller/admin
		$reseller_userdata['ftps'] = 0;

		// add new customer
		$data = [
			'new_loginname' => 'testftpx',
			'email' => 'testftp@froxlor.org',
			'firstname' => 'Test',
			'name' => 'Ftpman',
			'customernumber' => 1339,
			'new_customer_password' => 'h0lYmo1y'
		];
		Customers::getLocal($reseller_userdata, $data)->add();

		// get FTP user
		$json_result = Ftps::getLocal($reseller_userdata, [
			'username' => 'testftpx'
		])->get();
		$ftp_data = json_decode($json_result, true)['data'];
		$this->assertEquals("testftpx", $ftp_data['username']);

		// now get rid of the customer again
		$json_result = Customers::getLocal($reseller_userdata, array(
			'loginname' => 'testftpx'
		))->delete();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals('testftpx', $result['loginname']);
	}
}
