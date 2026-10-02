<?php
use PHPUnit\Framework\TestCase;

use Froxlor\Database\Database;
use Froxlor\Api\Commands\Admins;

/**
 *
 * @covers \Froxlor\Api\ApiCommand
 * @covers \Froxlor\Api\ApiParameter
 * @covers \Froxlor\Api\Commands\Admins
 */
class AdminsTest extends TestCase
{

	public function testAdminAdminsAdd()
	{
		global $admin_userdata;

		$data = [
			'new_loginname' => 'reseller',
			'email' => 'testreseller@froxlor.org',
			'name' => 'Testreseller',
			'admin_password' => 'h0lYmo1y',
			'diskspace' => - 1,
			'traffic' => - 1,
			'customers' => 15,
			'domains' => 15,
			'subdomains' => 15,
			'emails' => - 1,
			'email_accounts' => 15,
			'email_forwarders' => 15,
			'email_imap' => 1,
			'email_pop3' => 0,
			'ftps' => 15,
			'mysqls' => 15,
			'sendpassword' => 0,
			'phpenabled' => 1,
			'ip' => array()
		];

		$json_result = Admins::getLocal($admin_userdata, $data)->add();
		$result = json_decode($json_result, true)['data'];
		$admin_id = $result['adminid'];

		// get admin and check results
		$json_result = Admins::getLocal($admin_userdata, array(
			'id' => $admin_id
		))->get();
		$result = json_decode($json_result, true)['data'];

		$this->assertEquals('reseller', $result['loginname']);
		$this->assertEquals('testreseller@froxlor.org', $result['email']);
		$this->assertEquals(0, $result['customers_see_all']);
	}

	/**
	 *
	 * @depends testAdminAdminsAdd
	 */
	public function testAdminAdminsAddLoginnameExists()
	{
		global $admin_userdata;

		$data = [
			'new_loginname' => 'reseller',
			'email' => 'testreseller@froxlor.org',
			'name' => 'Testreseller'
		];

		$this->expectExceptionMessage('Loginname reseller already exists');
		Admins::getLocal($admin_userdata, $data)->add();
	}

	/**
	 *
	 * @depends testAdminAdminsAddLoginnameExists
	 */
	public function testAdminAdminsAddLoginnameIsSystemaccount()
	{
		global $admin_userdata;

		$data = [
			'new_loginname' => 'web2',
			'email' => 'testreseller@froxlor.org',
			'name' => 'Testreseller'
		];

		$this->expectExceptionMessage('You cannot create accounts that begin with "web", as this prefix is set to be used for the automatic account-naming. Please enter another account name.');
		Admins::getLocal($admin_userdata, $data)->add();
	}

	/**
	 *
	 * @depends testAdminAdminsAddLoginnameIsSystemaccount
	 */
	public function testAdminAdminsAddLoginnameInvalid()
	{
		global $admin_userdata;

		$data = [
			'new_loginname' => 'reslr-',
			'email' => 'testreseller@froxlor.org',
			'name' => 'Testreseller'
		];

		$this->expectExceptionMessage('Loginname "reslr-" contains illegal characters.');
		Admins::getLocal($admin_userdata, $data)->add();
	}

	/**
	 *
	 * @depends testAdminAdminsAddLoginnameIsSystemaccount
	 */
	public function testAdminAdminsAddLoginnameInvalidEmail()
	{
		global $admin_userdata;

		$data = [
			'new_loginname' => 'reslr',
			'email' => 'testreseller.froxlor.org',
			'name' => 'Testreseller'
		];

		$this->expectExceptionMessage('Email-address testreseller.froxlor.org contains invalid characters or is incomplete');
		Admins::getLocal($admin_userdata, $data)->add();
	}

	public function testAdminAdminsAddNotAllowed()
	{
		global $admin_userdata;
		$testadmin_userdata = $admin_userdata;
		$testadmin_userdata['adminsession'] = 0;

		$this->expectExceptionCode(403);
		$this->expectExceptionMessage("Not allowed to execute given command.");
		Admins::getLocal($testadmin_userdata, array())->add();
	}

	public function testAdminAdminsGetNotFound()
	{
		global $admin_userdata;

		$this->expectExceptionCode(404);
		$this->expectExceptionMessage("Admin with loginname 'unknown' could not be found");
		// get unknown admin
		Admins::getLocal($admin_userdata, array(
			'loginname' => 'unknown'
		))->get();
	}

	public function testAdminAdminsList()
	{
		global $admin_userdata;

		$json_result = Admins::getLocal($admin_userdata)->listing();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals(2, $result['count']);

		$json_result = Admins::getLocal($admin_userdata)->listingCount();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals(2, $result);
	}

	public function testAdminAdminsListLimitOffsetOrderSearch()
	{
		global $admin_userdata;

		$json_result = Admins::getLocal($admin_userdata, [
			'sql_orderby' => [
				'loginname' => 'DESC'
			]
		])->listing();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals(2, $result['count']);
		$this->assertEquals('reseller', $result['list'][0]['loginname']);

		$json_result = Admins::getLocal($admin_userdata, [
			'sql_limit' => 1
		])->listing();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals(1, $result['count']);
		$this->assertEquals('admin', $result['list'][0]['loginname']);

		$json_result = Admins::getLocal($admin_userdata, [
			'sql_limit' => 1,
			'sql_offset' => 1
		])->listing();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals(1, $result['count']);
		$this->assertEquals('reseller', $result['list'][0]['loginname']);

		$json_result = Admins::getLocal($admin_userdata, [
			'sql_search' => [
				'loginname' => [
					'value' => 'adm',
					'op' => null /* LIKE */
				]
			]
		])->listing();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals(1, $result['count']);
		$this->assertEquals('admin', $result['list'][0]['loginname']);
	}

	public function testResellerAdminsGet()
	{
		global $admin_userdata;
		// get reseller
		$json_result = Admins::getLocal($admin_userdata, array(
			'loginname' => 'reseller'
		))->get();
		$reseller_userdata = json_decode($json_result, true)['data'];
		$reseller_userdata['adminsession'] = 1;

		// try to read superadmin with an access-less reseller account
		$this->expectException(Exception::class);
		$this->expectExceptionCode(403);

		$json_result = Admins::getLocal($reseller_userdata, array(
			'loginname' => 'admin'
		))->get();
	}

	public function testResellerAdminsListNotAllowed()
	{
		global $admin_userdata;
		// get reseller
		$json_result = Admins::getLocal($admin_userdata, array(
			'loginname' => 'reseller'
		))->get();
		$reseller_userdata = json_decode($json_result, true)['data'];
		$reseller_userdata['adminsession'] = 1;

		$this->expectExceptionCode(403);
		$this->expectExceptionMessage("Not allowed to execute given command.");

		Admins::getLocal($reseller_userdata)->listing();
	}

	public function testAdminAdminsUnlock()
	{
		global $admin_userdata;
		// update reseller to have correct test-data
		Database::query("UPDATE `" . TABLE_PANEL_ADMINS . "` SET `loginfail_count` = '5' WHERE `loginname` = 'reseller'");
		$json_result = Admins::getLocal($admin_userdata, array(
			'loginname' => 'reseller'
		))->unlock();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals(0, $result['loginfail_count']);
	}

	public function testAdminAdminsUnlockNotAllowed()
	{
		global $admin_userdata;
		$testadmin_userdata = $admin_userdata;
		$testadmin_userdata['adminsession'] = 0;

		$this->expectExceptionCode(403);
		$this->expectExceptionMessage("Not allowed to execute given command.");
		Admins::getLocal($testadmin_userdata, array(
			'loginname' => 'admin'
		))->unlock();
	}

	public function testAdminAdminsDeleteMyOwn()
	{
		global $admin_userdata;
		$this->expectExceptionMessage("You cannot delete yourself for security reasons.");
		Admins::getLocal($admin_userdata, array(
			'loginname' => 'admin'
		))->delete();
	}

	public function testAdminAdminsDeleteReseller()
	{
		global $admin_userdata;

		// add test reseller
		$data = [
			'new_loginname' => 'resellertest',
			'email' => 'testreseller2@froxlor.org',
			'name' => 'Testreseller'
		];

		$json_result = Admins::getLocal($admin_userdata, $data)->add();

		$json_result = Admins::getLocal($admin_userdata, array(
			'loginname' => 'resellertest'
		))->delete();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals('resellertest', $result['loginname']);
	}

	public function testResellerAdminsDelete()
	{
		global $admin_userdata;
		// get reseller
		$json_result = Admins::getLocal($admin_userdata, array(
			'loginname' => 'reseller'
		))->get();
		$reseller_userdata = json_decode($json_result, true)['data'];
		$reseller_userdata['adminsession'] = 1;

		$this->expectExceptionCode(403);
		$this->expectExceptionMessage("Not allowed to execute given command.");
		Admins::getLocal($reseller_userdata, array(
			'loginname' => 'admin'
		))->delete();
	}

	public function testAdminAdminsEditMyOwn()
	{
		global $admin_userdata;
		// update admin to have correct test-data
		Database::query("UPDATE `" . TABLE_PANEL_ADMINS . "` SET `theme` = 'Froxlor', `def_language` = 'Deutsch' WHERE `loginname` = 'admin'");
		$json_result = Admins::getLocal($admin_userdata, array(
			'loginname' => 'admin',
			'theme' => '',
			'def_language' => 'English'
		))->update();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals('Froxlor', $result['theme']);
		$this->assertEquals('English', $result['def_language']);
	}

	public function testAdminAdminsEdit()
	{
		global $admin_userdata;
		// update admin to have correct test-data
		Database::query("UPDATE `" . TABLE_PANEL_ADMINS . "` SET `deactivated` = '0' WHERE `loginname` = 'reseller'");
		$json_result = Admins::getLocal($admin_userdata, array(
			'loginname' => 'reseller',
			'deactivated' => '1'
		))->update();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals(1, $result['deactivated']);

		// reactivate
		Admins::getLocal($admin_userdata, array(
			'loginname' => 'reseller',
			'deactivated' => '0'
		))->update();
	}

	public function testAdminsAdminsEditNotAllowed()
	{
		global $admin_userdata;
		$testadmin_userdata = $admin_userdata;
		$testadmin_userdata['adminsession'] = 0;

		$this->expectExceptionCode(403);
		$this->expectExceptionMessage("Not allowed to execute given command.");
		Admins::getLocal($testadmin_userdata, array(
			'loginname' => 'admin'
		))->update();
	}

	public function testAdminsAdminsCannotDeleteFirstAdmin()
	{
		global $admin_userdata;
		$testadmin_userdata = $admin_userdata;
		$testadmin_userdata['adminid'] = 10;

		$this->expectExceptionMessage("The first admin cannot be deleted.");
		Admins::getLocal($testadmin_userdata, array(
			'loginname' => 'admin'
		))->delete();
	}
}
