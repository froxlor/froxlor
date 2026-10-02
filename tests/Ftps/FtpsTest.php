<?php

use Froxlor\Api\Commands\Admins;
use Froxlor\Api\Commands\Customers;
use Froxlor\Api\Commands\Ftps;
use Froxlor\Froxlor;
use PHPUnit\Framework\TestCase;

/**
 *
 * @covers \Froxlor\Api\ApiCommand
 * @covers \Froxlor\Api\ApiParameter
 * @covers \Froxlor\Api\Commands\Admins
 * @covers \Froxlor\Api\Commands\Customers
 * @covers \Froxlor\Api\Commands\Ftps
 */
class FtpsTest extends TestCase
{

	public function testAdminFtpsGetId()
	{
		global $admin_userdata;

		$json_result = Ftps::getLocal($admin_userdata, array(
			'id' => 1
		))->get();
		$result = json_decode($json_result, true)['data'];

		// should be the ftp user of the first added customr 'test1'
		$this->assertEquals('test1', $result['username']);
	}

	public function testResellerFtpsGetId()
	{
		global $admin_userdata;
		// get reseller
		$json_result = Admins::getLocal($admin_userdata, array(
			'loginname' => 'reseller'
		))->get();
		$reseller_userdata = json_decode($json_result, true)['data'];
		$reseller_userdata['adminsession'] = 1;
		$json_result = Ftps::getLocal($reseller_userdata, array(
			'id' => 1
		))->get();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals('test1', $result['username']);
	}

	public function testCustomerFtpsGetId()
	{
		global $admin_userdata;

		// get customer
		$json_result = Customers::getLocal($admin_userdata, array(
			'id' => 1
		))->get();
		$customer_userdata = json_decode($json_result, true)['data'];

		$json_result = Ftps::getLocal($customer_userdata, array(
			'id' => 1
		))->get();
		$result = json_decode($json_result, true)['data'];

		// should be the ftp user of the first added customr 'test1'
		$this->assertEquals('test1', $result['username']);
	}

	public function testCustomerFtpsGetOtherId()
	{
		global $admin_userdata;

		// get customer
		$json_result = Customers::getLocal($admin_userdata, array(
			'id' => 1
		))->get();
		$customer_userdata = json_decode($json_result, true)['data'];

		$this->expectExceptionCode(404);

		Ftps::getLocal($customer_userdata, array(
			'id' => 10
		))->get();
	}

	public function testAdminFtpsList()
	{
		global $admin_userdata;

		$json_result = Ftps::getLocal($admin_userdata)->listing();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals(2, $result['count']);

		$json_result = Ftps::getLocal($admin_userdata)->listingCount();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals(2, $result);
	}

	public function testAdminFtpsListSpecificCustomer()
	{
		global $admin_userdata;

		$json_result = Ftps::getLocal($admin_userdata, array(
			'loginname' => 'test1'
		))->listing();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals(1, $result['count']);
		$this->assertEquals('test1', $result['list'][0]['username']);
	}

	public function testResellerFtpsList()
	{
		global $admin_userdata;
		// get reseller
		$json_result = Admins::getLocal($admin_userdata, array(
			'loginname' => 'reseller'
		))->get();
		$reseller_userdata = json_decode($json_result, true)['data'];
		$reseller_userdata['adminsession'] = 1;
		$json_result = Ftps::getLocal($reseller_userdata)->listing();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals(1, $result['count']);
		$this->assertEquals('test1', $result['list'][0]['username']);

		$json_result = Ftps::getLocal($reseller_userdata)->listingCount();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals(1, $result);
	}

	public function testCustomerFtpsList()
	{
		global $admin_userdata;
		// get customer
		$json_result = Customers::getLocal($admin_userdata, array(
			'loginname' => 'test1'
		))->get();
		$customer_userdata = json_decode($json_result, true)['data'];
		$json_result = Ftps::getLocal($customer_userdata)->listing();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals(1, $result['count']);
		$this->assertEquals('test1', $result['list'][0]['username']);

		$json_result = Ftps::getLocal($customer_userdata)->listingCount();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals(1, $result);
	}

	public function testCustomerFtpsAdd()
	{
		global $admin_userdata;

		// get customer
		$json_result = Customers::getLocal($admin_userdata, array(
			'loginname' => 'test1'
		))->get();
		$customer_userdata = json_decode($json_result, true)['data'];

		$data = [
			'ftp_password' => 'h4xXx0r',
			'path' => '/',
			'ftp_description' => 'testing',
			'sendinfomail' => TRAVIS_CI == 1 ? 0 : 1
		];
		$json_result = Ftps::getLocal($customer_userdata, $data)->add();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals($customer_userdata['documentroot'], $result['homedir']);
	}

	public function testCustomerFtpsAddSymlinkOutsideHomedir()
	{
		global $admin_userdata;

		// get customer
		$json_result = Customers::getLocal($admin_userdata, array(
			'loginname' => 'test1'
		))->get();
		$customer_userdata = json_decode($json_result, true)['data']; //

		$customer_userdata['documentroot'] = sys_get_temp_dir() . '/';
		@unlink($customer_userdata['documentroot'] . '/frx');
		symlink(Froxlor::getInstallDir(), $customer_userdata['documentroot'] . '/frx');

		$data = [
			'ftp_password' => 'h4xXx0r',
			'path' => '/frx/sub',
			'ftp_description' => 'testing',
			'sendinfomail' => TRAVIS_CI == 1 ? 0 : 1
		];

		// note: no leading slash here - the symlink-containment check in
		// FileDir::makeCorrectDir() reports the offending path component relative to
		// the (now consistently single-trailing-slash-normalized) customer homedir
		$this->expectExceptionMessage('Found symlink pointing outside of customer home directory: frx');
		Ftps::getLocal($customer_userdata, $data)->add();
	}

	public function testCustomerFtpsAddNoMoreResources()
	{
		global $admin_userdata;

		// get customer
		$json_result = Customers::getLocal($admin_userdata, array(
			'loginname' => 'test1'
		))->get();
		$customer_userdata = json_decode($json_result, true)['data']; //

		$customer_userdata['ftps_used'] = 100;

		$this->expectExceptionCode(406);
		$this->expectExceptionMessage('No more resources available');
		Ftps::getLocal($customer_userdata)->add();
	}

	public function testAdminFtpsAddCustomerRequired()
	{
		global $admin_userdata;

		$data = [
			'ftp_password' => 'h4xXx0r',
			'path' => '/',
			'ftp_description' => 'testing',
			'sendinfomail' => 1
		];

		$this->expectExceptionCode(406);
		$this->expectExceptionMessage('Requested parameter "loginname" is empty where it should not be for "Customers:get"');
		Ftps::getLocal($admin_userdata, $data)->add();
	}

	public function testCustomerFtpsEdit()
	{
		global $admin_userdata;

		// get customer
		$json_result = Customers::getLocal($admin_userdata, array(
			'loginname' => 'test1'
		))->get();
		$customer_userdata = json_decode($json_result, true)['data'];

		$data = [
			'username' => 'test1ftp1',
			'ftp_password' => 'h4xXx0r2',
			'path' => '/subfolder',
			'ftp_description' => 'testing2'
		];
		$json_result = Ftps::getLocal($customer_userdata, $data)->update();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals($customer_userdata['documentroot'] . 'subfolder/', $result['homedir']);
		$this->assertEquals('testing2', $result['description']);
	}

	public function testAdminFtpsEdit()
	{
		global $admin_userdata;
		// get customer
		$json_result = Customers::getLocal($admin_userdata, array(
			'loginname' => 'test1'
		))->get();
		$customer_userdata = json_decode($json_result, true)['data'];
		$data = [
			'username' => 'test1ftp1',
			'customerid' => 1,
			'ftp_password' => 'h4xXx0r2',
			'path' => '/anotherfolder',
			'ftp_description' => 'testing3'
		];
		$json_result = Ftps::getLocal($admin_userdata, $data)->update();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals($customer_userdata['documentroot'] . 'anotherfolder/', $result['homedir']);
		$this->assertEquals('testing3', $result['description']);
	}

	public function testAdminFtpsAdd()
	{
		global $admin_userdata;

		// get customer
		$json_result = Customers::getLocal($admin_userdata, array(
			'loginname' => 'test1'
		))->get();
		$customer_userdata = json_decode($json_result, true)['data'];

		$data = [
			'customerid' => $customer_userdata['customerid'],
			'ftp_password' => 'h4xXx0r',
			'path' => '/',
			'ftp_description' => 'testing',
			'sendinfomail' => TRAVIS_CI == 1 ? 0 : 1
		];
		$json_result = Ftps::getLocal($admin_userdata, $data)->add();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals($customer_userdata['documentroot'], $result['homedir']);
	}

	public function testCustomerFtpsDelete()
	{
		global $admin_userdata;

		// get customer
		$json_result = Customers::getLocal($admin_userdata, array(
			'loginname' => 'test1'
		))->get();
		$customer_userdata = json_decode($json_result, true)['data'];
		$data = [
			'username' => 'test1ftp1'
		];
		$json_result = Ftps::getLocal($customer_userdata, $data)->delete();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals('test1ftp1', $result['username']);
	}

	public function testAdminFtpsDelete()
	{
		global $admin_userdata;
		$data = [
			'username' => 'test1ftp2'
		];
		$json_result = Ftps::getLocal($admin_userdata, $data)->delete();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals('test1ftp2', $result['username']);
	}

	public function testCustomerFtpsDeleteDefaultUser()
	{
		global $admin_userdata;

		// get customer
		$json_result = Customers::getLocal($admin_userdata, array(
			'loginname' => 'test1'
		))->get();
		$customer_userdata = json_decode($json_result, true)['data'];
		$data = [
			'username' => 'test1'
		];
		$this->expectExceptionCode(400);
		$this->expectExceptionMessage('You cannot delete your main FTP account');
		Ftps::getLocal($customer_userdata, $data)->delete();
	}
}
