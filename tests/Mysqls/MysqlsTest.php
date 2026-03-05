<?php

use Froxlor\Api\Commands\Admins;
use Froxlor\Api\Commands\Customers;
use Froxlor\Api\Commands\Mysqls;
use Froxlor\Api\Commands\MysqlServer;
use Froxlor\Database\Database;
use Froxlor\Settings;
use Froxlor\Settings\Store;
use PHPUnit\Framework\TestCase;

/**
 *
 * @covers \Froxlor\Api\ApiCommand
 * @covers \Froxlor\Api\ApiParameter
 * @covers \Froxlor\Api\Commands\Mysqls
 * @covers \Froxlor\Api\Commands\MysqlServer
 * @covers \Froxlor\Api\Commands\Customers
 * @covers \Froxlor\Api\Commands\Admins
 * @covers \Froxlor\Database\DbManager
 * @covers \Froxlor\Database\Manager\DbManagerMySQL
 * @covers \Froxlor\Settings\Store
 */
class MysqlsTest extends TestCase
{

	public function testCustomerMysqlsAdd()
	{
		global $admin_userdata;

		// get customer
		$json_result = Customers::getLocal($admin_userdata, array(
			'loginname' => 'test1'
		))->get();
		$customer_userdata = json_decode($json_result, true)['data'];

		$newPwd = \Froxlor\System\Crypt::generatePassword();
		$data = [
			'mysql_password' => $newPwd,
			'description' => 'testdb',
			'sendinfomail' => TRAVIS_CI == 1 ? 0 : 1
		];
		$json_result = Mysqls::getLocal($customer_userdata, $data)->add();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals('testdb', $result['description']);
		$this->assertEquals(0, $result['dbserver']);

		// test connection
		try {
			$test_conn = new \PDO("mysql:host=127.0.0.1", 'test1sql1', $newPwd);
			unset($test_conn);
		} catch (PDOException $e) {
			$this->fail($e->getMessage());
		}
	}

	public function testCustomerMysqlsDBNameAdd()
	{
		global $admin_userdata;

		// get customer
		$json_result = Customers::getLocal($admin_userdata, array(
			'loginname' => 'test1'
		))->get();
		$customer_userdata = json_decode($json_result, true)['data'];

		// Set customer.mysqlprefix to DBNAME
		Settings::Set('customer.mysqlprefix', 'DBNAME');

		$newPwd = \Froxlor\System\Crypt::generatePassword();
		$data = [
			'mysql_password' => $newPwd,
			'custom_suffix' => 'abc123',
			'description' => 'testdb',
			'sendinfomail' => TRAVIS_CI == 1 ? 0 : 1
		];
		$json_result = Mysqls::getLocal($customer_userdata, $data)->add();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals('test1_abc123', $result['databasename']);
		$this->assertEquals(0, $result['dbserver']);

		// test connection
		try {
			$test_conn = new \PDO("mysql:host=127.0.0.1", 'test1_abc123', $newPwd);
			unset($test_conn);
		} catch (PDOException $e) {
			$this->fail($e->getMessage());
		}
	}

	/**
	 *
	 * @depends testCustomerMysqlsAdd
	 */
	public function testAdminMysqlsGet()
	{
		global $admin_userdata;

		$json_result = Mysqls::getLocal($admin_userdata, array(
			'dbname' => 'test1sql1'
		))->get();
		$result = json_decode($json_result, true)['data'];

		$this->assertEquals('test1sql1', $result['databasename']);
		$this->assertEquals('testdb', $result['description']);
	}

	/**
	 *
	 * @depends testCustomerMysqlsAdd
	 */
	public function testResellerMysqlsGet()
	{
		global $admin_userdata;
		// get reseller
		$json_result = Admins::getLocal($admin_userdata, array(
			'loginname' => 'reseller'
		))->get();
		$reseller_userdata = json_decode($json_result, true)['data'];
		$reseller_userdata['adminsession'] = 1;
		$json_result = Mysqls::getLocal($reseller_userdata, array(
			'dbname' => 'test1sql1'
		))->get();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals('test1sql1', $result['databasename']);
		$this->assertEquals('testdb', $result['description']);
	}

	public function testCustomerMysqlsGetUnknown()
	{
		global $admin_userdata;

		// get customer
		$json_result = Customers::getLocal($admin_userdata, array(
			'loginname' => 'test1'
		))->get();
		$customer_userdata = json_decode($json_result, true)['data'];

		$data = [
			'dbname' => 'test1sql5'
		];
		$this->expectExceptionCode(404);
		$this->expectExceptionMessage("MySQL database with dbname 'test1sql5' could not be found");
		Mysqls::getLocal($customer_userdata, $data)->get();
	}

	/**
	 *
	 * @depends testCustomerMysqlsAdd
	 */
	public function testAdminMysqlsUpdate()
	{
		global $admin_userdata;

		$newPwd = \Froxlor\System\Crypt::generatePassword();
		$data = [
			'dbname' => 'test1sql1',
			'mysql_password' => $newPwd,
			'description' => 'testdb-upd',
			'loginname' => 'test1'
		];
		$json_result = Mysqls::getLocal($admin_userdata, $data)->update();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals('testdb-upd', $result['description']);

		// test connection
		try {
			$test_conn = new \PDO("mysql:host=127.0.0.1", 'test1sql1', $newPwd);
			unset($test_conn);
		} catch (PDOException $e) {
			$this->fail($e->getMessage());
		}
	}


	/**
	 *
	 * @depends testCustomerMysqlsAdd
	 */
	public function testAdminMysqlsUpdatePwdOnly()
	{
		global $admin_userdata;

		$newPwd = \Froxlor\System\Crypt::generatePassword();
		$data = [
			'dbname' => 'test1sql1',
			'mysql_password' => $newPwd,
			'loginname' => 'test1'
		];
		$json_result = Mysqls::getLocal($admin_userdata, $data)->update();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals('testdb-upd', $result['description']);
	}

	/**
	 *
	 * @depends testCustomerMysqlsAdd
	 */
	public function testCustomerMysqlsList()
	{
		global $admin_userdata;

		// get customer
		$json_result = Customers::getLocal($admin_userdata, array(
			'loginname' => 'test1'
		))->get();
		$customer_userdata = json_decode($json_result, true)['data'];

		$json_result = Mysqls::getLocal($customer_userdata)->listing();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals(2, $result['count']);
		$this->assertEquals('test1sql1', $result['list'][0]['databasename']);
		$this->assertEquals('test1_abc123', $result['list'][1]['databasename']);

		$json_result = Mysqls::getLocal($customer_userdata)->listingCount();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals(2, $result);

		$data = [
			'mysql_server' => '0'
		];
		$json_result = MysqlServer::getLocal($admin_userdata, $data)->databasesOnServer();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals('2', $result['count']);

		$data = [
			'mysql_server' => '1'
		];
		$json_result = MysqlServer::getLocal($admin_userdata, $data)->databasesOnServer();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals('0', $result['count']);
	}

	/**
	 * @depends testCustomerMysqlsList
	 */
	public function testUpdateCustomerAllowedMysqlWithExistingDbs()
	{
		global $admin_userdata;

		$this->expectExceptionMessage("Cannot remove database server from customers allow-list as there are still databases on it.");
		// reactivate customer
		// get customer
		Customers::getLocal($admin_userdata, array(
			'loginname' => 'test1',
			'allowed_mysqlserver' => [1]
		))->update();
	}

	/**
	 *
	 * @depends testCustomerMysqlsList
	 */
	public function testCustomerMysqlsDelete()
	{
		global $admin_userdata;

		// get customer
		$json_result = Customers::getLocal($admin_userdata, array(
			'loginname' => 'test1'
		))->get();
		$customer_userdata = json_decode($json_result, true)['data'];

		$data = [
			'dbname' => 'test1sql1'
		];
		$json_result = Mysqls::getLocal($customer_userdata, $data)->delete();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals('test1sql1', $result['databasename']);
	}

	/**
	 *
	 * @depends testCustomerMysqlsList
	 */
	public function testCustomerMysqlsDBNameDelete()
	{
		global $admin_userdata;

		// get customer
		$json_result = Customers::getLocal($admin_userdata, array(
			'loginname' => 'test1'
		))->get();
		$customer_userdata = json_decode($json_result, true)['data'];

		$data = [
			'dbname' => 'test1_abc123'
		];
		$json_result = Mysqls::getLocal($customer_userdata, $data)->delete();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals('test1_abc123', $result['databasename']);
	}

	/**
	 *
	 * @depends testCustomerMysqlsAdd
	 */
	public function testStoreSettingIpAddress()
	{
		// this settings test is here because it directly changes mysql users / privileges
		$fielddata = array(
			'label' => 'serversettings.ipaddress',
			'settinggroup' => 'system',
			'varname' => 'ipaddress'
		);
		Store::storeSettingIpAddress('system_system_ipaddress', $fielddata, '82.149.225.47');

		$mysql_access_hosts = Settings::Get('system.mysql_access_host');
		$this->assertTrue(strpos($mysql_access_hosts, '82.149.225.47') !== false);
	}

	/**
	 *
	 * @depends testStoreSettingIpAddress
	 */
	public function testGetAllSqlUsers()
	{
		\Froxlor\Database\Database::needRoot(true);
		$dbm = new \Froxlor\Database\DbManager(\Froxlor\FroxlorLogger::getInstanceOf());
		$users = $dbm->getManager()->getAllSqlUsers(false);
		foreach ($users as $user => $data) {
			if (strtolower($user) == 'mariadb.sys' || strtolower($user) == 'public' || empty(trim($user))) {
				// some systems seem to have a user for mariadb on version 10.4
				// we do not want to test that one
				// as well as a PUBLIC user and an empty user
				continue;
			}
			$this->assertNotEmpty($data['password'], 'No password for user "' . $user . '"');
		}

		if (TRAVIS_CI == 0) {
			// just to be sure, not required for travis as the vm is fresh every time
			Database::needRoot(true);
			Database::query("DROP USER IF EXISTS froxlor010@10.0.0.10;");
		}

		// grant privileges to another host
		$testdata = $users['froxlor010'];
		$password = [
			'password' => $testdata['hosts']['localhost']['password'],
			'plugin' => $testdata['hosts']['localhost']['plugin']
		];
		$dbm->getManager()->grantPrivilegesTo('froxlor010', $password, '10.0.0.10', true);

		// select all entries from mysql.user for froxlor010 to compare password-hashes
		$sel_stmt = Database::prepare("SELECT * FROM mysql.user WHERE `User` = :usr");
		Database::pexecute($sel_stmt, [
			'usr' => 'froxlor010'
		]);
		$results = $sel_stmt->fetchAll(\PDO::FETCH_ASSOC);
		foreach ($results as $user) {
			$passwd = $user['Password'] ?? $user['authentication_string'];
			$this->assertEquals($testdata['hosts'][$user['Host']]['password'], $passwd, "Wrong authentication_string for user '" . $user['User'] . "'@'" . $user['Host'] . "'");
		}
	}
}
