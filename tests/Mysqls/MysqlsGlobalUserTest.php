<?php

use Froxlor\Api\Commands\Customers;
use Froxlor\Api\Commands\Mysqls;
use Froxlor\Database\Database;
use Froxlor\Database\DbManager;
use Froxlor\Settings;
use PHPUnit\Framework\TestCase;

/**
 * the customer's global database-user is named after the loginname, make sure
 * existing database-accounts which have not been created by froxlor cannot be taken over
 *
 * @covers \Froxlor\Api\Commands\Customers
 * @covers \Froxlor\Api\Commands\Mysqls
 * @covers \Froxlor\Database\DbManager
 * @covers \Froxlor\Database\Manager\DbManagerMySQL
 */
class MysqlsGlobalUserTest extends TestCase
{

	private static function rootQuery(string $query, array $params = [])
	{
		Database::needRoot(true, 0, false);
		$stmt = Database::prepare($query);
		Database::pexecute($stmt, $params);
		$result = $stmt->columnCount() > 0 ? $stmt->fetchAll(\PDO::FETCH_ASSOC) : [];
		Database::needRoot(false);
		return $result;
	}

	private static function sqlUserHosts(string $username): array
	{
		return array_column(self::rootQuery("SELECT `Host` FROM mysql.user WHERE `User` = :usr", ['usr' => $username]), 'Host');
	}

	private static function sqlUserGrants(string $username, string $host): string
	{
		return implode("\n", array_map(function ($row) {
			return array_values($row)[0];
		}, self::rootQuery("SHOW GRANTS FOR :usr@:host", ['usr' => $username, 'host' => $host])));
	}

	private static function sqlUserHash(string $username): string
	{
		$row = self::rootQuery("SELECT * FROM mysql.user WHERE `User` = :usr", ['usr' => $username])[0] ?? [];
		return $row['authentication_string'] ?? ($row['Password'] ?? '');
	}

	private static function addCustomer(string $loginname, int $mysqls = 0): array
	{
		global $admin_userdata;
		$json_result = Customers::getLocal($admin_userdata, [
			'new_loginname' => $loginname,
			'email' => $loginname . '@froxlor.org',
			'firstname' => 'Test',
			'name' => 'Globaluser',
			'new_customer_password' => 'h0lYmo1y-' . $loginname,
			'mysqls' => $mysqls,
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

	private static function addDatabase(string $loginname): string
	{
		$json_result = Mysqls::getLocal(self::getCustomer($loginname), [
			'mysql_password' => 'Db-S3cr3t-' . $loginname,
			'description' => 'testdb'
		])->add();
		return json_decode($json_result, true)['data']['databasename'];
	}

	private static function deleteCustomer(string $loginname)
	{
		global $admin_userdata;
		Customers::getLocal($admin_userdata, [
			'loginname' => $loginname
		])->delete();
	}

	/**
	 * simulate a global user created by former versions of froxlor which did not keep track of it
	 */
	private static function untrack(int $customerid)
	{
		DbManager::untrackGlobalUser($customerid);
	}

	public function testCustomersAddRejectsExistingSqlUser()
	{
		self::rootQuery("CREATE USER 'gufremote'@'localhost' IDENTIFIED BY 'S3cr3t-foreign'");
		self::rootQuery("GRANT ALL PRIVILEGES ON *.* TO 'gufremote'@'localhost' WITH GRANT OPTION");
		try {
			$this->expectExceptionMessage('The account-name "gufremote" cannot be used');
			self::addCustomer('gufremote', 1);
		} finally {
			self::rootQuery("DROP USER IF EXISTS 'gufremote'@'localhost'");
		}
	}

	public function testReservedSqlUsers()
	{
		// froxlor's own database-user and the privileged users of all database-servers
		$this->assertTrue(DbManager::isReservedSqlUser('froxlor010'));
		$this->assertTrue(DbManager::isReservedSqlUser('Root'));
		$this->assertFalse(DbManager::isReservedSqlUser('gufnotreserved'));
		$this->assertFalse(DbManager::isCustomerGlobalUserManageable('root', 1, 0));
	}

	public function testCustomersAddRejectsGeneratedDatabaseUserOfOtherCustomer()
	{
		self::addCustomer('gufvictim', 5);
		try {
			$this->expectExceptionMessage('The account-name "gufvictimSQL3" cannot be used');
			self::addCustomer('gufvictimSQL3');
		} finally {
			self::deleteCustomer('gufvictim');
		}
	}

	public function testGlobalUserIsTrackedAndManageable()
	{
		$customer = self::addCustomer('gufowner', 5);
		$customerid = (int)$customer['customerid'];
		try {
			// global user has been created and is known to froxlor
			$hosts = self::sqlUserHosts('gufowner');
			$this->assertNotEmpty($hosts);
			$this->assertEquals([0], DbManager::getGlobalUserServers($customerid));
			$this->assertTrue(DbManager::isGlobalUserTracked('gufowner', 0));
			$this->assertTrue(DbManager::isCustomerGlobalUserManageable('gufowner', $customerid, 0));

			// an additional privilege does not change the ownership
			self::rootQuery("GRANT SELECT ON `mysql`.`db` TO 'gufowner'@'" . $hosts[0] . "'");
			$this->assertTrue(DbManager::isCustomerGlobalUserManageable('gufowner', $customerid, 0));

			// changing the password
			$hash_before = self::sqlUserHash('gufowner');
			DbManager::setGlobalUserPassword('gufowner', $customerid, 0, 'N3w-gl0bal-Pwd');
			$this->assertNotEquals($hash_before, self::sqlUserHash('gufowner'));
			$this->assertEquals($hosts, self::sqlUserHosts('gufowner'));

			// unknown database-server
			$this->assertFalse(Database::canConnect(99));
			$this->assertFalse(DbManager::isCustomerGlobalUserManageable('gufowner', $customerid, 99));
		} finally {
			self::deleteCustomer('gufowner');
		}
		// deleting the customer removes the global user
		$this->assertEmpty(self::sqlUserHosts('gufowner'));
		$this->assertEmpty(DbManager::getGlobalUserServers($customerid));
	}

	public function testForeignAccountWithCustomerLoginnameIsNotTouched()
	{
		global $admin_userdata;

		// customer created without mysql, the colliding account appears afterwards; it does not have any
		// privileges, so it looks exactly like a global user without databases
		$customer = self::addCustomer('gufplanted');
		$customerid = (int)$customer['customerid'];
		self::rootQuery("CREATE USER 'gufplanted'@'localhost' IDENTIFIED BY 'S3cr3t-foreign'");
		$hash_before = self::sqlUserHash('gufplanted');

		try {
			$this->assertFalse(DbManager::isCustomerGlobalUserManageable('gufplanted', $customerid, 0));
			$migrated = DbManager::migrateGlobalUser(['customerid' => $customerid, 'loginname' => 'gufplanted', 'deactivated' => '0', 'mysqls' => 0], 0, false);
			$this->assertEquals('skipped', $migrated['result']);

			Customers::getLocal($admin_userdata, [
				'loginname' => 'gufplanted',
				'mysqls' => 1,
				'allowed_mysqlserver' => [0]
			])->update();

			// a new database must not be granted to the foreign account
			$dbname = self::addDatabase('gufplanted');
			$this->assertEquals('gufplantedsql1', $dbname);
			$this->assertStringNotContainsString('gufplantedsql1', self::sqlUserGrants('gufplanted', 'localhost'));
			$this->assertEquals(['localhost'], self::sqlUserHosts('gufplanted'));

			// deactivating, activating and deleting must not touch the foreign account
			Customers::getLocal($admin_userdata, [
				'loginname' => 'gufplanted',
				'deactivated' => 1
			])->update();
			Customers::getLocal($admin_userdata, [
				'loginname' => 'gufplanted',
				'deactivated' => 0
			])->update();
			$this->assertStringNotContainsString('gufplantedsql1', self::sqlUserGrants('gufplanted', 'localhost'));
			self::deleteCustomer('gufplanted');
			$this->assertEquals(['localhost'], self::sqlUserHosts('gufplanted'));
			$this->assertEquals($hash_before, self::sqlUserHash('gufplanted'));
		} finally {
			self::rootQuery("DROP USER IF EXISTS 'gufplanted'@'localhost'");
		}
		$this->assertEmpty(self::sqlUserHosts('gufplantedsql1'));
	}

	public function testOtherCustomersDatabaseUserIsNotManageable()
	{
		$victim = self::addCustomer('gufalice', 5);
		$attacker = self::addCustomer('gufmallory');
		try {
			$dbname = self::addDatabase('gufalice');
			$this->assertEquals('gufalicesql1', $dbname);

			// simulate a colliding customer created before the loginname check existed
			Database::needRoot(false);
			$stmt = Database::prepare("UPDATE `" . TABLE_PANEL_CUSTOMERS . "` SET `loginname` = :ln WHERE `customerid` = :cid");
			Database::pexecute($stmt, ['ln' => $dbname, 'cid' => $attacker['customerid']]);

			$this->assertFalse(DbManager::isCustomerGlobalUserManageable($dbname, (int)$attacker['customerid'], 0));
			$migrated = DbManager::migrateGlobalUser(['customerid' => $attacker['customerid'], 'loginname' => $dbname, 'deactivated' => '0', 'mysqls' => 1], 0, true);
			$this->assertEquals('skipped', $migrated['result']);
			// the victim itself is still fine
			$this->assertTrue(DbManager::isCustomerGlobalUserManageable('gufalice', (int)$victim['customerid'], 0));
		} finally {
			Database::needRoot(false);
			$stmt = Database::prepare("UPDATE `" . TABLE_PANEL_CUSTOMERS . "` SET `loginname` = 'gufmallory' WHERE `customerid` = :cid");
			Database::pexecute($stmt, ['cid' => $attacker['customerid']]);
			self::deleteCustomer('gufmallory');
			self::deleteCustomer('gufalice');
		}
		$this->assertEmpty(self::sqlUserHosts('gufalicesql1'));
	}

	public function testMysqlsAddSkipsNameInUseByOtherCustomer()
	{
		self::addCustomer('gufbob', 5);
		$attacker = self::addCustomer('gufeve');
		// simulate a customer named like bob's next database created before the loginname check existed
		Database::needRoot(false);
		$stmt = Database::prepare("UPDATE `" . TABLE_PANEL_CUSTOMERS . "` SET `loginname` = 'gufbobsql1' WHERE `customerid` = :cid");
		Database::pexecute($stmt, ['cid' => $attacker['customerid']]);
		try {
			$this->assertEquals('gufbobsql2', self::addDatabase('gufbob'));
			$this->assertEquals(2, (int)self::getCustomer('gufbob')['mysql_lastaccountnumber']);
			$this->assertEquals('gufbobsql3', self::addDatabase('gufbob'));
			$this->assertEmpty(self::sqlUserHosts('gufbobsql1'));
		} finally {
			Database::needRoot(false);
			$stmt = Database::prepare("UPDATE `" . TABLE_PANEL_CUSTOMERS . "` SET `loginname` = 'gufeve' WHERE `customerid` = :cid");
			Database::pexecute($stmt, ['cid' => $attacker['customerid']]);
			self::deleteCustomer('gufeve');
			self::deleteCustomer('gufbob');
		}
		$this->assertEmpty(self::sqlUserHosts('gufbobsql2'));
		$this->assertEmpty(self::sqlUserHosts('gufbobsql3'));
	}

	public function testMysqlsAddRequiresNameInDbnameMode()
	{
		self::addCustomer('gufdbname', 5);
		$prefix = Settings::Get('customer.mysqlprefix');
		Settings::Set('customer.mysqlprefix', 'DBNAME');
		try {
			$this->expectExceptionMessage('Please enter a name for the database.');
			self::addDatabase('gufdbname');
		} finally {
			Settings::Set('customer.mysqlprefix', $prefix);
			self::deleteCustomer('gufdbname');
		}
	}

	public function testMigrateLegacyGlobalUser()
	{
		$owner = self::addCustomer('gufw', 5);
		$ownerid = (int)$owner['customerid'];
		self::addCustomer('gufwx', 5);
		try {
			self::addDatabase('gufwx');
			$this->assertEquals('gufwsql1', self::addDatabase('gufw'));

			// global user of a former version: not tracked, wildcard-grant matching gufwxsql1 of the other
			// customer and a leftover grant of a deleted database
			self::untrack($ownerid);
			$hosts = self::sqlUserHosts('gufw');
			foreach ($hosts as $host) {
				self::rootQuery("GRANT ALL PRIVILEGES ON `gufw%`.* TO 'gufw'@'" . $host . "'");
				self::rootQuery("GRANT ALL PRIVILEGES ON `gufw\\_old`.* TO 'gufw'@'" . $host . "'");
			}
			$this->assertFalse(DbManager::isCustomerGlobalUserManageable('gufw', $ownerid, 0));

			$customer = ['customerid' => $ownerid, 'loginname' => 'gufw', 'deactivated' => '0', 'mysqls' => 5];
			$migrated = DbManager::migrateGlobalUser($customer, 0, true);
			$this->assertEquals('tracked', $migrated['result']);
			$this->assertEquals(2 * count($hosts), $migrated['revoked']);
			$this->assertTrue(DbManager::isCustomerGlobalUserManageable('gufw', $ownerid, 0));
			foreach ($hosts as $host) {
				$grants = self::sqlUserGrants('gufw', $host);
				$this->assertStringNotContainsString('gufw%', $grants);
				$this->assertStringNotContainsString('gufw\\_old', $grants);
				$this->assertStringContainsString('gufwsql1', $grants);
				$this->assertStringNotContainsString('gufwxsql1', $grants);
			}
			// nothing left to do
			$migrated = DbManager::migrateGlobalUser($customer, 0, true);
			$this->assertEquals(['result' => 'tracked', 'revoked' => 0, 'reason' => ''], $migrated);
		} finally {
			self::deleteCustomer('gufw');
			self::deleteCustomer('gufwx');
		}
		$this->assertEmpty(self::sqlUserHosts('gufw'));
		$this->assertEmpty(self::sqlUserHosts('gufwxsql1'));
	}

	public function testMigrateDeactivatedGlobalUserIsNotReenabled()
	{
		global $admin_userdata;

		$customer = self::addCustomer('gufdeact', 5);
		$customerid = (int)$customer['customerid'];
		try {
			self::addDatabase('gufdeact');
			Customers::getLocal($admin_userdata, [
				'loginname' => 'gufdeact',
				'deactivated' => 1
			])->update();
			$hosts = self::sqlUserHosts('gufdeact');
			foreach ($hosts as $host) {
				$this->assertStringNotContainsString('gufdeactsql1', self::sqlUserGrants('gufdeact', $host));
			}

			self::untrack($customerid);
			foreach ($hosts as $host) {
				self::rootQuery("GRANT ALL PRIVILEGES ON `gufdeact%`.* TO 'gufdeact'@'" . $host . "'");
			}
			$migrated = DbManager::migrateGlobalUser(['customerid' => $customerid, 'loginname' => 'gufdeact', 'deactivated' => '1', 'mysqls' => 5], 0, true);
			$this->assertEquals('tracked', $migrated['result']);
			foreach ($hosts as $host) {
				$grants = self::sqlUserGrants('gufdeact', $host);
				$this->assertStringNotContainsString('gufdeact%', $grants);
				$this->assertStringNotContainsString('gufdeactsql1', $grants);
			}
		} finally {
			self::deleteCustomer('gufdeact');
		}
		$this->assertEmpty(self::sqlUserHosts('gufdeact'));
	}

	public function testMigrateGlobalUserWithoutPrivileges()
	{
		$customer = self::addCustomer('gufusage', 5);
		$customerid = (int)$customer['customerid'];
		try {
			// global user without any database only has USAGE
			self::untrack($customerid);
			$data = ['customerid' => $customerid, 'loginname' => 'gufusage', 'deactivated' => '0', 'mysqls' => 5];
			// not allowed to use the server: ownership cannot be determined
			$this->assertEquals('skipped', DbManager::migrateGlobalUser($data, 0, false)['result']);
			$this->assertEquals('tracked', DbManager::migrateGlobalUser($data, 0, true)['result']);
		} finally {
			self::deleteCustomer('gufusage');
		}
		$this->assertEmpty(self::sqlUserHosts('gufusage'));
	}

	public function testCorrectMysqlUsersGrantsCustomerDatabasesToGlobalUser()
	{
		self::addCustomer('gufhost', 5);
		$access_hosts = array_map('trim', explode(',', Settings::Get('system.mysql_access_host')));
		try {
			self::addDatabase('gufhost');
			DbManager::correctMysqlUsers(array_merge($access_hosts, ['10.0.0.12']));
			$this->assertContains('10.0.0.12', self::sqlUserHosts('gufhost'));
			$grants = self::sqlUserGrants('gufhost', '10.0.0.12');
			$this->assertStringContainsString('gufhostsql1', $grants);
			$this->assertStringNotContainsString('`gufhost`.*', $grants);
			$this->assertContains('10.0.0.12', self::sqlUserHosts('gufhostsql1'));

			DbManager::correctMysqlUsers($access_hosts);
			$this->assertNotContains('10.0.0.12', self::sqlUserHosts('gufhost'));
			$this->assertNotContains('10.0.0.12', self::sqlUserHosts('gufhostsql1'));
		} finally {
			DbManager::correctMysqlUsers($access_hosts);
			self::deleteCustomer('gufhost');
		}
		$this->assertEmpty(self::sqlUserHosts('gufhost'));
	}
}
