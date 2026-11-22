<?php

/**
 * This file is part of the froxlor project.
 * Copyright (c) 2010 the froxlor Team (see authors).
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, you can also view it online at
 * https://files.froxlor.org/misc/COPYING.txt
 *
 * @copyright  the authors
 * @author     froxlor team <team@froxlor.org>
 * @license    https://files.froxlor.org/misc/COPYING.txt GPLv2
 */

namespace Froxlor\Database;

use Exception;
use Froxlor\Database\Manager\DbManagerMySQL;
use Froxlor\Froxlor;
use Froxlor\FroxlorLogger;
use Froxlor\Settings;
use PDO;

/**
 * Class DbManager
 *
 * Wrapper-class for database-management like creating
 * and removing databases, users and permissions
 */
class DbManager
{

	/**
	 * FroxlorLogger object
	 *
	 * @var object
	 */
	private $log = null;

	/**
	 * Manager object
	 *
	 * @var object
	 */
	private $manager = null;

	/**
	 * by how much the account-number has been increased by the last createDatabase() call
	 *
	 * @var int
	 */
	private $accnumber_increase = 1;

	/**
	 * main constructor
	 *
	 * @param FroxlorLogger $log
	 */
	public function __construct($log = null)
	{
		$this->log = $log;
		$this->setManager();
	}

	/**
	 * set manager-object by type of
	 * dbms: mysql only for now
	 *
	 * sets private $_manager variable
	 */
	private function setManager()
	{
		// TODO read different dbms from settings later
		$this->manager = new DbManagerMySQL($this->log);
	}

	/**
	 * function called when the mysql-access-host setting changes
	 *
	 * @param array $mysql_access_host_array
	 *
	 * @return void
	 * @throws Exception
	 */
	public static function correctMysqlUsers(array $mysql_access_host_array)
	{
		$mysql_access_host_array = array_map('trim', $mysql_access_host_array);

		// get all databases for all dbservers
		$databases = [];
		$databases_result_stmt = Database::prepare("
			SELECT d.`databasename`, d.`dbserver`, c.`deactivated`
			FROM `" . TABLE_PANEL_DATABASES . "` d
			LEFT JOIN `" . TABLE_PANEL_CUSTOMERS . "` c ON c.`customerid` = d.`customerid`
			ORDER BY d.`dbserver` ASC
		");
		Database::pexecute($databases_result_stmt);
		while ($databases_row = $databases_result_stmt->fetch(PDO::FETCH_ASSOC)) {
			$databases[(int)$databases_row['dbserver']][$databases_row['databasename']] = [
				'global_user' => false,
				'deactivated' => $databases_row['deactivated'] == '1'
			];
		}

		// add the global database-users of the customers (only those created by froxlor)
		foreach (self::getGlobalUsers() as $global_user) {
			$databases[$global_user['dbserver']][$global_user['loginname']] = [
				'global_user' => true,
				'deactivated' => $global_user['deactivated']
			];
		}

		foreach ($databases as $dbserver => $dbusers) {
			if (!Database::canConnect($dbserver)) {
				FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::ADM_ACTION, LOG_WARNING, "Unable to correct database-users on database server #" . $dbserver . " as it is not reachable");
				continue;
			}

			// require privileged access for target db-server
			Database::needRoot(true, $dbserver, false);

			$dbm = new DbManager(FroxlorLogger::getInstanceOf());
			$users = $dbm->getManager()->getAllSqlUsers(false);

			foreach ($dbusers as $username => $userdata) {
				$username = (string)$username;
				if (isset($users[$username]['hosts']) && is_array($users[$username]['hosts'])) {

					foreach ($mysql_access_host_array as $mysql_access_host) {
						if (!isset($users[$username]['hosts'][$mysql_access_host])) {
							// if this is a new host, use credentials from localhost (or any other existing host)
							$host_data = $users[$username]['hosts']['localhost'] ?? reset($users[$username]['hosts']);
							$password = [
								'password' => $host_data['password'],
								'plugin' => $host_data['plugin']
							];
							// global users get privileges on the customer's databases
							$dbm->getManager()->grantPrivilegesTo($username, $password, $mysql_access_host, true, false, $userdata['global_user']);
							if ($userdata['deactivated']) {
								// keep deactivated users deactivated on the new host
								$dbm->getManager()->disableUser($username, $mysql_access_host);
							}
						}
					}

					foreach (array_keys($users[$username]['hosts']) as $mysql_access_host) {
						if (!in_array($mysql_access_host, $mysql_access_host_array)) {
							$dbm->getManager()->deleteUser($username, $mysql_access_host);
						}
					}
				}
			}

			$dbm->getManager()->flushPrivileges();
			Database::needRoot(false);
		}
	}

	/**
	 * creates a new database and a user with the
	 * same name with all privileges granted on the db.
	 * DB-name and user-name are being generated and
	 * the password for the user will be set
	 *
	 * @param ?string $loginname
	 * @param ?string $password
	 * @param int $dbserver
	 * @param int $last_accnumber
	 * @param ?string $global_user
	 *
	 * @return string|bool $username if successful or false of username is equal to the password
	 * @throws Exception
	 */
	public function createDatabase(?string $loginname = null, ?string $password = null, int $dbserver = 0, int $last_accnumber = 0, string $global_user = "")
	{
		$mysqlprefix = (string)Settings::Get('customer.mysqlprefix');
		$this->accnumber_increase = 1;
		$tries = 0;
		do {
			if (strtoupper($mysqlprefix) == 'RANDOM') {
				// generate random username
				$username = $loginname . '-' . substr(Froxlor::genSessionId(), 20, 3);
			} elseif (strtoupper($mysqlprefix) == 'DBNAME') {
				$username = $loginname;
			} else {
				$username = $loginname . $mysqlprefix . (intval($last_accnumber) + $this->accnumber_increase);
			}

			// don't use a password that is the same as the username
			if ($username == $password) {
				return false;
			}

			// the generated database-user must not collide with an existing database-account, with the
			// customer's own global user, with a user froxlor uses itself or with the loginname (and therefore
			// the global database-user) or database of another customer
			$in_use = self::isSqlUsernameInUse($username, $global_user, $dbserver);
			if ($in_use) {
				$tries++;
				if (strtoupper($mysqlprefix) == 'DBNAME' || $tries >= 100) {
					throw new Exception(lng('error.sqlusernameinuse', [$username]), 406);
				}
				if (strtoupper($mysqlprefix) != 'RANDOM') {
					// skip the number which is already in use
					$this->accnumber_increase++;
				}
			}
		} while ($in_use);

		// only grant the customer's global user privileges on the new database if froxlor created that user
		if (!empty($global_user) && !self::isGlobalUserTracked($global_user, $dbserver)) {
			$global_user = "";
		}

		Database::needRoot(true, $dbserver, false);

		// now create the database itself
		$this->getManager()->createDatabase($username);

		// and give permission to the user on every access-host we have
		foreach (array_map('trim', explode(',', Settings::Get('system.mysql_access_host'))) as $mysql_access_host) {
			$this->getManager()->grantPrivilegesTo($username, $password, $mysql_access_host);
			if (!empty($global_user)) {
				$this->getManager()->grantCreateToDb($global_user, $username, $mysql_access_host);
			}
		}

		$this->getManager()->flushPrivileges();
		Database::needRoot();

		$this->log->logAction(FroxlorLogger::USR_ACTION, LOG_INFO, "created database '" . $username . "'");

		return $username;
	}

	/**
	 * returns by how much the customer's mysql_lastaccountnumber has to be increased after the
	 * last call of createDatabase() (numbers already in use are skipped)
	 *
	 * @return int
	 */
	public function getAccountNumberIncrease(): int
	{
		return $this->accnumber_increase;
	}

	/**
	 * check whether a generated database(-user) name may not be used
	 *
	 * Note: this resets the database-connection to the unprivileged froxlor-user
	 *
	 * @param string $username
	 * @param string $global_user
	 * @param int $dbserver
	 *
	 * @return bool
	 * @throws Exception
	 */
	private static function isSqlUsernameInUse(string $username, string $global_user, int $dbserver): bool
	{
		if ($username === '' || strtolower($username) === strtolower($global_user) || self::isReservedSqlUser($username)) {
			return true;
		}

		Database::needRoot(false);
		$cust_stmt = Database::prepare("
			SELECT `customerid` FROM `" . TABLE_PANEL_CUSTOMERS . "` WHERE `loginname` = :username
		");
		if (Database::pexecute_first($cust_stmt, ['username' => $username])) {
			return true;
		}
		$db_stmt = Database::prepare("
			SELECT `id` FROM `" . TABLE_PANEL_DATABASES . "` WHERE `databasename` = :username
		");
		if (Database::pexecute_first($db_stmt, ['username' => $username])) {
			return true;
		}

		try {
			Database::needRoot(true, $dbserver, false);
			$exists_stmt = Database::prepare("SELECT 1 FROM `mysql`.`user` WHERE `User` = :username LIMIT 1");
			Database::pexecute($exists_stmt, ['username' => $username]);
			$in_use = (bool)$exists_stmt->fetchColumn();
		} finally {
			Database::needRoot(false);
		}
		return $in_use;
	}

	/**
	 * returns the manager-object
	 * from where we can control it
	 */
	public function getManager()
	{
		return $this->manager;
	}

	/**
	 * returns the indices of all configured database-servers
	 *
	 * @return int[]
	 */
	public static function getDbServerIds(): array
	{
		$sql = [];
		$sql_root = [];
		require Froxlor::getInstallDir() . "/lib/userdata.inc.php";
		if (empty($sql_root) || !is_array($sql_root)) {
			return [0];
		}
		return array_map('intval', array_keys($sql_root));
	}

	/**
	 * returns the names of all database-users froxlor itself uses
	 * (froxlor's own user and the privileged user of every configured database-server)
	 *
	 * @return string[]
	 */
	public static function getReservedSqlUsers(): array
	{
		$sql = [];
		$sql_root = [];
		require Froxlor::getInstallDir() . "/lib/userdata.inc.php";
		$reserved = ['root'];
		if (!empty($sql['user'])) {
			$reserved[] = $sql['user'];
		}
		if (!empty($sql['root_user'])) {
			$reserved[] = $sql['root_user'];
		}
		if (is_array($sql_root)) {
			foreach ($sql_root as $sql_root_data) {
				if (!empty($sql_root_data['user'])) {
					$reserved[] = $sql_root_data['user'];
				}
			}
		}
		return array_values(array_unique($reserved));
	}

	/**
	 * whether the given name is used by froxlor itself (froxlor's own user or a privileged user of any database-server)
	 *
	 * @param string $username
	 *
	 * @return bool
	 */
	public static function isReservedSqlUser(string $username): bool
	{
		return in_array(strtolower($username), array_map('strtolower', self::getReservedSqlUsers()), true);
	}

	/**
	 * check whether a database-account with the given name exists (on any host) on any of the
	 * given database-servers
	 *
	 * Note: this resets the database-connection to the unprivileged froxlor-user
	 *
	 * @param string $username
	 * @param int[] $dbservers
	 *
	 * @return bool
	 * @throws Exception if a database-server cannot be checked
	 */
	public static function sqlUserExistsOnServers(string $username, array $dbservers): bool
	{
		$dbservers = array_intersect(array_unique(array_map('intval', $dbservers)), self::getDbServerIds());
		foreach ($dbservers as $dbserver) {
			if (!Database::canConnect($dbserver)) {
				FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::ADM_ACTION, LOG_WARNING, "Unable to check database-users on database server #" . $dbserver . " as it is not reachable");
				throw new Exception(lng('error.mysqlservercheckfailed', [$dbserver]), 503);
			}
			try {
				$exists = !empty(self::getSqlUserRows($username, $dbserver));
			} catch (Exception $e) {
				FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::ADM_ACTION, LOG_WARNING, "Unable to check database-users on database server #" . $dbserver . ": " . $e->getMessage());
				throw new Exception(lng('error.mysqlservercheckfailed', [$dbserver]), 503);
			}
			if ($exists) {
				return true;
			}
		}
		return false;
	}

	/**
	 * returns all rows of mysql.user for the given username
	 *
	 * Note: this resets the database-connection to the unprivileged froxlor-user,
	 * check reachability of the database-server via Database::canConnect() first
	 *
	 * @param string $username
	 * @param int $dbserver
	 *
	 * @return array
	 * @throws Exception
	 */
	private static function getSqlUserRows(string $username, int $dbserver): array
	{
		try {
			Database::needRoot(true, $dbserver, false);
			$stmt = Database::prepare("SELECT * FROM `mysql`.`user` WHERE `User` = :username");
			$stmt->execute(['username' => $username]);
			return $stmt->fetchAll(PDO::FETCH_ASSOC);
		} finally {
			Database::needRoot(false);
		}
	}

	/**
	 * whether the table to keep track of the customer's global database-users exists already
	 * (code might be deployed before the database-update has been run)
	 *
	 * @return bool
	 */
	private static function globalUserTrackingAvailable(): bool
	{
		return (int)Settings::Get('panel.db_version') >= 202611200;
	}

	/**
	 * whether froxlor created the global database-user named after the given loginname on the given database-server
	 *
	 * Note: this resets the database-connection to the unprivileged froxlor-user
	 *
	 * @param string $loginname
	 * @param int $dbserver
	 *
	 * @return bool
	 * @throws Exception
	 */
	public static function isGlobalUserTracked(string $loginname, int $dbserver): bool
	{
		if ($loginname === '' || !self::globalUserTrackingAvailable()) {
			return false;
		}
		Database::needRoot(false);
		$stmt = Database::prepare("
			SELECT g.`id` FROM `" . TABLE_PANEL_DATABASES_GLOBALUSERS . "` g
			INNER JOIN `" . TABLE_PANEL_CUSTOMERS . "` c ON c.`customerid` = g.`customerid`
			WHERE c.`loginname` = :loginname AND g.`dbserver` = :dbserver
		");
		return (bool)Database::pexecute_first($stmt, ['loginname' => $loginname, 'dbserver' => $dbserver]);
	}

	/**
	 * returns the indices of all database-servers on which froxlor created the customer's global database-user
	 *
	 * Note: this resets the database-connection to the unprivileged froxlor-user
	 *
	 * @param int $customerid
	 *
	 * @return int[]
	 * @throws Exception
	 */
	public static function getGlobalUserServers(int $customerid): array
	{
		if (!self::globalUserTrackingAvailable()) {
			return [];
		}
		Database::needRoot(false);
		$stmt = Database::prepare("
			SELECT `dbserver` FROM `" . TABLE_PANEL_DATABASES_GLOBALUSERS . "` WHERE `customerid` = :customerid ORDER BY `dbserver`
		");
		Database::pexecute($stmt, ['customerid' => $customerid]);
		return array_map('intval', $stmt->fetchAll(PDO::FETCH_COLUMN));
	}

	/**
	 * returns all global database-users created by froxlor
	 *
	 * @return array list of [loginname, customerid, dbserver, deactivated]
	 * @throws Exception
	 */
	private static function getGlobalUsers(): array
	{
		if (!self::globalUserTrackingAvailable()) {
			return [];
		}
		Database::needRoot(false);
		$stmt = Database::query("
			SELECT c.`loginname`, c.`customerid`, c.`deactivated`, g.`dbserver`
			FROM `" . TABLE_PANEL_DATABASES_GLOBALUSERS . "` g
			INNER JOIN `" . TABLE_PANEL_CUSTOMERS . "` c ON c.`customerid` = g.`customerid`
			ORDER BY g.`dbserver`
		");
		$global_users = [];
		while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
			$global_users[] = [
				'loginname' => $row['loginname'],
				'customerid' => (int)$row['customerid'],
				'dbserver' => (int)$row['dbserver'],
				'deactivated' => $row['deactivated'] == '1'
			];
		}
		return $global_users;
	}

	/**
	 * remember that froxlor created the customer's global database-user on the given database-server
	 *
	 * Note: this resets the database-connection to the unprivileged froxlor-user
	 *
	 * @param int $customerid
	 * @param int $dbserver
	 *
	 * @return void
	 * @throws Exception
	 */
	public static function trackGlobalUser(int $customerid, int $dbserver)
	{
		if (!self::globalUserTrackingAvailable()) {
			return;
		}
		Database::needRoot(false);
		$stmt = Database::prepare("
			INSERT IGNORE INTO `" . TABLE_PANEL_DATABASES_GLOBALUSERS . "` SET `customerid` = :customerid, `dbserver` = :dbserver
		");
		Database::pexecute($stmt, ['customerid' => $customerid, 'dbserver' => $dbserver]);
	}

	/**
	 * forget about the customer's global database-user on the given (or every) database-server
	 *
	 * Note: this resets the database-connection to the unprivileged froxlor-user
	 *
	 * @param int $customerid
	 *            customer-id, or 0 for all customers (requires $dbserver)
	 * @param int|null $dbserver
	 *            database-server, or null for all database-servers
	 *
	 * @return void
	 * @throws Exception
	 */
	public static function untrackGlobalUser(int $customerid, ?int $dbserver = null)
	{
		if (!self::globalUserTrackingAvailable() || ($customerid <= 0 && $dbserver === null)) {
			return;
		}
		Database::needRoot(false);
		$where = [];
		$params = [];
		if ($customerid > 0) {
			$where[] = "`customerid` = :customerid";
			$params['customerid'] = $customerid;
		}
		if ($dbserver !== null) {
			$where[] = "`dbserver` = :dbserver";
			$params['dbserver'] = $dbserver;
		}
		$stmt = Database::prepare("DELETE FROM `" . TABLE_PANEL_DATABASES_GLOBALUSERS . "` WHERE " . implode(" AND ", $where));
		Database::pexecute($stmt, $params);
	}

	/**
	 * Every customer has a "global" database-user which is named after the customer's loginname.
	 * Check whether the database-account with that name on the given database-server may be
	 * created/altered/disabled/deleted for the given customer, which is only the case if froxlor
	 * created it for this customer or if no account with that name exists yet.
	 * Accounts not created by froxlor are never touched.
	 *
	 * Note: this resets the database-connection to the unprivileged froxlor-user
	 *
	 * @param string $loginname
	 * @param int $customerid
	 * @param int $dbserver
	 *
	 * @return bool
	 * @throws Exception
	 */
	public static function isCustomerGlobalUserManageable(string $loginname, int $customerid, int $dbserver): bool
	{
		if ($loginname === '' || $customerid <= 0) {
			return false;
		}

		$refuse = function (string $reason) use ($loginname, $dbserver): bool {
			FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::ADM_ACTION, LOG_WARNING, "Global database-user '" . $loginname . "' on database server #" . $dbserver . " cannot be managed: " . $reason);
			return false;
		};

		// never touch any user froxlor uses itself
		if (self::isReservedSqlUser($loginname)) {
			return $refuse("name is used by froxlor itself");
		}

		Database::needRoot(false);

		// the loginname must belong to the given customer
		$cust_stmt = Database::prepare("
			SELECT `customerid` FROM `" . TABLE_PANEL_CUSTOMERS . "` WHERE `loginname` = :loginname
		");
		$cust = Database::pexecute_first($cust_stmt, ['loginname' => $loginname]);
		if (!$cust || (int)$cust['customerid'] !== $customerid) {
			return $refuse("loginname does not belong to customer #" . $customerid);
		}

		// the name must not be the database(-user) of another customer
		$db_stmt = Database::prepare("
			SELECT `id` FROM `" . TABLE_PANEL_DATABASES . "` WHERE `databasename` = :dbname AND `customerid` <> :customerid LIMIT 1
		");
		if (Database::pexecute_first($db_stmt, ['dbname' => $loginname, 'customerid' => $customerid])) {
			return $refuse("name is used by a database of another customer");
		}

		if (!Database::canConnect($dbserver)) {
			return $refuse("database server is not reachable");
		}

		// froxlor created it for this customer
		if (self::isGlobalUserTracked($loginname, $dbserver)) {
			return true;
		}

		// otherwise no account with that name must exist (on any host)
		try {
			$rows = self::getSqlUserRows($loginname, $dbserver);
		} catch (Exception $e) {
			return $refuse("unable to check existing database-accounts: " . $e->getMessage());
		}
		if (!empty($rows)) {
			return $refuse("a database-account with that name exists which has not been created by froxlor for this customer");
		}
		return true;
	}

	/**
	 * set the password of the customer's global database-user on the given database-server,
	 * the user is created on every access-host where it does not exist yet.
	 * Check DbManager::isCustomerGlobalUserManageable() before calling this.
	 *
	 * Note: this resets the database-connection to the unprivileged froxlor-user
	 *
	 * @param string $loginname
	 * @param int $customerid
	 * @param int $dbserver
	 * @param string $password
	 * @param FroxlorLogger|null $log
	 *
	 * @return void
	 * @throws Exception
	 */
	public static function setGlobalUserPassword(string $loginname, int $customerid, int $dbserver, string $password, $log = null)
	{
		try {
			// require privileged access for target db-server
			Database::needRoot(true, $dbserver, false);
			$dbm = new DbManager($log);
			// give permission to the user on every access-host we have
			foreach (array_map('trim', explode(',', Settings::Get('system.mysql_access_host'))) as $mysql_access_host) {
				if ($dbm->getManager()->userExistsOnHost($loginname, $mysql_access_host)) {
					// update password
					$dbm->getManager()->grantPrivilegesTo($loginname, $password, $mysql_access_host, false, true);
				} else {
					// create missing user
					$dbm->getManager()->grantPrivilegesTo($loginname, $password, $mysql_access_host, false, false, true);
				}
				// granting privileges on the customer's databases might have changed the connection
				Database::needRoot(true, $dbserver, false);
			}
			$dbm->getManager()->flushPrivileges();
		} finally {
			Database::needRoot(false);
		}
		self::trackGlobalUser($customerid, $dbserver);
	}

	/**
	 * disable (revoke all privileges) or (re-)enable the customer's global database-user on the given database-server
	 * if froxlor created it
	 *
	 * Note: this resets the database-connection to the unprivileged froxlor-user
	 *
	 * @param string $loginname
	 * @param int $customerid
	 * @param int $dbserver
	 * @param bool $enable
	 * @param FroxlorLogger|null $log
	 *
	 * @return bool whether the user has been changed
	 * @throws Exception
	 */
	public static function setGlobalUserEnabled(string $loginname, int $customerid, int $dbserver, bool $enable, $log = null): bool
	{
		if (!self::isGlobalUserTracked($loginname, $dbserver) || !self::isCustomerGlobalUserManageable($loginname, $customerid, $dbserver)) {
			return false;
		}
		$hosts = array_column(self::getSqlUserRows($loginname, $dbserver), 'Host');
		try {
			Database::needRoot(true, $dbserver, false);
			$dbm = new DbManager($log);
			foreach ($hosts as $host) {
				if ($enable) {
					$dbm->getManager()->enableUser($loginname, $host, true);
					Database::needRoot(true, $dbserver, false);
				} else {
					$dbm->getManager()->disableUser($loginname, $host);
				}
			}
			$dbm->getManager()->flushPrivileges();
		} finally {
			Database::needRoot(false);
		}
		return true;
	}

	/**
	 * delete the customer's global database-user on the given database-server if froxlor created it
	 *
	 * Note: this resets the database-connection to the unprivileged froxlor-user
	 *
	 * @param string $loginname
	 * @param int $customerid
	 * @param int $dbserver
	 * @param FroxlorLogger|null $log
	 *
	 * @return bool whether the user has been deleted (or did not exist anymore)
	 * @throws Exception
	 */
	public static function deleteGlobalUser(string $loginname, int $customerid, int $dbserver, $log = null): bool
	{
		if (!self::isGlobalUserTracked($loginname, $dbserver)) {
			// not created by froxlor
			return false;
		}
		if (!self::isCustomerGlobalUserManageable($loginname, $customerid, $dbserver)) {
			return false;
		}
		$hosts = array_column(self::getSqlUserRows($loginname, $dbserver), 'Host');
		try {
			Database::needRoot(true, $dbserver, false);
			$dbm = new DbManager($log);
			foreach ($hosts as $host) {
				$dbm->getManager()->deleteUser($loginname, $host);
			}
			$dbm->getManager()->flushPrivileges();
		} finally {
			Database::needRoot(false);
		}
		self::untrackGlobalUser($customerid, $dbserver);
		return true;
	}

	/**
	 * Former versions of froxlor did not keep track of the customer's global database-users. Check whether an
	 * existing database-account named after the customer's loginname has been created by froxlor (judged by its
	 * privileges), remember it if so and clean up its privileges: former versions granted the global user
	 * privileges on `<loginname>%`.* (and `<loginname>`.*), which matches databases of other customers too
	 * (e.g. web1% matches web10sql1). Those grants as well as leftover grants on deleted databases are revoked
	 * and the customer's own databases are granted explicitly (unless the customer is deactivated).
	 * Accounts which do not look like they were created by froxlor are not touched at all.
	 *
	 * Note: this resets the database-connection to the unprivileged froxlor-user
	 *
	 * @param array $customer customerid, loginname, deactivated, mysqls
	 * @param int $dbserver
	 * @param bool $allowed whether the customer is allowed to use the database-server
	 * @param array|null $databases optional, all rows (customerid, databasename, dbserver) of the databases table to
	 *            avoid reading them again for every customer and database-server
	 *
	 * @return array [result => none|tracked|skipped, revoked => number of revoked grants, reason => reason if skipped]
	 * @throws Exception
	 */
	public static function migrateGlobalUser(array $customer, int $dbserver, bool $allowed, ?array $databases = null): array
	{
		$loginname = (string)$customer['loginname'];
		$customerid = (int)$customer['customerid'];
		$result = ['result' => 'none', 'revoked' => 0, 'reason' => ''];
		$skip = function (string $reason) use ($result): array {
			$result['result'] = 'skipped';
			$result['reason'] = $reason;
			return $result;
		};

		if ($loginname === '' || $customerid <= 0) {
			return $result;
		}
		if (!Database::canConnect($dbserver)) {
			return $skip('database server not reachable');
		}
		if (self::isGlobalUserTracked($loginname, $dbserver)) {
			$result['result'] = 'tracked';
			return $result;
		}
		try {
			$rows = self::getSqlUserRows($loginname, $dbserver);
		} catch (Exception $e) {
			return $skip('unable to read database-accounts: ' . $e->getMessage());
		}
		if (empty($rows)) {
			return $result;
		}
		if (self::isReservedSqlUser($loginname)) {
			return $skip('name is used by froxlor itself');
		}
		foreach ($rows as $row) {
			if (strtoupper($row['account_locked'] ?? 'N') == 'Y' || strtoupper($row['is_role'] ?? 'N') == 'Y') {
				return $skip('locked account or role');
			}
		}

		// databases known to froxlor
		Database::needRoot(false);
		if ($databases === null) {
			$databases = Database::query("SELECT `customerid`, `databasename`, `dbserver` FROM `" . TABLE_PANEL_DATABASES . "`")->fetchAll(PDO::FETCH_ASSOC);
		}
		$own_dbs = [];
		$own_server_dbs = [];
		$managed_dbs = [];
		$other_dbs = [];
		foreach ($databases as $row) {
			$dbname = strtolower($row['databasename']);
			if ((int)$row['customerid'] == $customerid) {
				// own databases on any server (former versions granted those on every server)
				$own_dbs[] = $dbname;
				if ((int)$row['dbserver'] == $dbserver) {
					$own_server_dbs[] = $dbname;
				}
			} else {
				$other_dbs[] = $dbname;
			}
			if ((int)$row['dbserver'] == $dbserver) {
				$managed_dbs[] = $dbname;
			}
		}
		if (in_array(strtolower($loginname), $other_dbs, true)) {
			return $skip('name is used by a database of another customer');
		}

		// check every privilege of the account
		$revoke = [];
		$usage_only = true;
		try {
			Database::needRoot(true, $dbserver, false);
			$grants_stmt = Database::prepare("SHOW GRANTS FOR :username@:host");
			$schemas_stmt = Database::prepare("SELECT `SCHEMA_NAME` FROM `information_schema`.`SCHEMATA` WHERE `SCHEMA_NAME` LIKE :pattern");
			$schemas_like = function (string $pattern) use ($schemas_stmt): array {
				$schemas_stmt->execute(['pattern' => $pattern]);
				return $schemas_stmt->fetchAll(PDO::FETCH_COLUMN);
			};
			$schema_stmt = Database::prepare("SELECT `SCHEMA_NAME` FROM `information_schema`.`SCHEMATA` WHERE `SCHEMA_NAME` = :dbname");
			$schema_exists = function (string $dbname) use ($schema_stmt): bool {
				$schema_stmt->execute(['dbname' => $dbname]);
				return (bool)$schema_stmt->fetchColumn();
			};
			foreach (array_column($rows, 'Host') as $host) {
				$grants_stmt->execute(['username' => $loginname, 'host' => $host]);
				foreach ($grants_stmt->fetchAll(PDO::FETCH_COLUMN) as $grant) {
					$grant_type = self::classifyGlobalUserGrant((string)$grant, $loginname, $own_dbs, $managed_dbs, $other_dbs, $schemas_like, $schema_exists);
					if ($grant_type['type'] == 'foreign') {
						return $skip('privileges which do not belong to the customer: ' . $grant);
					}
					if ($grant_type['type'] != 'usage') {
						$usage_only = false;
					}
					if (in_array($grant_type['type'], ['legacy', 'stale']) && $grant_type['all_tables']) {
						$revoke[$host][] = $grant_type['raw'];
					}
				}
			}
		} catch (Exception $e) {
			return $skip('unable to read privileges: ' . $e->getMessage());
		} finally {
			Database::needRoot(false);
		}

		// an account without any privileges does not tell anything about who created it
		if ($usage_only && ($customer['mysqls'] == 0 || !$allowed)) {
			return $skip('account without any privileges on a database server the customer is not allowed to use');
		}

		self::trackGlobalUser($customerid, $dbserver);

		$reenable = $customer['deactivated'] == '0' && $allowed;
		try {
			Database::needRoot(true, $dbserver, false);
			$manager = new DbManagerMySQL();
			foreach (array_column($rows, 'Host') as $host) {
				foreach ($revoke[$host] ?? [] as $raw) {
					$rev_stmt = Database::prepare("REVOKE ALL PRIVILEGES ON `" . $raw . "`.* FROM :username@:host");
					$rev_stmt->execute(['username' => $loginname, 'host' => $host]);
					$result['revoked']++;
				}
				if ($reenable && !empty($own_server_dbs)) {
					$manager->enableUser($loginname, $host, true);
					Database::needRoot(true, $dbserver, false);
				}
			}
			$manager->flushPrivileges();
		} finally {
			Database::needRoot(false);
		}
		$result['result'] = 'tracked';
		return $result;
	}

	/**
	 * classify a single line of "SHOW GRANTS" of a customer's global database-user
	 *
	 * usage   - GRANT USAGE ON *.*
	 * own     - privileges on one of the customer's databases
	 * legacy  - `<loginname>`.* / `<loginname>%`.* granted by former versions, as long as no existing schema
	 *           matching it is not managed by froxlor
	 * stale   - privileges on a database in the customer's namespace that does not exist anymore and is
	 *           not known to froxlor (former versions did not always revoke these when deleting a database)
	 * foreign - anything else
	 *
	 * @param string $grant
	 * @param string $loginname
	 * @param array $own_dbs lowercase names of the customer's databases
	 * @param array $managed_dbs lowercase names of all froxlor-managed databases on that server
	 * @param array $other_dbs lowercase names of the databases of all other customers
	 * @param callable $schemas_like returns all existing schema-names matching the given LIKE pattern
	 * @param callable $schema_exists whether a schema with the given name exists
	 *
	 * @return array [type, raw, all_tables]
	 */
	private static function classifyGlobalUserGrant(string $grant, string $loginname, array $own_dbs, array $managed_dbs, array $other_dbs, callable $schemas_like, callable $schema_exists): array
	{
		$foreign = ['type' => 'foreign', 'raw' => '', 'all_tables' => false];
		if (!preg_match('/^GRANT\s+(.+?)\s+ON\s+(\S+)\s+TO\s+/i', trim($grant), $matches)) {
			// role-grants, proxy, default-roles, partial revokes, etc.
			return $foreign;
		}
		$privileges = strtoupper(trim($matches[1]));
		$target = trim($matches[2]);
		if ($target === '*.*') {
			return $privileges === 'USAGE' ? ['type' => 'usage', 'raw' => '', 'all_tables' => false] : $foreign;
		}
		$db_target = self::parseDbGrantTarget($target);
		if ($db_target === null) {
			return $foreign;
		}
		$dbname = strtolower($db_target['dbname']);
		$type = ['raw' => $db_target['raw'], 'all_tables' => $db_target['all_tables']];
		if (in_array($dbname, $own_dbs, true)) {
			return ['type' => 'own'] + $type;
		}
		// legacy grants of the global user
		if (self::isLegacyGlobalUserPattern($db_target['pattern'], $loginname)) {
			$is_wildcard = substr($db_target['pattern'], -1) === '%';
			foreach ($schemas_like($db_target['pattern']) as $schema) {
				$schema = strtolower($schema);
				if (!in_array($schema, $own_dbs, true) && !($is_wildcard && in_array($schema, $managed_dbs, true))) {
					return $foreign;
				}
			}
			return ['type' => 'legacy'] + $type;
		}
		// leftovers of deleted databases of the customer
		if ($db_target['all_tables']
			&& !preg_match('/(?<!\\\\)%/', $db_target['pattern'])
			&& strpos($dbname, strtolower($loginname)) === 0
			&& !in_array($dbname, $other_dbs, true)
			&& !$schema_exists($db_target['dbname'])
		) {
			return ['type' => 'stale'] + $type;
		}
		return $foreign;
	}

	/**
	 * parse a database-level grant target like `db\_name`.* or `db`.`table`
	 *
	 * @param string $target
	 *
	 * @return array|null [raw (as printed within the backticks), pattern (LIKE-pattern), dbname (unescaped), all_tables]
	 */
	private static function parseDbGrantTarget(string $target): ?array
	{
		if (!preg_match('/^`((?:[^`]|``)+)`\.(\*|`(?:[^`]|``)+`)$/', $target, $db_match)) {
			return null;
		}
		$pattern = str_replace('``', '`', $db_match[1]);
		return [
			'raw' => $db_match[1],
			'pattern' => $pattern,
			'dbname' => str_replace(['\\_', '\\%'], ['_', '%'], $pattern),
			'all_tables' => $db_match[2] === '*'
		];
	}

	/**
	 * whether the given LIKE-pattern of a grant is one that former versions of froxlor
	 * granted to the customer's global user
	 *
	 * @param string $pattern
	 * @param string $loginname
	 *
	 * @return bool
	 */
	private static function isLegacyGlobalUserPattern(string $pattern, string $loginname): bool
	{
		if ($loginname === '') {
			return false;
		}
		$loginname = strtolower($loginname);
		$escaped_loginname = str_replace('_', '\\_', $loginname);
		return in_array(strtolower($pattern), [$loginname, $loginname . '%', $escaped_loginname, $escaped_loginname . '%'], true);
	}
}
