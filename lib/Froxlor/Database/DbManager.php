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
		// get all databases for all dbservers
		$databases = [];
		$databases_result_stmt = Database::prepare("
			SELECT * FROM `" . TABLE_PANEL_DATABASES . "`
			ORDER BY `dbserver` ASC
		");
		Database::pexecute($databases_result_stmt);
		while ($databases_row = $databases_result_stmt->fetch(PDO::FETCH_ASSOC)) {
			if (!isset($databases[$databases_row['dbserver']])) {
				$databases[$databases_row['dbserver']] = [];
			}
			$databases[$databases_row['dbserver']][] = $databases_row['databasename'];
		}

		$customers_sel = Database::query("
			SELECT DISTINCT c.loginname
			FROM `" . TABLE_PANEL_CUSTOMERS . "` c
			LEFT JOIN `" . TABLE_PANEL_DATABASES . "` d ON c.customerid = d.customerid
			WHERE c.deactivated = '0' AND d.id IS NOT NULL
		");
		$customers = [];
		while ($customer = $customers_sel->fetch(\PDO::FETCH_ASSOC)) {
			$customers[] = $customer['loginname'];
		}

		$dbservers_stmt = Database::query("SELECT DISTINCT `dbserver` FROM `" . TABLE_PANEL_DATABASES . "`");
		while ($dbserver = $dbservers_stmt->fetch(PDO::FETCH_ASSOC)) {

			// add all customer loginnames to the $databases array for this database-server to correct
			// a possible existing global mysql-user for that customer
			foreach ($customers as $customer) {
				$databases[$dbserver['dbserver']][] = $customer;
			}

			// require privileged access for target db-server
			Database::needRoot(true, $dbserver['dbserver'], false);

			$dbm = new DbManager(FroxlorLogger::getInstanceOf());
			$users = $dbm->getManager()->getAllSqlUsers(false);

			foreach ($databases[$dbserver['dbserver']] as $username) {
				if (isset($users[$username]['hosts']) && is_array($users[$username]['hosts'])) {

					foreach ($mysql_access_host_array as $mysql_access_host) {
						$mysql_access_host = trim($mysql_access_host);

						if (!in_array($mysql_access_host, $users[$username]['hosts'])) {
							// if this is a new host, use credentials from localhost, which should always exist
							$password = [
								'password' => $users[$username]['hosts']['localhost']['password'],
								'plugin' => $users[$username]['hosts']['localhost']['plugin']
							];
							$dbm->getManager()->grantPrivilegesTo($username, $password, $mysql_access_host, true);
						}
					}

					foreach ($users[$username]['hosts'] as $mysql_access_host) {
						if (!in_array($mysql_access_host, $mysql_access_host_array)) {
							$dbm->getManager()->deleteUser($username, $mysql_access_host);
						}
					}
				}
			}

			$dbm->getManager()->flushPrivileges();
			Database::needRoot(false);

			unset($databases[$dbserver['dbserver']]);
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
	public function createDatabase(string $loginname = null, string $password = null, int $dbserver = 0, int $last_accnumber = 0, string $global_user = "")
	{
		Database::needRoot(true, $dbserver, false);

		// check whether we shall create a random username
		if (strtoupper(Settings::Get('customer.mysqlprefix')) == 'RANDOM') {
			// get all usernames from db-manager
			$allsqlusers = $this->getManager()->getAllSqlUsers();
			// generate random username
			$username = $loginname . '-' . substr(Froxlor::genSessionId(), 20, 3);
			// check whether it exists on the DBMS
			while (in_array($username, $allsqlusers)) {
				$username = $loginname . '-' . substr(Froxlor::genSessionId(), 20, 3);
			}
		} elseif (strtoupper(Settings::Get('customer.mysqlprefix')) == 'DBNAME') {
			$username = $loginname;
		} else {
			$username = $loginname . Settings::Get('customer.mysqlprefix') . (intval($last_accnumber) + 1);
		}

		// don't use a password that is the same as the username
		if ($username == $password) {
			return false;
		}

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
	 * returns the manager-object
	 * from where we can control it
	 */
	public function getManager()
	{
		return $this->manager;
	}
}
