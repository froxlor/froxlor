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

namespace Froxlor\Api\Commands;

use Exception;
use Froxlor\Api\ApiCommand;
use Froxlor\Api\ResourceEntity;
use Froxlor\Database\Database;
use Froxlor\FileDir;
use Froxlor\Froxlor;
use Froxlor\FroxlorLogger;
use Froxlor\PhpHelper;
use Froxlor\Validate\Validate;
use PDO;
use PDOException;

class MysqlServer extends ApiCommand implements ResourceEntity
{

	/**
	 * check whether the user is allowed
	 *
	 * @throws Exception
	 */
	private function validateAccess()
	{
		if ($this->isAdmin() == false || ($this->isAdmin() && $this->getUserDetail('change_serversettings') == 0)) {
			throw new Exception("You cannot access this resource", 405);
		}
	}

	/**
	 * add a new mysql-server
	 *
	 * @param string $mysql_host
	 *             ip/hostname of mysql-server
	 * @param string $mysql_port
	 *             optional, port to connect to
	 * @param string $mysql_ca
	 *             optional, path to certificate file
	 * @param string $mysql_verifycert
	 *             optional, verify server certificate
	 * @param string $privileged_user
	 *             privileged user on the mysql-server (must have GRANT privileges)
	 * @param string $privileged_password
	 *             password of privileged user
	 * @param string $description
	 *             optional, description for server
	 * @param bool $allow_all_customers
	 *             optional add this configuration to the list of every existing customer's allowed-mysqlserver-config list, default is false (no)
	 * @param bool $test_connection
	 *             optional, test connection with given credentials, default is true (yes)
	 *
	 * @access admin
	 * @return string json-encoded array
	 * @throws Exception
	 */
	public function add()
	{
		$this->validateAccess();

		$mysql_host = $this->getParam('mysql_host');
		$mysql_port = $this->getParam('mysql_port', true, 3306);
		$mysql_ca = $this->getParam('mysql_ca', true, '');
		$mysql_verifycert = $this->getBoolParam('mysql_verifycert', true, 0);
		$privileged_user = $this->getParam('privileged_user');
		$privileged_password = $this->getParam('privileged_password');
		$description = $this->getParam('description', true, '');
		$allow_all_customers = $this->getParam('allow_all_customers', true, 0);
		$test_connection = $this->getParam('test_connection', true, 1);

		// validation
		$mysql_host_chk = Validate::validate_ip2($mysql_host, true, 'invalidip', true, true, false);
		if ($mysql_host_chk === false) {
			$mysql_host_chk = Validate::validateLocalHostname($mysql_host);
			if ($mysql_host_chk === false) {
				$mysql_host_chk = Validate::validateDomain($mysql_host);
				if ($mysql_host_chk === false) {
					throw new Exception("Invalid mysql server ip/hostname", 406);
				}
			}
		}
		$mysql_port = Validate::validate($mysql_port, 'port', Validate::REGEX_PORT, '', [3306], true);
		$mysql_ca = !empty($mysql_ca) ? FileDir::makeCorrectFile($mysql_ca) : '';
		$privileged_user = Validate::validate($privileged_user, 'privileged_user', '/^[a-z][a-z0-9\-_]+$/i', '', [], true);
		$privileged_password = Validate::validate($privileged_password, 'password', '', '', [], true);
		$description = Validate::validate(trim($description), 'description', Validate::REGEX_DESC_TEXT, '', [], true);

		// testing connection with given credentials
		if ($test_connection) {
			$options = array(
				PDO::MYSQL_ATTR_INIT_COMMAND => 'SET names utf8'
			);
			if (!empty($mysql_ca)) {
				$options[PDO::MYSQL_ATTR_SSL_CA] = $mysql_ca;
				$options[PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT] = (bool)$mysql_verifycert;
			}

			$dsn = "mysql:host=" . $mysql_host . ";port=" . $mysql_port . ";";
			try {
				$db_test = new \PDO($dsn, $privileged_user, $privileged_password, $options);
				unset($db_test);
			} catch (PDOException $e) {
				throw new Exception("Connection to given mysql database could not be established. Error-message: " . $e->getMessage(), $e->getCode());
			}
		}

		$sql = [];
		$sql_root = [];

		// get all data from lib/userdata
		require Froxlor::getInstallDir() . "/lib/userdata.inc.php";

		// le format
		if (isset($sql['root_user']) && isset($sql['root_password']) && !is_array($sql_root)) {
			$sql_root = array(
				0 => array(
					'caption' => 'Default',
					'host' => $sql['host'],
					'socket' => (isset($sql['socket']) ? $sql['socket'] : null),
					'user' => $sql['root_user'],
					'password' => $sql['root_password']
				)
			);
			unset($sql['root_user']);
			unset($sql['root_password']);
		}

		// add new values to sql_root array
		$sql_root[] = [
			'caption' => $description,
			'host' => $mysql_host,
			'port' => $mysql_port,
			'user' => $privileged_user,
			'password' => $privileged_password,
			'ssl' => [
				'caFile' => $mysql_ca ?? "",
				'verifyServerCertificate' => $mysql_verifycert
			]
		];

		$this->generateNewUserData($sql, $sql_root);

		// last added to array
		$newdbserver = array_key_last($sql_root);

		if ($allow_all_customers) {
			$this->addDatabaseFromCustomerAllowedList($newdbserver);
		}

		$this->logger()->logAction(FroxlorLogger::ADM_ACTION, LOG_WARNING, "[API] added new database server '" . $description . "' (" . $mysql_host . ")");

		return $this->response(['dbserver' => $newdbserver]);
	}

	/**
	 * remove a mysql-server
	 *
	 * @param int $id
	 *             optional the number of the mysql server (either id or dbserver must be set)
	 * @param int $dbserver
	 *             optional the number of the mysql server (either id or dbserver must be set)
	 *
	 * @access admin
	 * @return string json-encoded array
	 * @throws Exception
	 */
	public function delete()
	{
		$this->validateAccess();

		$id = (int)$this->getParam('id', true, -1);
		$dn_optional = $id >= 0;
		$dbserver = (int)$this->getParam('dbserver', $dn_optional, -1);
		$dbserver = $id >= 0 ? $id : $dbserver;

		if ($dbserver == 0) {
			throw new Exception('Cannot delete first/default mysql-server', 406);
		}

		$sql_root = [];
		// get all data from lib/userdata
		require Froxlor::getInstallDir() . "/lib/userdata.inc.php";

		if (!isset($sql_root[$dbserver])) {
			throw new Exception('Mysql server not found', 404);
		}

		// check whether the server is in use by any customer
		$result_ms = $this->databasesOnServer(true, $dbserver);
		if ($result_ms > 0) {
			throw new Exception(lng('error.mysqlserverstillhasdbs'), 406);
		}

		// when removing, remove from list of allowed_mysqlservers from any customers
		$this->removeDatabaseFromCustomerAllowedList($dbserver);

		$description = $sql_root[$dbserver]['caption'] ?? "unknown";
		$mysql_host = $sql_root[$dbserver]['host'] ?? "unknown";
		unset($sql_root[$dbserver]);

		$this->logger()->logAction(FroxlorLogger::ADM_ACTION, LOG_WARNING, "[API] removed database server '" . $description . "' (" . $mysql_host . ")");

		$this->generateNewUserData($sql, $sql_root);
		return $this->response(['true']);
	}

	/**
	 * list available mysql-server
	 *
	 * @access admin, customer
	 * @return string json-encoded array
	 */
	public function listing()
	{
		// a reseller (admin-type account without change_serversettings) is not permitted to see mysql
		// server configuration at all - same boundary the admin UI and the write commands (validateAccess())
		// already enforce; customers are handled further down via their own allowed_mysqlserver restriction
		if ($this->isAdmin() && $this->getUserDetail('change_serversettings') == 0) {
			throw new Exception("You cannot access this resource", 405);
		}

		$sql = [];
		$sql_root = [];
		// get all data from lib/userdata
		require Froxlor::getInstallDir() . "/lib/userdata.inc.php";

		// limit customer to its allowed servers
		$allowed_mysqls = [];
		if ($this->isAdmin() == false) {
			$allowed_mysqls = json_decode($this->getUserDetail('allowed_mysqlserver'), true);
		}

		$result = [];
		foreach ($sql_root as $index => $sqlrootdata) {
			if ($this->isAdmin() == false) {
				if ($allowed_mysqls === false || empty($allowed_mysqls)) {
					break;
				} elseif (!in_array($index, $allowed_mysqls)) {
					continue;
				}
				// no usernames required for non-admins
				unset($sqlrootdata['user']);
			}
			// passwords will not be returned in any case for security reasons
			unset($sqlrootdata['password']);
			$sqlrootdata['id'] = $index;
			$result[$index] = $sqlrootdata;
		}

		return $this->response(['list' => $result, 'count' => count($result)]);
	}

	/**
	 * returns the total number of mysql servers
	 *
	 * @access admin, customer
	 * @return string json-encoded response message
	 */
	public function listingCount()
	{
		// see listing() - a reseller is not permitted to see mysql server configuration at all
		if ($this->isAdmin() && $this->getUserDetail('change_serversettings') == 0) {
			throw new Exception("You cannot access this resource", 405);
		}

		if ($this->isAdmin() == false) {
			$allowed_mysqls = json_decode($this->getUserDetail('allowed_mysqlserver'), true);
			if ($allowed_mysqls) {
				return $this->response(count($allowed_mysqls));
			}
			return $this->response(0);
		}
		$sql_root = [];
		// get all data from lib/userdata
		require Froxlor::getInstallDir() . "/lib/userdata.inc.php";
		return $this->response(count($sql_root));
	}

	/**
	 * Return info about a specific mysql-server
	 *
	 * @param int $id
	 *             optional the number of the mysql server (either id or dbserver must be set)
	 * @param int $dbserver
	 *             optional the number of the mysql server (either id or dbserver must be set)
	 *
	 * @access admin, customer
	 * @return string json-encoded array
	 * @throws Exception
	 */
	public function get()
	{
		// see listing() - a reseller is not permitted to see mysql server configuration at all
		if ($this->isAdmin() && $this->getUserDetail('change_serversettings') == 0) {
			throw new Exception("You cannot access this resource", 405);
		}

		$id = (int)$this->getParam('id', true, -1);
		$dn_optional = $id >= 0;
		$dbserver = (int)$this->getParam('dbserver', $dn_optional, -1);
		$dbserver = $id >= 0 ? $id : $dbserver;

		$sql_root = [];
		// get all data from lib/userdata
		require Froxlor::getInstallDir() . "/lib/userdata.inc.php";

		if (!isset($sql_root[$dbserver])) {
			throw new Exception('Mysql server not found', 404);
		}

		// limit customer to its allowed servers
		if ($this->isAdmin() == false) {
			$allowed_mysqls = json_decode($this->getUserDetail('allowed_mysqlserver'), true);
			if ($allowed_mysqls === false || empty($allowed_mysqls) || !in_array($dbserver, $allowed_mysqls)) {
				throw new Exception("You cannot access this resource", 405);
			}
			// no usernames required for non-admins
			unset($sql_root[$dbserver]['user']);
		}

		unset($sql_root[$dbserver]['password']);
		$sql_root[$dbserver]['id'] = $dbserver;
		$this->logger()->logAction(FroxlorLogger::ADM_ACTION, LOG_INFO, "[API] get database-server '" . $sql_root[$dbserver]['caption'] . "'");
		return $this->response($sql_root[$dbserver]);
	}

	/**
	 * update given mysql-server
	 *
	 * @param int $id
	 *             optional the number of the mysql server (either id or dbserver must be set)
	 * @param int $dbserver
	 *             optional the number of the mysql server (either id or dbserver must be set)
	 * @param string $mysql_host
	 *             ip/hostname of mysql-server
	 * @param string $mysql_port
	 *             optional, port to connect to
	 * @param string $mysql_ca
	 *             optional, path to certificate file
	 * @param string $mysql_verifycert
	 *             optional, verify server certificate
	 * @param string $privileged_user
	 *             privileged user on the mysql-server (must have GRANT privileges)
	 * @param string $privileged_password
	 *             password of privileged user
	 * @param string $description
	 *             optional, description for server
	 * @param bool $allow_all_customers
	 *             optional add this configuration to the list of every existing customer's allowed-mysqlserver-config list, default is false (no)
	 * @param bool $test_connection
	 *             optional, test connection with given credentials, default is true (yes)
	 *
	 * @access admin
	 * @return string json-encoded array
	 * @throws Exception
	 */
	public function update()
	{
		$this->validateAccess();

		$id = (int)$this->getParam('id', true, -1);
		$dn_optional = $id >= 0;
		$dbserver = (int)$this->getParam('dbserver', $dn_optional, -1);
		$dbserver = $id >= 0 ? $id : $dbserver;

		$sql_root = [];
		require Froxlor::getInstallDir() . "/lib/userdata.inc.php";

		if (!isset($sql_root[$dbserver])) {
			throw new Exception('Mysql server not found', 404);
		}

		$result = $sql_root[$dbserver];

		if ($dbserver == 0) {
			$mysql_host = $result['host'];
		} else {
			$mysql_host = $this->getParam('mysql_host', true, $result['host']);
		}
		$mysql_port = $this->getParam('mysql_port', true, $result['port'] ?? 3306);
		$mysql_ca = $this->getParam('mysql_ca', true, $result['ssl']['caFile'] ?? '');
		$mysql_verifycert = $this->getBoolParam('mysql_verifycert', true, $result['ssl']['verifyServerCertificate'] ?? 0);
		$privileged_user = $this->getParam('privileged_user', true, $result['user']);
		$privileged_password = $this->getParam('privileged_password', true, '');
		$description = $this->getParam('description', true, $result['caption']);
		$allow_all_customers = $this->getParam('allow_all_customers', true, 0);
		$test_connection = $this->getParam('test_connection', true, 1);

		// validation
		$mysql_host_chk = Validate::validate_ip2($mysql_host, true, 'invalidip', true, true, false);
		if ($mysql_host_chk === false) {
			$mysql_host_chk = Validate::validateLocalHostname($mysql_host);
			if ($mysql_host_chk === false) {
				$mysql_host_chk = Validate::validateDomain($mysql_host);
				if ($mysql_host_chk === false) {
					throw new Exception("Invalid mysql server ip/hostname", 406);
				}
			}
		}
		$mysql_port = Validate::validate($mysql_port, 'port', Validate::REGEX_PORT, '', [3306], true);
		$mysql_ca = !empty($mysql_ca) ? FileDir::makeCorrectFile($mysql_ca) : '';
		$privileged_user = Validate::validate($privileged_user, 'privileged_user', '/^[a-z][a-z0-9\-_]+$/i', '', [], true);
		$privileged_password = Validate::validate($privileged_password, 'password', '', '', [], true);
		$description = Validate::validate(trim($description), 'description', Validate::REGEX_DESC_TEXT, '', [], true);

		// keep old password?
		if (empty($privileged_password)) {
			$privileged_password = $result['password'];
		}

		if ($mysql_host != $result['host']) {
			// check whether the server is in use by any customer
			$result_ms = $this->databasesOnServer(true, $dbserver);
			if ($result_ms > 0) {
				throw new Exception("Unable to update mysql-host as there are still databases on it", 406);
			}
		}

		// testing connection with given credentials
		if ($test_connection) {
			$options = array(
				PDO::MYSQL_ATTR_INIT_COMMAND => 'SET names utf8'
			);
			if (!empty($mysql_ca)) {
				$options[PDO::MYSQL_ATTR_SSL_CA] = $mysql_ca;
				$options[PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT] = (bool)$mysql_verifycert;
			}

			$dsn = "mysql:host=" . $mysql_host . ";port=" . $mysql_port . ";";
			try {
				$db_test = new \PDO($dsn, $privileged_user, $privileged_password, $options);
				unset($db_test);
			} catch (PDOException $e) {
				throw new Exception("Connection to given mysql database could not be established. Error-message: " . $e->getMessage(), $e->getCode());
			}
		}

		// set new values to sql_root array
		$sql_root[$dbserver] = [
			'caption' => $description,
			'host' => $mysql_host,
			'port' => $mysql_port,
			'user' => $privileged_user,
			'password' => $privileged_password,
			'ssl' => [
				'caFile' => $mysql_ca ?? "",
				'verifyServerCertificate' => $mysql_verifycert ?? false
			]
		];

		$this->generateNewUserData($sql, $sql_root);

		if ($allow_all_customers) {
			$this->addDatabaseFromCustomerAllowedList($dbserver);
		}

		$this->logger()->logAction(FroxlorLogger::ADM_ACTION, LOG_WARNING, "[API] edited database server '" . $description . "' (" . $mysql_host . ")");

		return $this->response(['true']);
	}

	/**
	 * check whether a given customer / current user (as customer) has
	 * databases on the given dbserver
	 *
	 * @param int $mysql_server
	 * @param int $customerid
	 *            optional, admin-only, select ftp-users of a specific customer by id
	 * @param string $loginname
	 *            optional, admin-only, select ftp-users of a specific customer by loginname
	 *
	 * @access admin, customer
	 * @return string json-encoded array count
	 */
	public function databasesOnServer(bool $internal_all = false, int $dbserver = 0)
	{
		if ($internal_all) {
			$result_stmt = Database::prepare("
				SELECT COUNT(*) num_dbs FROM `" . TABLE_PANEL_DATABASES . "`
				WHERE `dbserver` = :dbserver
			");
			$result = Database::pexecute_first($result_stmt, ['dbserver' => $dbserver], true, true);
			return (int)$result['num_dbs'];
		} else {
			$dbserver = $this->getParam('mysql_server');
			$customer_ids = $this->getAllowedCustomerIds();
			$result_stmt = Database::prepare("
				SELECT COUNT(*) num_dbs FROM `" . TABLE_PANEL_DATABASES . "`
				WHERE `customerid` IN (" . implode(", ", $customer_ids) . ") AND `dbserver` = :dbserver
			");
			$result = Database::pexecute_first($result_stmt, ['dbserver' => $dbserver], true, true);
			return $this->response(['count' => $result['num_dbs']]);
		}
	}

	private function removeDatabaseFromCustomerAllowedList(int $dbserver)
	{
		$sel_stmt = Database::prepare("
			SELECT customerid, allowed_mysqlserver FROM `" . TABLE_PANEL_CUSTOMERS . "`
		");
		Database::pexecute($sel_stmt);
		$upd_stmt = Database::prepare("
			UPDATE `" . TABLE_PANEL_CUSTOMERS . "` SET
			`allowed_mysqlserver` = :am WHERE `customerid` = :cid
		");
		while ($customer = $sel_stmt->fetch(PDO::FETCH_ASSOC)) {
			$allowed_mysqls = json_decode(($customer['allowed_mysqlserver'] ?? '[]'), true);
			if (($key = array_search($dbserver, $allowed_mysqls)) !== false) {
				unset($allowed_mysqls[$key]);
				$allowed_mysqls = json_encode($allowed_mysqls);
				Database::pexecute($upd_stmt, ['am' => $allowed_mysqls, 'cid' => $customer['customerid']]);
			}
		}
	}

	private function addDatabaseFromCustomerAllowedList(int $dbserver)
	{
		$sel_stmt = Database::prepare("
			SELECT customerid, allowed_mysqlserver FROM `" . TABLE_PANEL_CUSTOMERS . "`
		");
		Database::pexecute($sel_stmt);
		$upd_stmt = Database::prepare("
			UPDATE `" . TABLE_PANEL_CUSTOMERS . "` SET
			`allowed_mysqlserver` = :am WHERE `customerid` = :cid
		");
		while ($customer = $sel_stmt->fetch(PDO::FETCH_ASSOC)) {
			$allowed_mysqls = json_decode(($customer['allowed_mysqlserver'] ?: '[]'), true);
			if (!in_array($dbserver, $allowed_mysqls)) {
				$allowed_mysqls[] = $dbserver;
				$allowed_mysqls = json_encode($allowed_mysqls);
				Database::pexecute($upd_stmt, ['am' => $allowed_mysqls, 'cid' => $customer['customerid']]);
			}
		}
	}

	/**
	 * write new userdata.inc.php file
	 */
	private function generateNewUserData(array $sql, array $sql_root)
	{
		$content = PhpHelper::parseArrayToPhpFile(
			['sql' => $sql, 'sql_root' => $sql_root],
			'automatically generated userdata.inc.php for froxlor'
		);
		chmod(Froxlor::getInstallDir() . "/lib/userdata.inc.php", 0700);
		file_put_contents(Froxlor::getInstallDir() . "/lib/userdata.inc.php", $content);
		chmod(Froxlor::getInstallDir() . "/lib/userdata.inc.php", 0400);
		clearstatcache();
		if (function_exists('opcache_invalidate')) {
			@opcache_invalidate(Froxlor::getInstallDir() . "/lib/userdata.inc.php", true);
		}
	}
}
