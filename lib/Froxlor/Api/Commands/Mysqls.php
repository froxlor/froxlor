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
use Froxlor\Database\DbManager;
use Froxlor\FroxlorLogger;
use Froxlor\Settings;
use Froxlor\System\Crypt;
use Froxlor\UI\Response;
use Froxlor\User;
use Froxlor\Validate\Validate;
use PDO;

/**
 * @since 0.10.0
 */
class Mysqls extends ApiCommand implements ResourceEntity
{

	/**
	 * add a new mysql-database
	 *
	 * @param string $mysql_password
	 *            password for the created database and database-user
	 * @param int $mysql_server
	 *            optional, default is 0
	 * @param string $description
	 *            optional, description for database
	 * @param string $custom_suffix
	 *            optional, name for database if customer.mysqlprefix setting is set to "DBNAME"
	 * @param bool $sendinfomail
	 *            optional, send created resource-information to customer, default: false
	 * @param int $customerid
	 *            optional, required when called as admin (if $loginname is not specified)
	 * @param string $loginname
	 *            optional, required when called as admin (if $customerid is not specified)
	 *
	 * @access admin, customer
	 * @return string json-encoded array
	 * @throws Exception
	 */
	public function add()
	{
		if (($this->getUserDetail('mysqls_used') < $this->getUserDetail('mysqls') || $this->getUserDetail('mysqls') == '-1') || $this->isAdmin()) {
			// required parameters
			$password = $this->getParam('mysql_password');

			// parameters
			$databasedescription = $this->getParam('description', true, '');
			$databasename = $this->getParam('custom_suffix', true, '');
			$sendinfomail = $this->getBoolParam('sendinfomail', true, 0);
			// get needed customer info to reduce the mysql-usage-counter by one
			$customer = $this->getCustomerData('mysqls');
			$dbserver = $this->getParam('mysql_server', true, $this->getDefaultMySqlServer($customer));

			// validation
			$password = Validate::validate($password, 'password', '', '', [], true);
			$password = Crypt::validatePassword($password, true);
			$databasedescription = Validate::validate(trim($databasedescription), 'description', Validate::REGEX_DESC_TEXT, '', [], true);
			if (!empty($databasename)) {
				$databasename = Validate::validate(trim($databasename), 'database_name', '/^[A-Za-z0-9][A-Za-z0-9\-_]+$/i', '', [], true);
			}

			// validate whether the dbserver exists
			$dbserver = Validate::validate($dbserver, html_entity_decode(lng('mysql.mysql_server')), '/^[0-9]+$/', '', 0, true);
			// enforce per-customer allowed_mysqlserver allowlist
			if (!$this->isAdmin()) {
				$allowed = json_decode($customer['allowed_mysqlserver'] ?? '[]', true);
				if (!is_array($allowed) || empty($allowed)
					|| !in_array((int)$dbserver, array_map('intval', $allowed), true)) {
					throw new Exception('You cannot access this resource', 405);
				}
			}
			Database::needRoot(true, $dbserver, false);
			Database::needSqlData();
			$sql_root = Database::getSqlData();
			Database::needRoot(false);
			if (!is_array($sql_root)) {
				throw new Exception("Database server with index #" . $dbserver . " is unknown", 404);
			}

			if ($sendinfomail != 1) {
				$sendinfomail = 0;
			}

			$newdb_params = [
				'loginname' => ($this->isAdmin() ? $customer['loginname'] : $this->getUserDetail('loginname')),
				'mysql_lastaccountnumber' => ($this->isAdmin() ? $customer['mysql_lastaccountnumber'] : $this->getUserDetail('mysql_lastaccountnumber'))
			];
			// create database, user, set permissions, etc.pp.
			$dbm = new DbManager($this->logger());

			if (strtoupper(Settings::Get('customer.mysqlprefix')) == 'DBNAME' && !empty($databasename)) {
				if (strlen($newdb_params['loginname'] . '_' . $databasename) > Database::getSqlUsernameLength()) {
					throw new Exception("Database name cannot be longer than " . (Database::getSqlUsernameLength() - strlen($newdb_params['loginname'] . '_')) . " characters.", 406);
				}
				$username = $dbm->createDatabase($newdb_params['loginname'] . '_' . $databasename, $password, $dbserver, 0, $newdb_params['loginname']);
			} else {
				$username = $dbm->createDatabase($newdb_params['loginname'], $password, $dbserver, $newdb_params['mysql_lastaccountnumber'], $newdb_params['loginname']);
			}

			// we've checked against the password in dbm->createDatabase
			if ($username == false) {
				Response::standardError('passwordshouldnotbeusername', '', true);
			}

			// add database info to froxlor
			$stmt = Database::prepare("
				INSERT INTO `" . TABLE_PANEL_DATABASES . "`
				SET
				`customerid` = :customerid,
				`databasename` = :databasename,
				`description` = :description,
				`dbserver` = :dbserver
			");
			$params = [
				"customerid" => $customer['customerid'],
				"databasename" => $username,
				"description" => $databasedescription,
				"dbserver" => $dbserver
			];
			Database::pexecute($stmt, $params, true, true);
			$databaseid = Database::lastInsertId();
			$params['id'] = $databaseid;

			// update customer usage
			Customers::increaseUsage($customer['customerid'], 'mysqls_used');
			Customers::increaseUsage($customer['customerid'], 'mysql_lastaccountnumber');

			// send info-mail?
			if ($sendinfomail == 1) {
				$pma = lng('admin.notgiven');
				if (Settings::Get('panel.phpmyadmin_url') != '') {
					$pma = Settings::Get('panel.phpmyadmin_url');
				}

				Database::needRoot(true, $dbserver, false);
				Database::needSqlData();
				$sql_root = Database::getSqlData();
				Database::needRoot(false);
				$userinfo = $customer;

				$replace_arr = [
					'SALUTATION' => User::getCorrectUserSalutation($userinfo),
					'CUST_NAME' => User::getCorrectUserSalutation($userinfo), // < keep this for compatibility
					'NAME' => $userinfo['name'],
					'FIRSTNAME' => $userinfo['firstname'],
					'COMPANY' => $userinfo['company'],
					'USERNAME' => $userinfo['loginname'],
					'CUSTOMER_NO' => $userinfo['customernumber'],
					'DB_NAME' => $username,
					'DB_PASS' => htmlentities(htmlentities($password)),
					'DB_DESC' => $databasedescription,
					'DB_SRV' => $sql_root['host'],
					'PMA_URI' => $pma
				];

				// get template for mail subject
				$mail_subject = $this->getMailTemplate($userinfo, 'mails', 'new_database_by_customer_subject', $replace_arr, lng('mails.new_database_by_customer.subject'));
				// get template for mail body
				$mail_body = $this->getMailTemplate($userinfo, 'mails', 'new_database_by_customer_mailbody', $replace_arr, lng('mails.new_database_by_customer.mailbody'));

				$_mailerror = false;
				$mailerr_msg = "";
				try {
					$this->mailer()->Subject = $mail_subject;
					$this->mailer()->AltBody = $mail_body;
					$this->mailer()->Body = str_replace("\n", "<br />", $mail_body);
					$this->mailer()->addAddress($userinfo['email'], User::getCorrectUserSalutation($userinfo));
					$this->mailer()->send();
				} catch (\PHPMailer\PHPMailer\Exception $e) {
					$mailerr_msg = $e->errorMessage();
					$_mailerror = true;
				} catch (Exception $e) {
					$mailerr_msg = $e->getMessage();
					$_mailerror = true;
				}

				if ($_mailerror) {
					$this->logger()->logAction($this->isAdmin() ? FroxlorLogger::ADM_ACTION : FroxlorLogger::USR_ACTION, LOG_ERR, "[API] Error sending mail: " . $mailerr_msg);
					Response::standardError('errorsendingmail', $userinfo['email'], true);
				}

				$this->mailer()->clearAddresses();
			}
			$this->logger()->logAction($this->isAdmin() ? FroxlorLogger::ADM_ACTION : FroxlorLogger::USR_ACTION, LOG_NOTICE, "[API] added mysql-database '" . $username . "'");

			$result = $this->apiCall('Mysqls.get', [
				'dbname' => $username,
				'mysql_server' => $dbserver
			]);
			return $this->response($result);
		}
		throw new Exception("No more resources available", 406);
	}

	/**
	 * return a mysql database entry by either id or dbname
	 *
	 * @param int $id
	 *            optional, the database-id
	 * @param string $dbname
	 *            optional, the databasename
	 * @param int $mysql_server
	 *            optional, specify database-server, default is none
	 *
	 * @access admin, customer
	 * @return string json-encoded array
	 * @throws Exception
	 */
	public function get()
	{
		$id = $this->getParam('id', true, 0);
		$dn_optional = $id > 0;
		$dbname = $this->getParam('dbname', $dn_optional, '');
		$dbserver = $this->getParam('mysql_server', true, -1);

		if ($dbserver != -1) {
			$dbserver = Validate::validate($dbserver, html_entity_decode(lng('mysql.mysql_server')), '/^[0-9]+$/', '', 0, true);
		}

		if ($this->isAdmin()) {
			if ($this->getUserDetail('customers_see_all') != 1) {
				// if it's a reseller or an admin who cannot see all customers, we need to check
				// whether the database belongs to one of his customers
				$_custom_list_result = $this->apiCall('Customers.listing');
				$custom_list_result = $_custom_list_result['list'];
				$customer_ids = [];
				foreach ($custom_list_result as $customer) {
					$customer_ids[] = $customer['customerid'];
				}
				if (count($customer_ids) > 0) {
					$result_stmt = Database::prepare("
						SELECT * FROM `" . TABLE_PANEL_DATABASES . "`
						WHERE " . ($id > 0 ? "`id` = :iddn" : "`databasename` = :iddn") . ($dbserver >= 0 ? " AND `dbserver` = :dbserver" : "") . " AND `customerid` IN (" . implode(", ", $customer_ids) . ")
					");
					$params = [
						'iddn' => ($id <= 0 ? $dbname : $id)
					];
					if ($dbserver >= 0) {
						$params['dbserver'] = $dbserver;
					}
				} else {
					throw new Exception("You do not have any customers yet", 406);
				}
			} else {
				$result_stmt = Database::prepare("
					SELECT * FROM `" . TABLE_PANEL_DATABASES . "`
					WHERE " . ($id > 0 ? "`id` = :iddn" : "`databasename` = :iddn") . ($dbserver >= 0 ? " AND `dbserver` = :dbserver" : ""));
				$params = [
					'iddn' => ($id <= 0 ? $dbname : $id)
				];
				if ($dbserver >= 0) {
					$params['dbserver'] = $dbserver;
				}
			}
		} else {
			if (Settings::IsInList('panel.customer_hide_options', 'mysql')) {
				throw new Exception("You cannot access this resource", 405);
			}
			$result_stmt = Database::prepare("
				SELECT * FROM `" . TABLE_PANEL_DATABASES . "`
				WHERE `customerid`= :customerid AND " . ($id > 0 ? "`id` = :iddn" : "`databasename` = :iddn") . ($dbserver >= 0 ? " AND `dbserver` = :dbserver" : ""));
			$params = [
				'customerid' => $this->getUserDetail('customerid'),
				'iddn' => ($id <= 0 ? $dbname : $id)
			];
			if ($dbserver >= 0) {
				$params['dbserver'] = $dbserver;
			}
		}
		$result = Database::pexecute_first($result_stmt, $params, true, true);
		if ($result) {
			Database::needRoot(true, $result['dbserver'], false);
			$mbdata_stmt = Database::prepare("
				SELECT SUM(data_length + index_length) as MB FROM information_schema.TABLES
				WHERE table_schema = :table_schema
				GROUP BY table_schema
			");
			Database::pexecute($mbdata_stmt, [
				"table_schema" => $result['databasename']
			], true, true);
			$mbdata = $mbdata_stmt->fetch(PDO::FETCH_ASSOC);
			Database::needRoot(false);
			$result['size'] = $mbdata['MB'] ?? 0;
			$this->logger()->logAction($this->isAdmin() ? FroxlorLogger::ADM_ACTION : FroxlorLogger::USR_ACTION, LOG_INFO, "[API] get database '" . $result['databasename'] . "'");
			return $this->response($result);
		}
		$key = ($id > 0 ? "id #" . $id : "dbname '" . $dbname . "'");
		throw new Exception("MySQL database with " . $key . " could not be found", 404);
	}

	/**
	 * update a mysql database entry by either id or dbname
	 *
	 * @param int $id
	 *            optional, the database-id
	 * @param string $dbname
	 *            optional, the databasename
	 * @param int $mysql_server
	 *            optional, specify database-server, default is none
	 * @param string $mysql_password
	 *            optional, update password for the database
	 * @param string $description
	 *            optional, description for database
	 * @param int $customerid
	 *            optional, required when called as admin (if $loginname is not specified)
	 * @param string $loginname
	 *            optional, required when called as admin (if $customerid is not specified)
	 *
	 * @access admin, customer
	 * @return string json-encoded array
	 * @throws Exception
	 */
	public function update()
	{
		$id = $this->getParam('id', true, 0);
		$dn_optional = $id > 0;
		$dbname = $this->getParam('dbname', $dn_optional, '');
		$dbserver = $this->getParam('mysql_server', true, -1);
		$customer = $this->getCustomerData();

		if ($this->isAdmin() == false && Settings::IsInList('panel.customer_hide_options', 'mysql')) {
			throw new Exception("You cannot access this resource", 405);
		}

		$result = $this->apiCall('Mysqls.get', [
			'id' => $id,
			'dbname' => $dbname,
			'mysql_server' => $dbserver
		]);
		$id = $result['id'];

		// parameters
		$password = $this->getParam('mysql_password', true, '');
		$databasedescription = $this->getParam('description', true, $result['description']);

		// validation
		$password = Validate::validate($password, 'password', '', '', [], true);
		$databasedescription = Validate::validate(trim($databasedescription), 'description', Validate::REGEX_DESC_TEXT, '', [], true);

		if ($password != '') {
			// validate password
			$password = Crypt::validatePassword($password, true);

			if ($password == $result['databasename']) {
				Response::standardError('passwordshouldnotbeusername', '', true);
			}

			// Begin root-session
			Database::needRoot(true, $result['dbserver'], false);
			$dbmgr = new DbManager($this->logger());
			foreach (array_map('trim', explode(',', Settings::Get('system.mysql_access_host'))) as $mysql_access_host) {
				$dbmgr->getManager()->grantPrivilegesTo($result['databasename'], $password, $mysql_access_host, false, true);
			}

			$stmt = Database::prepare("FLUSH PRIVILEGES");
			Database::pexecute($stmt, null, true, true);
			Database::needRoot(false);
			// End root-session
		}
		$stmt = Database::prepare("
			UPDATE `" . TABLE_PANEL_DATABASES . "`
			SET `description` = :desc
			WHERE `customerid` = :customerid
			AND `id` = :id
		");
		$params = [
			"desc" => $databasedescription,
			"customerid" => $customer['customerid'],
			"id" => $id
		];
		Database::pexecute($stmt, $params, true, true);

		$this->logger()->logAction($this->isAdmin() ? FroxlorLogger::ADM_ACTION : FroxlorLogger::USR_ACTION, LOG_NOTICE, "[API] updated mysql-database '" . $result['databasename'] . "'");
		$result = $this->apiCall('Mysqls.get', [
			'dbname' => $result['databasename']
		]);
		return $this->response($result);
	}

	/**
	 * list all databases, if called from an admin, list all databases of all customers you are allowed to view, or
	 * specify id or loginname for one specific customer
	 *
	 * @param int $mysql_server
	 *            optional, specify dbserver to select from, else use all available
	 * @param int $customerid
	 *            optional, admin-only, select dbs of a specific customer by id
	 * @param string $loginname
	 *            optional, admin-only, select dbs of a specific customer by loginname
	 * @param array $sql_search
	 *            optional array with index = fieldname, and value = array with 'op' => operator (one of <, > or =),
	 *            LIKE is used if left empty and 'value' => searchvalue
	 * @param int $sql_limit
	 *            optional specify number of results to be returned
	 * @param int $sql_offset
	 *            optional specify offset for resultset
	 * @param array $sql_orderby
	 *            optional array with index = fieldname and value = ASC|DESC to order the resultset by one or more
	 *            fields
	 *
	 * @access admin, customer
	 * @return string json-encoded array count|list
	 * @throws Exception
	 */
	public function listing()
	{
		$result = [];
		$dbserver = $this->getParam('mysql_server', true, -1);
		$customer_ids = $this->getAllowedCustomerIds('mysql');
		$query_fields = [];
		$result_stmt = Database::prepare("
			SELECT * FROM `" . TABLE_PANEL_DATABASES . "`
			WHERE `customerid`= :customerid AND `dbserver` = :dbserver" . $this->getSearchWhere($query_fields, true) . $this->getOrderBy() . $this->getLimit());
		if ($dbserver < 0) {
			// use all dbservers
			$dbservers_stmt = Database::query("SELECT DISTINCT `dbserver` FROM `" . TABLE_PANEL_DATABASES . "`");
			$dbservers = $dbservers_stmt->fetchAll(PDO::FETCH_ASSOC);
		} else {
			// use specific dbserver
			$dbservers = [
				[
					'dbserver' => $dbserver
				]
			];
		}

		foreach ($customer_ids as $customer_id) {
			foreach ($dbservers as $_dbserver) {
				Database::pexecute($result_stmt, array_merge([
					'customerid' => $customer_id,
					'dbserver' => $_dbserver['dbserver']
				], $query_fields), true, true);
				// Begin root-session
				Database::needRoot(true, $_dbserver['dbserver'], false);
				while ($row = $result_stmt->fetch(PDO::FETCH_ASSOC)) {
					$mbdata_stmt = Database::prepare("
						SELECT SUM(data_length + index_length) as MB FROM information_schema.TABLES
						WHERE table_schema = :table_schema
						GROUP BY table_schema
					");
					Database::pexecute($mbdata_stmt, [
						"table_schema" => $row['databasename']
					], true, true);
					$mbdata = $mbdata_stmt->fetch(PDO::FETCH_ASSOC);
					$row['size'] = $mbdata['MB'] ?? 0;
					$result[] = $row;
				}
				Database::needRoot(false);
			}
		}
		return $this->response([
			'count' => count($result),
			'list' => $result
		]);
	}

	/**
	 * returns the total number of accessible databases
	 *
	 * @param int $customerid
	 *            optional, admin-only, select dbs of a specific customer by id
	 * @param string $loginname
	 *            optional, admin-only, select dbs of a specific customer by loginname
	 *
	 * @access admin, customer
	 * @return string json-encoded response message
	 * @throws Exception
	 */
	public function listingCount()
	{
		$customer_ids = $this->getAllowedCustomerIds('mysql');
		$query_fields = [];
		$result_stmt = Database::prepare("
			SELECT COUNT(*) as num_dbs FROM `" . TABLE_PANEL_DATABASES . "`
			WHERE `customerid` IN (" . implode(", ", $customer_ids) . ")
		" . $this->getSearchWhere($query_fields, true));
		$result = Database::pexecute_first($result_stmt, $query_fields, true, true);
		if ($result) {
			return $this->response($result['num_dbs']);
		}
		return $this->response(0);
	}

	/**
	 * delete a mysql database by either id or dbname
	 *
	 * @param int $id
	 *            optional, the database-id
	 * @param string $dbname
	 *            optional, the databasename
	 * @param int $mysql_server
	 *            optional, specify database-server, default is none
	 * @param int $customerid
	 *            optional, required when called as admin (if $loginname is not specified)
	 * @param string $loginname
	 *            optional, required when called as admin (if $customerid is not specified)
	 *
	 * @access admin, customer
	 * @return string json-encoded array
	 * @throws Exception
	 */
	public function delete()
	{
		$id = $this->getParam('id', true, 0);
		$dn_optional = $id > 0;
		$dbname = $this->getParam('dbname', $dn_optional, '');
		$dbserver = $this->getParam('mysql_server', true, -1);
		$customer = $this->getCustomerData();

		if ($this->isAdmin() == false && Settings::IsInList('panel.customer_hide_options', 'mysql')) {
			throw new Exception("You cannot access this resource", 405);
		}

		$result = $this->apiCall('Mysqls.get', [
			'id' => $id,
			'dbname' => $dbname,
			'mysql_server' => $dbserver
		]);
		$id = $result['id'];

		// Begin root-session
		Database::needRoot(true, $result['dbserver'], false);
		$dbm = new DbManager($this->logger());
		$dbm->getManager()->deleteDatabase($result['databasename'], $customer['loginname']);
		Database::needRoot(false);
		// End root-session

		// delete from table
		$stmt = Database::prepare("DELETE FROM `" . TABLE_PANEL_DATABASES . "` WHERE `id` = :id");
		Database::pexecute($stmt, [
			"id" => $id
		], true, true);

		// get needed customer info to reduce the mysql-usage-counter by one
		$mysql_used = $customer['mysqls_used'];

		// reduce mysql-usage-counter
		$resetaccnumber = ($mysql_used == '1') ? " , `mysql_lastaccountnumber` = '0' " : '';
		Customers::decreaseUsage($customer['customerid'], 'mysqls_used', $resetaccnumber);

		$this->logger()->logAction($this->isAdmin() ? FroxlorLogger::ADM_ACTION : FroxlorLogger::USR_ACTION, LOG_WARNING, "[API] deleted database '" . $result['databasename'] . "'");
		return $this->response($result);
	}

	private function getDefaultMySqlServer(array $customer) {
		$allowed_mysqlservers = json_decode($customer['allowed_mysqlserver'] ?? '[]', true);
		asort($allowed_mysqlservers, SORT_NUMERIC);
		if (count($allowed_mysqlservers) == 1 && $allowed_mysqlservers[0] != 0) {
			return (int) $allowed_mysqlservers[0];
		}
		return (int) array_shift($allowed_mysqlservers);
	}
}
