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
use Froxlor\Cron\TaskId;
use Froxlor\Database\Database;
use Froxlor\FileDir;
use Froxlor\FroxlorLogger;
use Froxlor\Settings;
use Froxlor\System\Cronjob;
use Froxlor\System\Crypt;
use Froxlor\UI\Response;
use Froxlor\Validate\Validate;
use PDO;

/**
 * @since 0.10.0
 */
class DirProtections extends ApiCommand implements ResourceEntity
{

	/**
	 * add htaccess protection to a given directory
	 *
	 * @param int $customerid
	 *            optional, required when called as admin (if $loginname is not specified)
	 * @param string $loginname
	 *            optional, required when called as admin (if $customerid is not specified)
	 * @param string $path
	 * @param string $username
	 * @param string $directory_password
	 * @param string $directory_authname
	 *            optional name/description for the protection
	 *
	 * @access admin, customer
	 * @return string json-encoded array
	 * @throws Exception
	 */
	public function add()
	{
		if ($this->isAdmin() == false && Settings::IsInList('panel.customer_hide_options', 'extras')) {
			throw new Exception("You cannot access this resource", 405);
		}
		if ($this->isAdmin() == false && Settings::IsInList('panel.customer_hide_options', 'extras.directoryprotection')) {
			throw new Exception("You cannot access this resource", 405);
		}

		// get needed customer info to reduce the email-address-counter by one
		$customer = $this->getCustomerData();

		// required parameters
		$path = $this->getParam('path');
		$username = $this->getParam('username');
		$password = $this->getParam('directory_password');

		// parameters
		$authname = $this->getParam('directory_authname', true, '');

		// validation
		$path = FileDir::makeCorrectDir(Validate::validate($path, 'path', Validate::REGEX_DIR, '', [], true));
		$path = FileDir::makeCorrectDir($customer['documentroot'] . '/' . $path, $customer['documentroot']);
		$username = Validate::validate($username, 'username', '/^[a-zA-Z0-9][a-zA-Z0-9\-_]+\$?$/', '', [], true);
		$authname = Validate::validate($authname, 'directory_authname', '/^[a-zA-Z0-9][a-zA-Z0-9\-_ ]+\$?$/', '', [], true);
		$password = Validate::validate($password, 'password', '', '', [], true);
		$password = Crypt::validatePassword($password, true);

		// check for duplicate usernames for the path
		$username_path_check_stmt = Database::prepare("
			SELECT `id`, `username`, `path` FROM `" . TABLE_PANEL_HTPASSWDS . "`
			WHERE `username`= :username AND `path`= :path AND `customerid`= :customerid
		");
		$params = [
			"username" => $username,
			"path" => $path,
			"customerid" => $customer['customerid']
		];
		$username_path_check = Database::pexecute_first($username_path_check_stmt, $params, true, true);

		$password_enc = Crypt::makeCryptPassword($password, true);

		// duplicate check
		if ($username_path_check && $username_path_check['username'] == $username && $username_path_check['path'] == $path) {
			Response::standardError('userpathcombinationdupe', '', true);
		} elseif ($password == $username) {
			Response::standardError('passwordshouldnotbeusername', '', true);
		}

		// insert the entry
		$stmt = Database::prepare("
			INSERT INTO `" . TABLE_PANEL_HTPASSWDS . "` SET
			`customerid` = :customerid,
			`username` = :username,
			`password` = :password,
			`path` = :path,
			`authname` = :authname
		");
		$params = [
			"customerid" => $customer['customerid'],
			"username" => $username,
			"password" => $password_enc,
			"path" => $path,
			"authname" => $authname
		];
		Database::pexecute($stmt, $params, true, true);
		$id = Database::lastInsertId();
		$this->logger()->logAction($this->isAdmin() ? FroxlorLogger::ADM_ACTION : FroxlorLogger::USR_ACTION, LOG_NOTICE, "[API] added directory-protection for '" . $username . " (" . $path . ")'");
		Cronjob::inserttask(TaskId::REBUILD_VHOST);

		$result = $this->apiCall('DirProtections.get', [
			'id' => $id
		]);
		return $this->response($result);
	}

	/**
	 * return a directory-protection entry by either id or username
	 *
	 * @param int $id
	 *            optional, the directory-protection-id
	 * @param string $username
	 *            optional, the username
	 *
	 * @access admin, customer
	 * @return string json-encoded array
	 * @throws Exception
	 */
	public function get()
	{
		if ($this->isAdmin() == false && Settings::IsInList('panel.customer_hide_options', 'extras')) {
			throw new Exception("You cannot access this resource", 405);
		}

		$id = $this->getParam('id', true, 0);
		$un_optional = $id > 0;
		$username = $this->getParam('username', $un_optional, '');

		$params = [];
		if ($this->isAdmin()) {
			if ($this->getUserDetail('customers_see_all') == false) {
				// if it's a reseller or an admin who cannot see all customers, we need to check
				// whether the database belongs to one of his customers
				$_custom_list_result = $this->apiCall('Customers.listing');
				$custom_list_result = $_custom_list_result['list'];
				$customer_ids = [];
				foreach ($custom_list_result as $customer) {
					$customer_ids[] = $customer['customerid'];
				}
				$result_stmt = Database::prepare("
					SELECT * FROM `" . TABLE_PANEL_HTPASSWDS . "`
					WHERE `customerid` IN (" . implode(", ", $customer_ids) . ")
					AND (`id` = :idun OR `username` = :idun)
				");
			} else {
				$result_stmt = Database::prepare("
					SELECT * FROM `" . TABLE_PANEL_HTPASSWDS . "`
					WHERE (`id` = :idun OR `username` = :idun)
				");
			}
		} else {
			if (Settings::IsInList('panel.customer_hide_options', 'extras.directoryprotection')) {
				throw new Exception("You cannot access this resource", 405);
			}
			$result_stmt = Database::prepare("
				SELECT * FROM `" . TABLE_PANEL_HTPASSWDS . "`
				WHERE `customerid` = :customerid
				AND (`id` = :idun OR `username` = :idun)
			");
			$params['customerid'] = $this->getUserDetail('customerid');
		}
		$params['idun'] = ($id <= 0 ? $username : $id);
		$result = Database::pexecute_first($result_stmt, $params, true, true);
		if ($result) {
			if (!$this->isInternal()) {
				// unset sensitive data
				unset($result['password']);
			}
			$this->logger()->logAction($this->isAdmin() ? FroxlorLogger::ADM_ACTION : FroxlorLogger::USR_ACTION, LOG_INFO, "[API] get directory protection for '" . $result['path'] . "'");
			return $this->response($result);
		}
		$key = ($id > 0 ? "id #" . $id : "username '" . $username . "'");
		throw new Exception("Directory protection with " . $key . " could not be found", 404);
	}

	/**
	 * update htaccess protection of a given directory
	 *
	 * @param int $id
	 *            optional the directory-protection-id
	 * @param string $username
	 *            optional, the username
	 * @param int $customerid
	 *            optional, required when called as admin (if $loginname is not specified)
	 * @param string $loginname
	 *            optional, required when called as admin (if $customerid is not specified)
	 * @param string $directory_password
	 *            optional, leave empty for no change
	 * @param string $directory_authname
	 *            optional name/description for the protection
	 *
	 * @access admin, customer
	 * @return string json-encoded array
	 * @throws Exception
	 */
	public function update()
	{
		$id = $this->getParam('id', true, 0);
		$un_optional = $id > 0;
		$username = $this->getParam('username', $un_optional, '');

		// validation
		$result = $this->apiCall('DirProtections.get', [
			'id' => $id,
			'username' => $username
		]);
		$id = $result['id'];

		// parameters
		$password = $this->getParam('directory_password', true, '');
		$authname = $this->getParam('directory_authname', true, $result['authname']);

		// get needed customer info
		$customer = $this->getCustomerData();

		// validation
		$authname = Validate::validate($authname, 'directory_authname', '/^[a-zA-Z0-9][a-zA-Z0-9\-_ ]+\$?$/', '', [], true);
		$password = Validate::validate($password, 'password', '', '', [], true);
		$password = Crypt::validatePassword($password, true);

		$upd_query = "";
		$upd_params = [
			"id" => $result['id'],
			"cid" => $customer['customerid']
		];
		if (!empty($password)) {
			if ($password == $result['username']) {
				Response::standardError('passwordshouldnotbeusername', '', true);
			}
			$password_enc = Crypt::makeCryptPassword($password, true);

			$upd_query .= "`password`= :password_enc";
			$upd_params['password_enc'] = $password_enc;
		}
		if ($authname != $result['authname']) {
			if (!empty($upd_query)) {
				$upd_query .= ", ";
			}
			$upd_query .= "`authname` = :authname";
			$upd_params['authname'] = $authname;
		}

		// build update query
		if (!empty($upd_query)) {
			$upd_stmt = Database::prepare("
				UPDATE `" . TABLE_PANEL_HTPASSWDS . "` SET " . $upd_query . " WHERE `id` = :id AND `customerid`= :cid
			");
			Database::pexecute($upd_stmt, $upd_params, true, true);
			Cronjob::inserttask(TaskId::REBUILD_VHOST);
		}

		$this->logger()->logAction($this->isAdmin() ? FroxlorLogger::ADM_ACTION : FroxlorLogger::USR_ACTION, LOG_NOTICE, "[API] updated directory-protection '" . $result['username'] . " (" . $result['path'] . ")'");
		$result = $this->apiCall('DirProtections.get', [
			'id' => $result['id']
		]);
		return $this->response($result);
	}

	/**
	 * list all directory-protections, if called from an admin, list all directory-protections of all customers you are
	 * allowed to view, or specify id or loginname for one specific customer
	 *
	 * @param int $customerid
	 *            optional, admin-only, select directory-protections of a specific customer by id
	 * @param string $loginname
	 *            optional, admin-only, select directory-protections of a specific customer by loginname
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
		if ($this->isAdmin() == false && Settings::IsInList('panel.customer_hide_options', 'extras')) {
			throw new Exception("You cannot access this resource", 405);
		}
		$customer_ids = $this->getAllowedCustomerIds('extras.directoryprotection');

		$result = [];
		$query_fields = [];
		$result_stmt = Database::prepare("
			SELECT * FROM `" . TABLE_PANEL_HTPASSWDS . "`
			WHERE `customerid` IN (" . implode(', ', $customer_ids) . ")" . $this->getSearchWhere($query_fields, true) . $this->getOrderBy() . $this->getLimit());
		Database::pexecute($result_stmt, $query_fields, true, true);
		while ($row = $result_stmt->fetch(PDO::FETCH_ASSOC)) {
			// unset sensitive data
			unset($row['password']);
			$result[] = $row;
		}
		$this->logger()->logAction($this->isAdmin() ? FroxlorLogger::ADM_ACTION : FroxlorLogger::USR_ACTION, LOG_INFO, "[API] list directory-protections");
		return $this->response([
			'count' => count($result),
			'list' => $result
		]);
	}

	/**
	 * returns the total number of accessible directory protections
	 *
	 * @param int $customerid
	 *            optional, admin-only, select directory-protections of a specific customer by id
	 * @param string $loginname
	 *            optional, admin-only, select directory-protections of a specific customer by loginname
	 *
	 * @access admin, customer
	 * @return string json-encoded response message
	 * @throws Exception
	 */
	public function listingCount()
	{
		if ($this->isAdmin() == false && Settings::IsInList('panel.customer_hide_options', 'extras')) {
			throw new Exception("You cannot access this resource", 405);
		}
		$customer_ids = $this->getAllowedCustomerIds('extras.directoryprotection');

		$result = [];
		$query_fields = [];
		$result_stmt = Database::prepare("
			SELECT COUNT(*) as num_htpasswd FROM `" . TABLE_PANEL_HTPASSWDS . "`
			WHERE `customerid` IN (" . implode(', ', $customer_ids) . ")
		" . $this->getSearchWhere($query_fields, true));
		$result = Database::pexecute_first($result_stmt, $query_fields, true, true);
		if ($result) {
			return $this->response($result['num_htpasswd']);
		}
		return $this->response(0);
	}

	/**
	 * delete a directory-protection by either id or username
	 *
	 * @param int $id
	 *            optional, the directory-protection-id
	 * @param string $username
	 *            optional, the username
	 *
	 * @access admin, customer
	 * @return string json-encoded array
	 * @throws Exception
	 */
	public function delete()
	{
		if ($this->isAdmin() == false && Settings::IsInList('panel.customer_hide_options', 'extras')) {
			throw new Exception("You cannot access this resource", 405);
		}

		$id = $this->getParam('id', true, 0);
		$un_optional = $id > 0;
		$username = $this->getParam('username', $un_optional, '');

		if ($this->isAdmin() == false && Settings::IsInList('panel.customer_hide_options', 'extras.directoryprotection')) {
			throw new Exception("You cannot access this resource", 405);
		}

		// get directory protection
		$result = $this->apiCall('DirProtections.get', [
			'id' => $id,
			'username' => $username
		]);
		$id = $result['id'];

		if ($this->isAdmin()) {
			// get customer-data
			$customer_data = $this->apiCall('Customers.get', [
				'id' => $result['customerid']
			]);
		} else {
			$customer_data = $this->getUserData();
		}

		$stmt = Database::prepare("
			DELETE FROM `" . TABLE_PANEL_HTPASSWDS . "` WHERE `customerid`= :customerid	AND `id`= :id
		");
		Database::pexecute($stmt, [
			"customerid" => $customer_data['customerid'],
			"id" => $id
		]);

		$this->logger()->logAction($this->isAdmin() ? FroxlorLogger::ADM_ACTION : FroxlorLogger::USR_ACTION, LOG_WARNING, "[API] deleted htpasswd for '" . $result['username'] . " (" . $result['path'] . ")'");
		Cronjob::inserttask(TaskId::REBUILD_VHOST);
		return $this->response($result);
	}
}
