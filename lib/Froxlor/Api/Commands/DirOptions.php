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
use Froxlor\UI\Response;
use Froxlor\Validate\Validate;
use PDO;

/**
 * @since 0.10.0
 */
class DirOptions extends ApiCommand implements ResourceEntity
{

	/**
	 * add options for a given directory
	 *
	 * @param int $customerid
	 *            optional, required when called as admin (if $loginname is not specified)
	 * @param string $loginname
	 *            optional, required when called as admin (if $customerid is not specified)
	 * @param string $path
	 *            path relative to the customer's home-Directory
	 * @param bool $options_indexes
	 *            optional, activate directory-listing for this path, default 0 (false)
	 * @param bool $options_cgi
	 *            optional, allow Perl/CGI execution, default 0 (false)
	 * @param string $error404path
	 *            optional, custom 404 error string/file
	 * @param string $error403path
	 *            optional, custom 403 error string/file
	 * @param string $error500path
	 *            optional, custom 500 error string/file
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
		if ($this->isAdmin() == false && Settings::IsInList('panel.customer_hide_options', 'extras.pathoptions')) {
			throw new Exception("You cannot access this resource", 405);
		}

		// get needed customer info to reduce the email-address-counter by one
		$customer = $this->getCustomerData();

		// required parameters
		$path = $this->getParam('path');

		// parameters
		$options_indexes = $this->getBoolParam('options_indexes', true, 0);
		$options_cgi = $this->getBoolParam('options_cgi', true, 0);
		$error404path = $this->getParam('error404path', true, '');
		$error403path = $this->getParam('error403path', true, '');
		$error500path = $this->getParam('error500path', true, '');

		// validation
		$path = FileDir::makeCorrectDir(Validate::validate($path, 'path', Validate::REGEX_DIR, '', [], true));
		$userpath = $path;
		$path = FileDir::makeCorrectDir($customer['documentroot'] . '/' . $path, $customer['documentroot']);

		if (!empty($error404path)) {
			$error404path = $this->correctErrorDocument($error404path, true);
		}

		if (!empty($error403path)) {
			$error403path = $this->correctErrorDocument($error403path, true);
		}

		if (!empty($error500path)) {
			$error500path = $this->correctErrorDocument($error500path, true);
		}

		// check for duplicate path
		$path_dupe_check_stmt = Database::prepare("
			SELECT `id`, `path` FROM `" . TABLE_PANEL_HTACCESS . "`
			WHERE `path`= :path AND `customerid`= :customerid
		");
		$path_dupe_check = Database::pexecute_first($path_dupe_check_stmt, [
			"path" => $path,
			"customerid" => $customer['customerid']
		], true, true);

		// duplicate check
		if ($path_dupe_check && $path_dupe_check['path'] == $path) {
			Response::standardError('errordocpathdupe', $userpath, true);
		}

		// insert the entry
		$stmt = Database::prepare('
			INSERT INTO `' . TABLE_PANEL_HTACCESS . '` SET
			`customerid` = :customerid,
			`path` = :path,
			`options_indexes` = :options_indexes,
			`error404path` = :error404path,
			`error403path` = :error403path,
			`error500path` = :error500path,
			`options_cgi` = :options_cgi
		');
		$params = [
			"customerid" => $customer['customerid'],
			"path" => $path,
			"options_indexes" => $options_indexes,
			"error403path" => $error403path,
			"error404path" => $error404path,
			"error500path" => $error500path,
			"options_cgi" => $options_cgi
		];
		Database::pexecute($stmt, $params, true, true);
		$id = Database::lastInsertId();
		$this->logger()->logAction($this->isAdmin() ? FroxlorLogger::ADM_ACTION : FroxlorLogger::USR_ACTION, LOG_NOTICE, "[API] added directory-option for '" . $userpath . "'");
		Cronjob::inserttask(TaskId::REBUILD_VHOST);

		$result = $this->apiCall('DirOptions.get', [
			'id' => $id
		]);
		return $this->response($result);
	}

	/**
	 * this functions validates a given value as ErrorDocument
	 * refs #267
	 *
	 * @param string $errdoc
	 * @param bool $throw_exception
	 *
	 * @return string error-document-string
	 *
	 */
	private function correctErrorDocument(string $errdoc, $throw_exception = false)
	{
		if (trim($errdoc) != '') {
			// not a URL
			if ((strtoupper(substr($errdoc, 0, 5)) != 'HTTP:' && strtoupper(substr($errdoc, 0, 6)) != 'HTTPS:') || !Validate::validateUrl($errdoc)) {
				// a file
				if (substr($errdoc, 0, 1) != '"') {
					$errdoc = FileDir::makeCorrectFile($errdoc);
					// apache needs a starting-slash (starting at the domains-docroot)
					if (!substr($errdoc, 0, 1) == '/') {
						$errdoc = '/' . $errdoc;
					}
				} elseif (preg_match('/^"([^\r\n\t\f\0"]+)"$/', $errdoc)) {
					// a string (check for ending ")
				} else {
					Response::standardError('invaliderrordocumentvalue', '', $throw_exception);
				}
			}
		}
		return trim($errdoc);
	}

	/**
	 * return a directory-protection entry by id
	 *
	 * @param int $id
	 *            id of dir-protection entry
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
					SELECT * FROM `" . TABLE_PANEL_HTACCESS . "`
					WHERE `customerid` IN (" . implode(", ", $customer_ids) . ")
					AND `id` = :id
				");
			} else {
				$result_stmt = Database::prepare("
					SELECT * FROM `" . TABLE_PANEL_HTACCESS . "`
					WHERE `id` = :id
				");
			}
		} else {
			if (Settings::IsInList('panel.customer_hide_options', 'extras.pathoptions')) {
				throw new Exception("You cannot access this resource", 405);
			}
			$result_stmt = Database::prepare("
				SELECT * FROM `" . TABLE_PANEL_HTACCESS . "`
				WHERE `customerid` = :customerid
				AND `id` = :id
			");
			$params['customerid'] = $this->getUserDetail('customerid');
		}
		$params['id'] = $id;
		$result = Database::pexecute_first($result_stmt, $params, true, true);
		if ($result) {
			$this->logger()->logAction($this->isAdmin() ? FroxlorLogger::ADM_ACTION : FroxlorLogger::USR_ACTION, LOG_INFO, "[API] get directory options for '" . $result['path'] . "'");
			return $this->response($result);
		}
		$key = "id #" . $id;
		throw new Exception("Directory option with " . $key . " could not be found", 404);
	}

	/**
	 * update options for a given directory by id
	 *
	 * @param int $id
	 *            id of dir-protection entry
	 * @param int $customerid
	 *            optional, required when called as admin (if $loginname is not specified)
	 * @param string $loginname
	 *            optional, required when called as admin (if $customerid is not specified)
	 * @param bool $options_indexes
	 *            optional, activate directory-listing for this path, default 0 (false)
	 * @param bool $options_cgi
	 *            optional, allow Perl/CGI execution, default 0 (false)
	 * @param string $error404path
	 *            optional, custom 404 error string/file
	 * @param string $error403path
	 *            optional, custom 403 error string/file
	 * @param string $error500path
	 *            optional, custom 500 error string/file
	 *
	 * @access admin, customer
	 * @return string json-encoded array
	 * @throws Exception
	 */
	public function update()
	{
		$id = $this->getParam('id', true, 0);

		// validation
		$result = $this->apiCall('DirOptions.get', [
			'id' => $id
		]);

		// get needed customer info to reduce the email-address-counter by one
		$customer = $this->getCustomerData();

		// parameters
		$options_indexes = $this->getBoolParam('options_indexes', true, $result['options_indexes']);
		$options_cgi = $this->getBoolParam('options_cgi', true, $result['options_cgi']);
		$error404path = $this->getParam('error404path', true, $result['error404path']);
		$error403path = $this->getParam('error403path', true, $result['error403path']);
		$error500path = $this->getParam('error500path', true, $result['error500path']);

		if (!empty($error404path)) {
			$error404path = $this->correctErrorDocument($error404path, true);
		}

		if (!empty($error403path)) {
			$error403path = $this->correctErrorDocument($error403path, true);
		}

		if (!empty($error500path)) {
			$error500path = $this->correctErrorDocument($error500path, true);
		}

		if (($options_indexes != $result['options_indexes']) || ($error404path != $result['error404path']) || ($error403path != $result['error403path']) || ($error500path != $result['error500path']) || ($options_cgi != $result['options_cgi'])) {
			Cronjob::inserttask(TaskId::REBUILD_VHOST);
			$stmt = Database::prepare("
				UPDATE `" . TABLE_PANEL_HTACCESS . "`
				SET `options_indexes` = :options_indexes,
				`error404path` = :error404path,
				`error403path` = :error403path,
				`error500path` = :error500path,
				`options_cgi` = :options_cgi
				WHERE `customerid` = :customerid
				AND `id` = :id
			");
			$params = [
				"customerid" => $customer['customerid'],
				"options_indexes" => $options_indexes,
				"error403path" => $error403path,
				"error404path" => $error404path,
				"error500path" => $error500path,
				"options_cgi" => $options_cgi,
				"id" => $id
			];
			Database::pexecute($stmt, $params, true, true);
			$this->logger()->logAction($this->isAdmin() ? FroxlorLogger::ADM_ACTION : FroxlorLogger::USR_ACTION, LOG_NOTICE, "[API] edited directory options for '" . str_replace($customer['documentroot'], '/', $result['path']) . "'");
		}

		$result = $this->apiCall('DirOptions.get', [
			'id' => $id
		]);
		return $this->response($result);
	}

	/**
	 * list all directory-options, if called from an admin, list all directory-options of all customers you are allowed
	 * to view, or specify id or loginname for one specific customer
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
		$customer_ids = $this->getAllowedCustomerIds('extras.pathoptions');

		$result = [];
		$query_fields = [];
		$result_stmt = Database::prepare("
			SELECT * FROM `" . TABLE_PANEL_HTACCESS . "`
			WHERE `customerid` IN (" . implode(', ', $customer_ids) . ")" . $this->getSearchWhere($query_fields, true) . $this->getOrderBy() . $this->getLimit());
		Database::pexecute($result_stmt, $query_fields, true, true);
		while ($row = $result_stmt->fetch(PDO::FETCH_ASSOC)) {
			$result[] = $row;
		}
		$this->logger()->logAction($this->isAdmin() ? FroxlorLogger::ADM_ACTION : FroxlorLogger::USR_ACTION, LOG_INFO, "[API] list directory-options");
		return $this->response([
			'count' => count($result),
			'list' => $result
		]);
	}

	/**
	 * returns the total number of accessible directory options
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
		$customer_ids = $this->getAllowedCustomerIds('extras.pathoptions');

		$result = [];
		$query_fields = [];
		$result_stmt = Database::prepare("
			SELECT COUNT(*) as num_htaccess FROM `" . TABLE_PANEL_HTACCESS . "`
			WHERE `customerid` IN (" . implode(', ', $customer_ids) . ")
		" . $this->getSearchWhere($query_fields, true));
		$result = Database::pexecute_first($result_stmt, $query_fields, true, true);
		if ($result) {
			return $this->response($result['num_htaccess']);
		}
		return $this->response(0);
	}

	/**
	 * delete a directory-options by id
	 *
	 * @param int $id
	 *            id of dir-protection entry
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

		$id = $this->getParam('id');

		if ($this->isAdmin() == false && Settings::IsInList('panel.customer_hide_options', 'extras.pathoptions')) {
			throw new Exception("You cannot access this resource", 405);
		}

		// get directory-option
		$result = $this->apiCall('DirOptions.get', [
			'id' => $id
		]);

		if ($this->isAdmin()) {
			// get customer-data
			$customer_data = $this->apiCall('Customers.get', [
				'id' => $result['customerid']
			]);
		} else {
			$customer_data = $this->getUserData();
		}

		// do we have to remove the symlink and folder in suexecpath?
		if ((int)Settings::Get('perl.suexecworkaround') == 1) {
			$loginname = $customer_data['loginname'];
			$suexecpath = FileDir::makeCorrectDir(Settings::Get('perl.suexecpath') . '/' . $loginname . '/' . md5($result['path']) . '/');
			$perlsymlink = FileDir::makeCorrectFile($result['path'] . '/cgi-bin');
			// remove symlink
			if (file_exists($perlsymlink)) {
				FileDir::safe_exec('rm -f ' . escapeshellarg($perlsymlink));
				$this->logger()->logAction($this->isAdmin() ? FroxlorLogger::ADM_ACTION : FroxlorLogger::USR_ACTION, LOG_DEBUG, "[API] deleted suexecworkaround symlink '" . $perlsymlink . "'");
			}
			// remove folder in suexec-path
			if (file_exists($suexecpath)) {
				FileDir::safe_exec('rm -rf ' . escapeshellarg($suexecpath));
				$this->logger()->logAction($this->isAdmin() ? FroxlorLogger::ADM_ACTION : FroxlorLogger::USR_ACTION, LOG_DEBUG, "[API] deleted suexecworkaround path '" . $suexecpath . "'");
			}
		}
		$stmt = Database::prepare("
			DELETE FROM `" . TABLE_PANEL_HTACCESS . "`
			WHERE `customerid`= :customerid
			AND `id`= :id
		");
		Database::pexecute($stmt, [
			"customerid" => $customer_data['customerid'],
			"id" => $id
		], true, true);
		$this->logger()->logAction($this->isAdmin() ? FroxlorLogger::ADM_ACTION : FroxlorLogger::USR_ACTION, LOG_NOTICE, "[API] deleted directory-option for '" . str_replace($customer_data['documentroot'], '/', $result['path']) . "'");
		Cronjob::inserttask(TaskId::REBUILD_VHOST);
		return $this->response($result);
	}
}
