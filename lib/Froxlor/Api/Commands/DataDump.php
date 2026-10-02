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
class DataDump extends ApiCommand implements ResourceEntity
{

	/**
	 * add a new data dump job
	 *
	 * @param string $path
	 *            path to store the dumped data to
	 * @param string $pgp_public_key
	 *            optional pgp public key to encrypt the archive, default is empty
	 * @param bool $dump_dbs
	 *            optional whether to include databases, default is 0 (false)
	 * @param bool $dump_mail
	 *            optional whether to include mail-data, default is 0 (false)
	 * @param bool $dump_web
	 *            optional whether to incoude web-data, default is 0 (false)
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
		$this->validateAccess();

		// required parameter
		$path = $this->getParam('path');

		// parameter
		$pgp_public_key = $this->getParam('pgp_public_key', true, '');
		$dump_dbs = $this->getBoolParam('dump_dbs', true, 0);
		$dump_mail = $this->getBoolParam('dump_mail', true, 0);
		$dump_web = $this->getBoolParam('dump_web', true, 0);

		// get customer data
		$customer = $this->getCustomerData();

		// validation
		$path = FileDir::makeCorrectDir(Validate::validate($path, 'path', '', '', [], true));
		$userpath = $path;
		$path = FileDir::makeCorrectDir($customer['documentroot'] . '/' . $path, $customer['documentroot']);

		// path cannot be the customers docroot
		if ($path == FileDir::makeCorrectDir($customer['documentroot'])) {
			Response::standardError('dumpfoldercannotbedocroot', '', true);
		}

		// pgp public key validation
		if (!empty($pgp_public_key)) {
			// check if gnupg extension is loaded
			if (!extension_loaded('gnupg')) {
				Response::standardError('gnupgextensionnotavailable', '', true);
			}
			// check if the pgp public key is a valid key
			putenv('GNUPGHOME='.sys_get_temp_dir());
			if (gnupg_import(gnupg_init(), $pgp_public_key) === false) {
				Response::standardError('invalidpgppublickey', '', true);
			}
		}

		if ($dump_dbs != '1') {
			$dump_dbs = '0';
		}

		if ($dump_mail != '1') {
			$dump_mail = '0';
		}

		if ($dump_web != '1') {
			$dump_web = '0';
		}

		$task_data = [
			'customerid' => $customer['customerid'],
			'uid' => $customer['guid'],
			'gid' => $customer['guid'],
			'loginname' => $customer['loginname'],
			'destdir' => $path,
			'pgp_public_key' => $pgp_public_key,
			'dump_dbs' => $dump_dbs,
			'dump_mail' => $dump_mail,
			'dump_web' => $dump_web
		];

		// schedule export job
		Cronjob::inserttask(TaskId::CREATE_CUSTOMER_DATADUMP, $task_data);

		$this->logger()->logAction($this->isAdmin() ? FroxlorLogger::ADM_ACTION : FroxlorLogger::USR_ACTION, LOG_NOTICE, "[API] added customer data export job for '" . $customer['loginname'] . "'. Target directory: " . $userpath);
		return $this->response($task_data);
	}

	/**
	 * check whether data dump is enabled systemwide and if accessible for customer (hide_options)
	 *
	 * @throws Exception
	 */
	private function validateAccess()
	{
		if (Settings::Get('system.exportenabled') != 1) {
			throw new Exception("You cannot access this resource", 405);
		}
		if ($this->isAdmin() == false && Settings::IsInList('panel.customer_hide_options', 'extras')) {
			throw new Exception("You cannot access this resource", 405);
		}
		if ($this->isAdmin() == false && Settings::IsInList('panel.customer_hide_options', 'extras.export')) {
			throw new Exception("You cannot access this resource", 405);
		}
	}

	/**
	 * You cannot get a planned data export.
	 * Try DataDump.listing()
	 */
	public function get()
	{
		throw new Exception('You cannot get a planned data export. Try DataDump.listing()', 303);
	}

	/**
	 * You cannot update a planned data export.
	 * You need to delete it and re-add it.
	 */
	public function update()
	{
		throw new Exception('You cannot update a planned data export. You need to delete it and re-add it.', 303);
	}

	/**
	 * list all planned data export jobs, if called from an admin, list all planned data export jobs of all customers you are
	 * allowed to view, or specify id or loginname for one specific customer
	 *
	 * @param int $customerid
	 *            optional, admin-only, select data export jobs of a specific customer by id
	 * @param string $loginname
	 *            optional, admin-only, select data export jobs of a specific customer by loginname
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
		$this->validateAccess();

		$customer_ids = $this->getAllowedCustomerIds('extras.export');

		// check whether there is a data export job for this customer
		$query_fields = [];
		$sel_stmt = Database::prepare("SELECT * FROM `" . TABLE_PANEL_TASKS . "` WHERE `type` = '20'" . $this->getSearchWhere($query_fields, true) . $this->getOrderBy() . $this->getLimit());
		Database::pexecute($sel_stmt, $query_fields, true, true);
		$result = [];
		while ($entry = $sel_stmt->fetch(PDO::FETCH_ASSOC)) {
			$entry['data'] = json_decode($entry['data'], true);
			if (in_array($entry['data']['customerid'], $customer_ids)) {
				$result[] = $entry;
			}
		}
		$this->logger()->logAction($this->isAdmin() ? FroxlorLogger::ADM_ACTION : FroxlorLogger::USR_ACTION, LOG_INFO, "[API] list customer data dump jobs");
		return $this->response([
			'count' => count($result),
			'list' => $result
		]);
	}

	/**
	 * returns the total number of planned data exports
	 *
	 * @param int $customerid
	 *            optional, admin-only, select data export jobs of a specific customer by id
	 * @param string $loginname
	 *            optional, admin-only, select data export jobs of a specific customer by loginname
	 *
	 * @access admin, customer
	 * @return string json-encoded response message
	 * @throws Exception
	 */
	public function listingCount()
	{
		$this->validateAccess();

		$customer_ids = $this->getAllowedCustomerIds('extras.export');

		// check whether there is a data export job for this customer
		$result_count = 0;
		$query_fields = [];
		$sel_stmt = Database::prepare("SELECT * FROM `" . TABLE_PANEL_TASKS . "` WHERE `type` = '20' " . $this->getSearchWhere($query_fields, true));
		Database::pexecute($sel_stmt, $query_fields, true, true);
		while ($entry = $sel_stmt->fetch(PDO::FETCH_ASSOC)) {
			$entry['data'] = json_decode($entry['data'], true);
			if (in_array($entry['data']['customerid'], $customer_ids)) {
				$result_count++;
			}
		}
		return $this->response($result_count);
	}

	/**
	 * delete a planned data export jobs by id, if called from an admin you need to specify the customerid/loginname
	 *
	 * @param int $job_entry
	 *            id of data export job
	 * @param int $customerid
	 *            optional, required when called as admin (if $loginname is not specified)
	 * @param string $loginname
	 *            optional, required when called as admin (if $customerid is not specified)
	 *
	 * @access admin, customer
	 * @return bool
	 * @throws Exception
	 */
	public function delete()
	{
		// get planned exports
		$result = $this->apiCall('DataDump.listing', $this->getParamList());

		$entry = $this->getParam('job_entry');
		$customer_ids = $this->getAllowedCustomerIds('extras.export');

		if ($result['count'] > 0 && $entry > 0) {
			// prepare statement
			$del_stmt = Database::prepare("DELETE FROM `" . TABLE_PANEL_TASKS . "` WHERE `id` = :tid");
			// check for the correct job
			foreach ($result['list'] as $exportjob) {
				if ($exportjob['id'] == $entry && in_array($exportjob['data']['customerid'], $customer_ids)) {
					Database::pexecute($del_stmt, [
						'tid' => $entry
					], true, true);
					$this->logger()->logAction($this->isAdmin() ? FroxlorLogger::ADM_ACTION : FroxlorLogger::USR_ACTION, LOG_NOTICE, "[API] deleted planned customer data export job #" . $entry);
					return $this->response(true);
				}
			}
		}
		throw new Exception('Data export job with id #' . $entry . ' could not be found', 404);
	}
}
