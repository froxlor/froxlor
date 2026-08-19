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
use Froxlor\FroxlorLogger;
use Froxlor\Settings;
use Froxlor\System\Cronjob;
use Froxlor\Validate\Validate;
use phpseclib3\Crypt\PublicKeyLoader;

/**
 * @since 2.3.0
 */
class SshKeys extends ApiCommand implements ResourceEntity
{

	/**
	 * add a new ssh-key
	 *
	 * @param int $id
	 *            optional id of ftp-user to add the ssh-key for, required if `ftpuser` is empty
	 * @param string $ftpuser
	 *            optional loginname of ftp-user to add the ssh-key for, required if `id` is empty
	 * @param int $customerid
	 *             optional, required when called as admin (if $loginname is not specified)
	 * @param string $loginname
	 *             optional, required when called as admin (if $customerid is not specified)
	 * @param string $ssh_pubkey
	 *            ssh public key to add for the given user
	 * @param string $description
	 *            optional, description for ssh-key
	 *
	 * @access admin, customer
	 * @return string json-encoded array
	 * @throws Exception
	 */
	public function add()
	{
		if ($this->isAdmin() == false &&
			(Settings::IsInList('panel.customer_hide_options', 'ftp')
				|| intval(Settings::Get('system.allow_customer_shell')) == 0
				|| intval($this->getUserDetail('shell_allowed')) == 0)
		) {
			throw new Exception("You cannot access this resource", 405);
		}

		// get needed customer info
		$customer = $this->getCustomerData();

		$id = $this->getParam('id', true, 0);
		$ea_optional = $id > 0;
		$ftpuser = $this->getParam('ftpuser', $ea_optional);

		// get ftp user
		$ftp_user = $this->apiCall('Ftps.get', [
			'id' => $id,
			'username' => $ftpuser
		]);
		$id = $ftp_user['id'];

		// parameters
		$ssh_pubkey = $this->getParam('ssh_pubkey');
		$description = $this->getParam('description', true, '');

		// validation
		if ($customer['customerid'] != $ftp_user['customerid']) {
			throw new Exception("ftp user not found", 404);
		}
		if (!$this->isValidSshPublicKey($ssh_pubkey)) {
			throw new Exception("Given SSH-key does not seem to be a valid public key", 406);
		}
		$key = PublicKeyLoader::loadPublicKey(trim($ssh_pubkey));
		if (empty($description)) {
			$description = $key->getComment() ?? '';
		}
		$description = Validate::validate(trim($description), 'description', Validate::REGEX_DESC_TEXT, '', [], true);

		// check for existing ssh-key for given user
		$check_stmt = Database::prepare("
			SELECT `ssh_pubkey`
			FROM `" . TABLE_PANEL_USER_SSHKEYS . "`
			WHERE `ftp_user_id` = :fuid
		");
		Database::pexecute($check_stmt, ['fuid' => $id]);
		while ($row = $check_stmt->fetch(\PDO::FETCH_ASSOC)) {
			$rowkey = PublicKeyLoader::loadPublicKey($row['ssh_pubkey']);
			if ($rowkey->getFingerprint('sha256') == $key->getFingerprint('sha256')) {
				throw new Exception("This SSH-key already exists for the given user", 406);
			}
		}

		// insert data
		$stmt = Database::prepare("
			INSERT INTO `" . TABLE_PANEL_USER_SSHKEYS . "` SET
			`customerid` = :cid,
			`ftp_user_id` = :fid,
			`ssh_pubkey` = :sshpub,
			`description` = :desc
		");
		$params = [
			"cid" => $customer['customerid'],
			"fid" => $id,
			"sshpub" => trim($ssh_pubkey),
			"desc" => $description
		];
		Database::pexecute($stmt, $params, true, true);
		$sshkeyid = Database::lastInsertId();

		$this->logger()->logAction($this->isAdmin() ? FroxlorLogger::ADM_ACTION : FroxlorLogger::USR_ACTION, LOG_NOTICE, "[API] added ssh key for '" . $ftp_user['username'] . "'");
		$result = $this->apiCall('SshKeys.get', [
			'id' => $sshkeyid
		]);

		if (Settings::Get('system.nssextrausers') == 1) {
			// this is used so that the libnss-extrausers cron is fired
			Cronjob::inserttask(TaskId::REBUILD_NSSUSERS);
		}

		return $this->response($result);
	}

	/**
	 * return a ssh-key entry by id
	 *
	 * @param int $id
	 *            the ssh-key id
	 *
	 * @access admin, customer
	 * @return string json-encoded array
	 * @throws Exception
	 */
	public function get()
	{
		$id = $this->getParam('id');

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
					SELECT s.*, f.username
					FROM `" . TABLE_PANEL_USER_SSHKEYS . "` s
					LEFT JOIN `" . TABLE_FTP_USERS . "` f ON f.id = s.ftp_user_id
					WHERE s.`customerid` IN (" . implode(", ", $customer_ids) . ")
					AND s.`id` = :id
				");
			} else {
				$result_stmt = Database::prepare("
					SELECT s.*, f.username
					FROM `" . TABLE_PANEL_USER_SSHKEYS . "` s
					LEFT JOIN `" . TABLE_FTP_USERS . "` f ON f.id = s.ftp_user_id
					WHERE s.`id` = :id
				");
			}
		} else {
			if (Settings::IsInList('panel.customer_hide_options', 'ftp')
				|| intval(Settings::Get('system.allow_customer_shell')) == 0
				|| intval($this->getUserDetail('shell_allowed')) == 0) {
				throw new Exception("You cannot access this resource", 405);
			}
			$result_stmt = Database::prepare("
				SELECT s.*, f.username
				FROM `" . TABLE_PANEL_USER_SSHKEYS . "` s
				LEFT JOIN `" . TABLE_FTP_USERS . "` f ON f.id = s.ftp_user_id
				WHERE s.`customerid` = :customerid
				AND s.`id` = :id
			");
			$params['customerid'] = $this->getUserDetail('customerid');
		}
		$params['id'] = $id;
		$result = Database::pexecute_first($result_stmt, $params, true, true);
		if ($result) {
			$key = PublicKeyLoader::loadPublicKey($result['ssh_pubkey']);
			$result['fingerprint'] = 'SHA256:' . $key->getFingerprint('sha256');
			$this->logger()->logAction($this->isAdmin() ? FroxlorLogger::ADM_ACTION : FroxlorLogger::USR_ACTION, LOG_INFO, "[API] get ssh-key for ftp-user '" . $result['ftp_user_id'] . "'");
			return $this->response($result);
		}
		$key = "id #" . $id;
		throw new Exception("FTP user with " . $key . " could not be found", 404);
	}

	/**
	 * update a given ftp-user by id or username
	 *
	 * @param int $id
	 *            the ssh-key id
	 * @param string $description
	 *            optional, description for ssh-key
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
		if ($this->isAdmin() == false &&
			(Settings::IsInList('panel.customer_hide_options', 'ftp')
				|| intval(Settings::Get('system.allow_customer_shell')) == 0
				|| intval($this->getUserDetail('shell_allowed')) == 0)
		) {
			throw new Exception("You cannot access this resource", 405);
		}

		$id = $this->getParam('id');

		$result = $this->apiCall('SshKeys.get', [
			'id' => $id
		]);
		$id = $result['id'];

		// parameters
		$description = $this->getParam('description', true, $result['description']);

		// validation
		$description = Validate::validate(trim($description), 'description', Validate::REGEX_DESC_TEXT, '', [], true);

		// get needed customer info
		$customer = $this->getCustomerData();

		$stmt = Database::prepare("
			UPDATE `" . TABLE_PANEL_USER_SSHKEYS . "`
			SET `description` = :desc
			WHERE `customerid` = :customerid
			AND `id` = :id
		");
		Database::pexecute($stmt, [
			"desc" => $description,
			"customerid" => $customer['customerid'],
			"id" => $id
		], true, true);

		$result = $this->apiCall('SshKeys.get', [
			'id' => $result['id']
		]);
		$this->logger()->logAction($this->isAdmin() ? FroxlorLogger::ADM_ACTION : FroxlorLogger::USR_ACTION, LOG_NOTICE, "[API] updated ssh-key '" . $result['id'] . "'");

		if (Settings::Get('system.nssextrausers') == 1) {
			// this is used so that the libnss-extrausers cron is fired
			Cronjob::inserttask(TaskId::REBUILD_NSSUSERS);
		}

		return $this->response($result);
	}

	/**
	 * list all ssh-keys, if called from an admin, list all ssh-keys of all customers you are allowed to view, or
	 * specify id or loginname for one specific customer
	 *
	 * @param int $customerid
	 *            optional, admin-only, select ftp-users of a specific customer by id
	 * @param string $loginname
	 *            optional, admin-only, select ftp-users of a specific customer by loginname
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
		if ($this->isAdmin() == false &&
			(Settings::IsInList('panel.customer_hide_options', 'ftp')
				|| intval(Settings::Get('system.allow_customer_shell')) == 0
				|| intval($this->getUserDetail('shell_allowed')) == 0)
		) {
			throw new Exception("You cannot access this resource", 405);
		}

		$customer_ids = $this->getAllowedCustomerIds('ftp');
		$result = [];
		$query_fields = [];
		$result_stmt = Database::prepare("
			SELECT s.*, f.username
			FROM `" . TABLE_PANEL_USER_SSHKEYS . "` s
			LEFT JOIN `" . TABLE_FTP_USERS . "` f ON f.id = s.ftp_user_id
			WHERE s.`customerid` IN (" . implode(", ", $customer_ids) . ")" . $this->getSearchWhere($query_fields, true) . $this->getOrderBy() . $this->getLimit());
		Database::pexecute($result_stmt, $query_fields, true, true);
		while ($row = $result_stmt->fetch(\PDO::FETCH_ASSOC)) {
			$key = PublicKeyLoader::loadPublicKey($row['ssh_pubkey']);
			$row['fingerprint'] = 'SHA256:' . $key->getFingerprint('sha256');
			$result[] = $row;
		}
		$this->logger()->logAction($this->isAdmin() ? FroxlorLogger::ADM_ACTION : FroxlorLogger::USR_ACTION, LOG_INFO, "[API] list ssh-keys");
		return $this->response([
			'count' => count($result),
			'list' => $result
		]);
	}

	/**
	 * returns the total number of accessible ssh keys
	 *
	 * @param int $customerid
	 *            optional, admin-only, select ftp-users of a specific customer by id
	 * @param string $loginname
	 *            optional, admin-only, select ftp-users of a specific customer by loginname
	 *
	 * @access admin, customer
	 * @return string json-encoded response message
	 * @throws Exception
	 */
	public function listingCount()
	{
		if ($this->isAdmin() == false &&
			(Settings::IsInList('panel.customer_hide_options', 'ftp')
				|| intval(Settings::Get('system.allow_customer_shell')) == 0
				|| intval($this->getUserDetail('shell_allowed')) == 0)
		) {
			throw new Exception("You cannot access this resource", 405);
		}

		$customer_ids = $this->getAllowedCustomerIds('ftp');
		$result = [];
		$query_fields = [];
		$result_stmt = Database::prepare("
			SELECT COUNT(*) as num_sshkeys FROM `" . TABLE_PANEL_USER_SSHKEYS . "`
			WHERE `customerid` IN (" . implode(", ", $customer_ids) . ")
		" . $this->getSearchWhere($query_fields, true));
		$result = Database::pexecute_first($result_stmt, $query_fields, true, true);
		if ($result) {
			return $this->response($result['num_sshkeys']);
		}
		return $this->response(0);
	}

	/**
	 * delete a ftp-user by either id or username
	 *
	 * @param int $id
	 *            the ssh-key id
	 * @param int $customerid
	 *             optional, required when called as admin (if $loginname is not specified)
	 * @param string $loginname
	 *             optional, required when called as admin (if $customerid is not specified)
	 *
	 * @access admin, customer
	 * @return string json-encoded array
	 * @throws Exception
	 */
	public function delete()
	{
		$id = $this->getParam('id');

		if ($this->isAdmin() == false &&
			(Settings::IsInList('panel.customer_hide_options', 'ftp')
				|| intval(Settings::Get('system.allow_customer_shell')) == 0
				|| intval($this->getUserDetail('shell_allowed')) == 0)
		) {
			throw new Exception("You cannot access this resource", 405);
		}

		// get ssh-key
		$result = $this->apiCall('SshKeys.get', [
			'id' => $id
		]);
		$id = $result['id'];

		$customer = $this->getCustomerData();

		// remove entry
		$stmt = Database::prepare("
			DELETE FROM `" . TABLE_PANEL_USER_SSHKEYS . "` WHERE `customerid` = :customerid AND `id` = :id
		");
		Database::pexecute($stmt, [
			"customerid" => $customer['customerid'],
			"id" => $id
		], true, true);

		$this->logger()->logAction($this->isAdmin() ? FroxlorLogger::ADM_ACTION : FroxlorLogger::USR_ACTION, LOG_WARNING, "[API] deleted ssh-key '" . $result['id'] . "'");

		if (Settings::Get('system.nssextrausers') == 1) {
			// this is used so that the libnss-extrausers cron is fired
			Cronjob::inserttask(TaskId::REBUILD_NSSUSERS);
		}

		return $this->response($result);
	}

	private function isValidSshPublicKey(string $key): bool
	{
		// reject multi-line input outright: PublicKeyLoader only parses the first key
		// token and folds everything after the first newline into the comment, so a
		// value like "<valid-key>\n<attacker-controlled authorized_keys line>" would
		// otherwise validate and later be written verbatim into authorized_keys as an
		// independent, fully honored entry
		if (trim($key) !== str_replace(["\r", "\n"], '', trim($key))) {
			return false;
		}
		try {
			$loaded = PublicKeyLoader::loadPublicKey($key);
			return $loaded !== null;
		} catch (\Exception $e) {
			return false;
		}
	}
}
