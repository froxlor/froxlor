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
use Froxlor\Idna\IdnaWrapper;
use Froxlor\Settings;
use Froxlor\System\Cronjob;
use Froxlor\System\Crypt;
use Froxlor\UI\Response;
use Froxlor\User;
use Froxlor\Validate\Validate;
use PDO;

/**
 * @since 0.10.0
 */
class Ftps extends ApiCommand implements ResourceEntity
{

	/**
	 * add a new ftp-user
	 *
	 * @param string $ftp_password
	 *            password for the created database and database-user
	 * @param string $path
	 *            destination path relative to the customers-homedir
	 * @param string $ftp_description
	 *            optional, description for ftp-user
	 * @param bool $sendinfomail
	 *            optional, send created resource-information to customer, default: false
	 * @param string $shell
	 *            optional, default /bin/false (not changeable when deactivated)
	 * @param string $ftp_username
	 *            optional if customer.ftpatdomain is allowed, specify an username
	 * @param string $ftp_domain
	 *            optional if customer.ftpatdomain is allowed, specify a domain (customer must be owner)
	 * @param int $customerid
	 *            optional, required when called as admin (if $loginname is not specified)
	 * @param string $loginname
	 *            optional, required when called as admin (if $customerid is not specified)
	 * @param array $additional_members
	 *            optional whether to add additional usernames to the group
	 * @param bool $is_defaultuser
	 *            optional whether this is the standard default ftp user which is being added so no usage is decreased
	 * @param bool $login_enabled
	 *            optional whether to allow login (default) or not
	 *
	 * @access admin, customer
	 * @return string json-encoded array
	 * @throws Exception
	 */
	public function add()
	{
		if ($this->isAdmin() == false && Settings::IsInList('panel.customer_hide_options', 'ftp')) {
			throw new Exception("You cannot access this resource", 405);
		}

		$is_defaultuser = $this->getBoolParam('is_defaultuser', true, 0);
		$login_enabled = $this->getBoolParam('login_enabled', true, 1);

		if (($this->getUserDetail('ftps_used') < $this->getUserDetail('ftps') || $this->getUserDetail('ftps') == '-1') || $this->isAdmin() && $is_defaultuser == 1) {
			// required parameters
			$path = $this->getParam('path');
			$password = $this->getParam('ftp_password');

			// parameters
			$description = $this->getParam('ftp_description', true, '');
			$sendinfomail = $this->getBoolParam('sendinfomail', true, 0);
			$shell = $this->getParam('shell', true, '/bin/false');

			$ftpusername = $this->getParam('ftp_username', true, '');
			$ftpdomain = $this->getParam('ftp_domain', true, '');

			$additional_members = $this->getParam('additional_members', true, []);

			// validation
			$password = Validate::validate($password, 'password', '', '', [], true);
			$password = Crypt::validatePassword($password, true);
			$description = Validate::validate(trim($description), 'description', Validate::REGEX_DESC_TEXT, '', [], true);

			// get needed customer info to reduce the ftp-user-counter by one
			if ($is_defaultuser) {
				// no resource check for default user
				$customer = $this->getCustomerData();
			} else {
				$customer = $this->getCustomerData('ftps');
			}

			if (Settings::Get('system.allow_customer_shell') == '1' && $customer['shell_allowed'] == '1') {
				$shell = Validate::validate(trim($shell), 'shell', '', '', [], true);
				$availableshells = explode(',', Settings::Get('system.available_shells'));
				if (!is_array($availableshells) || empty($availableshells) || !in_array($shell, $availableshells)) {
					$shell = "/bin/false";
				}
			} else {
				$shell = "/bin/false";
			}

			if (Settings::Get('customer.ftpatdomain') == '1') {
				$ftpusername = Validate::validate(trim($ftpusername), 'username', '/^[a-zA-Z0-9][a-zA-Z0-9\-_]+\$?$/', '', [], true);
				if (substr($ftpdomain, 0, 4) != 'xn--') {
					$idna_convert = new IdnaWrapper();
					$ftpdomain = $idna_convert->encode(Validate::validate($ftpdomain, 'domain', '', '', [], true));
				}
			}

			$params = [];

			if ($sendinfomail != 1) {
				$sendinfomail = 0;
			}

			if (Settings::Get('customer.ftpatdomain') == '1' && !$is_defaultuser) {
				if ($ftpusername == '') {
					Response::standardError([
						'stringisempty',
						'username'
					], '', true);
				}
				$ftpdomain_check_stmt = Database::prepare("SELECT `id`, `domain`, `customerid` FROM `" . TABLE_PANEL_DOMAINS . "`
						WHERE `domain` = :domain
						AND `customerid` = :customerid");
				$ftpdomain_check = Database::pexecute_first($ftpdomain_check_stmt, [
					"domain" => $ftpdomain,
					"customerid" => $customer['customerid']
				], true, true);

				if ($ftpdomain_check && $ftpdomain_check['domain'] != $ftpdomain) {
					Response::standardError('maindomainnonexist', $ftpdomain, true);
				}
				$username = $ftpusername . "@" . $ftpdomain;
			} else {
				if ($is_defaultuser) {
					$username = $customer['loginname'];
				} else {
					$username = $customer['loginname'] . Settings::Get('customer.ftpprefix') . (intval($customer['ftp_lastaccountnumber']) + 1);
				}
			}

			$username_check_stmt = Database::prepare("
				SELECT * FROM `" . TABLE_FTP_USERS . "`	WHERE `username` = :username
			");
			$username_check = Database::pexecute_first($username_check_stmt, [
				"username" => $username
			], true, true);

			if (!empty($username_check) && $username_check['username'] = $username) {
				Response::standardError('usernamealreadyexists', $username, true);
			} elseif ($username == $password) {
				Response::standardError('passwordshouldnotbeusername', '', true);
			} else {
				$path = FileDir::makeCorrectDir($customer['documentroot'] . '/' . $path, $customer['documentroot']);
				$cryptPassword = Crypt::makeCryptPassword($password, false, true);

				$stmt = Database::prepare("INSERT INTO `" . TABLE_FTP_USERS . "`
						(`customerid`, `username`, `description`, `password`, `homedir`, `login_enabled`, `uid`, `gid`, `shell`)
						VALUES (:customerid, :username, :description, :password, :homedir, :loginenabled, :guid, :guid, :shell)");
				$params = [
					"customerid" => $customer['customerid'],
					"username" => $username,
					"description" => $description,
					"password" => $cryptPassword,
					"homedir" => $path,
					"loginenabled" => $login_enabled ? 'Y' : 'N',
					"guid" => $customer['guid'],
					"shell" => $shell
				];
				Database::pexecute($stmt, $params, true, true);

				$result_stmt = Database::prepare("
					SELECT `bytes_in_used` FROM `" . TABLE_FTP_QUOTATALLIES . "` WHERE `name` = :name
				");
				Database::pexecute($result_stmt, [
					"name" => $customer['loginname']
				], true, true);

				while ($row = $result_stmt->fetch(PDO::FETCH_ASSOC)) {
					$stmt = Database::prepare("INSERT INTO `" . TABLE_FTP_QUOTATALLIES . "`
						(`name`, `quota_type`, `bytes_in_used`, `bytes_out_used`, `bytes_xfer_used`, `files_in_used`, `files_out_used`, `files_xfer_used`)
						VALUES (:name, 'user', :bytes_in_used, '0', '0', '0', '0', '0')
					");
					Database::pexecute($stmt, [
						"name" => $username,
						"bytes_in_used" => $row['bytes_in_used']
					], true, true);
				}

				// create quotatallies entry if it not exists, refs #885
				if ($result_stmt->rowCount() == 0) {
					$stmt = Database::prepare("INSERT INTO `" . TABLE_FTP_QUOTATALLIES . "`
						(`name`, `quota_type`, `bytes_in_used`, `bytes_out_used`, `bytes_xfer_used`, `files_in_used`, `files_out_used`, `files_xfer_used`)
						VALUES (:name, 'user', '0', '0', '0', '0', '0', '0')
					");
					Database::pexecute($stmt, [
						"name" => $username
					], true, true);
				}

				$group_upd_stmt = Database::prepare("
					UPDATE `" . TABLE_FTP_GROUPS . "`
					SET `members` = CONCAT_WS(',',`members`, :username)
					WHERE `customerid`= :customerid AND `gid`= :guid
				");
				$params = [
					"username" => $username,
					"customerid" => $customer['customerid'],
					"guid" => $customer['guid']
				];

				if ($is_defaultuser) {
					// add the new group
					$group_ins_stmt = Database::prepare("
						INSERT INTO `" . TABLE_FTP_GROUPS . "`
						SET `customerid`= :customerid, `gid`= :guid, `groupname` = :username, `members` = :username
					");
					Database::pexecute($group_ins_stmt, $params, true, true);
				} else {
					// just update
					Database::pexecute($group_upd_stmt, $params, true, true);
				}

				if (count($additional_members) > 0) {
					foreach ($additional_members as $add_member) {
						$params = [
							"username" => $add_member,
							"customerid" => $customer['customerid'],
							"guid" => $customer['guid']
						];
						Database::pexecute($group_upd_stmt, $params, true, true);
					}
				}

				if (!$is_defaultuser) {
					// update customer usage
					Customers::increaseUsage($customer['customerid'], 'ftps_used');
					Customers::increaseUsage($customer['customerid'], 'ftp_lastaccountnumber');
					Cronjob::inserttask(TaskId::REBUILD_NSSUSERS);
				}

				$this->logger()->logAction($this->isAdmin() ? FroxlorLogger::ADM_ACTION : FroxlorLogger::USR_ACTION, LOG_NOTICE, "[API] added ftp-account '" . $username . " (" . $path . ")'");
				Cronjob::inserttask(TaskId::CREATE_FTP);

				if ($sendinfomail == 1) {
					$replace_arr = [
						'SALUTATION' => User::getCorrectUserSalutation($customer),
						'CUST_NAME' => User::getCorrectUserSalutation($customer),
						// < keep this for compatibility
						'NAME' => $customer['name'],
						'FIRSTNAME' => $customer['firstname'],
						'COMPANY' => $customer['company'],
						'USERNAME' => $customer['loginname'],
						'CUSTOMER_NO' => $customer['customernumber'],
						'USR_NAME' => $username,
						'USR_PASS' => htmlentities(htmlentities($password)),
						'USR_PATH' => FileDir::makeCorrectDir(str_replace($customer['documentroot'], "/", $path))
					];
					// get template for mail subject
					$mail_subject = $this->getMailTemplate($customer, 'mails', 'new_ftpaccount_by_customer_subject', $replace_arr, lng('mails.new_ftpaccount_by_customer.subject'));
					// get template for mail body
					$mail_body = $this->getMailTemplate($customer, 'mails', 'new_ftpaccount_by_customer_mailbody', $replace_arr, lng('mails.new_ftpaccount_by_customer.mailbody'));

					$_mailerror = false;
					$mailerr_msg = "";
					try {
						$this->mailer()->Subject = $mail_subject;
						$this->mailer()->AltBody = $mail_body;
						$this->mailer()->Body = str_replace("\n", "<br />", $mail_body);
						$this->mailer()->addAddress($customer['email'], User::getCorrectUserSalutation($customer));
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
						Response::standardError('errorsendingmail', $customer['email'], true);
					}

					$this->mailer()->clearAddresses();
				}
				$this->logger()->logAction($this->isAdmin() ? FroxlorLogger::ADM_ACTION : FroxlorLogger::USR_ACTION, LOG_NOTICE, "[API] added ftp-user '" . $username . "'");

				$result = $this->apiCall('Ftps.get', [
					'username' => $username
				]);
				return $this->response($result);
			}
		}
		throw new Exception("No more resources available", 406);
	}

	/**
	 * return a ftp-user entry by either id or username
	 *
	 * @param int $id
	 *            optional, the customer-id
	 * @param string $username
	 *            optional, the username
	 *
	 * @access admin, customer
	 * @return string json-encoded array
	 * @throws Exception
	 */
	public function get()
	{
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
					SELECT * FROM `" . TABLE_FTP_USERS . "`
					WHERE `customerid` IN (" . implode(", ", $customer_ids) . ")
					AND (`id` = :idun OR `username` = :idun)
				");
			} else {
				$result_stmt = Database::prepare("
					SELECT * FROM `" . TABLE_FTP_USERS . "`
					WHERE (`id` = :idun OR `username` = :idun)
				");
			}
		} else {
			if (Settings::IsInList('panel.customer_hide_options', 'ftp')) {
				throw new Exception("You cannot access this resource", 405);
			}
			$result_stmt = Database::prepare("
				SELECT * FROM `" . TABLE_FTP_USERS . "`
				WHERE `customerid` = :customerid
				AND (`id` = :idun OR `username` = :idun)
			");
			$params['customerid'] = $this->getUserDetail('customerid');
		}
		$params['idun'] = ($id <= 0 ? $username : $id);
		$result = Database::pexecute_first($result_stmt, $params, true, true);
		if ($result) {
			// unset sensitive data
			unset($row['password']);
			$this->logger()->logAction($this->isAdmin() ? FroxlorLogger::ADM_ACTION : FroxlorLogger::USR_ACTION, LOG_INFO, "[API] get ftp-user '" . $result['username'] . "'");
			return $this->response($result);
		}
		$key = ($id > 0 ? "id #" . $id : "username '" . $username . "'");
		throw new Exception("FTP user with " . $key . " could not be found", 404);
	}

	/**
	 * update a given ftp-user by id or username
	 *
	 * @param int $id
	 *            optional, the ftp-user-id
	 * @param string $username
	 *            optional, the username
	 * @param string $ftp_password
	 *            optional, update password if specified
	 * @param string $path
	 *            destination path relative to the customers-homedir
	 * @param string $ftp_description
	 *            optional, description for ftp-user
	 * @param string $shell
	 *            optional, default /bin/false (not changeable when deactivated)
	 * @param bool $login_enabled
	 *            optional whether to allow login (default) or not
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
		if ($this->isAdmin() == false && Settings::IsInList('panel.customer_hide_options', 'ftp')) {
			throw new Exception("You cannot access this resource", 405);
		}

		$id = $this->getParam('id', true, 0);
		$un_optional = $id > 0;
		$username = $this->getParam('username', $un_optional, '');

		$result = $this->apiCall('Ftps.get', [
			'id' => $id,
			'username' => $username
		]);
		$id = $result['id'];

		// parameters
		$path = $this->getParam('path', true, '');
		$password = $this->getParam('ftp_password', true, '');
		$description = $this->getParam('ftp_description', true, $result['description']);
		$shell = $this->getParam('shell', true, $result['shell']);
		$login_enabled = $this->getBoolParam('login_enabled', true, ($result['login_enabled'] == 'Y' ? 1 : 0));

		// validation
		$password = Validate::validate($password, 'password', '', '', [], true);
		$description = Validate::validate(trim($description), 'description', Validate::REGEX_DESC_TEXT, '', [], true);

		// get needed customer info to reduce the ftp-user-counter by one
		$customer = $this->getCustomerData();

		if (Settings::Get('system.allow_customer_shell') == '1' && $customer['shell_allowed'] == '1') {
			$shell = Validate::validate(trim($shell), 'shell', '', '', [], true);
			$availableshells = explode(',', Settings::Get('system.available_shells'));
			if (!is_array($availableshells) || empty($availableshells) || !in_array($shell, $availableshells)) {
				$shell = "/bin/false";
			}
		} else {
			$shell = "/bin/false";
		}

		if ($login_enabled != 1) {
			$login_enabled = 0;
		}

		// password update?
		if ($password != '') {
			// validate password
			$password = Crypt::validatePassword($password, true);

			if ($password == $result['username']) {
				Response::standardError('passwordshouldnotbeusername', '', true);
			}
			$cryptPassword = Crypt::makeCryptPassword($password, false, true);

			$stmt = Database::prepare("UPDATE `" . TABLE_FTP_USERS . "`
				SET `password` = :password
				WHERE `customerid` = :customerid
				AND `id` = :id
			");
			Database::pexecute($stmt, [
				"customerid" => $customer['customerid'],
				"id" => $id,
				"password" => $cryptPassword
			], true, true);
			$this->logger()->logAction($this->isAdmin() ? FroxlorLogger::ADM_ACTION : FroxlorLogger::USR_ACTION, LOG_NOTICE, "[API] updated ftp-account password for '" . $result['username'] . "'");
		}

		// path update?
		if ($path != '') {
			$path = FileDir::makeCorrectDir($customer['documentroot'] . '/' . $path, $customer['documentroot']);

			if ($path != $result['homedir']) {
				$stmt = Database::prepare("UPDATE `" . TABLE_FTP_USERS . "`
					SET `homedir` = :homedir
					WHERE `customerid` = :customerid
					AND `id` = :id
				");
				Database::pexecute($stmt, [
					"homedir" => $path,
					"customerid" => $customer['customerid'],
					"id" => $id
				], true, true);
				$this->logger()->logAction($this->isAdmin() ? FroxlorLogger::ADM_ACTION : FroxlorLogger::USR_ACTION, LOG_NOTICE, "[API] updated ftp-account homdir for '" . $result['username'] . "'");
			}
		}
		// it's the task for "new ftp" but that will
		// create all directories and correct their permissions
		Cronjob::inserttask(TaskId::CREATE_FTP);
		Cronjob::inserttask(TaskId::REBUILD_NSSUSERS);

		$stmt = Database::prepare("
			UPDATE `" . TABLE_FTP_USERS . "`
			SET `description` = :desc, `shell` = :shell, `login_enabled` = :loginenabled
			WHERE `customerid` = :customerid
			AND `id` = :id
		");
		Database::pexecute($stmt, [
			"desc" => $description,
			"shell" => $shell,
			"loginenabled" => $login_enabled ? 'Y' : 'N',
			"customerid" => $customer['customerid'],
			"id" => $id
		], true, true);

		$result = $this->apiCall('Ftps.get', [
			'username' => $result['username']
		]);
		$this->logger()->logAction($this->isAdmin() ? FroxlorLogger::ADM_ACTION : FroxlorLogger::USR_ACTION, LOG_NOTICE, "[API] updated ftp-user '" . $result['username'] . "'");
		return $this->response($result);
	}

	/**
	 * list all ftp-users, if called from an admin, list all ftp-users of all customers you are allowed to view, or
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
		$customer_ids = $this->getAllowedCustomerIds('ftp');
		$result = [];
		$query_fields = [];
		$result_stmt = Database::prepare("
			SELECT * FROM `" . TABLE_FTP_USERS . "`
			WHERE `customerid` IN (" . implode(", ", $customer_ids) . ")" . $this->getSearchWhere($query_fields, true) . $this->getOrderBy() . $this->getLimit());
		Database::pexecute($result_stmt, $query_fields, true, true);
		while ($row = $result_stmt->fetch(PDO::FETCH_ASSOC)) {
			// unset sensitive data
			unset($row['password']);
			$result[] = $row;
		}
		$this->logger()->logAction($this->isAdmin() ? FroxlorLogger::ADM_ACTION : FroxlorLogger::USR_ACTION, LOG_INFO, "[API] list ftp-users");
		return $this->response([
			'count' => count($result),
			'list' => $result
		]);
	}

	/**
	 * returns the total number of accessible ftp accounts
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
		$customer_ids = $this->getAllowedCustomerIds('ftp');
		$result = [];
		$query_fields = [];
		$result_stmt = Database::prepare("
			SELECT COUNT(*) as num_ftps FROM `" . TABLE_FTP_USERS . "`
			WHERE `customerid` IN (" . implode(", ", $customer_ids) . ")
		" . $this->getSearchWhere($query_fields, true));
		$result = Database::pexecute_first($result_stmt, $query_fields, true, true);
		if ($result) {
			return $this->response($result['num_ftps']);
		}
		return $this->response(0);
	}

	/**
	 * delete a ftp-user by either id or username
	 *
	 * @param int $id
	 *            optional, the ftp-user-id
	 * @param string $username
	 *            optional, the username
	 * @param bool $delete_userfiles
	 *            optional, default false
	 *
	 * @access admin, customer
	 * @return string json-encoded array
	 * @throws Exception
	 */
	public function delete()
	{
		$id = $this->getParam('id', true, 0);
		$un_optional = $id > 0;
		$username = $this->getParam('username', $un_optional, '');
		$delete_userfiles = $this->getBoolParam('delete_userfiles', true, 0);

		if ($this->isAdmin() == false && Settings::IsInList('panel.customer_hide_options', 'ftp')) {
			throw new Exception("You cannot access this resource", 405);
		}

		// get ftp-user
		$result = $this->apiCall('Ftps.get', [
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

		// add usage of this ftp-user to main-ftp user of customer if different
		if ($result['username'] != $customer_data['loginname']) {
			$stmt = Database::prepare("UPDATE `" . TABLE_FTP_USERS . "`
				SET `up_count` = `up_count` + :up_count,
				`up_bytes` = `up_bytes` + :up_bytes,
				`down_count` = `down_count` + :down_count,
				`down_bytes` = `down_bytes` + :down_bytes
				WHERE `username` = :username
			");
			$params = [
				"up_count" => $result['up_count'],
				"up_bytes" => $result['up_bytes'],
				"down_count" => $result['down_count'],
				"down_bytes" => $result['down_bytes'],
				"username" => $customer_data['loginname']
			];
			Database::pexecute($stmt, $params, true, true);
		} else {
			// do not allow removing default ftp-account
			Response::standardError('ftp_cantdeletemainaccount', '', true);
		}

		// remove all quotatallies
		$stmt = Database::prepare("DELETE FROM `" . TABLE_FTP_QUOTATALLIES . "` WHERE `name` = :name");
		Database::pexecute($stmt, [
			"name" => $result['username']
		], true, true);

		// remove user itself
		$stmt = Database::prepare("
			DELETE FROM `" . TABLE_FTP_USERS . "` WHERE `customerid` = :customerid AND `id` = :id
		");
		Database::pexecute($stmt, [
			"customerid" => $customer_data['customerid'],
			"id" => $id
		], true, true);

		// update ftp-groups
		$stmt = Database::prepare("
			UPDATE `" . TABLE_FTP_GROUPS . "` SET
			`members` = REPLACE(`members`, :username,'')
			WHERE `customerid` = :customerid
		");
		Database::pexecute($stmt, [
			"username" => "," . $result['username'],
			"customerid" => $customer_data['customerid']
		], true, true);

		// refs #293
		if ($delete_userfiles == 1) {
			Cronjob::inserttask(TaskId::DELETE_FTP_DATA, $customer_data['loginname'], $result['homedir']);
		} else {
			if (Settings::Get('system.nssextrausers') == 1) {
				// this is used so that the libnss-extrausers cron is fired
				Cronjob::inserttask(TaskId::CREATE_FTP);
			}
		}
		Cronjob::inserttask(TaskId::REBUILD_NSSUSERS);

		// decrease ftp-user usage for customer
		$resetaccnumber = ($customer_data['ftps_used'] == '1') ? " , `ftp_lastaccountnumber`='0'" : '';
		Customers::decreaseUsage($customer_data['customerid'], 'ftps_used', $resetaccnumber);

		$this->logger()->logAction($this->isAdmin() ? FroxlorLogger::ADM_ACTION : FroxlorLogger::USR_ACTION, LOG_WARNING, "[API] deleted ftp-user '" . $result['username'] . "'");
		return $this->response($result);
	}
}
