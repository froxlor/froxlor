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
use Froxlor\FroxlorLogger;
use Froxlor\Idna\IdnaWrapper;
use Froxlor\Language;
use Froxlor\Settings;
use Froxlor\System\Crypt;
use Froxlor\UI\Response;
use Froxlor\User;
use Froxlor\Validate\Validate;
use PDO;

/**
 * @since 0.10.0
 */
class Admins extends ApiCommand implements ResourceEntity
{

	/**
	 * increase resource-usage
	 *
	 * @param int $adminid
	 * @param string $resource
	 * @param string $extra
	 *            optional, default empty
	 * @param int $increase_by
	 *            optional, default 1
	 */
	public static function increaseUsage($adminid = 0, $resource = null, $extra = '', $increase_by = 1)
	{
		self::updateResourceUsage(TABLE_PANEL_ADMINS, 'adminid', $adminid, '+', $resource, $extra, $increase_by);
	}

	/**
	 * decrease resource-usage
	 *
	 * @param int $adminid
	 * @param string $resource
	 * @param string $extra
	 *            optional, default empty
	 * @param int $decrease_by
	 *            optional, default 1
	 */
	public static function decreaseUsage($adminid = 0, $resource = null, $extra = '', $decrease_by = 1)
	{
		self::updateResourceUsage(TABLE_PANEL_ADMINS, 'adminid', $adminid, '-', $resource, $extra, $decrease_by);
	}

	/**
	 * lists all admin entries
	 *
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
	 * @access admin
	 * @return string json-encoded array count|list
	 * @throws Exception
	 */
	public function listing()
	{
		if ($this->isAdmin() && $this->getUserDetail('change_serversettings') == 1) {
			$this->logger()->logAction(FroxlorLogger::ADM_ACTION, LOG_INFO, "[API] list admins");
			$query_fields = [];
			$result_stmt = Database::prepare("
				SELECT *
				FROM `" . TABLE_PANEL_ADMINS . "`" . $this->getSearchWhere($query_fields) . $this->getOrderBy() . $this->getLimit());
			Database::pexecute($result_stmt, $query_fields, true, true);
			$result = [];
			while ($row = $result_stmt->fetch(PDO::FETCH_ASSOC)) {
				$result[] = $row;
			}
			return $this->response([
				'count' => count($result),
				'list' => $result
			]);
		}
		throw new Exception("Not allowed to execute given command.", 403);
	}

	/**
	 * returns the total number of admins for the given admin
	 *
	 * @access admin
	 * @return string json-encoded response message
	 * @throws Exception
	 */
	public function listingCount()
	{
		if ($this->isAdmin() && $this->getUserDetail('change_serversettings') == 1) {
			$query_fields = [];
			$result_stmt = Database::prepare("
				SELECT COUNT(*) as num_admins
				FROM `" . TABLE_PANEL_ADMINS . "`
			" . $this->getSearchWhere($query_fields));
			$result = Database::pexecute_first($result_stmt, $query_fields, true, true);
			if ($result) {
				return $this->response($result['num_admins']);
			}
			$this->response(0);
		}
		throw new Exception("Not allowed to execute given command.", 403);
	}

	/**
	 * create a new admin user
	 *
	 * @param string $name
	 *            required, name of the adminstrator
	 * @param string $email
	 *            required, email address of the administrator
	 * @param string $new_loginname
	 *            required, loginname/username of the administrator
	 * @param string $admin_password
	 *            optional, default auto-generated
	 * @param string $def_language
	 *            optional, ISO 639-1 language code (e.g. 'en', 'de', see lng-folder for supported languages),
	 *            default is system-default language
	 * @param bool $gui_access
	 *            optional, allow login via webui, if false ONLY the login via webui is disallowed; default true
	 * @param bool $api_allowed
	 *            optional, default is true if system setting api.enabled is true, else false
	 * @param string $custom_notes
	 *            optional, default empty
	 * @param bool $custom_notes_show
	 *            optional, default false
	 * @param int $diskspace
	 *            optional, default 0
	 * @param bool $diskspace_ul
	 *            optional, default false
	 * @param int $traffic
	 *            optional, default 0
	 * @param bool $traffic_ul
	 *            optional, default false
	 * @param int $customers
	 *            optional, default 0
	 * @param bool $customers_ul
	 *            optional, default false
	 * @param int $domains
	 *            optional, default 0
	 * @param bool $domains_ul
	 *            optional, default false
	 * @param int $subdomains
	 *            optional, default 0
	 * @param bool $subdomains_ul
	 *            optional, default false
	 * @param int $emails
	 *            optional, default 0
	 * @param bool $emails_ul
	 *            optional, default false
	 * @param int $email_accounts
	 *            optional, default 0
	 * @param bool $email_accounts_ul
	 *            optional, default false
	 * @param int $email_forwarders
	 *            optional, default 0
	 * @param bool $email_forwarders_ul
	 *            optional, default false
	 * @param int $email_quota
	 *            optional, default 0
	 * @param bool $email_quota_ul
	 *            optional, default false
	 * @param int $ftps
	 *            optional, default 0
	 * @param bool $ftps_ul
	 *            optional, default false
	 * @param int $mysqls
	 *            optional, default 0
	 * @param bool $mysqls_ul
	 *            optional, default false
	 * @param bool $customers_see_all
	 *            optional, default false
	 * @param bool $caneditphpsettings
	 *            optional, default false
	 * @param bool $change_serversettings
	 *            optional, default false
	 * @param array $ipaddress
	 *            optional, list of ip-address id's; default -1 (all IP's)
	 *
	 * @access admin
	 * @return string json-encoded array
	 * @throws Exception
	 */
	public function add()
	{
		if ($this->isAdmin() && $this->getUserDetail('change_serversettings') == 1) {
			// required parameters
			$name = $this->getParam('name');
			$email = $this->getParam('email');
			$loginname = $this->getParam('new_loginname');

			// parameters
			$def_language = $this->getParam('def_language', true, Settings::Get('panel.standardlanguage'));
			$gui_access = $this->getBoolParam('gui_access', true, true);
			$api_allowed = $this->getBoolParam('api_allowed', true, Settings::Get('api.enabled'));
			$custom_notes = $this->getParam('custom_notes', true, '');
			$custom_notes_show = $this->getBoolParam('custom_notes_show', true, 0);
			$password = $this->getParam('admin_password', true, '');

			$diskspace = $this->getUlParam('diskspace', 'diskspace_ul', true, 0);
			$traffic = $this->getUlParam('traffic', 'traffic_ul', true, 0);
			$customers = $this->getUlParam('customers', 'customers_ul', true, 0);
			$domains = $this->getUlParam('domains', 'domains_ul', true, 0);
			$subdomains = $this->getUlParam('subdomains', 'subdomains_ul', true, 0);
			$emails = $this->getUlParam('emails', 'emails_ul', true, 0);
			$email_accounts = $this->getUlParam('email_accounts', 'email_accounts_ul', true, 0);
			$email_forwarders = $this->getUlParam('email_forwarders', 'email_forwarders_ul', true, 0);
			$email_quota = $this->getUlParam('email_quota', 'email_quota_ul', true, 0);
			$ftps = $this->getUlParam('ftps', 'ftps_ul', true, 0);
			$mysqls = $this->getUlParam('mysqls', 'mysqls_ul', true, 0);

			$customers_see_all = $this->getBoolParam('customers_see_all', true, 0);
			$caneditphpsettings = $this->getBoolParam('caneditphpsettings', true, 0);
			$change_serversettings = $this->getBoolParam('change_serversettings', true, 0);
			$ipaddress = $this->getParam('ipaddress', true, -1);

			// validation
			$name = Validate::validate($name, 'name', Validate::REGEX_DESC_TEXT, '', [], true);
			$idna_convert = new IdnaWrapper();
			$email = $idna_convert->encode(Validate::validate($email, 'email', '', '', [], true));
			$def_language = Validate::validate($def_language, 'default language', '', '', [], true);
			if (!empty($def_language) && !isset(Language::getLanguages()[$def_language])) {
				$def_language = Settings::Get('panel.standardlanguage');
			}
			$custom_notes = Validate::validate(str_replace("\r\n", "\n", $custom_notes), 'custom_notes', Validate::REGEX_CONF_TEXT, '', [], true);

			if (Settings::Get('system.mail_quota_enabled') != '1') {
				$email_quota = -1;
			}

			$password = Validate::validate($password, 'password', '', '', [], true);
			// only check if not empty,
			// cause empty == generate password automatically
			if ($password != '') {
				$password = Crypt::validatePassword($password, true);
			}

			$diskspace *= 1024;
			$traffic *= 1024 * 1024;

			// Check if the account already exists
			// do not check via api as we skip any permission checks for this task
			$loginname_check_stmt = Database::prepare("
				SELECT `loginname` FROM `" . TABLE_PANEL_CUSTOMERS . "` WHERE `loginname` = :login
			");
			$loginname_check = Database::pexecute_first($loginname_check_stmt, [
				'login' => $loginname
			], true, true);

			// Check if an admin with the loginname already exists
			// do not check via api as we skip any permission checks for this task
			$loginname_check_admin_stmt = Database::prepare("
				SELECT `loginname` FROM `" . TABLE_PANEL_ADMINS . "` WHERE `loginname` = :login
			");
			$loginname_check_admin = Database::pexecute_first($loginname_check_admin_stmt, [
				'login' => $loginname
			], true, true);

			// Check for existing email address
			// do not check via api as we skip any permission checks for this task
			$email_check_admin_stmt = Database::prepare("
				SELECT `email` FROM `" . TABLE_PANEL_ADMINS . "` WHERE `email` = :email
			");
			$email_check_admin = Database::pexecute_first($email_check_admin_stmt, [
				'email' => $email
			], true, true);

			if (($loginname_check && strtolower($loginname_check['loginname']) == strtolower($loginname)) || ($loginname_check_admin && strtolower($loginname_check_admin['loginname']) == strtolower($loginname))) {
				Response::standardError('loginnameexists', $loginname, true);
			} elseif (preg_match('/^' . preg_quote(Settings::Get('customer.accountprefix'), '/') . '([0-9]+)/', $loginname)) {
				// Accounts which match systemaccounts are not allowed, filtering them
				Response::standardError('loginnameisusingprefix', Settings::Get('customer.accountprefix'), true);
			} elseif (function_exists('posix_getpwnam') && !in_array("posix_getpwnam", explode(",", ini_get('disable_functions'))) && posix_getpwnam($loginname)) {
				Response::standardError('loginnameissystemaccount', $loginname, true);
			} elseif (!Validate::validateUsername($loginname)) {
				Response::standardError('loginnameiswrong', $loginname, true);
			} elseif (!Validate::validateEmail($email)) {
				Response::standardError('emailiswrong', $email, true);
			} elseif ($email_check_admin && strtolower($email_check_admin['email']) == strtolower($email)) {
				Response::standardError('emailexists', $email, true);
			} else {
				if ($customers_see_all != '1') {
					$customers_see_all = '0';
				}

				if ($caneditphpsettings != '1') {
					$caneditphpsettings = '0';
				}

				if ($change_serversettings != '1') {
					$change_serversettings = '0';
				}

				if ($password == '') {
					$password = Crypt::generatePassword();
				}

				$_theme = Settings::Get('panel.default_theme');

				$ins_data = [
					'loginname' => $loginname,
					'password' => Crypt::makeCryptPassword($password),
					'name' => $name,
					'email' => $email,
					'lang' => $def_language,
					'gui_access' => $gui_access,
					'api_allowed' => $api_allowed,
					'change_serversettings' => $change_serversettings,
					'customers' => $customers,
					'customers_see_all' => $customers_see_all,
					'domains' => $domains,
					'caneditphpsettings' => $caneditphpsettings,
					'diskspace' => $diskspace,
					'traffic' => $traffic,
					'subdomains' => $subdomains,
					'emails' => $emails,
					'accounts' => $email_accounts,
					'forwarders' => $email_forwarders,
					'quota' => $email_quota,
					'ftps' => $ftps,
					'mysqls' => $mysqls,
					'ip' => empty($ipaddress) ? "" : (is_array($ipaddress) && $ipaddress > 0 ? json_encode($ipaddress) : -1),
					'theme' => $_theme,
					'custom_notes' => $custom_notes,
					'custom_notes_show' => $custom_notes_show
				];

				$ins_stmt = Database::prepare("
					INSERT INTO `" . TABLE_PANEL_ADMINS . "` SET
					`loginname` = :loginname,
					`password` = :password,
					`name` = :name,
					`email` = :email,
					`def_language` = :lang,
					`gui_access` = :gui_access,
					`api_allowed` = :api_allowed,
					`change_serversettings` = :change_serversettings,
					`customers` = :customers,
					`customers_see_all` = :customers_see_all,
					`domains` = :domains,
					`caneditphpsettings` = :caneditphpsettings,
					`diskspace` = :diskspace,
					`traffic` = :traffic,
					`subdomains` = :subdomains,
					`emails` = :emails,
					`email_accounts` = :accounts,
					`email_forwarders` = :forwarders,
					`email_quota` = :quota,
					`ftps` = :ftps,
					`mysqls` = :mysqls,
					`ip` = :ip,
					`theme` = :theme,
					`custom_notes` = :custom_notes,
					`custom_notes_show` = :custom_notes_show
				");
				Database::pexecute($ins_stmt, $ins_data, true, true);

				$adminid = Database::lastInsertId();
				$ins_data['adminid'] = $adminid;
				$this->logger()->logAction(FroxlorLogger::ADM_ACTION, LOG_WARNING, "[API] added admin '" . $loginname . "'");

				// get all admin-data for return-array
				$result = $this->apiCall('Admins.get', [
					'id' => $adminid
				]);
				return $this->response($result);
			}
		}
		throw new Exception("Not allowed to execute given command.", 403);
	}

	/**
	 * return an admin entry by either id or loginname
	 *
	 * @param int $id
	 *            optional, the admin-id
	 * @param string $loginname
	 *            optional, the loginname
	 *
	 * @access admin
	 * @return string json-encoded array
	 * @throws Exception
	 */
	public function get()
	{
		$id = $this->getParam('id', true, 0);
		$ln_optional = $id > 0;
		$loginname = $this->getParam('loginname', $ln_optional, '');

		if ($this->isAdmin() && ($this->getUserDetail('change_serversettings') == 1 || ($this->getUserDetail('adminid') == $id || $this->getUserDetail('loginname') == $loginname))) {
			$result_stmt = Database::prepare("
				SELECT * FROM `" . TABLE_PANEL_ADMINS . "`
				WHERE " . ($id > 0 ? "`adminid` = :idln" : "`loginname` = :idln"));
			$params = [
				'idln' => ($id <= 0 ? $loginname : $id)
			];
			$result = Database::pexecute_first($result_stmt, $params, true, true);
			if ($result) {
				$this->logger()->logAction(FroxlorLogger::ADM_ACTION, LOG_INFO, "[API] get admin '" . $result['loginname'] . "'");
				return $this->response($result);
			}
			$key = ($id > 0 ? "id #" . $id : "loginname '" . $loginname . "'");
			throw new Exception("Admin with " . $key . " could not be found", 404);
		}
		throw new Exception("Not allowed to execute given command.", 403);
	}

	/**
	 * update an admin user by given id or loginname
	 *
	 * @param int $id
	 *            optional, the admin-id
	 * @param string $loginname
	 *            optional, the loginname
	 * @param string $name
	 *            optional
	 * @param string $email
	 *            optional
	 * @param string $admin_password
	 *            optional, default auto-generated
	 * @param string $def_language
	 *            optional, ISO 639-1 language code (e.g. 'en', 'de', see lng-folder for supported languages),
	 *            default is system-default language
	 * @param bool $gui_access
	 *            optional, allow login via webui, if false ONLY the login via webui is disallowed; default true
	 * @param bool $api_allowed
	 *            optional, default is true if system setting api.enabled is true, else false
	 * @param string $custom_notes
	 *            optional, default empty
	 * @param string $theme
	 *            optional
	 * @param bool $deactivated
	 *            optional, default false
	 * @param bool $custom_notes_show
	 *            optional, default false
	 * @param int $diskspace
	 *            optional, default 0
	 * @param bool $diskspace_ul
	 *            optional, default false
	 * @param int $traffic
	 *            optional, default 0
	 * @param bool $traffic_ul
	 *            optional, default false
	 * @param int $customers
	 *            optional, default 0
	 * @param bool $customers_ul
	 *            optional, default false
	 * @param int $domains
	 *            optional, default 0
	 * @param bool $domains_ul
	 *            optional, default false
	 * @param int $subdomains
	 *            optional, default 0
	 * @param bool $subdomains_ul
	 *            optional, default false
	 * @param int $emails
	 *            optional, default 0
	 * @param bool $emails_ul
	 *            optional, default false
	 * @param int $email_accounts
	 *            optional, default 0
	 * @param bool $email_accounts_ul
	 *            optional, default false
	 * @param int $email_forwarders
	 *            optional, default 0
	 * @param bool $email_forwarders_ul
	 *            optional, default false
	 * @param int $email_quota
	 *            optional, default 0
	 * @param bool $email_quota_ul
	 *            optional, default false
	 * @param int $ftps
	 *            optional, default 0
	 * @param bool $ftps_ul
	 *            optional, default false
	 * @param int $mysqls
	 *            optional, default 0
	 * @param bool $mysqls_ul
	 *            optional, default false
	 * @param bool $customers_see_all
	 *            optional, default false
	 * @param bool $caneditphpsettings
	 *            optional, default false
	 * @param bool $change_serversettings
	 *            optional, default false
	 * @param array $ipaddress
	 *            optional, list of ip-address id's; default -1 (all IP's)
	 *
	 * @access admin
	 * @return string json-encoded array
	 * @throws Exception
	 */
	public function update()
	{
		if ($this->isAdmin()) {
			$id = $this->getParam('id', true, 0);
			$ln_optional = $id > 0;
			$loginname = $this->getParam('loginname', $ln_optional, '');

			$result = $this->apiCall('Admins.get', [
				'id' => $id,
				'loginname' => $loginname
			]);
			$id = $result['adminid'];

			if ($this->getUserDetail('change_serversettings') == 1 || $result['adminid'] == $this->getUserDetail('adminid')) {
				// parameters
				$name = $this->getParam('name', true, $result['name']);
				$idna_convert = new IdnaWrapper();
				$email = $this->getParam('email', true, $idna_convert->decode($result['email']));
				$password = $this->getParam('admin_password', true, '');
				$def_language = $this->getParam('def_language', true, $result['def_language']);
				$custom_notes = $this->getParam('custom_notes', true, ($result['custom_notes'] ?? ""));
				$custom_notes_show = $this->getBoolParam('custom_notes_show', true, $result['custom_notes_show']);
				$theme = $this->getParam('theme', true, $result['theme']);

				// you cannot edit some of the details of yourself
				if ($result['adminid'] == $this->getUserDetail('adminid')) {
					$gui_access = $result['gui_access'];
					$api_allowed = $result['api_allowed'];
					$deactivated = $result['deactivated'];
					$customers = $result['customers'];
					$domains = $result['domains'];
					$subdomains = $result['subdomains'];
					$emails = $result['emails'];
					$email_accounts = $result['email_accounts'];
					$email_forwarders = $result['email_forwarders'];
					$email_quota = $result['email_quota'];
					$ftps = $result['ftps'];
					$mysqls = $result['mysqls'];
					$customers_see_all = $result['customers_see_all'];
					$caneditphpsettings = $result['caneditphpsettings'];
					$change_serversettings = $result['change_serversettings'];
					$diskspace = $result['diskspace'];
					$traffic = $result['traffic'];
					$ipaddress = ($result['ip'] != -1 ? json_decode($result['ip'], true) : -1);
				} else {
					$gui_access = $this->getBoolParam('gui_access', true, $result['gui_access']);
					$api_allowed = $this->getBoolParam('api_allowed', true, $result['api_allowed']);
					$deactivated = $this->getBoolParam('deactivated', true, $result['deactivated']);

					$dec_places = Settings::Get('panel.decimal_places');
					$diskspace = $this->getUlParam('diskspace', 'diskspace_ul', true, round($result['diskspace'] / 1024, $dec_places));
					$traffic = $this->getUlParam('traffic', 'traffic_ul', true, round($result['traffic'] / (1024 * 1024), $dec_places));
					$customers = $this->getUlParam('customers', 'customers_ul', true, $result['customers']);
					$domains = $this->getUlParam('domains', 'domains_ul', true, $result['domains']);
					$subdomains = $this->getUlParam('subdomains', 'subdomains_ul', true, $result['subdomains']);
					$emails = $this->getUlParam('emails', 'emails_ul', true, $result['emails']);
					$email_accounts = $this->getUlParam('email_accounts', 'email_accounts_ul', true, $result['email_accounts']);
					$email_forwarders = $this->getUlParam('email_forwarders', 'email_forwarders_ul', true, $result['email_forwarders']);
					$email_quota = $this->getUlParam('email_quota', 'email_quota_ul', true, $result['email_quota']);
					$ftps = $this->getUlParam('ftps', 'ftps_ul', true, $result['ftps']);
					$mysqls = $this->getUlParam('mysqls', 'mysqls_ul', true, $result['mysqls']);

					$customers_see_all = $this->getBoolParam('customers_see_all', true, $result['customers_see_all']);
					$caneditphpsettings = $this->getBoolParam('caneditphpsettings', true, $result['caneditphpsettings']);
					$change_serversettings = $this->getBoolParam('change_serversettings', true, $result['change_serversettings']);
					$ipaddress = $this->getParam('ipaddress', true, ($result['ip'] != -1 ? json_decode($result['ip'], true) : -1));

					$diskspace *= 1024;
					$traffic *= 1024 * 1024;
				}

				// validation
				$name = Validate::validate($name, 'name', Validate::REGEX_DESC_TEXT, '', [], true);
				$idna_convert = new IdnaWrapper();
				$email = $idna_convert->encode(Validate::validate($email, 'email', '', '', [], true));
				$def_language = Validate::validate($def_language, 'default language', '', '', [], true);
				if (!empty($def_language) && !isset(Language::getLanguages()[$def_language])) {
					$def_language = Settings::Get('panel.standardlanguage');
				}
				$custom_notes = Validate::validate(str_replace("\r\n", "\n", $custom_notes ?? ""), 'custom_notes', Validate::REGEX_CONF_TEXT, '', [], true);
				$theme = Validate::validate($theme, 'theme', '', '', [], true);
				$password = Validate::validate($password, 'password', '', '', [], true);

				if (Settings::Get('system.mail_quota_enabled') != '1') {
					$email_quota = -1;
				}

				if (empty($theme)) {
					$theme = Settings::Get('panel.default_theme');
				}

				if (empty(trim($name))) {
					Response::standardError([
						'stringisempty',
						'admin.name'
					], '', true);
				}
				if (empty(trim($email))) {
					Response::standardError([
						'stringisempty',
						'admin.email'
					], '', true);
				}
				// Check for existing email address
				// do not check via api as we skip any permission checks for this task
				$email_check_admin_stmt = Database::prepare("
					SELECT `email` FROM `" . TABLE_PANEL_ADMINS . "` WHERE `email` = :email and `adminid` <> :adminid
				");
				$email_check_admin = Database::pexecute_first($email_check_admin_stmt, [
					'email' => $email,
					'adminid' => $id,
				], true, true);

				if (!Validate::validateEmail($email)) {
					Response::standardError('emailiswrong', $email, true);
				} elseif ($email_check_admin && strtolower($email_check_admin['email']) == strtolower($email)) {
					Response::standardError('emailexists', $email, true);
				} else {
					if ($deactivated != '1') {
						$deactivated = '0';
					}

					if ($customers_see_all != '1') {
						$customers_see_all = '0';
					}

					if ($caneditphpsettings != '1') {
						$caneditphpsettings = '0';
					}

					if ($change_serversettings != '1') {
						$change_serversettings = '0';
					}

					if ($password != '') {
						$password = Crypt::validatePassword($password, true);
						$password = Crypt::makeCryptPassword($password);
					} else {
						$password = $result['password'];
					}

					// check if a resource was set to something lower
					// than actually used by the admin/reseller
					$res_warning = "";
					if ($customers != $result['customers'] && $customers != -1 && $customers < $result['customers_used']) {
						$res_warning .= lng('error.setlessthanalreadyused', ['customers']);
					}
					if ($domains != $result['domains'] && $domains != -1 && $domains < $result['domains_used']) {
						$res_warning .= lng('error.setlessthanalreadyused', ['domains']);
					}
					if ($diskspace != $result['diskspace'] && ($diskspace / 1024) != -1 && $diskspace < $result['diskspace_used']) {
						$res_warning .= lng('error.setlessthanalreadyused', ['diskspace']);
					}
					if ($traffic != $result['traffic'] && ($traffic / 1024 / 1024) != -1 && $traffic < $result['traffic_used']) {
						$res_warning .= lng('error.setlessthanalreadyused', ['traffic']);
					}
					if ($emails != $result['emails'] && $emails != -1 && $emails < $result['emails_used']) {
						$res_warning .= lng('error.setlessthanalreadyused', ['emails']);
					}
					if ($email_accounts != $result['email_accounts'] && $email_accounts != -1 && $email_accounts < $result['email_accounts_used']) {
						$res_warning .= lng('error.setlessthanalreadyused', ['email accounts']);
					}
					if ($email_forwarders != $result['email_forwarders'] && $email_forwarders != -1 && $email_forwarders < $result['email_forwarders_used']) {
						$res_warning .= lng('error.setlessthanalreadyused', ['email forwarders']);
					}
					if ($email_quota != $result['email_quota'] && $email_quota != -1 && $email_quota < $result['email_quota_used']) {
						$res_warning .= lng('error.setlessthanalreadyused', ['email quota']);
					}
					if ($ftps != $result['ftps'] && $ftps != -1 && $ftps < $result['ftps_used']) {
						$res_warning .= lng('error.setlessthanalreadyused', ['ftps']);
					}
					if ($mysqls != $result['mysqls'] && $mysqls != -1 && $mysqls < $result['mysqls_used']) {
						$res_warning .= lng('error.setlessthanalreadyused', ['mysqls']);
					}

					if (!empty($res_warning)) {
						throw new Exception($res_warning, 406);
					}

					$upd_data = [
						'password' => $password,
						'name' => $name,
						'email' => $email,
						'lang' => $def_language,
						'gui_access' => $gui_access,
						'api_allowed' => $api_allowed,
						'change_serversettings' => $change_serversettings,
						'customers' => $customers,
						'customers_see_all' => $customers_see_all,
						'domains' => $domains,
						'caneditphpsettings' => $caneditphpsettings,
						'diskspace' => $diskspace,
						'traffic' => $traffic,
						'subdomains' => $subdomains,
						'emails' => $emails,
						'accounts' => $email_accounts,
						'forwarders' => $email_forwarders,
						'quota' => $email_quota,
						'ftps' => $ftps,
						'mysqls' => $mysqls,
						'ip' => empty($ipaddress) ? "" : (is_array($ipaddress) && $ipaddress > 0 ? json_encode($ipaddress) : -1),
						'deactivated' => $deactivated,
						'custom_notes' => $custom_notes,
						'custom_notes_show' => $custom_notes_show,
						'theme' => $theme,
						'adminid' => $id
					];

					$upd_stmt = Database::prepare("
						UPDATE `" . TABLE_PANEL_ADMINS . "` SET
						`password` = :password,
						`name` = :name,
						`email` = :email,
						`def_language` = :lang,
						`gui_access` = :gui_access,
						`api_allowed` = :api_allowed,
						`change_serversettings` = :change_serversettings,
						`customers` = :customers,
						`customers_see_all` = :customers_see_all,
						`domains` = :domains,
						`caneditphpsettings` = :caneditphpsettings,
						`diskspace` = :diskspace,
						`traffic` = :traffic,
						`subdomains` = :subdomains,
						`emails` = :emails,
						`email_accounts` = :accounts,
						`email_forwarders` = :forwarders,
						`email_quota` = :quota,
						`ftps` = :ftps,
						`mysqls` = :mysqls,
						`ip` = :ip,
						`deactivated` = :deactivated,
						`custom_notes` = :custom_notes,
						`custom_notes_show` = :custom_notes_show,
						`theme` = :theme
						WHERE `adminid` = :adminid
					");
					Database::pexecute($upd_stmt, $upd_data, true, true);
					$this->logger()->logAction(FroxlorLogger::ADM_ACTION, LOG_NOTICE, "[API] edited admin '" . $result['loginname'] . "'");

					// get all admin-data for return-array
					$result = $this->apiCall('Admins.get', [
						'id' => $result['adminid']
					]);
					return $this->response($result);
				}
			}
		}
		throw new Exception("Not allowed to execute given command.", 403);
	}

	/**
	 * delete a admin entry by either id or loginname
	 *
	 * @param int $id
	 *            optional, the admin-id
	 * @param string $loginname
	 *            optional, the loginname
	 *
	 * @access admin
	 * @return string json-encoded array
	 * @throws Exception
	 */
	public function delete()
	{
		if ($this->isAdmin() && $this->getUserDetail('change_serversettings') == 1) {
			$id = $this->getParam('id', true, 0);
			$ln_optional = $id > 0;
			$loginname = $this->getParam('loginname', $ln_optional, '');

			$result = $this->apiCall('Admins.get', [
				'id' => $id,
				'loginname' => $loginname
			]);
			$id = $result['adminid'];

			// don't be stupid
			if ($id == $this->getUserDetail('adminid')) {
				Response::standardError('youcantdeleteyourself', '', true);
			}
			// can't delete the first superadmin
			if ($id == 1) {
				Response::standardError('cannotdeletesuperadmin', '', true);
			}

			// delete admin
			$del_stmt = Database::prepare("
				DELETE FROM `" . TABLE_PANEL_ADMINS . "` WHERE `adminid` = :adminid
			");
			Database::pexecute($del_stmt, [
				'adminid' => $id
			], true, true);

			// delete the traffic-usage
			$del_stmt = Database::prepare("
				DELETE FROM `" . TABLE_PANEL_TRAFFIC_ADMINS . "` WHERE `adminid` = :adminid
			");
			Database::pexecute($del_stmt, [
				'adminid' => $id
			], true, true);

			// set admin-id of the old admin's customer to current admins
			$upd_stmt = Database::prepare("
				UPDATE `" . TABLE_PANEL_CUSTOMERS . "` SET
				`adminid` = :userid WHERE `adminid` = :adminid
			");
			Database::pexecute($upd_stmt, [
				'userid' => $this->getUserDetail('adminid'),
				'adminid' => $id
			], true, true);

			// set admin-id of the old admin's domains to current admins
			$upd_stmt = Database::prepare("
				UPDATE `" . TABLE_PANEL_DOMAINS . "` SET
				`adminid` = :userid WHERE `adminid` = :adminid
			");
			Database::pexecute($upd_stmt, [
				'userid' => $this->getUserDetail('adminid'),
				'adminid' => $id
			], true, true);

			// delete old admin's api keys if exists (no customer keys)
			$upd_stmt = Database::prepare("
				DELETE FROM `" . TABLE_API_KEYS . "` WHERE
				`adminid` = :adminid AND `customerid` = '0'
			");
			Database::pexecute($upd_stmt, [
				'adminid' => $id
			], true, true);

			// set admin-id of the old admin's api-keys to current admins
			$upd_stmt = Database::prepare("
				UPDATE `" . TABLE_API_KEYS . "` SET
				`adminid` = :userid WHERE `adminid` = :adminid
			");
			Database::pexecute($upd_stmt, [
				'userid' => $this->getUserDetail('adminid'),
				'adminid' => $id
			], true, true);

			$this->logger()->logAction(FroxlorLogger::ADM_ACTION, LOG_WARNING, "[API] deleted admin '" . $result['loginname'] . "'");
			User::updateCounters();
			return $this->response($result);
		}
		throw new Exception("Not allowed to execute given command.", 403);
	}

	/**
	 * unlock a locked admin by either id or loginname
	 *
	 * @param int $id
	 *            optional, the admin-id
	 * @param string $loginname
	 *            optional, the loginname
	 *
	 * @access admin
	 * @return string json-encoded array
	 * @throws Exception
	 */
	public function unlock()
	{
		if ($this->isAdmin() && $this->getUserDetail('change_serversettings') == 1) {
			$id = $this->getParam('id', true, 0);
			$ln_optional = $id > 0;
			$loginname = $this->getParam('loginname', $ln_optional, '');

			$result = $this->apiCall('Admins.get', [
				'id' => $id,
				'loginname' => $loginname
			]);
			$id = $result['adminid'];

			$result_stmt = Database::prepare("
				UPDATE `" . TABLE_PANEL_ADMINS . "` SET
				`loginfail_count` = '0'
				WHERE `adminid`= :id
			");
			Database::pexecute($result_stmt, [
				'id' => $id
			], true, true);
			// set the new value for result-array
			$result['loginfail_count'] = 0;

			$this->logger()->logAction(FroxlorLogger::ADM_ACTION, LOG_WARNING, "[API] unlocked admin '" . $result['loginname'] . "'");
			return $this->response($result);
		}
		throw new Exception("Not allowed to execute given command.", 403);
	}
}
