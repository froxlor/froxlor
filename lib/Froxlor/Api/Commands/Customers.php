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
use Froxlor\Database\DbManager;
use Froxlor\FileDir;
use Froxlor\FroxlorLogger;
use Froxlor\Idna\IdnaWrapper;
use Froxlor\Language;
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
class Customers extends ApiCommand implements ResourceEntity
{

	/**
	 * lists all customer entries
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
	 * @param bool $show_usages
	 *            optional, default false
	 *
	 * @access admin
	 * @return string json-encoded array count|list
	 * @throws Exception
	 */
	public function listing()
	{
		if ($this->isAdmin()) {
			$show_usages = $this->getBoolParam('show_usages', true, false);
			$this->logger()->logAction(FroxlorLogger::ADM_ACTION, LOG_NOTICE, "[API] list customers");
			$query_fields = [];
			$result_stmt = Database::prepare("
				SELECT `c`.*, `a`.`loginname` AS `adminname`
				FROM `" . TABLE_PANEL_CUSTOMERS . "` `c`, `" . TABLE_PANEL_ADMINS . "` `a`
				WHERE " . ($this->getUserDetail('customers_see_all') ? '' : " `c`.`adminid` = :adminid AND ") . "
				`c`.`adminid` = `a`.`adminid`" . $this->getSearchWhere($query_fields, true) . $this->getOrderBy() . $this->getLimit());
			$params = [];
			if ($this->getUserDetail('customers_see_all') == '0') {
				$params = [
					'adminid' => $this->getUserDetail('adminid')
				];
			}
			$params = array_merge($params, $query_fields);
			Database::pexecute($result_stmt, $params, true, true);
			$result = [];

			$domains_stmt = null;
			$usages_stmt = null;
			if ($show_usages) {
				$domains_stmt = Database::prepare("
					SELECT COUNT(`id`) AS `domains`
					FROM `" . TABLE_PANEL_DOMAINS . "`
					WHERE `customerid` = :cid
					AND `parentdomainid` = '0'
					AND `id`<> :stdd
				");
				$usages_stmt = Database::prepare("
					SELECT webspace, mail, mysql FROM `" . TABLE_PANEL_DISKSPACE . "`
					WHERE `customerid` = :cid
					ORDER BY `stamp` DESC LIMIT 1
				");
			}

			while ($row = $result_stmt->fetch(PDO::FETCH_ASSOC)) {
				if ($show_usages) {
					// get number of domains
					$domains = Database::pexecute_first($domains_stmt, [
						'cid' => $row['customerid'],
						'stdd' => $row['standardsubdomain']
					]);
					$row['domains'] = intval($domains['domains']);
					// get disk-space usages for web, mysql and mail
					$usages = Database::pexecute_first($usages_stmt, [
						'cid' => $row['customerid']
					]);
					if ($usages) {
						$row['webspace_used'] = $usages['webspace'];
						$row['mailspace_used'] = $usages['mail'];
						$row['dbspace_used'] = $usages['mysql'];
					} else {
						$row['webspace_used'] = 0;
						$row['mailspace_used'] = 0;
						$row['dbspace_used'] = 0;
					}
				}
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
	 * returns the total number of customers for the given admin
	 *
	 * @access admin
	 * @return string json-encoded response message
	 * @throws Exception
	 */
	public function listingCount()
	{
		if ($this->isAdmin()) {
			$query_fields = [];
			$result_stmt = Database::prepare("
				SELECT COUNT(*) as num_customers
				FROM `" . TABLE_PANEL_CUSTOMERS . "` `c`, `" . TABLE_PANEL_ADMINS . "` `a`
				WHERE `c`.`adminid` = `a`.`adminid` AND " . ($this->getUserDetail('customers_see_all') ? "1" : " `c`.`adminid` = :adminid ") . $this->getSearchWhere($query_fields, true));
			$params = [];
			if ($this->getUserDetail('customers_see_all') == '0') {
				$params = [
					'adminid' => $this->getUserDetail('adminid')
				];
			}
			$params = array_merge($params, $query_fields);
			$result = Database::pexecute_first($result_stmt, $params, true, true);
			if ($result) {
				return $this->response($result['num_customers']);
			}
			return $this->response(0);
		}
		throw new Exception("Not allowed to execute given command.", 403);
	}

	/**
	 * create a new customer with default ftp-user and standard-subdomain (if wanted)
	 *
	 * @param string $email
	 *                             required, email address of new customer
	 * @param string $name
	 *                             optional if company is set, else required
	 * @param string $firstname
	 *                             optional if company is set, else required
	 * @param string $company
	 *                             optional but required if name/firstname empty
	 * @param string $street
	 *                             optional
	 * @param string $zipcode
	 *                             optional
	 * @param string $city
	 *                             optional
	 * @param string $phone
	 *                             optional
	 * @param string $fax
	 *                             optional
	 * @param int $customernumber
	 *                             optional
	 * @param string $def_language
	 *                             optional, ISO 639-1 language code (e.g. 'en', 'de', see lng-folder for supported languages),
	 *                             default is system-default language
	 * @param bool $gui_access
	 *                             optional, allow login via webui, if false ONLY the login via webui is disallowed; default true
	 * @param bool $api_allowed
	 *                             optional, default is true if system setting api.enabled is true, else false
	 * @param bool $shell_allowed
	 *                             optional, default is true if system setting system.allow_customer_shell is true, else false
	 * @param int $gender
	 *                             optional, 0 = no-gender, 1 = male, 2 = female
	 * @param string $custom_notes
	 *                             optional notes
	 * @param bool $custom_notes_show
	 *                             optional, whether to show the content of custom_notes to the customer, default 0
	 *                             (false)
	 * @param string $new_loginname
	 *                             optional, if empty generated automatically using customer-prefix and increasing
	 *                             number
	 * @param string $new_customer_password
	 *                             optional, if empty generated automatically and send to the customer's email if
	 *                             $sendpassword is 1
	 * @param bool $sendpassword
	 *                             optional, whether to send the password to the customer after creation, default 0
	 *                             (false)
	 * @param int $diskspace
	 *                             optional disk-space available for customer in MB, default 0
	 * @param bool $diskspace_ul
	 *                             optional, whether customer should have unlimited diskspace, default 0 (false)
	 * @param int $traffic
	 *                             optional traffic available for customer in GB, default 0
	 * @param bool $traffic_ul
	 *                             optional, whether customer should have unlimited traffic, default 0 (false)
	 * @param int $subdomains
	 *                             optional amount of subdomains available for customer, default 0
	 * @param bool $subdomains_ul
	 *                             optional, whether customer should have unlimited subdomains, default 0 (false)
	 * @param int $emails
	 *                             optional amount of emails available for customer, default 0
	 * @param bool $emails_ul
	 *                             optional, whether customer should have unlimited emails, default 0 (false)
	 * @param int $email_accounts
	 *                             optional amount of email-accounts available for customer, default 0
	 * @param bool $email_accounts_ul
	 *                             optional, whether customer should have unlimited email-accounts, default 0 (false)
	 * @param int $email_forwarders
	 *                             optional amount of email-forwarders available for customer, default 0
	 * @param bool $email_forwarders_ul
	 *                             optional, whether customer should have unlimited email-forwarders, default 0 (false)
	 * @param int $email_quota
	 *                             optional size of email-quota available for customer in MB, default is system-setting
	 *                             mail_quota
	 * @param bool $email_quota_ul
	 *                             optional, whether customer should have unlimited email-quota, default 0 (false)
	 * @param bool $email_imap
	 *                             optional, whether to allow IMAP access, default 0 (false)
	 * @param bool $email_pop3
	 *                             optional, whether to allow POP3 access, default 0 (false)
	 * @param int $ftps
	 *                             optional amount of ftp-accounts available for customer, default 0
	 * @param bool $ftps_ul
	 *                             optional, whether customer should have unlimited ftp-accounts, default 0 (false)
	 * @param int $mysqls
	 *                             optional amount of mysql-databases available for customer, default 0
	 * @param bool $mysqls_ul
	 *                             optional, whether customer should have unlimited mysql-databases, default 0 (false)
	 * @param bool $createstdsubdomain
	 *                             optional, whether to create a standard-subdomain ([loginname].froxlor-hostname.tld),
	 *                             default [system.createstdsubdom_default]
	 * @param bool $phpenabled
	 *                             optional, whether to allow usage of PHP, default 0 (false)
	 * @param array $allowed_phpconfigs
	 *                             optional, array of IDs of php-config that the customer is allowed to use, default
	 *                             empty (none)
	 * @param bool $perlenabled
	 *                             optional, whether to allow usage of Perl/CGI, default 0 (false)
	 * @param bool $dnsenabled
	 *                             optional, whether to allow usage of the DNS editor (requires activated nameserver in
	 *                             settings), default 0 (false)
	 * @param bool $logviewenabled
	 *                             optional, whether to allow access to webserver access/error-logs, default 0 (false)
	 * @param bool $store_defaultindex
	 *                             optional, whether to store the default index file to customers homedir
	 * @param int $hosting_plan_id
	 *                             optional, specify a hosting-plan to set certain resource-values from the plan
	 *                             instead of specifying them
	 * @param array $allowed_mysqlserver
	 *                             optional, array of IDs of defined mysql-servers the customer is allowed to use,
	 *                             default is to allow the default dbserver (id=0)
	 *
	 * @access admin
	 * @return string json-encoded array
	 * @throws Exception
	 */
	public function add()
	{
		if ($this->isAdmin()) {
			if ($this->getUserDetail('customers_used') < $this->getUserDetail('customers') || $this->getUserDetail('customers') == '-1') {
				// required parameters
				$email = $this->getParam('email');

				// parameters
				$name = $this->getParam('name', true, '');
				$firstname = $this->getParam('firstname', true, '');
				$company_required = (!empty($name) && empty($firstname)) || (empty($name) && !empty($firstname)) || (empty($name) && empty($firstname));
				$company = $this->getParam('company', !$company_required, '');
				$street = $this->getParam('street', true, '');
				$zipcode = $this->getParam('zipcode', true, '');
				$city = $this->getParam('city', true, '');
				$phone = $this->getParam('phone', true, '');
				$fax = $this->getParam('fax', true, '');
				$customernumber = $this->getParam('customernumber', true, '');
				$def_language = $this->getParam('def_language', true, Settings::Get('panel.standardlanguage'));
				$gui_access = $this->getBoolParam('gui_access', true, 1);
				$api_allowed = $this->getBoolParam('api_allowed', true, (Settings::Get('api.enabled') && Settings::Get('api.customer_default')));
				$shell_allowed = $this->getBoolParam('shell_allowed', true, intval(Settings::Get('system.allow_customer_shell')));
				$gender = (int)$this->getParam('gender', true, 0);
				$custom_notes = $this->getParam('custom_notes', true, '');
				$custom_notes_show = $this->getBoolParam('custom_notes_show', true, 0);
				$createstdsubdomain = $this->getBoolParam('createstdsubdomain', true, Settings::Get('system.createstdsubdom_default'));
				$password = $this->getParam('new_customer_password', true, '');
				$sendpassword = $this->getBoolParam('sendpassword', true, 0);
				$store_defaultindex = $this->getBoolParam('store_defaultindex', true, 0);
				$loginname = $this->getParam('new_loginname', true, '');

				// hosting-plan values
				$hosting_plan_id = $this->getParam('hosting_plan_id', true, 0);
				if ($hosting_plan_id > 0) {
					$hp_result = $this->apiCall('HostingPlans.get', [
						'id' => $hosting_plan_id
					]);
					$hp_result['value'] = json_decode($hp_result['value'], true);
					foreach ($hp_result['value'] as $index => $value) {
						$hp_result[$index] = $value;
					}
					$diskspace = $hp_result['diskspace'] ?? 0;
					$traffic = $hp_result['traffic'] ?? 0;
					$subdomains = $hp_result['subdomains'] ?? 0;
					$emails = $hp_result['emails'] ?? 0;
					$email_accounts = $hp_result['email_accounts'] ?? 0;
					$email_forwarders = $hp_result['email_forwarders'] ?? 0;
					$email_quota = $hp_result['email_quota'] ?? Settings::Get('system.mail_quota');
					$email_imap = $hp_result['email_imap'] ?? 0;
					$email_pop3 = $hp_result['email_pop3'] ?? 0;
					$ftps = $hp_result['ftps'] ?? 0;
					$mysqls = $hp_result['mysqls'] ?? 0;
					$phpenabled = $hp_result['phpenabled'] ?? 0;
					$p_allowed_phpconfigs = $hp_result['allowed_phpconfigs'] ?? 0;
					$perlenabled = $hp_result['perlenabled'] ?? 0;
					$dnsenabled = $hp_result['dnsenabled'] ?? 0;
					$logviewenabled = $hp_result['logviewenabled'] ?? 0;
				} else {
					$diskspace = $this->getUlParam('diskspace', 'diskspace_ul', true, 0);
					$traffic = $this->getUlParam('traffic', 'traffic_ul', true, 0);
					$subdomains = $this->getUlParam('subdomains', 'subdomains_ul', true, 0);
					$emails = $this->getUlParam('emails', 'emails_ul', true, 0);
					$email_accounts = $this->getUlParam('email_accounts', 'email_accounts_ul', true, 0);
					$email_forwarders = $this->getUlParam('email_forwarders', 'email_forwarders_ul', true, 0);
					$email_quota = $this->getUlParam('email_quota', 'email_quota_ul', true, Settings::Get('system.mail_quota'));
					$email_imap = $this->getBoolParam('email_imap', true, 0);
					$email_pop3 = $this->getBoolParam('email_pop3', true, 0);
					$ftps = $this->getUlParam('ftps', 'ftps_ul', true, 0);
					$mysqls = $this->getUlParam('mysqls', 'mysqls_ul', true, 0);
					$phpenabled = $this->getBoolParam('phpenabled', true, 0);
					$p_allowed_phpconfigs = $this->getParam('allowed_phpconfigs', true, []);
					$perlenabled = $this->getBoolParam('perlenabled', true, 0);
					$dnsenabled = $this->getBoolParam('dnsenabled', true, 0);
					$logviewenabled = $this->getBoolParam('logviewenabled', true, 0);
				}

				if ($mysqls == -1 || $mysqls > 0) {
					$p_allowed_mysqlserver = $this->getParam('allowed_mysqlserver', true, [0]);
				} else {
					// mysql not allowed, so no mysql available for customer
					$p_allowed_mysqlserver = [];
				}

				// validation
				$name = Validate::validate($name, 'name', Validate::REGEX_DESC_TEXT, '', [], true);
				$firstname = Validate::validate($firstname, 'first name', Validate::REGEX_DESC_TEXT, '', [], true);
				$company = Validate::validate($company, 'company', Validate::REGEX_DESC_TEXT, '', [], true);
				$street = Validate::validate($street, 'street', Validate::REGEX_DESC_TEXT, '', [], true);
				$zipcode = Validate::validate($zipcode, 'zipcode', '/^[0-9 \-A-Z]*$/', '', [], true);
				$city = Validate::validate($city, 'city', Validate::REGEX_DESC_TEXT, '', [], true);
				$phone = Validate::validate($phone, 'phone', '/^[0-9\- \+\(\)\/]*$/', '', [], true);
				$fax = Validate::validate($fax, 'fax', '/^[0-9\- \+\(\)\/]*$/', '', [], true);
				$idna_convert = new IdnaWrapper();
				$email = $idna_convert->encode(Validate::validate($email, 'email', '', '', [], true));
				$customernumber = Validate::validate($customernumber, 'customer number', '/^[A-Za-z0-9 \-]*$/Di', '', [], true);
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

				// gender out of range? [0,2]
				if ($gender < 0 || $gender > 2) {
					$gender = 0;
				}

				$allowed_phpconfigs = [];
				if (!empty($p_allowed_phpconfigs) && is_array($p_allowed_phpconfigs)) {
					foreach ($p_allowed_phpconfigs as $allowed_phpconfig) {
						$allowed_phpconfig = intval($allowed_phpconfig);
						$allowed_phpconfigs[] = $allowed_phpconfig;
					}
				}
				$allowed_phpconfigs = array_map('intval', $allowed_phpconfigs);

				if (empty($allowed_phpconfigs) && $phpenabled == 1) {
					// only required if not using mod_php
					if ((int)Settings::Get('system.mod_fcgid') == 1 || (int)Settings::Get('phpfpm.enabled') == 1) {
						Response::standardError('customerphpenabledbutnoconfig', '', true);
					}
				}

				$allowed_mysqlserver = array();
				if (!empty($p_allowed_mysqlserver) && is_array($p_allowed_mysqlserver)) {
					foreach ($p_allowed_mysqlserver as $allowed_ms) {
						$allowed_ms = intval($allowed_ms);
						$allowed_mysqlserver[] = $allowed_ms;
					}
				}
				$allowed_mysqlserver = array_map('intval', $allowed_mysqlserver);

				$diskspace *= 1024;
				$traffic *= 1024 * 1024;

				if (
					($diskspace != 0 && (($this->getUserDetail('diskspace_used') + $diskspace) > $this->getUserDetail('diskspace')) && ($this->getUserDetail('diskspace') / 1024) != '-1')
					|| ($mysqls != 0 && (($this->getUserDetail('mysqls_used') + $mysqls) > $this->getUserDetail('mysqls')) && $this->getUserDetail('mysqls') != '-1')
					|| ($emails != 0 && (($this->getUserDetail('emails_used') + $emails) > $this->getUserDetail('emails')) && $this->getUserDetail('emails') != '-1')
					|| ($email_accounts != 0 && (($this->getUserDetail('email_accounts_used') + $email_accounts) > $this->getUserDetail('email_accounts')) && $this->getUserDetail('email_accounts') != '-1')
					|| ($email_forwarders != 0 && (($this->getUserDetail('email_forwarders_used') + $email_forwarders) > $this->getUserDetail('email_forwarders')) && $this->getUserDetail('email_forwarders') != '-1')
					|| ($email_quota != 0 && (($this->getUserDetail('email_quota_used') + $email_quota) > $this->getUserDetail('email_quota')) && $this->getUserDetail('email_quota') != '-1' && Settings::Get('system.mail_quota_enabled') == '1')
					|| ($ftps != 0 && (($this->getUserDetail('ftps_used') + $ftps) > $this->getUserDetail('ftps')) && $this->getUserDetail('ftps') != '-1')
					|| ($subdomains != 0 && (($this->getUserDetail('subdomains_used') + $subdomains) > $this->getUserDetail('subdomains')) && $this->getUserDetail('subdomains') != '-1')
					|| (($diskspace / 1024) == '-1' && ($this->getUserDetail('diskspace') / 1024) != '-1')
					|| ($mysqls == '-1' && $this->getUserDetail('mysqls') != '-1')
					|| ($emails == '-1' && $this->getUserDetail('emails') != '-1')
					|| ($email_accounts == '-1' && $this->getUserDetail('email_accounts') != '-1')
					|| ($email_forwarders == '-1' && $this->getUserDetail('email_forwarders') != '-1')
					|| ($email_quota == '-1' && $this->getUserDetail('email_quota') != '-1' && Settings::Get('system.mail_quota_enabled') == '1')
					|| ($ftps == '-1' && $this->getUserDetail('ftps') != '-1')
					|| ($subdomains == '-1' && $this->getUserDetail('subdomains') != '-1')
				) {
					Response::standardError('youcantallocatemorethanyouhave', '', true);
				}

				if (!Validate::validateEmail($email)) {
					Response::standardError('emailiswrong', $email, true);
				} else {
					if ($loginname != '') {
						$accountnumber = intval(Settings::Get('system.lastaccountnumber'));
						$loginname = Validate::validate($loginname, 'loginname', '/^[a-z][a-z0-9\-_]+$/i', '', [], true);

						// Accounts which match systemaccounts are not allowed, filtering them
						if (preg_match('/^' . preg_quote(Settings::Get('customer.accountprefix'), '/') . '([0-9]+)/', $loginname)) {
							Response::standardError('loginnameisusingprefix', Settings::Get('customer.accountprefix'), true);
						}

						// Additional filtering for Bug #962
						if (function_exists('posix_getpwnam') && !in_array("posix_getpwnam", explode(",", ini_get('disable_functions'))) && posix_getpwnam($loginname)) {
							Response::standardError('loginnameissystemaccount', $loginname, true);
						}

						// blacklist some system-internal names that might lead to issues
						Database::needSqlData();
						$sqldata = Database::getSqlData();
						Database::needRoot(true);
						Database::needSqlData();
						$sqlrdata = Database::getSqlData();
						$login_blacklist = [
							'root',
							'admin',
							'froxroot',
							'froxlor',
							$sqldata['user'],
							$sqldata['db'],
							$sqlrdata['user'],
						];
						unset($sqldata);
						unset($sqlrdata);
						$login_blacklist = array_unique($login_blacklist);
						if (in_array($loginname, $login_blacklist)) {
							Response::standardError('loginnameisreservedname', $loginname, true);
						}
					} else {
						$accountnumber = intval(Settings::Get('system.lastaccountnumber')) + 1;
						$loginname = Settings::Get('customer.accountprefix') . $accountnumber;
					}

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

					$mysql_maxlen = Database::getSqlUsernameLength() - strlen(Settings::Get('customer.mysqlprefix'));
					if (($loginname_check && strtolower($loginname_check['loginname']) == strtolower($loginname)) || ($loginname_check_admin && strtolower($loginname_check_admin['loginname']) == strtolower($loginname))) {
						Response::standardError('loginnameexists', $loginname, true);
					} elseif (!Validate::validateUsername($loginname, Settings::Get('panel.unix_names'), $mysql_maxlen)) {
						if (strlen($loginname) > $mysql_maxlen) {
							Response::standardError('loginnameiswrong2', $mysql_maxlen, true);
						} else {
							Response::standardError('loginnameiswrong', $loginname, true);
						}
					} elseif ($email_check_admin && strtolower($email_check_admin['email']) == strtolower($email)) {
						Response::standardError('emailexistsanon', $email, true);
					}

					$guid = intval(Settings::Get('system.lastguid')) + 1;
					$documentroot = FileDir::makeCorrectDir(Settings::Get('system.documentroot_prefix') . '/' . $loginname);

					if (file_exists($documentroot)) {
						Response::standardError('documentrootexists', $documentroot, true);
					}

					if ($password == '') {
						$password = Crypt::generatePassword();
					}

					$_theme = Settings::Get('panel.default_theme');

					$ins_data = [
						'adminid' => $this->getUserDetail('adminid'),
						'loginname' => $loginname,
						'passwd' => Crypt::makeCryptPassword($password),
						'name' => $name,
						'firstname' => $firstname,
						'gender' => $gender,
						'company' => $company,
						'street' => $street,
						'zipcode' => $zipcode,
						'city' => $city,
						'phone' => $phone,
						'fax' => $fax,
						'email' => $email,
						'customerno' => $customernumber,
						'lang' => $def_language,
						'gui_access' => $gui_access,
						'api_allowed' => $api_allowed,
						'shell_allowed' => $shell_allowed,
						'docroot' => $documentroot,
						'guid' => $guid,
						'diskspace' => $diskspace,
						'traffic' => $traffic,
						'subdomains' => $subdomains,
						'emails' => $emails,
						'email_accounts' => $email_accounts,
						'email_forwarders' => $email_forwarders,
						'email_quota' => $email_quota,
						'ftps' => $ftps,
						'mysqls' => $mysqls,
						'phpenabled' => $phpenabled,
						'allowed_phpconfigs' => empty($allowed_phpconfigs) ? "" : json_encode($allowed_phpconfigs),
						'imap' => $email_imap,
						'pop3' => $email_pop3,
						'perlenabled' => $perlenabled,
						'dnsenabled' => $dnsenabled,
						'logviewenabled' => $logviewenabled,
						'theme' => $_theme,
						'custom_notes' => $custom_notes,
						'custom_notes_show' => $custom_notes_show,
						'allowed_mysqlserver' => empty($allowed_mysqlserver) ? "" : json_encode($allowed_mysqlserver)
					];

					$ins_stmt = Database::prepare("
						INSERT INTO `" . TABLE_PANEL_CUSTOMERS . "` SET
						`adminid` = :adminid,
						`loginname` = :loginname,
						`password` = :passwd,
						`name` = :name,
						`firstname` = :firstname,
						`gender` = :gender,
						`company` = :company,
						`street` = :street,
						`zipcode` = :zipcode,
						`city` = :city,
						`phone` = :phone,
						`fax` = :fax,
						`email` = :email,
						`customernumber` = :customerno,
						`def_language` = :lang,
						`gui_access` = :gui_access,
						`api_allowed` = :api_allowed,
						`shell_allowed` = :shell_allowed,
						`documentroot` = :docroot,
						`guid` = :guid,
						`diskspace` = :diskspace,
						`traffic` = :traffic,
						`subdomains` = :subdomains,
						`emails` = :emails,
						`email_accounts` = :email_accounts,
						`email_forwarders` = :email_forwarders,
						`email_quota` = :email_quota,
						`ftps` = :ftps,
						`mysqls` = :mysqls,
						`standardsubdomain` = '0',
						`phpenabled` = :phpenabled,
						`allowed_phpconfigs` = :allowed_phpconfigs,
						`imap` = :imap,
						`pop3` = :pop3,
						`perlenabled` = :perlenabled,
						`dnsenabled` = :dnsenabled,
						`logviewenabled` = :logviewenabled,
						`theme` = :theme,
						`custom_notes` = :custom_notes,
						`custom_notes_show` = :custom_notes_show,
						`allowed_mysqlserver`= :allowed_mysqlserver
					");
					Database::pexecute($ins_stmt, $ins_data, true, true);

					$customerid = Database::lastInsertId();
					$ins_data['customerid'] = $customerid;

					Admins::increaseUsage($this->getUserDetail('adminid'), 'customers_used');

					// update admin resource-usage
					if ($mysqls != '-1') {
						Admins::increaseUsage($this->getUserDetail('adminid'), 'mysqls_used', '', (int)$mysqls);
					}

					if ($emails != '-1') {
						Admins::increaseUsage($this->getUserDetail('adminid'), 'emails_used', '', (int)$emails);
					}

					if ($email_accounts != '-1') {
						Admins::increaseUsage($this->getUserDetail('adminid'), 'email_accounts_used', '', (int)$email_accounts);
					}

					if ($email_forwarders != '-1') {
						Admins::increaseUsage($this->getUserDetail('adminid'), 'email_forwarders_used', '', (int)$email_forwarders);
					}

					if ($email_quota != '-1') {
						Admins::increaseUsage($this->getUserDetail('adminid'), 'email_quota_used', '', (int)$email_quota);
					}

					if ($subdomains != '-1') {
						Admins::increaseUsage($this->getUserDetail('adminid'), 'subdomains_used', '', (int)$subdomains);
					}

					if ($ftps != '-1') {
						Admins::increaseUsage($this->getUserDetail('adminid'), 'ftps_used', '', (int)$ftps);
					}

					if (($diskspace / 1024) != '-1') {
						Admins::increaseUsage($this->getUserDetail('adminid'), 'diskspace_used', '', (int)$diskspace);
					}

					// update last guid
					Settings::Set('system.lastguid', $guid, true);

					if ($accountnumber != intval(Settings::Get('system.lastaccountnumber'))) {
						// update last account number
						Settings::Set('system.lastaccountnumber', $accountnumber, true);
					}

					$this->logger()->logAction(FroxlorLogger::ADM_ACTION, LOG_INFO, "[API] added customer '" . $loginname . "'");
					unset($ins_data);

					// insert task to create homedir etc.
					Cronjob::inserttask(TaskId::CREATE_HOME, $loginname, $guid, $guid, $store_defaultindex);

					// Using filesystem - quota, insert a task which cleans the filesystem - quota
					Cronjob::inserttask(TaskId::CREATE_QUOTA);

					// Add htpasswd for the stats-pages
					$htpasswdPassword = Crypt::makeCryptPassword($password, true);

					$ins_stmt = Database::prepare("
						INSERT INTO `" . TABLE_PANEL_HTPASSWDS . "` SET
						`customerid` = :customerid,
						`username` = :username,
						`password` = :passwd,
						`path` = :path
					");
					$ins_data = [
						'customerid' => $customerid,
						'username' => $loginname,
						'passwd' => $htpasswdPassword
					];

					$stats_folder = Settings::Get('system.traffictool');
					$ins_data['path'] = FileDir::makeCorrectDir($documentroot . '/' . $stats_folder . '/');
					$this->logger()->logAction(FroxlorLogger::ADM_ACTION, LOG_NOTICE, "[API] automatically added " . $stats_folder . " htpasswd for user '" . $loginname . "'");
					Database::pexecute($ins_stmt, $ins_data, true, true);

					Cronjob::inserttask(TaskId::REBUILD_VHOST);

					// add default FTP-User
					// also, add froxlor-local user to ftp-group (if exists!) to
					// allow access to customer-directories from within the panel, which
					// is necessary when pathedit = Dropdown
					$local_users = [
						Settings::Get('system.httpuser')
					];
					if ((int)Settings::Get('system.mod_fcgid_ownvhost') == 1 || (int)Settings::Get('phpfpm.enabled_ownvhost') == 1) {
						if ((int)Settings::Get('system.mod_fcgid') == 1) {
							$local_user = Settings::Get('system.mod_fcgid_httpuser');
						} else {
							$local_user = Settings::Get('phpfpm.vhost_httpuser');
						}
						// check froxlor-local user membership in ftp-group
						// without this check addition may duplicate user in list if httpuser == local_user
						if (in_array($local_user, $local_users) == false) {
							$local_users[] = $local_user;
						}
					}
					$this->apiCall('Ftps.add', [
						'customerid' => $customerid,
						'path' => '/',
						'ftp_password' => $password,
						'ftp_description' => "Default",
						'sendinfomail' => 0,
						'ftp_username' => $loginname,
						'additional_members' => $local_users,
						'is_defaultuser' => 1
					]);

					$_stdsubdomain = '';
					if ($createstdsubdomain == '1') {
						if (Settings::Get('system.stdsubdomain') !== null && Settings::Get('system.stdsubdomain') != '') {
							$_stdsubdomain = $loginname . '.' . Settings::Get('system.stdsubdomain');
						} else {
							$_stdsubdomain = $loginname . '.' . Settings::Get('system.hostname');
						}

						$ins_data = [
							'domain' => $_stdsubdomain,
							'customerid' => $customerid,
							'adminid' => $this->getUserDetail('adminid'),
							'docroot' => $documentroot,
							'phpenabled' => $phpenabled,
							'openbasedir' => '1',
							'is_stdsubdomain' => 1
						];
						$domainid = -1;
						try {
							$std_domain = $this->apiCall('Domains.add', $ins_data, true);
							$domainid = $std_domain['id'];
						} catch (Exception $e) {
							$this->logger()->logAction(FroxlorLogger::ADM_ACTION, LOG_ERR, "[API] Unable to add standard-subdomain: " . $e->getMessage());
						}

						if ($domainid > 0) {
							$upd_stmt = Database::prepare("
								UPDATE `" . TABLE_PANEL_CUSTOMERS . "` SET `standardsubdomain` = :domainid WHERE `customerid` = :customerid
							");
							Database::pexecute($upd_stmt, [
								'domainid' => $domainid,
								'customerid' => $customerid
							], true, true);
							$this->logger()->logAction(FroxlorLogger::ADM_ACTION, LOG_NOTICE, "[API] automatically added standardsubdomain for user '" . $loginname . "'");
							Cronjob::inserttask(TaskId::REBUILD_VHOST);
						}
					}

					// Create default mysql-user if enabled
					if ($mysqls != 0) {
						foreach ($allowed_mysqlserver as $dbserver) {
							// require privileged access for target db-server
							Database::needRoot(true, $dbserver, false);
							// get DbManager
							$dbm = new DbManager($this->logger());
							// give permission to the user on every access-host we have
							foreach (array_map('trim', explode(',', Settings::Get('system.mysql_access_host'))) as $mysql_access_host) {
								$dbm->getManager()->grantPrivilegesTo($loginname, $password, $mysql_access_host, false, false, true);
							}
							$dbm->getManager()->flushPrivileges();
							Database::needRoot(false);
						}
					}

					if ($sendpassword == '1') {
						$srv_hostname = Settings::Get('system.hostname');
						if (Settings::Get('system.froxlordirectlyviahostname') == '0') {
							$srv_hostname .= '/' . basename(\Froxlor\Froxlor::getInstallDir());
						}

						$srv_ip_stmt = Database::prepare("
							SELECT ip, port FROM `" . TABLE_PANEL_IPSANDPORTS . "`
							WHERE `id` = :defaultip
						");
						$default_ips = Settings::Get('system.defaultip');
						$default_ips = explode(',', $default_ips);
						$srv_ip = Database::pexecute_first($srv_ip_stmt, [
							'defaultip' => reset($default_ips)
						], true, true);

						$replace_arr = [
							'FIRSTNAME' => $firstname,
							'NAME' => $name,
							'COMPANY' => $company,
							'SALUTATION' => User::getCorrectUserSalutation([
								'firstname' => $firstname,
								'name' => $name,
								'company' => $company
							]),
							'CUSTOMER_NO' => $customernumber,
							'USERNAME' => $loginname,
							'PASSWORD' => $password,
							'SERVER_HOSTNAME' => $srv_hostname,
							'SERVER_IP' => $srv_ip['ip'] ?? '',
							'SERVER_PORT' => $srv_ip['port'] ?? '',
							'DOMAINNAME' => $_stdsubdomain
						];

						// get template for mail subject
						$mail_subject = $this->getMailTemplate([
							'adminid' => $this->getUserDetail('adminid'),
							'def_language' => $def_language
						], 'mails', 'createcustomer_subject', $replace_arr, lng('mails.createcustomer.subject'));
						// get template for mail body
						$mail_body = $this->getMailTemplate([
							'adminid' => $this->getUserDetail('adminid'),
							'def_language' => $def_language
						], 'mails', 'createcustomer_mailbody', $replace_arr, lng('mails.createcustomer.mailbody'));

						$_mailerror = false;
						$mailerr_msg = "";
						try {
							$this->mailer()->Subject = $mail_subject;
							$this->mailer()->AltBody = $mail_body;
							$this->mailer()->Body = str_replace("\n", "<br />", $mail_body);
							$this->mailer()->addAddress($email, User::getCorrectUserSalutation([
								'firstname' => $firstname,
								'name' => $name,
								'company' => $company
							]));
							$this->mailer()->send();
						} catch (\PHPMailer\PHPMailer\Exception $e) {
							$mailerr_msg = $e->errorMessage();
							$_mailerror = true;
						} catch (Exception $e) {
							$mailerr_msg = $e->getMessage();
							$_mailerror = true;
						}

						if ($_mailerror) {
							$this->logger()->logAction(FroxlorLogger::ADM_ACTION, LOG_ERR, "[API] Error sending mail: " . $mailerr_msg);
							Response::standardError('errorsendingmail', $email, true);
						}

						$this->mailer()->clearAddresses();
						$this->logger()->logAction(FroxlorLogger::ADM_ACTION, LOG_NOTICE, "[API] automatically sent password to user '" . $loginname . "'");
					}
				}
				$this->logger()->logAction(FroxlorLogger::ADM_ACTION, LOG_WARNING, "[API] added customer '" . $loginname . "'");

				$result = $this->apiCall('Customers.get', [
					'loginname' => $loginname
				]);
				return $this->response($result);
			}
			throw new Exception("No more resources available", 406);
		}
		throw new Exception("Not allowed to execute given command.", 403);
	}

	/**
	 * return a customer entry by either id or loginname
	 *
	 * @param int $id
	 *            optional, the customer-id
	 * @param string $loginname
	 *            optional, the loginname
	 * @param bool $show_usages
	 *            optional, default false
	 *
	 * @access admin, customer
	 * @return string json-encoded array
	 * @throws Exception
	 */
	public function get()
	{
		$id = $this->getParam('id', true, 0);
		$ln_optional = $id > 0;
		$loginname = $this->getParam('loginname', $ln_optional, '');
		$show_usages = $this->getBoolParam('show_usages', true, false);

		if ($this->isAdmin()) {
			$result_stmt = Database::prepare("
			SELECT `c`.*, `a`.`loginname` AS `adminname`
			FROM `" . TABLE_PANEL_CUSTOMERS . "` `c`, `" . TABLE_PANEL_ADMINS . "` `a`
			WHERE " . ($id > 0 ? "`c`.`customerid` = :idln" : "`c`.`loginname` = :idln") . ($this->getUserDetail('customers_see_all') ? '' : " AND `c`.`adminid` = :adminid") . " AND `c`.`adminid` = `a`.`adminid`");
			$params = [
				'idln' => ($id <= 0 ? $loginname : $id)
			];
			if ($this->getUserDetail('customers_see_all') == '0') {
				$params['adminid'] = $this->getUserDetail('adminid');
			}
		} else {
			if (($id > 0 && $id != $this->getUserDetail('customerid')) || !empty($loginname) && $loginname != $this->getUserDetail('loginname')) {
				throw new Exception("You cannot access data of other customers", 401);
			}
			$result_stmt = Database::prepare("
				SELECT * FROM `" . TABLE_PANEL_CUSTOMERS . "`
				WHERE " . ($id > 0 ? "`customerid` = :idln" : "`loginname` = :idln"));
			$params = [
				'idln' => ($id <= 0 ? $loginname : $id)
			];
		}
		$result = Database::pexecute_first($result_stmt, $params, true, true);
		if ($result) {
			// check whether the admin does not want the customer to see the notes
			if (!$this->isAdmin() && $result['custom_notes_show'] != 1) {
				$result['custom_notes'] = "";
			}
			if ($show_usages) {
				// get number of domains
				$domains_stmt = Database::prepare("
					SELECT COUNT(`id`) AS `domains`
					FROM `" . TABLE_PANEL_DOMAINS . "`
					WHERE `customerid` = :cid
					AND `parentdomainid` = '0'
					AND `id`<> :stdd
				");
				Database::pexecute($domains_stmt, [
					'cid' => $result['customerid'],
					'stdd' => $result['standardsubdomain']
				]);
				$domains = $domains_stmt->fetch(PDO::FETCH_ASSOC);
				$result['domains'] = intval($domains['domains']);
				// get disk-space usages for web, mysql and mail
				$usages_stmt = Database::prepare("
					SELECT * FROM `" . TABLE_PANEL_DISKSPACE . "`
					WHERE `customerid` = :cid
					ORDER BY `stamp` DESC LIMIT 1
				");
				$usages = Database::pexecute_first($usages_stmt, [
					'cid' => $result['customerid']
				]);
				if ($usages) {
					$result['webspace_used'] = $usages['webspace'];
					$result['mailspace_used'] = $usages['mail'];
					$result['dbspace_used'] = $usages['mysql'];
				} else {
					$result['webspace_used'] = 0;
					$result['mailspace_used'] = 0;
					$result['dbspace_used'] = 0;
				}
			}
			$this->logger()->logAction($this->isAdmin() ? FroxlorLogger::ADM_ACTION : FroxlorLogger::USR_ACTION, LOG_INFO, "[API] get customer '" . $result['loginname'] . "'");
			return $this->response($result);
		}
		$key = ($id > 0 ? "id #" . $id : "loginname '" . $loginname . "'");
		throw new Exception("Customer with " . $key . " could not be found", 404);
	}

	/**
	 * increase resource-usage
	 *
	 * @param int $customerid
	 * @param string $resource
	 * @param string $extra
	 *            optional, default empty
	 * @param int $increase_by
	 *            optional, default 1
	 */
	public static function increaseUsage($customerid = 0, $resource = null, $extra = '', $increase_by = 1)
	{
		self::updateResourceUsage(TABLE_PANEL_CUSTOMERS, 'customerid', $customerid, '+', $resource, $extra, $increase_by);
	}

	/**
	 * update customer entry by either id or loginname, customer can only change language, password and theme
	 *
	 * @param int $id
	 *                             optional, the customer-id
	 * @param string $loginname
	 *                             optional, the loginname
	 * @param string $email
	 *                             optional
	 * @param string $name
	 *                             optional if company is set, else required
	 * @param string $firstname
	 *                             optional if company is set, else required
	 * @param string $company
	 *                             optional but required if name/firstname empty
	 * @param string $street
	 *                             optional
	 * @param string $zipcode
	 *                             optional
	 * @param string $city
	 *                             optional
	 * @param string $phone
	 *                             optional
	 * @param string $fax
	 *                             optional
	 * @param int $customernumber
	 *                             optional
	 * @param string $def_language
	 *                             optional, ISO 639-1 language code (e.g. 'en', 'de', see lng-folder for supported languages),
	 *                             default is system-default language
	 * @param bool $gui_access
	 *                             optional, allow login via webui, if false ONLY the login via webui is disallowed; default true
	 * @param bool $api_allowed
	 *                             optional, default is true if system setting api.enabled is true, else false
	 * @param bool $shell_allowed
	 *                             optional, default is true if system setting system.allow_customer_shell is true, else false
	 * @param int $gender
	 *                             optional, 0 = no-gender, 1 = male, 2 = female
	 * @param string $custom_notes
	 *                             optional notes
	 * @param bool $custom_notes_show
	 *                             optional, whether to show the content of custom_notes to the customer, default 0
	 *                             (false)
	 * @param string $new_customer_password
	 *                             optional, set new password
	 * @param bool $sendpassword
	 *                             optional, whether to send the password to the customer after creation, default 0
	 *                             (false)
	 * @param int $move_to_admin
	 *                             optional, if valid admin-id is given here, the customer's admin/reseller can be
	 *                             changed
	 * @param bool $deactivated
	 *                             optional, if 1 (true) the customer can be deactivated/suspended
	 * @param int $diskspace
	 *                             optional disk-space available for customer in MB, default 0
	 * @param bool $diskspace_ul
	 *                             optional, whether customer should have unlimited diskspace, default 0 (false)
	 * @param int $traffic
	 *                             optional traffic available for customer in GB, default 0
	 * @param bool $traffic_ul
	 *                             optional, whether customer should have unlimited traffic, default 0 (false)
	 * @param int $subdomains
	 *                             optional amount of subdomains available for customer, default 0
	 * @param bool $subdomains_ul
	 *                             optional, whether customer should have unlimited subdomains, default 0 (false)
	 * @param int $emails
	 *                             optional amount of emails available for customer, default 0
	 * @param bool $emails_ul
	 *                             optional, whether customer should have unlimited emails, default 0 (false)
	 * @param int $email_accounts
	 *                             optional amount of email-accounts available for customer, default 0
	 * @param bool $email_accounts_ul
	 *                             optional, whether customer should have unlimited email-accounts, default 0 (false)
	 * @param int $email_forwarders
	 *                             optional amount of email-forwarders available for customer, default 0
	 * @param bool $email_forwarders_ul
	 *                             optional, whether customer should have unlimited email-forwarders, default 0 (false)
	 * @param int $email_quota
	 *                             optional size of email-quota available for customer in MB, default is system-setting
	 *                             mail_quota
	 * @param bool $email_quota_ul
	 *                             optional, whether customer should have unlimited email-quota, default 0 (false)
	 * @param bool $email_imap
	 *                             optional, whether to allow IMAP access, default 0 (false)
	 * @param bool $email_pop3
	 *                             optional, whether to allow POP3 access, default 0 (false)
	 * @param int $ftps
	 *                             optional amount of ftp-accounts available for customer, default 0
	 * @param bool $ftps_ul
	 *                             optional, whether customer should have unlimited ftp-accounts, default 0 (false)
	 * @param int $mysqls
	 *                             optional amount of mysql-databases available for customer, default 0
	 * @param bool $mysqls_ul
	 *                             optional, whether customer should have unlimited mysql-databases, default 0 (false)
	 * @param bool $createstdsubdomain
	 *                             optional, whether to create a standard-subdomain ([loginname].froxlor-hostname.tld),
	 *                             default 1 (if customer has std-subdomain) else 0 (false)
	 * @param bool $phpenabled
	 *                             optional, whether to allow usage of PHP, default 0 (false)
	 * @param array $allowed_phpconfigs
	 *                             optional, array of IDs of php-config that the customer is allowed to use, default
	 *                             empty (none)
	 * @param bool $perlenabled
	 *                             optional, whether to allow usage of Perl/CGI, default 0 (false)
	 * @param bool $dnsenabled
	 *                             optional, whether to allow usage of the DNS editor (requires activated nameserver in
	 *                             settings), default 0 (false)
	 * @param bool $logviewenabled
	 *                             optional, whether to allow access to webserver access/error-logs, default 0 (false)
	 * @param string $theme
	 *                             optional, change theme
	 * @param array $allowed_mysqlserver
	 *                             optional, array of IDs of defined mysql-servers the customer is allowed to use,
	 *                             default is to allow the default dbserver (id=0)
	 *
	 * @access admin, customer
	 * @return string json-encoded array
	 * @throws Exception
	 */
	public function update()
	{
		$id = $this->getParam('id', true, 0);
		$ln_optional = $id > 0;
		$loginname = $this->getParam('loginname', $ln_optional, '');

		$result = $this->apiCall('Customers.get', [
			'id' => $id,
			'loginname' => $loginname
		]);
		$id = $result['customerid'];

		if ($this->isAdmin()) {
			// parameters
			$move_to_admin = (int)($this->getParam('move_to_admin', true, 0));

			$idna_convert = new IdnaWrapper();
			$email = $this->getParam('email', true, $idna_convert->decode($result['email']));
			$name = $this->getParam('name', true, $result['name']);
			$firstname = $this->getParam('firstname', true, $result['firstname']);
			$company_required = ((!empty($name) && empty($firstname)) || (empty($name) && !empty($firstname)) || (empty($name) && empty($firstname))) && empty($result['company']);
			$company = $this->getParam('company', !$company_required, $result['company']);
			$street = $this->getParam('street', true, $result['street']);
			$zipcode = $this->getParam('zipcode', true, $result['zipcode']);
			$city = $this->getParam('city', true, $result['city']);
			$phone = $this->getParam('phone', true, $result['phone']);
			$fax = $this->getParam('fax', true, $result['fax']);
			$customernumber = $this->getParam('customernumber', true, $result['customernumber']);
			$def_language = $this->getParam('def_language', true, $result['def_language']);
			$gui_access = $this->getBoolParam('gui_access', true, $result['gui_access']);
			$api_allowed = $this->getBoolParam('api_allowed', true, $result['api_allowed']);
			$shell_allowed = $this->getBoolParam('shell_allowed', true, $result['shell_allowed']);
			$gender = (int)$this->getParam('gender', true, $result['gender']);
			$custom_notes = $this->getParam('custom_notes', true, $result['custom_notes']);
			$custom_notes_show = $this->getBoolParam('custom_notes_show', true, $result['custom_notes_show']);

			$dec_places = Settings::Get('panel.decimal_places');
			$diskspace = $this->getUlParam('diskspace', 'diskspace_ul', true, round($result['diskspace'] / 1024, $dec_places));
			$traffic = $this->getUlParam('traffic', 'traffic_ul', true, round($result['traffic'] / (1024 * 1024), $dec_places));
			$subdomains = $this->getUlParam('subdomains', 'subdomains_ul', true, $result['subdomains']);
			$emails = $this->getUlParam('emails', 'emails_ul', true, $result['emails']);
			$email_accounts = $this->getUlParam('email_accounts', 'email_accounts_ul', true, $result['email_accounts']);
			$email_forwarders = $this->getUlParam('email_forwarders', 'email_forwarders_ul', true, $result['email_forwarders']);
			$email_quota = $this->getUlParam('email_quota', 'email_quota_ul', true, $result['email_quota']);
			$email_imap = $this->getParam('email_imap', true, $result['imap']);
			$email_pop3 = $this->getParam('email_pop3', true, $result['pop3']);
			$ftps = $this->getUlParam('ftps', 'ftps_ul', true, $result['ftps']);
			$mysqls = $this->getUlParam('mysqls', 'mysqls_ul', true, $result['mysqls']);
			$createstdsubdomain = $this->getBoolParam('createstdsubdomain', true, ($result['standardsubdomain'] != 0 ? 1 : 0));
			$password = $this->getParam('new_customer_password', true, '');
			$phpenabled = $this->getBoolParam('phpenabled', true, $result['phpenabled']);
			$allowed_phpconfigs = $this->getParam('allowed_phpconfigs', true, json_decode($result['allowed_phpconfigs'], true));
			$perlenabled = $this->getBoolParam('perlenabled', true, $result['perlenabled']);
			$dnsenabled = $this->getBoolParam('dnsenabled', true, $result['dnsenabled']);
			$logviewenabled = $this->getBoolParam('logviewenabled', true, $result['logviewenabled']);
			$deactivated = $this->getBoolParam('deactivated', true, $result['deactivated']);
			$theme = $this->getParam('theme', true, $result['theme']);
			$allowed_mysqlserver = $this->getParam('allowed_mysqlserver', true, json_decode($result['allowed_mysqlserver'], true));
		} else {
			// allowed parameters
			$def_language = $this->getParam('def_language', true, $result['def_language']);
			$password = $this->getParam('new_customer_password', true, '');
			$theme = $this->getParam('theme', true, $result['theme']);
		}

		// validation
		if ($this->isAdmin()) {
			$idna_convert = new IdnaWrapper();
			$name = Validate::validate($name, 'name', Validate::REGEX_DESC_TEXT, '', [], true);
			$firstname = Validate::validate($firstname, 'first name', Validate::REGEX_DESC_TEXT, '', [], true);
			$company = Validate::validate($company, 'company', Validate::REGEX_DESC_TEXT, '', [], true);
			$street = Validate::validate($street, 'street', Validate::REGEX_DESC_TEXT, '', [], true);
			$zipcode = Validate::validate($zipcode, 'zipcode', '/^[0-9 \-A-Z]*$/', '', [], true);
			$city = Validate::validate($city, 'city', Validate::REGEX_DESC_TEXT, '', [], true);
			$phone = Validate::validate($phone, 'phone', '/^[0-9\- \+\(\)\/]*$/', '', [], true);
			$fax = Validate::validate($fax, 'fax', '/^[0-9\- \+\(\)\/]*$/', '', [], true);
			$email = $idna_convert->encode(Validate::validate($email, 'email', '', '', [], true));
			$customernumber = Validate::validate($customernumber, 'customer number', '/^[A-Za-z0-9 \-]*$/Di', '', [], true);
			$custom_notes = Validate::validate(str_replace("\r\n", "\n", $custom_notes), 'custom_notes', Validate::REGEX_CONF_TEXT, '', [], true);
			if (!empty($allowed_phpconfigs)) {
				$allowed_phpconfigs = array_map('intval', $allowed_phpconfigs);
			}
			if (empty($allowed_phpconfigs) && $phpenabled == 1) {
				// only required if not using mod_php
				if ((int)Settings::Get('system.mod_fcgid') == 1 || (int)Settings::Get('phpfpm.enabled') == 1) {
					Response::standardError('customerphpenabledbutnoconfig', '', true);
				}
			}

			// add permission for allowed mysql usage if customer was not allowed to use mysql prior
			if ($result['mysqls'] == 0 && ($mysqls == -1 || $mysqls > 0)) {
				$allowed_mysqlserver = $this->getParam('allowed_mysqlserver', true, [0]);
			}
			if (!empty($allowed_mysqlserver)) {
				$allowed_mysqlserver = array_map('intval', $allowed_mysqlserver);
			}

		}
		$def_language = Validate::validate($def_language, 'default language', '', '', [], true);
		if (!empty($def_language) && !isset(Language::getLanguages()[$def_language])) {
			$def_language = Settings::Get('panel.standardlanguage');
		}

		$theme = Validate::validate($theme, 'theme', '', '', [], true);

		if (Settings::Get('system.mail_quota_enabled') != '1') {
			$email_quota = -1;
		}

		if (empty($theme)) {
			$theme = Settings::Get('panel.default_theme');
		}

		if ($this->isAdmin()) {
			$diskspace *= 1024;
			$traffic *= 1024 * 1024;

			if (
				($diskspace != 0 && (($this->getUserDetail('diskspace_used') + $diskspace - $result['diskspace']) > $this->getUserDetail('diskspace')) && ($this->getUserDetail('diskspace') / 1024) != '-1')
				|| ($mysqls != 0 && (($this->getUserDetail('mysqls_used') + $mysqls - $result['mysqls']) > $this->getUserDetail('mysqls')) && $this->getUserDetail('mysqls') != '-1')
				|| ($emails != 0 && (($this->getUserDetail('emails_used') + $emails - $result['emails']) > $this->getUserDetail('emails')) && $this->getUserDetail('emails') != '-1')
				|| ($email_accounts != 0 && (($this->getUserDetail('email_accounts_used') + $email_accounts - $result['email_accounts']) > $this->getUserDetail('email_accounts')) && $this->getUserDetail('email_accounts') != '-1')
				|| ($email_forwarders != 0 && (($this->getUserDetail('email_forwarders_used') + $email_forwarders - $result['email_forwarders']) > $this->getUserDetail('email_forwarders')) && $this->getUserDetail('email_forwarders') != '-1')
				|| ($email_quota != 0 && (($this->getUserDetail('email_quota_used') + $email_quota - $result['email_quota']) > $this->getUserDetail('email_quota')) && $this->getUserDetail('email_quota') != '-1' && Settings::Get('system.mail_quota_enabled') == '1')
				|| ($ftps != 0 && (($this->getUserDetail('ftps_used') + $ftps - $result['ftps']) > $this->getUserDetail('ftps')) && $this->getUserDetail('ftps') != '-1')
				|| ($subdomains != 0 && (($this->getUserDetail('subdomains_used') + $subdomains - $result['subdomains']) > $this->getUserDetail('subdomains')) && $this->getUserDetail('subdomains') != '-1')
				|| (($diskspace / 1024) == '-1' && ($this->getUserDetail('diskspace') / 1024) != '-1')
				|| ($mysqls == '-1' && $this->getUserDetail('mysqls') != '-1')
				|| ($emails == '-1' && $this->getUserDetail('emails') != '-1')
				|| ($email_accounts == '-1' && $this->getUserDetail('email_accounts') != '-1')
				|| ($email_forwarders == '-1' && $this->getUserDetail('email_forwarders') != '-1')
				|| ($email_quota == '-1' && $this->getUserDetail('email_quota') != '-1' && Settings::Get('system.mail_quota_enabled') == '1')
				|| ($ftps == '-1' && $this->getUserDetail('ftps') != '-1')
				|| ($subdomains == '-1' && $this->getUserDetail('subdomains') != '-1')
			) {
				Response::standardError('youcantallocatemorethanyouhave', '', true);
			}

			// validate allowed_mysqls whether the customer has databases on a removed, now disallowed db-server and abort if true
			$former_allowed_mysqlserver = json_decode($result['allowed_mysqlserver'], true);
			if ($allowed_mysqlserver != $former_allowed_mysqlserver && !empty($former_allowed_mysqlserver)) {
				$to_remove_mysqlserver = array_diff($former_allowed_mysqlserver, $allowed_mysqlserver);
				if (count($to_remove_mysqlserver) > 0) {
					foreach ($to_remove_mysqlserver as $mysqlserver_check) {
						$result_ms = $this->apiCall('MysqlServer.databasesOnServer', [
							'mysql_server' => $mysqlserver_check,
							'customerid' => $id
						]);
						if ($result_ms['count'] > 0) {
							Response::standardError('mysqlserverstillhasdbs', '', true);
						}
					}
				}
			}

			if ($email == '') {
				Response::standardError([
					'stringisempty',
					'customer.email'
				], '', true);
			} elseif (!Validate::validateEmail($email)) {
				Response::standardError('emailiswrong', $email, true);
			} else {
				// Check for existing email address
				// do not check via api as we skip any permission checks for this task
				$email_check_admin_stmt = Database::prepare("
						SELECT `email` FROM `" . TABLE_PANEL_ADMINS . "` WHERE `email` = :email
					");
				$email_check_admin = Database::pexecute_first($email_check_admin_stmt, [
					'email' => $email
				], true, true);
				if ($email_check_admin && strtolower($email_check_admin['email']) == strtolower($email)) {
					Response::standardError('emailexistsanon', $email, true);
				}
			}
		}

		if ($password != '') {
			$password = Crypt::validatePassword($password, true);
			$password = Crypt::makeCryptPassword($password);
		} else {
			$password = $result['password'];
		}

		if ($this->isAdmin()) {
			if ($createstdsubdomain != '1' || $deactivated) {
				$createstdsubdomain = '0';
			}

			if ($createstdsubdomain == '1' && $result['standardsubdomain'] == '0') {
				if (Settings::Get('system.stdsubdomain') !== null && Settings::Get('system.stdsubdomain') != '') {
					$_stdsubdomain = $result['loginname'] . '.' . Settings::Get('system.stdsubdomain');
				} else {
					$_stdsubdomain = $result['loginname'] . '.' . Settings::Get('system.hostname');
				}

				$ins_data = [
					'domain' => $_stdsubdomain,
					'customerid' => $result['customerid'],
					'adminid' => $this->getUserDetail('adminid'),
					'docroot' => $result['documentroot'],
					'phpenabled' => $phpenabled,
					'openbasedir' => '1'
				];
				$domainid = -1;
				try {
					$std_domain = $this->apiCall('Domains.add', $ins_data);
					$domainid = $std_domain['id'];
				} catch (Exception $e) {
					$this->logger()->logAction(FroxlorLogger::ADM_ACTION, LOG_ERR, "[API] Unable to add standard-subdomain: " . $e->getMessage());
				}

				if ($domainid > 0) {
					$upd_stmt = Database::prepare("
							UPDATE `" . TABLE_PANEL_CUSTOMERS . "` SET `standardsubdomain` = :domainid WHERE `customerid` = :customerid
						");
					Database::pexecute($upd_stmt, [
						'domainid' => $domainid,
						'customerid' => $result['customerid']
					], true, true);
					$this->logger()->logAction(FroxlorLogger::ADM_ACTION, LOG_NOTICE, "[API] automatically added standardsubdomain for user '" . $result['loginname'] . "'");
					Cronjob::inserttask(TaskId::REBUILD_VHOST);
				}
			}

			if ($createstdsubdomain == '0' && $result['standardsubdomain'] != '0') {
				try {
					$std_domain = $this->apiCall('Domains.delete', [
						'id' => $result['standardsubdomain'],
						'is_stdsubdomain' => 1
					]);
				} catch (Exception $e) {
					$this->logger()->logAction(FroxlorLogger::ADM_ACTION, LOG_ERR, "[API] Unable to delete standard-subdomain: " . $e->getMessage());
				}
				$this->logger()->logAction(FroxlorLogger::ADM_ACTION, LOG_NOTICE, "[API] automatically deleted standardsubdomain for user '" . $result['loginname'] . "'");
				Cronjob::inserttask(TaskId::REBUILD_VHOST);
			}

			if ($phpenabled != $result['phpenabled'] || $perlenabled != $result['perlenabled'] || $email != $result['email']) {
				Cronjob::inserttask(TaskId::REBUILD_VHOST);
			}

			// activate/deactivate customer services
			if ($deactivated != $result['deactivated']) {
				$yesno = ($deactivated ? 'N' : 'Y');
				$pop3 = ($deactivated ? '0' : (int)$result['pop3']);
				$imap = ($deactivated ? '0' : (int)$result['imap']);

				$upd_stmt = Database::prepare("
					UPDATE `" . TABLE_MAIL_USERS . "` SET `postfix`= :yesno, `pop3` = :pop3, `imap` = :imap WHERE `customerid` = :customerid
				");
				Database::pexecute($upd_stmt, [
					'yesno' => $yesno,
					'pop3' => $pop3,
					'imap' => $imap,
					'customerid' => $id
				]);

				$upd_stmt = Database::prepare("
					UPDATE `" . TABLE_FTP_USERS . "` SET `login_enabled` = :yesno WHERE `customerid` = :customerid
				");
				Database::pexecute($upd_stmt, [
					'yesno' => $yesno,
					'customerid' => $id
				]);

				$upd_stmt = Database::prepare("
					UPDATE `" . TABLE_PANEL_DOMAINS . "` SET `deactivated`= :deactivated WHERE `customerid` = :customerid
				");
				Database::pexecute($upd_stmt, [
					'deactivated' => $deactivated,
					'customerid' => $id
				]);

				// enable/disable global mysql-user (loginname)
				$current_allowed_mysqlserver = isset($result['allowed_mysqlserver']) && !empty($result['allowed_mysqlserver']) ? json_decode($result['allowed_mysqlserver'], true) : [];
				foreach ($current_allowed_mysqlserver as $dbserver) {
					// require privileged access for target db-server
					Database::needRoot(true, $dbserver, true);
					// get DbManager
					$dbm = new DbManager($this->logger());
					foreach (array_map('trim', explode(',', Settings::Get('system.mysql_access_host'))) as $mysql_access_host) {
						// Prevent access, if deactivated
						if ($deactivated) {
							// failsafe if user has been deleted manually (requires MySQL 4.1.2+)
							$dbm->getManager()->disableUser($result['loginname'], $mysql_access_host);
						} else {
							// Otherwise grant access
							$dbm->getManager()->enableUser($result['loginname'], $mysql_access_host, true);
						}
					}
					$dbm->getManager()->flushPrivileges();
					Database::needRoot(false);
				}

				// Retrieve customer's databases
				$databases_stmt = Database::prepare("SELECT * FROM " . TABLE_PANEL_DATABASES . " WHERE customerid = :customerid ORDER BY `dbserver`");
				Database::pexecute($databases_stmt, [
					'customerid' => $id
				]);

				Database::needRoot(true);
				$last_dbserver = 0;

				$dbm = new DbManager($this->logger());

				// For each of them
				$priv_changed = false;
				while ($row_database = $databases_stmt->fetch(PDO::FETCH_ASSOC)) {
					if ($last_dbserver != $row_database['dbserver']) {
						$dbm->getManager()->flushPrivileges();
						Database::needRoot(true, $row_database['dbserver']);
						$last_dbserver = $row_database['dbserver'];
					}

					foreach (array_map('trim', explode(',', Settings::Get('system.mysql_access_host'))) as $mysql_access_host) {
						// Prevent access, if deactivated
						if ($deactivated) {
							// failsafe if user has been deleted manually (requires MySQL 4.1.2+)
							$dbm->getManager()->disableUser($row_database['databasename'], $mysql_access_host);
						} else {
							// Otherwise grant access
							$dbm->getManager()->enableUser($row_database['databasename'], $mysql_access_host);
						}
					}
					$priv_changed = true;
				}

				// At last flush the new privileges
				if ($priv_changed) {
					$dbm->getManager()->flushPrivileges();
				}
				Database::needRoot(false);

				// reactivate/deactivate api-keys
				$valid_until = $deactivated ? 0 : -1;
				$stmt = Database::prepare("UPDATE `" . TABLE_API_KEYS . "` SET `valid_until` = :vu WHERE `customerid` = :id");
				Database::pexecute($stmt, [
					'id' => $id,
					'vu' => $valid_until
				], true, true);

				$this->logger()->logAction(FroxlorLogger::ADM_ACTION, LOG_NOTICE, "[API] " . ($deactivated ? 'deactivated' : 'reactivated') . " user '" . $result['loginname'] . "'");
				Cronjob::inserttask(TaskId::REBUILD_VHOST);
			}

			// Disable or enable POP3 Login for customers Mail Accounts
			if ($email_pop3 != $result['pop3']) {
				$upd_stmt = Database::prepare("UPDATE `" . TABLE_MAIL_USERS . "` SET `pop3` = :pop3 WHERE `customerid` = :customerid");
				Database::pexecute($upd_stmt, [
					'pop3' => $email_pop3,
					'customerid' => $id
				]);
			}

			// Disable or enable IMAP Login for customers Mail Accounts
			if ($email_imap != $result['imap']) {
				$upd_stmt = Database::prepare("UPDATE `" . TABLE_MAIL_USERS . "` SET `imap` = :imap WHERE `customerid` = :customerid");
				Database::pexecute($upd_stmt, [
					'imap' => $email_imap,
					'customerid' => $id
				]);
			}
		}

		$upd_data = [
			'customerid' => $id,
			'passwd' => $password,
			'lang' => $def_language,
			'theme' => $theme
		];

		if ($this->isAdmin()) {
			$admin_upd_data = [
				'name' => $name,
				'firstname' => $firstname,
				'gender' => $gender,
				'company' => $company,
				'street' => $street,
				'zipcode' => $zipcode,
				'city' => $city,
				'phone' => $phone,
				'fax' => $fax,
				'email' => $email,
				'customerno' => $customernumber,
				'diskspace' => $diskspace,
				'traffic' => $traffic,
				'subdomains' => $subdomains,
				'emails' => $emails,
				'email_accounts' => $email_accounts,
				'email_forwarders' => $email_forwarders,
				'email_quota' => $email_quota,
				'ftps' => $ftps,
				'mysqls' => $mysqls,
				'deactivated' => $deactivated,
				'phpenabled' => $phpenabled,
				'allowed_phpconfigs' => empty($allowed_phpconfigs) ? "" : json_encode($allowed_phpconfigs),
				'imap' => $email_imap,
				'pop3' => $email_pop3,
				'perlenabled' => $perlenabled,
				'dnsenabled' => $dnsenabled,
				'logviewenabled' => $logviewenabled,
				'custom_notes' => $custom_notes,
				'custom_notes_show' => $custom_notes_show,
				'gui_access' => $gui_access,
				'api_allowed' => $api_allowed,
				'shell_allowed' => $shell_allowed,
				'allowed_mysqlserver' => empty($allowed_mysqlserver) ? "" : json_encode($allowed_mysqlserver)
			];
			$upd_data += $admin_upd_data;
		}

		$upd_query = "UPDATE `" . TABLE_PANEL_CUSTOMERS . "` SET
				`def_language` = :lang,
				`password` = :passwd,
				`theme` = :theme";

		if ($this->isAdmin()) {
			$admin_upd_query = ",
				`name` = :name,
				`firstname` = :firstname,
				`gender` = :gender,
				`company` = :company,
				`street` = :street,
				`zipcode` = :zipcode,
				`city` = :city,
				`phone` = :phone,
				`fax` = :fax,
				`email` = :email,
				`customernumber` = :customerno,
				`diskspace` = :diskspace,
				`traffic` = :traffic,
				`subdomains` = :subdomains,
				`emails` = :emails,
				`email_accounts` = :email_accounts,
				`email_forwarders` = :email_forwarders,
				`ftps` = :ftps,
				`mysqls` = :mysqls,
				`deactivated` = :deactivated,
				`phpenabled` = :phpenabled,
				`allowed_phpconfigs` = :allowed_phpconfigs,
				`email_quota` = :email_quota,
				`imap` = :imap,
				`pop3` = :pop3,
				`perlenabled` = :perlenabled,
				`dnsenabled` = :dnsenabled,
				`logviewenabled` = :logviewenabled,
				`custom_notes` = :custom_notes,
				`custom_notes_show` = :custom_notes_show,
				`gui_access` = :gui_access,
				`api_allowed` = :api_allowed,
				`shell_allowed` = :shell_allowed,
				`allowed_mysqlserver` = :allowed_mysqlserver";
			$upd_query .= $admin_upd_query;
		}
		$upd_query .= " WHERE `customerid` = :customerid";
		$upd_stmt = Database::prepare($upd_query);
		Database::pexecute($upd_stmt, $upd_data);

		if ($this->isAdmin()) {
			// Using filesystem - quota, insert a task which cleans the filesystem - quota
			Cronjob::inserttask(TaskId::CREATE_QUOTA);

			$admin_update_query = "UPDATE `" . TABLE_PANEL_ADMINS . "` SET `customers_used` = `customers_used` ";

			if ($mysqls != '-1' || $result['mysqls'] != '-1') {
				$admin_update_query .= ", `mysqls_used` = `mysqls_used` ";

				if ($mysqls != '-1') {
					$admin_update_query .= " + 0" . (int)$mysqls . " ";
				}
				if ($result['mysqls'] != '-1') {
					$admin_update_query .= " - 0" . (int)$result['mysqls'] . " ";
				}
			}

			if ($emails != '-1' || $result['emails'] != '-1') {
				$admin_update_query .= ", `emails_used` = `emails_used` ";

				if ($emails != '-1') {
					$admin_update_query .= " + 0" . (int)$emails . " ";
				}
				if ($result['emails'] != '-1') {
					$admin_update_query .= " - 0" . (int)$result['emails'] . " ";
				}
			}

			if ($email_accounts != '-1' || $result['email_accounts'] != '-1') {
				$admin_update_query .= ", `email_accounts_used` = `email_accounts_used` ";

				if ($email_accounts != '-1') {
					$admin_update_query .= " + 0" . (int)$email_accounts . " ";
				}
				if ($result['email_accounts'] != '-1') {
					$admin_update_query .= " - 0" . (int)$result['email_accounts'] . " ";
				}
			}

			if ($email_forwarders != '-1' || $result['email_forwarders'] != '-1') {
				$admin_update_query .= ", `email_forwarders_used` = `email_forwarders_used` ";

				if ($email_forwarders != '-1') {
					$admin_update_query .= " + 0" . (int)$email_forwarders . " ";
				}
				if ($result['email_forwarders'] != '-1') {
					$admin_update_query .= " - 0" . (int)$result['email_forwarders'] . " ";
				}
			}

			if ($email_quota != '-1' || $result['email_quota'] != '-1') {
				$admin_update_query .= ", `email_quota_used` = `email_quota_used` ";

				if ($email_quota != '-1') {
					$admin_update_query .= " + 0" . (int)$email_quota . " ";
				}
				if ($result['email_quota'] != '-1') {
					$admin_update_query .= " - 0" . (int)$result['email_quota'] . " ";
				}
			}

			if ($subdomains != '-1' || $result['subdomains'] != '-1') {
				$admin_update_query .= ", `subdomains_used` = `subdomains_used` ";

				if ($subdomains != '-1') {
					$admin_update_query .= " + 0" . (int)$subdomains . " ";
				}
				if ($result['subdomains'] != '-1') {
					$admin_update_query .= " - 0" . (int)$result['subdomains'] . " ";
				}
			}

			if ($ftps != '-1' || $result['ftps'] != '-1') {
				$admin_update_query .= ", `ftps_used` = `ftps_used` ";

				if ($ftps != '-1') {
					$admin_update_query .= " + 0" . (int)$ftps . " ";
				}
				if ($result['ftps'] != '-1') {
					$admin_update_query .= " - 0" . (int)$result['ftps'] . " ";
				}
			}

			if (($diskspace / 1024) != '-1' || ($result['diskspace'] / 1024) != '-1') {
				$admin_update_query .= ", `diskspace_used` = `diskspace_used` ";

				if (($diskspace / 1024) != '-1') {
					$admin_update_query .= " + 0" . (int)$diskspace . " ";
				}
				if (($result['diskspace'] / 1024) != '-1') {
					$admin_update_query .= " - 0" . (int)$result['diskspace'] . " ";
				}
			}

			$admin_update_query .= " WHERE `adminid` = '" . (int)$result['adminid'] . "'";
			Database::query($admin_update_query);
		}

		// shell allowance has changed
		if ($result['shell_allowed'] == '1' && $shell_allowed == '0') {
			// update all users with a valid shell to have /bin/false (disable shell)
			$ftp_upd_stmt = Database::prepare("UPDATE `" . TABLE_FTP_USERS . "` SET `shell` = '/bin/false' WHERE `customerid` = :cid");
			Database::pexecute($ftp_upd_stmt, ['cid' => (int)$result['customerid']]);
		}

		$this->logger()->logAction($this->isAdmin() ? FroxlorLogger::ADM_ACTION : FroxlorLogger::USR_ACTION, LOG_NOTICE, "[API] edited user '" . $result['loginname'] . "'");

		/*
		 * move customer to another admin/reseller; #1166
		 */
		if ($this->isAdmin()) {
			if ($move_to_admin > 0 && $move_to_admin != $result['adminid']) {
				$move_result = $this->apiCall('Customers.move', [
					'id' => $result['customerid'],
					'adminid' => $move_to_admin
				]);
				if ($move_result != true) {
					Response::standardError('moveofcustomerfailed', $move_result, true);
				}
			}
		}

		$result = $this->apiCall('Customers.get', [
			'id' => $result['customerid']
		]);
		return $this->response($result);
	}

	/**
	 * delete a customer entry by either id or loginname
	 *
	 * @param int $id
	 *            optional, the customer-id
	 * @param string $loginname
	 *            optional, the loginname
	 * @param bool $delete_userfiles
	 *            optional, default false
	 *
	 * @access admin
	 * @return string json-encoded array
	 * @throws Exception
	 */
	public function delete()
	{
		if ($this->isAdmin()) {
			$id = $this->getParam('id', true, 0);
			$ln_optional = $id > 0;
			$loginname = $this->getParam('loginname', $ln_optional, '');
			$delete_userfiles = $this->getParam('delete_userfiles', true, 0);

			$result = $this->apiCall('Customers.get', [
				'id' => $id,
				'loginname' => $loginname
			]);
			$id = $result['customerid'];

			// remove global mysql-user (loginname)
			$current_allowed_mysqlserver = isset($result['allowed_mysqlserver']) && !empty($result['allowed_mysqlserver']) ? json_decode($result['allowed_mysqlserver'], true) : [];
			foreach ($current_allowed_mysqlserver as $dbserver) {
				// require privileged access for target db-server
				Database::needRoot(true, $dbserver, false);
				// get DbManager
				$dbm = new DbManager($this->logger());
				foreach (array_map('trim', explode(',', Settings::Get('system.mysql_access_host'))) as $mysql_access_host) {
					$dbm->getManager()->deleteUser($result['loginname'], $mysql_access_host);
				}
				$dbm->getManager()->flushPrivileges();
				Database::needRoot(false);
			}

			// remove all databases
			$databases_stmt = Database::prepare("
				SELECT * FROM `" . TABLE_PANEL_DATABASES . "`
				WHERE `customerid` = :id ORDER BY `dbserver`
			");
			Database::pexecute($databases_stmt, [
				'id' => $id
			]);
			Database::needRoot(true);
			$last_dbserver = 0;

			$dbm = new DbManager($this->logger());

			$priv_changed = false;
			while ($row_database = $databases_stmt->fetch(PDO::FETCH_ASSOC)) {
				if ($last_dbserver != $row_database['dbserver']) {
					$dbm->getManager()->flushPrivileges();
					Database::needRoot(true, $row_database['dbserver']);
					$last_dbserver = $row_database['dbserver'];
				}
				$dbm->getManager()->deleteDatabase($row_database['databasename']);
				$priv_changed = true;
			}
			if ($priv_changed) {
				$dbm->getManager()->flushPrivileges();
			}
			Database::needRoot(false);

			// delete customer itself
			$stmt = Database::prepare("DELETE FROM `" . TABLE_PANEL_CUSTOMERS . "` WHERE `customerid` = :id");
			Database::pexecute($stmt, [
				'id' => $id
			], true, true);

			// delete customer databases
			$stmt = Database::prepare("DELETE FROM `" . TABLE_PANEL_DATABASES . "` WHERE `customerid` = :id");
			Database::pexecute($stmt, [
				'id' => $id
			], true, true);

			// first gather all domain-id's to clean up panel_domaintoip, dns-entries and certificates accordingly
			$did_stmt = Database::prepare("SELECT `id`, `domain` FROM `" . TABLE_PANEL_DOMAINS . "` WHERE `customerid` = :id");
			Database::pexecute($did_stmt, [
				'id' => $id
			], true, true);
			while ($row = $did_stmt->fetch(PDO::FETCH_ASSOC)) {
				// remove domain->ip connection
				$stmt = Database::prepare("DELETE FROM `" . TABLE_DOMAINTOIP . "` WHERE `id_domain` = :did");
				Database::pexecute($stmt, [
					'did' => $row['id']
				], true, true);
				// remove domain->dns entries
				$stmt = Database::prepare("DELETE FROM `" . TABLE_DOMAIN_DNS . "` WHERE `domain_id` = :did");
				Database::pexecute($stmt, [
					'did' => $row['id']
				], true, true);
				// remove domain->certificates entries
				$stmt = Database::prepare("DELETE FROM `" . TABLE_PANEL_DOMAIN_SSL_SETTINGS . "` WHERE `domainid` = :did");
				Database::pexecute($stmt, [
					'did' => $row['id']
				], true, true);
				// remove domains DNS from powerDNS if used, #581
				Cronjob::inserttask(TaskId::DELETE_DOMAIN_PDNS, $row['domain']);
				// remove domain from acme.sh / lets encrypt if used
				Cronjob::inserttask(TaskId::DELETE_DOMAIN_SSL, $row['domain']);
			}
			// remove customer domains
			$stmt = Database::prepare("DELETE FROM `" . TABLE_PANEL_DOMAINS . "` WHERE `customerid` = :id");
			Database::pexecute($stmt, [
				'id' => $id
			], true, true);
			$domains_deleted = $stmt->rowCount();

			// delete htpasswds
			$stmt = Database::prepare("DELETE FROM `" . TABLE_PANEL_HTPASSWDS . "` WHERE `customerid` = :id");
			Database::pexecute($stmt, [
				'id' => $id
			], true, true);

			// delete htaccess options
			$stmt = Database::prepare("DELETE FROM `" . TABLE_PANEL_HTACCESS . "` WHERE `customerid` = :id");
			Database::pexecute($stmt, [
				'id' => $id
			], true, true);

			// delete traffic information
			$stmt = Database::prepare("DELETE FROM `" . TABLE_PANEL_TRAFFIC . "` WHERE `customerid` = :id");
			Database::pexecute($stmt, [
				'id' => $id
			], true, true);

			// remove diskspace analysis
			$stmt = Database::prepare("DELETE FROM `" . TABLE_PANEL_DISKSPACE . "` WHERE `customerid` = :id");
			Database::pexecute($stmt, [
				'id' => $id
			], true, true);

			// delete mail-accounts
			$stmt = Database::prepare("DELETE FROM `" . TABLE_MAIL_USERS . "` WHERE `customerid` = :id");
			Database::pexecute($stmt, [
				'id' => $id
			], true, true);

			// delete mail-addresses
			$stmt = Database::prepare("DELETE FROM `" . TABLE_MAIL_VIRTUAL . "` WHERE `customerid` = :id");
			Database::pexecute($stmt, [
				'id' => $id
			], true, true);

			// gather ftp-user names
			$result2_stmt = Database::prepare("SELECT `username` FROM `" . TABLE_FTP_USERS . "` WHERE `customerid` = :id");
			Database::pexecute($result2_stmt, [
				'id' => $id
			], true, true);
			while ($row = $result2_stmt->fetch(PDO::FETCH_ASSOC)) {
				// delete ftp-quotatallies by username
				$stmt = Database::prepare("DELETE FROM `" . TABLE_FTP_QUOTATALLIES . "` WHERE `name` = :name");
				Database::pexecute($stmt, [
					'name' => $row['username']
				], true, true);
			}

			// remove ftp-group
			$stmt = Database::prepare("DELETE FROM `" . TABLE_FTP_GROUPS . "` WHERE `customerid` = :id");
			Database::pexecute($stmt, [
				'id' => $id
			], true, true);

			// remove ftp-users
			$stmt = Database::prepare("DELETE FROM `" . TABLE_FTP_USERS . "` WHERE `customerid` = :id");
			Database::pexecute($stmt, [
				'id' => $id
			], true, true);

			// remove api-keys
			$stmt = Database::prepare("DELETE FROM `" . TABLE_API_KEYS . "` WHERE `customerid` = :id");
			Database::pexecute($stmt, [
				'id' => $id
			], true, true);

			// Delete all waiting "create user" -tasks for this user, #276
			// Note: the WHERE selects part of a serialized array, but it should be safe this way
			$del_stmt = Database::prepare("
				DELETE FROM `" . TABLE_PANEL_TASKS . "`
				WHERE `type` = '2' AND `data` LIKE :loginname
			");
			Database::pexecute($del_stmt, [
				'loginname' => "%:{$result['loginname']};%"
			], true, true);

			// update admin-resource-usage
			Admins::decreaseUsage($result['adminid'], 'customers_used');
			Admins::decreaseUsage($result['adminid'], 'domains_used', '', (int)($domains_deleted - $result['subdomains_used']));

			if ($result['mysqls'] != '-1') {
				Admins::decreaseUsage($result['adminid'], 'mysqls_used', '', (int)$result['mysqls']);
			}

			if ($result['emails'] != '-1') {
				Admins::decreaseUsage($result['adminid'], 'emails_used', '', (int)$result['emails']);
			}

			if ($result['email_accounts'] != '-1') {
				Admins::decreaseUsage($result['adminid'], 'email_accounts_used', '', (int)$result['email_accounts']);
			}

			if ($result['email_forwarders'] != '-1') {
				Admins::decreaseUsage($result['adminid'], 'email_forwarders_used', '', (int)$result['email_forwarders']);
			}

			if ($result['email_quota'] != '-1') {
				Admins::decreaseUsage($result['adminid'], 'email_quota_used', '', (int)$result['email_quota']);
			}

			if ($result['subdomains'] != '-1') {
				Admins::decreaseUsage($result['adminid'], 'subdomains_used', '', (int)$result['subdomains']);
			}

			if ($result['ftps'] != '-1') {
				Admins::decreaseUsage($result['adminid'], 'ftps_used', '', (int)$result['ftps']);
			}

			if (($result['diskspace'] / 1024) != '-1') {
				Admins::decreaseUsage($result['adminid'], 'diskspace_used', '', (int)$result['diskspace']);
			}

			// rebuild configs
			Cronjob::inserttask(TaskId::REBUILD_VHOST);

			// Using nameserver, insert a task which rebuilds the server config
			Cronjob::inserttask(TaskId::REBUILD_DNS);

			if ($delete_userfiles == 1) {
				// insert task to remove the customers files from the filesystem
				Cronjob::inserttask(TaskId::DELETE_CUSTOMER_FILES, $result['loginname']);
			}

			// Using filesystem - quota, insert a task which cleans the filesystem - quota
			Cronjob::inserttask(TaskId::CREATE_QUOTA);

			$this->logger()->logAction(FroxlorLogger::ADM_ACTION, LOG_WARNING, "[API] deleted customer '" . $result['loginname'] . "'");
			return $this->response($result);
		}
		throw new Exception("Not allowed to execute given command.", 403);
	}

	/**
	 * decrease resource-usage
	 *
	 * @param int $customerid
	 * @param string $resource
	 * @param string $extra
	 *            optional, default empty
	 * @param int $decrease_by
	 *            optional, default 1
	 */
	public static function decreaseUsage($customerid = 0, $resource = null, $extra = '', $decrease_by = 1)
	{
		self::updateResourceUsage(TABLE_PANEL_CUSTOMERS, 'customerid', $customerid, '-', $resource, $extra, $decrease_by);
	}

	/**
	 * unlock a locked customer by either id or loginname
	 *
	 * @param int $id
	 *            optional, the customer-id
	 * @param string $loginname
	 *            optional, the loginname
	 *
	 * @access admin
	 * @return string json-encoded array
	 * @throws Exception
	 */
	public function unlock()
	{
		if ($this->isAdmin()) {
			$id = $this->getParam('id', true, 0);
			$ln_optional = $id > 0;
			$loginname = $this->getParam('loginname', $ln_optional, '');

			$result = $this->apiCall('Customers.get', [
				'id' => $id,
				'loginname' => $loginname
			]);
			$id = $result['customerid'];

			$result_stmt = Database::prepare("
				UPDATE `" . TABLE_PANEL_CUSTOMERS . "` SET
				`loginfail_count` = '0'
				WHERE `customerid`= :id
			");
			Database::pexecute($result_stmt, [
				'id' => $id
			], true, true);
			// set the new value for result-array
			$result['loginfail_count'] = 0;

			$this->logger()->logAction(FroxlorLogger::ADM_ACTION, LOG_WARNING, "[API] unlocked customer '" . $result['loginname'] . "'");
			return $this->response($result);
		}
		throw new Exception("Not allowed to execute given command.", 403);
	}

	/**
	 * Function to move a given customer to a given admin/reseller
	 * and update all its references accordingly
	 *
	 * @param int $id
	 *            optional, the customer-id
	 * @param string $loginname
	 *            optional, the loginname
	 * @param int $adminid
	 *            target-admin-id
	 *
	 * @access admin
	 * @return string json-encoded array
	 * @throws Exception
	 */
	public function move()
	{
		if ($this->isAdmin() && $this->getUserDetail('change_serversettings') == 1) {
			$adminid = $this->getParam('adminid');
			$id = $this->getParam('id', true, 0);
			$ln_optional = $id > 0;
			$loginname = $this->getParam('loginname', $ln_optional, '');

			$c_result = $this->apiCall('Customers.get', [
				'id' => $id,
				'loginname' => $loginname
			]);
			$id = $c_result['customerid'];

			// check if target-admin is the current admin
			if ($adminid == $c_result['adminid']) {
				throw new Exception("Cannot move customer to the same admin/reseller as he currently is assigned to", 406);
			}

			// get target admin
			$a_result = $this->apiCall('Admins.get', [
				'id' => $adminid
			]);

			// Update customer entry
			$updCustomer_stmt = Database::prepare("
				UPDATE `" . TABLE_PANEL_CUSTOMERS . "` SET `adminid` = :adminid WHERE `customerid` = :cid
			");
			Database::pexecute($updCustomer_stmt, [
				'adminid' => $adminid,
				'cid' => $id
			], true, true);

			// Update customer-domains
			$updDomains_stmt = Database::prepare("
				UPDATE `" . TABLE_PANEL_DOMAINS . "` SET `adminid` = :adminid WHERE `customerid` = :cid
			");
			Database::pexecute($updDomains_stmt, [
				'adminid' => $adminid,
				'cid' => $id
			], true, true);

			// now, recalculate the resource-usage for the old and the new admin
			User::updateCounters(false);

			$this->logger()->logAction(FroxlorLogger::ADM_ACTION, LOG_NOTICE, "[API] moved user '" . $c_result['loginname'] . "' from admin/reseller '" . $c_result['adminname'] . " to admin/reseller '" . $a_result['loginname'] . "'");

			$result = $this->apiCall('Customers.get', [
				'id' => $c_result['customerid']
			]);
			return $this->response($result);
		}
		throw new Exception("Not allowed to execute given command.", 403);
	}
}
