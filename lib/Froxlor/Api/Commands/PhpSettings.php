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
class PhpSettings extends ApiCommand implements ResourceEntity
{

	/**
	 * lists all php-setting entries
	 *
	 * @param bool $with_subdomains
	 *            optional, also include subdomains to the list domains that use the config, default 0 (false)
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
		if ($this->isAdmin()) {
			$this->logger()->logAction(FroxlorLogger::ADM_ACTION, LOG_INFO, "[API] list php-configs");

			$with_subdomains = $this->getBoolParam('with_subdomains', true, false);
			$query_fields = [];
			$result_stmt = Database::prepare("
				SELECT c.*, fd.description as fpmdesc
				FROM `" . TABLE_PANEL_PHPCONFIGS . "` c
				LEFT JOIN `" . TABLE_PANEL_FPMDAEMONS . "` fd ON fd.id = c.fpmsettingid" . $this->getSearchWhere($query_fields) . $this->getOrderBy() . $this->getLimit());
			Database::pexecute($result_stmt, $query_fields, true, true);
			$phpconfigs = [];
			while ($row = $result_stmt->fetch(PDO::FETCH_ASSOC)) {
				$query_params = [
					'id' => $row['id']
				];

				$query = "SELECT * FROM `" . TABLE_PANEL_DOMAINS . "`
					WHERE `phpsettingid` = :id AND `email_only` = '0' AND `phpenabled` = '1'";

				if (!$with_subdomains) {
					$query .= " AND `parentdomainid` = '0'";
				}

				if ((int)$this->getUserDetail('customers_see_all') == 0) {
					$query .= " AND `adminid` = :adminid";
					$query_params['adminid'] = $this->getUserDetail('adminid');
				}

				if ((int)Settings::Get('panel.phpconfigs_hidestdsubdomain') == 1) {
					$ssdids_res = Database::query("
					SELECT DISTINCT `standardsubdomain` FROM `" . TABLE_PANEL_CUSTOMERS . "`
					WHERE `standardsubdomain` > 0 ORDER BY `standardsubdomain` ASC;");
					$ssdids = [];
					while ($ssd = $ssdids_res->fetch(PDO::FETCH_ASSOC)) {
						$ssdids[] = $ssd['standardsubdomain'];
					}
					if (count($ssdids) > 0) {
						$query .= " AND `id` NOT IN (" . implode(', ', $ssdids) . ")";
					}
				}

				$domains = [];
				$subdomains = [];
				$domainresult_stmt = Database::prepare($query);
				Database::pexecute($domainresult_stmt, $query_params, true, true);

				if (Database::num_rows() > 0) {
					while ($row2 = $domainresult_stmt->fetch(PDO::FETCH_ASSOC)) {
						if ($row2['parentdomainid'] != 0) {
							$subdomains[] = $row2['domain'];
						} else {
							$domains[] = $row2['domain'];
						}
					}
				}

				// check whether we use that config as froxor-vhost config
				if ((Settings::Get('system.mod_fcgid') == '1' && Settings::Get('system.mod_fcgid_defaultini_ownvhost') == $row['id']) || (Settings::Get('phpfpm.enabled') == '1' && Settings::Get('phpfpm.vhost_defaultini') == $row['id'])) {
					$domains[] = Settings::Get('system.hostname');
				}

				// check whether this is our default config
				if ((Settings::Get('system.mod_fcgid') == '1' && Settings::Get('system.mod_fcgid_defaultini') == $row['id']) || (Settings::Get('phpfpm.enabled') == '1' && Settings::Get('phpfpm.defaultini') == $row['id'])) {
					$row['is_default'] = true;
				}

				$row['domains'] = $domains;
				$row['subdomains'] = $subdomains;
				$phpconfigs[] = $row;
			}

			return $this->response([
				'count' => count($phpconfigs),
				'list' => $phpconfigs
			]);
		}
		throw new Exception("Not allowed to execute given command.", 403);
	}

	/**
	 * return a php-setting entry by id
	 *
	 * @param int $id
	 *            php-settings-id
	 *
	 * @access admin
	 * @return string json-encoded array
	 * @throws Exception
	 */
	public function get()
	{
		if ($this->isAdmin()) {
			$id = $this->getParam('id');

			$result_stmt = Database::prepare("
				SELECT * FROM `" . TABLE_PANEL_PHPCONFIGS . "` WHERE `id` = :id
			");
			$result = Database::pexecute_first($result_stmt, [
				'id' => $id
			], true, true);
			if ($result) {
				return $this->response($result);
			}
			throw new Exception("php-config with id #" . $id . " could not be found", 404);
		}
		throw new Exception("Not allowed to execute given command.", 403);
	}

	/**
	 * returns the total number of accessible php-setting entries
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
				SELECT COUNT(*) as num_phps
				FROM `" . TABLE_PANEL_PHPCONFIGS . "` c
				LEFT JOIN `" . TABLE_PANEL_FPMDAEMONS . "` fd ON fd.id = c.fpmsettingid" .
				$this->getSearchWhere($query_fields));
			$result = Database::pexecute_first($result_stmt, $query_fields, true, true);
			if ($result) {
				return $this->response($result['num_phps']);
			}
			return $this->response(0);
		}
		throw new Exception("Not allowed to execute given command.", 403);
	}

	/**
	 * add new php-settings entry
	 *
	 * @param string $description
	 *            description of the php-config
	 * @param string $phpsettings
	 *            the actual ini-settings
	 * @param string $binary
	 *            optional the binary to php-cgi if FCGID is used
	 * @param string $file_extensions
	 *            optional allowed php-file-extensions if FCGID is used, default is 'php'
	 * @param int $mod_fcgid_starter
	 *            optional number of fcgid-starters if FCGID is used, default is -1
	 * @param int $mod_fcgid_maxrequests
	 *            optional number of fcgid-maxrequests if FCGID is used, default is -1
	 * @param string $mod_fcgid_umask
	 *            optional umask if FCGID is used, default is '022'
	 * @param int $fpmconfig
	 *            optional id of the fpm-daemon-config if FPM is used
	 * @param bool $phpfpm_enable_slowlog
	 *            optional whether to write a slowlog or not if FPM is used, default is 0 (false)
	 * @param string $phpfpm_reqtermtimeout
	 *            optional request terminate timeout if FPM is used, default is '60s'
	 * @param string $phpfpm_reqslowtimeout
	 *            optional request slowlog timeout if FPM is used, default is '5s'
	 * @param bool $pass_authorizationheader
	 *            optional whether to pass authorization header to webserver if FPM/FCGID is used, default is 0 (false)
	 * @param bool $override_fpmconfig
	 *            optional whether to override fpm-daemon-config value for the following settings if FPM is used,
	 *            default is 0 (false)
	 * @param string $pm
	 *            optional process-manager to use if FPM is used (allowed values are 'static', 'dynamic' and
	 *            'ondemand'), default is fpm-daemon-value
	 * @param int $max_children
	 *            optional number of max children if FPM is used, default is the fpm-daemon-value
	 * @param int $start_server
	 *            optional number of servers to start if FPM is used, default is fpm-daemon-value
	 * @param int $min_spare_servers
	 *            optional number of minimum spare servers if FPM is used, default is fpm-daemon-value
	 * @param int $max_spare_servers
	 *            optional number of maximum spare servers if FPM is used, default is fpm-daemon-value
	 * @param int $max_requests
	 *            optional number of maximum requests if FPM is used, default is fpm-daemon-value
	 * @param int $idle_timeout
	 *            optional number of seconds for idle-timeout if FPM is used, default is fpm-daemon-value
	 * @param string $limit_extensions
	 *            optional limitation of php-file-extensions if FPM is used, default is fpm-daemon-value
	 * @param bool $allow_all_customers
	 *            optional add this configuration to the list of every existing customer's allowed-fpm-config list,
	 *            default is false (no)
	 *
	 * @access admin
	 * @return string json-encoded array
	 * @throws Exception
	 */
	public function add()
	{
		if ($this->isAdmin() && $this->getUserDetail('change_serversettings') == 1) {
			// required parameter
			$description = $this->getParam('description');
			$phpsettings = $this->getParam('phpsettings');

			if (Settings::Get('system.mod_fcgid') == 1) {
				$binary = $this->getParam('binary');
				$fpm_config_id = 1;
			} elseif (Settings::Get('phpfpm.enabled') == 1) {
				$fpm_config_id = intval($this->getParam('fpmconfig'));
			} else {
				$fpm_config_id = 1;
			}

			// parameters
			$file_extensions = $this->getParam('file_extensions', true, 'php');
			$mod_fcgid_starter = $this->getParam('mod_fcgid_starter', true, -1);
			$mod_fcgid_maxrequests = $this->getParam('mod_fcgid_maxrequests', true, -1);
			$mod_fcgid_umask = $this->getParam('mod_fcgid_umask', true, "022");
			$fpm_enableslowlog = $this->getBoolParam('phpfpm_enable_slowlog', true, 0);
			$fpm_reqtermtimeout = $this->getParam('phpfpm_reqtermtimeout', true, "60s");
			$fpm_reqslowtimeout = $this->getParam('phpfpm_reqslowtimeout', true, "5s");
			$pass_authorizationheader = $this->getBoolParam('pass_authorizationheader', true, 0);

			$override_fpmconfig = $this->getBoolParam('override_fpmconfig', true, 0);
			$def_fpmconfig = $this->apiCall('FpmDaemons.get', [
				'id' => $fpm_config_id
			]);
			$pmanager = $this->getParam('pm', true, $def_fpmconfig['pm']);
			$max_children = $this->getParam('max_children', true, $def_fpmconfig['max_children']);
			$start_servers = $this->getParam('start_servers', true, $def_fpmconfig['start_servers']);
			$min_spare_servers = $this->getParam('min_spare_servers', true, $def_fpmconfig['min_spare_servers']);
			$max_spare_servers = $this->getParam('max_spare_servers', true, $def_fpmconfig['max_spare_servers']);
			$max_requests = $this->getParam('max_requests', true, $def_fpmconfig['max_requests']);
			$idle_timeout = $this->getParam('idle_timeout', true, $def_fpmconfig['idle_timeout']);
			$limit_extensions = $this->getParam('limit_extensions', true, $def_fpmconfig['limit_extensions']);
			$allow_all_customers = $this->getBoolParam('allow_all_customers', true, 0);

			// validation
			$description = Validate::validate($description, 'description', Validate::REGEX_DESC_TEXT, '', [], true);
			$phpsettings = Validate::validate(str_replace("\r\n", "\n", $phpsettings), 'phpsettings', '/^[^\0]*$/', '', [], true);
			if (Settings::Get('system.mod_fcgid') == 1) {
				$binary = FileDir::makeCorrectFile(Validate::validate($binary, 'binary', '', '', [], true));
				$file_extensions = Validate::validate($file_extensions, 'file_extensions', '/^[a-zA-Z0-9\s]*$/', '', [], true);
				$mod_fcgid_starter = Validate::validate($mod_fcgid_starter, 'mod_fcgid_starter', '/^[0-9]*$/', '', [
					'-1',
					''
				], true);
				$mod_fcgid_maxrequests = Validate::validate($mod_fcgid_maxrequests, 'mod_fcgid_maxrequests', '/^[0-9]*$/', '', [
					'-1',
					''
				], true);
				$mod_fcgid_umask = Validate::validate($mod_fcgid_umask, 'mod_fcgid_umask', '/^[0-9]*$/', '', [], true);
				// disable fpm stuff
				$fpm_config_id = 1;
				$fpm_enableslowlog = 0;
				$fpm_reqtermtimeout = 0;
				$fpm_reqslowtimeout = 0;
				$override_fpmconfig = 0;
			} elseif (Settings::Get('phpfpm.enabled') == 1) {
				$fpm_reqtermtimeout = Validate::validate($fpm_reqtermtimeout, 'phpfpm_reqtermtimeout', '/^([0-9]+)(|s|m|h|d)$/', '', [], true);
				$fpm_reqslowtimeout = Validate::validate($fpm_reqslowtimeout, 'phpfpm_reqslowtimeout', '/^([0-9]+)(|s|m|h|d)$/', '', [], true);
				if (!in_array($pmanager, [
					'static',
					'dynamic',
					'ondemand'
				])) {
					throw new Exception("Unknown process manager", 406);
				}
				if (empty($limit_extensions)) {
					$limit_extensions = '.php';
				}
				$limit_extensions = Validate::validate($limit_extensions, 'limit_extensions', '/^(\.[a-z]([a-z0-9]+)\ ?)+$/', '', [], true);

				// disable fcgid stuff
				$binary = '/usr/bin/php-cgi';
				$file_extensions = 'php';
				$mod_fcgid_starter = 0;
				$mod_fcgid_maxrequests = 0;
				$mod_fcgid_umask = "022";
			}

			if (strlen($description) == 0 || strlen($description) > 50) {
				Response::standardError('descriptioninvalid', '', true);
			}

			$ins_stmt = Database::prepare("
				INSERT INTO `" . TABLE_PANEL_PHPCONFIGS . "` SET
				`description` = :desc,
				`binary` = :binary,
				`file_extensions` = :fext,
				`mod_fcgid_starter` = :starter,
				`mod_fcgid_maxrequests` = :mreq,
				`mod_fcgid_umask` = :umask,
				`fpm_slowlog` = :fpmslow,
				`fpm_reqterm` = :fpmreqterm,
				`fpm_reqslow` = :fpmreqslow,
				`phpsettings` = :phpsettings,
				`fpmsettingid` = :fpmsettingid,
				`pass_authorizationheader` = :fpmpassauth,
				`override_fpmconfig` = :ofc,
				`pm` = :pm,
				`max_children` = :max_children,
				`start_servers` = :start_servers,
				`min_spare_servers` = :min_spare_servers,
				`max_spare_servers` = :max_spare_servers,
				`max_requests` = :max_requests,
				`idle_timeout` = :idle_timeout,
				`limit_extensions` = :limit_extensions
			");
			$ins_data = [
				'desc' => $description,
				'binary' => $binary,
				'fext' => $file_extensions,
				'starter' => $mod_fcgid_starter,
				'mreq' => $mod_fcgid_maxrequests,
				'umask' => $mod_fcgid_umask,
				'fpmslow' => $fpm_enableslowlog,
				'fpmreqterm' => $fpm_reqtermtimeout,
				'fpmreqslow' => $fpm_reqslowtimeout,
				'phpsettings' => $phpsettings,
				'fpmsettingid' => $fpm_config_id,
				'fpmpassauth' => $pass_authorizationheader,
				'ofc' => $override_fpmconfig,
				'pm' => $pmanager,
				'max_children' => $max_children,
				'start_servers' => $start_servers,
				'min_spare_servers' => $min_spare_servers,
				'max_spare_servers' => $max_spare_servers,
				'max_requests' => $max_requests,
				'idle_timeout' => $idle_timeout,
				'limit_extensions' => $limit_extensions
			];
			Database::pexecute($ins_stmt, $ins_data, true, true);
			$ins_data['id'] = Database::lastInsertId();

			Cronjob::inserttask(TaskId::REBUILD_VHOST);
			$this->logger()->logAction(FroxlorLogger::ADM_ACTION, LOG_NOTICE, "[API] php setting with description '" . $description . "' has been created by '" . $this->getUserDetail('loginname') . "'");

			$result = $this->apiCall('PhpSettings.get', [
				'id' => $ins_data['id']
			]);

			$this->addForAllCustomers($allow_all_customers, $ins_data['id']);
			return $this->response($result);
		}
		throw new Exception("Not allowed to execute given command.", 403);
	}

	/**
	 * add given php-config id to the list of allowed php-config to all currently existing customers
	 * if allow_all_customers parameter is true in PhpSettings::add() or PhpSettings::update()
	 *
	 * @param bool $allow_all_customers
	 * @param int $config_id
	 */
	private function addForAllCustomers(bool $allow_all_customers, int $config_id)
	{
		// should this config be added to the allowed list of all existing customers?
		if ($allow_all_customers) {
			$sel_stmt = Database::prepare("SELECT customerid, allowed_phpconfigs FROM `" . TABLE_PANEL_CUSTOMERS . "`");
			$upd_stmt = Database::prepare("UPDATE `" . TABLE_PANEL_CUSTOMERS . "` SET allowed_phpconfigs = :ap WHERE customerid = :cid");
			Database::pexecute($sel_stmt);
			while ($cust = $sel_stmt->fetch(PDO::FETCH_ASSOC)) {
				// get existing entries of customer
				$ap = json_decode($cust['allowed_phpconfigs'], true);
				// initialize array if it's empty
				if (empty($ap)) {
					$ap = [];
				}
				// add this config
				$ap[] = $config_id;
				// check for duplicates and force value-type to be int
				$ap = array_map('intval', array_unique($ap));
				// update customer-entry
				Database::pexecute($upd_stmt, [
					'ap' => json_encode($ap),
					'cid' => $cust['customerid']
				]);
			}
		}
	}

	/**
	 * update a php-setting entry by given id
	 *
	 * @param int $id
	 * @param string $description
	 *            description of the php-config
	 * @param string $phpsettings
	 *            the actual ini-settings
	 * @param string $binary
	 *            optional the binary to php-cgi if FCGID is used
	 * @param string $file_extensions
	 *            optional allowed php-file-extensions if FCGID is used, default is 'php'
	 * @param int $mod_fcgid_starter
	 *            optional number of fcgid-starters if FCGID is used, default is -1
	 * @param int $mod_fcgid_maxrequests
	 *            optional number of fcgid-maxrequests if FCGID is used, default is -1
	 * @param string $mod_fcgid_umask
	 *            optional umask if FCGID is used, default is '022'
	 * @param int $fpmconfig
	 *            optional id of the fpm-daemon-config if FPM is used
	 * @param bool $phpfpm_enable_slowlog
	 *            optional whether to write a slowlog or not if FPM is used, default is 0 (false)
	 * @param string $phpfpm_reqtermtimeout
	 *            optional request terminate timeout if FPM is used, default is '60s'
	 * @param string $phpfpm_reqslowtimeout
	 *            optional request slowlog timeout if FPM is used, default is '5s'
	 * @param bool $pass_authorizationheader
	 *            optional whether to pass authorization header to webserver if FPM is used, default is 0 (false)
	 * @param bool $override_fpmconfig
	 *            optional whether to override fpm-daemon-config value for the following settings if FPM is used,
	 *            default is 0 (false)
	 * @param string $pm
	 *            optional process-manager to use if FPM is used (allowed values are 'static', 'dynamic' and
	 *            'ondemand'), default is fpm-daemon-value
	 * @param int $max_children
	 *            optional number of max children if FPM is used, default is the fpm-daemon-value
	 * @param int $start_server
	 *            optional number of servers to start if FPM is used, default is fpm-daemon-value
	 * @param int $min_spare_servers
	 *            optional number of minimum spare servers if FPM is used, default is fpm-daemon-value
	 * @param int $max_spare_servers
	 *            optional number of maximum spare servers if FPM is used, default is fpm-daemon-value
	 * @param int $max_requests
	 *            optional number of maximum requests if FPM is used, default is fpm-daemon-value
	 * @param int $idle_timeout
	 *            optional number of seconds for idle-timeout if FPM is used, default is fpm-daemon-value
	 * @param string $limit_extensions
	 *            optional limitation of php-file-extensions if FPM is used, default is fpm-daemon-value
	 * @param bool $allow_all_customers
	 *            optional add this configuration to the list of every existing customer's allowed-fpm-config list,
	 *            default is false (no)
	 *
	 * @access admin
	 * @return string json-encoded array
	 * @throws Exception
	 */
	public function update()
	{
		if ($this->isAdmin() && $this->getUserDetail('change_serversettings') == 1) {
			// required parameter
			$id = $this->getParam('id');

			$result = $this->apiCall('PhpSettings.get', [
				'id' => $id
			]);

			// parameters
			$description = $this->getParam('description', true, $result['description']);
			$phpsettings = $this->getParam('phpsettings', true, $result['phpsettings']);
			$binary = $this->getParam('binary', true, $result['binary']);
			$fpm_config_id = intval($this->getParam('fpmconfig', true, $result['fpmsettingid']));
			$file_extensions = $this->getParam('file_extensions', true, $result['file_extensions']);
			$mod_fcgid_starter = $this->getParam('mod_fcgid_starter', true, $result['mod_fcgid_starter']);
			$mod_fcgid_maxrequests = $this->getParam('mod_fcgid_maxrequests', true, $result['mod_fcgid_maxrequests']);
			$mod_fcgid_umask = $this->getParam('mod_fcgid_umask', true, $result['mod_fcgid_umask']);
			$fpm_enableslowlog = $this->getBoolParam('phpfpm_enable_slowlog', true, $result['fpm_slowlog']);
			$fpm_reqtermtimeout = $this->getParam('phpfpm_reqtermtimeout', true, $result['fpm_reqterm']);
			$fpm_reqslowtimeout = $this->getParam('phpfpm_reqslowtimeout', true, $result['fpm_reqslow']);
			$pass_authorizationheader = $this->getBoolParam('pass_authorizationheader', true, $result['pass_authorizationheader']);
			$override_fpmconfig = $this->getBoolParam('override_fpmconfig', true, $result['override_fpmconfig']);
			$pmanager = $this->getParam('pm', true, $result['pm']);
			$max_children = $this->getParam('max_children', true, $result['max_children']);
			$start_servers = $this->getParam('start_servers', true, $result['start_servers']);
			$min_spare_servers = $this->getParam('min_spare_servers', true, $result['min_spare_servers']);
			$max_spare_servers = $this->getParam('max_spare_servers', true, $result['max_spare_servers']);
			$max_requests = $this->getParam('max_requests', true, $result['max_requests']);
			$idle_timeout = $this->getParam('idle_timeout', true, $result['idle_timeout']);
			$limit_extensions = $this->getParam('limit_extensions', true, $result['limit_extensions']);
			$allow_all_customers = $this->getBoolParam('allow_all_customers', true, 0);

			// validation
			$description = Validate::validate($description, 'description', Validate::REGEX_DESC_TEXT, '', [], true);
			$phpsettings = Validate::validate(str_replace("\r\n", "\n", $phpsettings), 'phpsettings', '/^[^\0]*$/', '', [], true);
			if (Settings::Get('system.mod_fcgid') == 1) {
				$binary = FileDir::makeCorrectFile(Validate::validate($binary, 'binary', '', '', [], true));
				$file_extensions = Validate::validate($file_extensions, 'file_extensions', '/^[a-zA-Z0-9\s]*$/', '', [], true);
				$mod_fcgid_starter = Validate::validate($mod_fcgid_starter, 'mod_fcgid_starter', '/^[0-9]*$/', '', [
					'-1',
					''
				], true);
				$mod_fcgid_maxrequests = Validate::validate($mod_fcgid_maxrequests, 'mod_fcgid_maxrequests', '/^[0-9]*$/', '', [
					'-1',
					''
				], true);
				$mod_fcgid_umask = Validate::validate($mod_fcgid_umask, 'mod_fcgid_umask', '/^[0-9]*$/', '', [], true);
				// disable fpm stuff
				$fpm_config_id = 1;
				$fpm_enableslowlog = 0;
				$fpm_reqtermtimeout = 0;
				$fpm_reqslowtimeout = 0;
				$override_fpmconfig = 0;
			} elseif (Settings::Get('phpfpm.enabled') == 1) {
				$fpm_reqtermtimeout = Validate::validate($fpm_reqtermtimeout, 'phpfpm_reqtermtimeout', '/^([0-9]+)(|s|m|h|d)$/', '', [], true);
				$fpm_reqslowtimeout = Validate::validate($fpm_reqslowtimeout, 'phpfpm_reqslowtimeout', '/^([0-9]+)(|s|m|h|d)$/', '', [], true);
				if (!in_array($pmanager, [
					'static',
					'dynamic',
					'ondemand'
				])) {
					throw new Exception("Unknown process manager", 406);
				}
				if (empty($limit_extensions)) {
					$limit_extensions = '.php';
				}
				$limit_extensions = Validate::validate($limit_extensions, 'limit_extensions', '/^(\.[a-z]([a-z0-9]+)\ ?)+$/', '', [], true);

				// disable fcgid stuff
				$binary = '/usr/bin/php-cgi';
				$file_extensions = 'php';
				$mod_fcgid_starter = 0;
				$mod_fcgid_maxrequests = 0;
				$mod_fcgid_umask = "022";
			}

			if (strlen($description) == 0 || strlen($description) > 50) {
				Response::standardError('descriptioninvalid', '', true);
			}

			$upd_stmt = Database::prepare("
				UPDATE `" . TABLE_PANEL_PHPCONFIGS . "` SET
				`description` = :desc,
				`binary` = :binary,
				`file_extensions` = :fext,
				`mod_fcgid_starter` = :starter,
				`mod_fcgid_maxrequests` = :mreq,
				`mod_fcgid_umask` = :umask,
				`fpm_slowlog` = :fpmslow,
				`fpm_reqterm` = :fpmreqterm,
				`fpm_reqslow` = :fpmreqslow,
				`phpsettings` = :phpsettings,
				`fpmsettingid` = :fpmsettingid,
				`pass_authorizationheader` = :fpmpassauth,
				`override_fpmconfig` = :ofc,
				`pm` = :pm,
				`max_children` = :max_children,
				`start_servers` = :start_servers,
				`min_spare_servers` = :min_spare_servers,
				`max_spare_servers` = :max_spare_servers,
				`max_requests` = :max_requests,
				`idle_timeout` = :idle_timeout,
				`limit_extensions` = :limit_extensions
				WHERE `id` = :id
			");
			$upd_data = [
				'desc' => $description,
				'binary' => $binary,
				'fext' => $file_extensions,
				'starter' => $mod_fcgid_starter,
				'mreq' => $mod_fcgid_maxrequests,
				'umask' => $mod_fcgid_umask,
				'fpmslow' => $fpm_enableslowlog,
				'fpmreqterm' => $fpm_reqtermtimeout,
				'fpmreqslow' => $fpm_reqslowtimeout,
				'phpsettings' => $phpsettings,
				'fpmsettingid' => $fpm_config_id,
				'fpmpassauth' => $pass_authorizationheader,
				'ofc' => $override_fpmconfig,
				'pm' => $pmanager,
				'max_children' => $max_children,
				'start_servers' => $start_servers,
				'min_spare_servers' => $min_spare_servers,
				'max_spare_servers' => $max_spare_servers,
				'max_requests' => $max_requests,
				'idle_timeout' => $idle_timeout,
				'limit_extensions' => $limit_extensions,
				'id' => $id
			];
			Database::pexecute($upd_stmt, $upd_data, true, true);

			Cronjob::inserttask(TaskId::REBUILD_VHOST);
			$this->logger()->logAction(FroxlorLogger::ADM_ACTION, LOG_NOTICE, "[API] php setting with description '" . $description . "' has been updated by '" . $this->getUserDetail('loginname') . "'");

			$result = $this->apiCall('PhpSettings.get', [
				'id' => $id
			]);

			$this->addForAllCustomers($allow_all_customers, $id);
			return $this->response($result);
		}
		throw new Exception("Not allowed to execute given command.", 403);
	}

	/**
	 * delete a php-setting entry by id
	 *
	 * @param int $id
	 *            php-settings-id
	 *
	 * @access admin
	 * @return string json-encoded array
	 * @throws Exception
	 */
	public function delete()
	{
		if ($this->isAdmin() && $this->getUserDetail('change_serversettings') == 1) {
			$id = $this->getParam('id');

			$result = $this->apiCall('PhpSettings.get', [
				'id' => $id
			]);

			if ((Settings::Get('system.mod_fcgid') == '1' && Settings::Get('system.mod_fcgid_defaultini_ownvhost') == $id) || (Settings::Get('phpfpm.enabled') == '1' && Settings::Get('phpfpm.vhost_defaultini') == $id)) {
				Response::standardError('cannotdeletehostnamephpconfig', '', true);
			}

			if ((Settings::Get('system.mod_fcgid') == '1' && Settings::Get('system.mod_fcgid_defaultini') == $id) || (Settings::Get('phpfpm.enabled') == '1' && Settings::Get('phpfpm.defaultini') == $id)) {
				Response::standardError('cannotdeletedefaultphpconfig', '', true);
			}

			// set php-config to default for all domains using the
			// config that is to be deleted
			$upd_stmt = Database::prepare("
				UPDATE `" . TABLE_PANEL_DOMAINS . "` SET
				`phpsettingid` = '1' WHERE `phpsettingid` = :id
			");
			Database::pexecute($upd_stmt, [
				'id' => $id
			], true, true);

			$del_stmt = Database::prepare("
				DELETE FROM `" . TABLE_PANEL_PHPCONFIGS . "` WHERE `id` = :id
			");
			Database::pexecute($del_stmt, [
				'id' => $id
			], true, true);

			Cronjob::inserttask(TaskId::REBUILD_VHOST);
			$this->logger()->logAction(FroxlorLogger::ADM_ACTION, LOG_WARNING, "[API] php setting '" . $result['description'] . "' has been deleted by '" . $this->getUserDetail('loginname') . "'");
			return $this->response($result);
		}
		throw new Exception("Not allowed to execute given command.", 403);
	}
}
