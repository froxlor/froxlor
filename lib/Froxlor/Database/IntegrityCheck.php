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

namespace Froxlor\Database;

use Froxlor\FroxlorLogger;
use Froxlor\Settings;
use PDO;

class IntegrityCheck
{

	// Store all available checks
	public $available = [];

	// logger object
	private $log = null;

	/**
	 * Constructor
	 * Parses all available checks into $this->available
	 */
	public function __construct()
	{
		global $userinfo;
		if (!isset($userinfo) || !is_array($userinfo)) {
			$userinfo = [
				'loginname' => 'integrity-check'
			];
		}
		$this->log = FroxlorLogger::getInstanceOf($userinfo);
		$this->available = get_class_methods($this);
		unset($this->available[array_search('__construct', $this->available)]);
		unset($this->available[array_search('checkAll', $this->available)]);
		unset($this->available[array_search('fixAll', $this->available)]);
		sort($this->available);
	}

	/**
	 * Check all occurring integrity problems at once
	 */
	public function checkAll()
	{
		$integrityok = true;
		foreach ($this->available as $check) {
			$integrityok = $this->$check() ? $integrityok : false;
		}
		return $integrityok;
	}

	/**
	 * Fix all occurring integrity problems at once with default settings
	 */
	public function fixAll()
	{
		$integrityok = true;
		foreach ($this->available as $check) {
			$integrityok = $this->$check(true) ? $integrityok : false;
		}
		return $integrityok;
	}

	/**
	 * check whether the froxlor database and its tables are in utf-8 character-set
	 *
	 * @param bool $fix fix db charset/collation if not utf8
	 *
	 * @return bool
	 * @throws \Exception
	 */
	public function databaseCharset(bool $fix = false): bool
	{
		// get character-set
		$cs_stmt = Database::prepare('SELECT default_character_set_name FROM information_schema.SCHEMATA WHERE schema_name = :dbname');
		$resp = Database::pexecute_first($cs_stmt, [
			'dbname' => Database::getDbName()
		]);
		$charset = $resp['default_character_set_name'] ?? null;
		if (!empty($charset) && substr(strtolower($charset), 0, 4) != 'utf8') {
			$this->log->logAction(FroxlorLogger::ADM_ACTION, LOG_NOTICE,
				"database charset seems to be different from UTF-8, integrity-check can fix that");
			if ($fix) {
				// fix database
				Database::query('ALTER DATABASE `' . Database::getDbName() . '` CHARACTER SET utf8 COLLATE utf8_general_ci');
				// fix all tables
				$handle = Database::query('SHOW FULL TABLES WHERE Table_type != "VIEW"');
				while ($row = $handle->fetch(PDO::FETCH_BOTH)) {
					$table = $row[0];
					Database::query('ALTER TABLE `' . $table . '` CONVERT TO CHARACTER SET utf8 COLLATE utf8_general_ci;');
				}
				$this->log->logAction(FroxlorLogger::ADM_ACTION, LOG_WARNING,
					"database charset was different from UTF-8, integrity-check fixed that");
			} else {
				return false;
			}
		}

		if ($fix) {
			return $this->databaseCharset();
		}
		return true;
	}

	/**
	 * Check the integrity of the domain to ip/port - association
	 *
	 * @param bool $fix fix everything found directly
	 *
	 * @return bool
	 * @throws \Exception
	 */
	public function domainIpTable(bool $fix = false): bool
	{
		$ips = [];
		$domains = [];
		$ipstodomains = [];
		$admips = [];

		if ($fix) {
			// Prepare insert / delete statement for the fixes
			$del_stmt = Database::prepare("
				DELETE FROM `" . TABLE_DOMAINTOIP . "`
				WHERE `id_domain` = :domainid AND `id_ipandports` = :ipandportid ");
			$ins_stmt = Database::prepare("
				INSERT INTO `" . TABLE_DOMAINTOIP . "`
				SET `id_domain` = :domainid, `id_ipandports` = :ipandportid ");

			// Cache all IPs the admins have assigned
			$adm_stmt = Database::prepare("SELECT `adminid`, `ip` FROM `" . TABLE_PANEL_ADMINS . "` ORDER BY `adminid` ASC");
			Database::pexecute($adm_stmt);
			$default_ips = explode(',', Settings::Get('system.defaultip'));
			$default_ssl_ips = explode(',', Settings::Get('system.defaultsslip'));
			while ($row = $adm_stmt->fetch(PDO::FETCH_ASSOC)) {
				if ($row['ip'] < 0 || is_null($row['ip']) || empty($row['ip'])) {
					// Admin uses default-IP
					$admips[$row['adminid']] = array_merge($default_ips, $default_ssl_ips);
				} else {
					$admips[$row['adminid']] = [
						$row['ip']
					];
				}
			}
		}

		// Cache all available ip/port - combinations
		$result_stmt = Database::prepare("SELECT `id`, `ip`, `port` FROM `" . TABLE_PANEL_IPSANDPORTS . "` ORDER BY `id` ASC");
		Database::pexecute($result_stmt);
		while ($row = $result_stmt->fetch(PDO::FETCH_ASSOC)) {
			$ips[$row['id']] = $row['ip'] . ':' . $row['port'];
		}

		// Cache all configured domains
		$result_stmt = Database::prepare("SELECT `id`, `adminid` FROM `" . TABLE_PANEL_DOMAINS . "` ORDER BY `id` ASC");
		Database::pexecute($result_stmt);
		while ($row = $result_stmt->fetch(PDO::FETCH_ASSOC)) {
			$domains[$row['id']] = $row['adminid'];
		}

		// Check if every domain to ip/port - association is valid in TABLE_DOMAINTOIP
		$result_stmt = Database::prepare("SELECT `id_domain`, `id_ipandports` FROM `" . TABLE_DOMAINTOIP . "`");
		Database::pexecute($result_stmt);
		while ($row = $result_stmt->fetch(PDO::FETCH_ASSOC)) {
			if (!array_key_exists($row['id_ipandports'], $ips)) {
				if ($fix) {
					Database::pexecute($del_stmt, [
						'domainid' => $row['id_domain'],
						'ipandportid' => $row['id_ipandports']
					]);
					$this->log->logAction(FroxlorLogger::ADM_ACTION, LOG_WARNING,
						"found an ip/port-id in domain <> ip table which does not exist, integrity check fixed this");
				} else {
					$this->log->logAction(FroxlorLogger::ADM_ACTION, LOG_NOTICE,
						"found an ip/port-id in domain <> ip table which does not exist, integrity check can fix this");
					return false;
				}
			}
			if (!array_key_exists($row['id_domain'], $domains)) {
				if ($fix) {
					Database::pexecute($del_stmt, [
						'domainid' => $row['id_domain'],
						'ipandportid' => $row['id_ipandports']
					]);
					$this->log->logAction(FroxlorLogger::ADM_ACTION, LOG_WARNING,
						"found a domain-id in domain <> ip table which does not exist, integrity check fixed this");
				} else {
					$this->log->logAction(FroxlorLogger::ADM_ACTION, LOG_NOTICE,
						"found a domain-id in domain <> ip table which does not exist, integrity check can fix this");
					return false;
				}
			}
			// Save one IP/Port combination per domain, so we know, if one domain is missing an IP
			$ipstodomains[$row['id_domain']] = $row['id_ipandports'];
		}

		// Check that all domains have at least one IP/Port combination
		foreach ($domains as $domainid => $adminid) {
			if (!array_key_exists($domainid, $ipstodomains)) {
				if ($fix) {
					foreach ($admips[$adminid] as $defaultip) {
						Database::pexecute($ins_stmt, [
							'domainid' => $domainid,
							'ipandportid' => $defaultip
						]);
					}
					$this->log->logAction(FroxlorLogger::ADM_ACTION, LOG_WARNING,
						"found a domain-id with no entry in domain <> ip table, integrity check fixed this");
				} else {
					$this->log->logAction(FroxlorLogger::ADM_ACTION, LOG_NOTICE,
						"found a domain-id with no entry in domain <> ip table, integrity check can fix this");
					return false;
				}
			}
		}

		if ($fix) {
			return $this->domainIpTable();
		}
		return true;
	}

	/**
	 * Check if all subdomains have ssl-redirect = 0 if domain has no ssl-port
	 *
	 * @param bool $fix fix everything found directly
	 *
	 * @return bool
	 * @throws \Exception
	 */
	public function subdomainSslRedirect(bool $fix = false): bool
	{
		$ips = [];
		$parentdomains = [];
		$subdomains = [];

		if ($fix) {
			// Prepare update statement for the fixes
			$upd_stmt = Database::prepare("
				UPDATE `" . TABLE_PANEL_DOMAINS . "`
				SET `ssl_redirect` = 0 WHERE `parentdomainid` = :domainid");
		}

		// Cache all ssl ip/port - combinations
		$result_stmt = Database::prepare("SELECT `id`, `ip`, `port` FROM `" . TABLE_PANEL_IPSANDPORTS . "` WHERE `ssl` = 1 ORDER BY `id` ASC");
		Database::pexecute($result_stmt);
		while ($row = $result_stmt->fetch(PDO::FETCH_ASSOC)) {
			$ips[$row['id']] = $row['ip'] . ':' . $row['port'];
		}

		// Cache all configured domains
		$result_stmt = Database::prepare("SELECT `id`, `parentdomainid`, `ssl_redirect` FROM `" . TABLE_PANEL_DOMAINS . "` ORDER BY `id` ASC");
		$ip_stmt = Database::prepare("SELECT `id_domain`, `id_ipandports` FROM `" . TABLE_DOMAINTOIP . "` WHERE `id_domain` = :domainid");
		Database::pexecute($result_stmt);
		while ($row = $result_stmt->fetch(PDO::FETCH_ASSOC)) {
			if ($row['parentdomainid'] == 0) {
				// All parentdomains by default have no ssl - ip/port
				$parentdomains[$row['id']] = false;
				Database::pexecute($ip_stmt, [
					'domainid' => $row['id']
				]);
				while ($iprow = $ip_stmt->fetch(PDO::FETCH_ASSOC)) {
					// If the parentdomain has an ip/port assigned which we know is SSL enabled, set the parentdomain to "true"
					if (array_key_exists($iprow['id_ipandports'], $ips)) {
						$parentdomains[$row['id']] = true;
					}
				}
			} elseif ($row['ssl_redirect'] == 1) {
				// All subdomains with enabled ssl_redirect enabled are stored
				if (!isset($subdomains[$row['parentdomainid']])) {
					$subdomains[$row['parentdomainid']] = [];
				}
				$subdomains[$row['parentdomainid']][] = $row['id'];
			}
		}

		// Check if every parentdomain with enabled ssl_redirect as SSL enabled
		foreach ($parentdomains as $id => $sslavailable) {
			// This parentdomain has no subdomains
			if (!isset($subdomains[$id])) {
				continue;
			}
			// This parentdomain has SSL enabled, doesn't matter what status the subdomains have
			if ($sslavailable) {
				continue;
			}

			// At this point only parentdomains reside which have ssl_redirect enabled subdomains
			if ($fix) {
				// We make a blanket update to all subdomains of this parentdomain, doesn't matter which one is wrong, all have to be disabled
				Database::pexecute($upd_stmt, [
					'domainid' => $id
				]);
				$this->log->logAction(FroxlorLogger::ADM_ACTION, LOG_WARNING,
					"found a subdomain with ssl_redirect=1 but parent-domain has ssl=0, integrity check fixed this");
			} else {
				// It's just the check, let the function fail
				$this->log->logAction(FroxlorLogger::ADM_ACTION, LOG_NOTICE,
					"found a subdomain with ssl_redirect=1 but parent-domain has ssl=0, integrity check can fix this");
				return false;
			}
		}

		if ($fix) {
			return $this->subdomainSslRedirect();
		}
		return true;
	}

	/**
	 * Check if all subdomain have letsencrypt = 0 if domain has no ssl-port
	 *
	 * @param bool $fix fix everything found directly
	 *
	 * @return bool
	 * @throws \Exception
	 */
	public function subdomainLetsencrypt(bool $fix = false): bool
	{
		$ips = [];
		$parentdomains = [];
		$subdomains = [];

		if ($fix) {
			// Prepare update statement for the fixes
			$upd_stmt = Database::prepare("
				UPDATE `" . TABLE_PANEL_DOMAINS . "`
				SET `letsencrypt` = 0 WHERE `parentdomainid` = :domainid");
		}

		// Cache all ssl ip/port - combinations
		$result_stmt = Database::prepare("SELECT `id`, `ip`, `port` FROM `" . TABLE_PANEL_IPSANDPORTS . "` WHERE `ssl` = 1 ORDER BY `id` ASC");
		Database::pexecute($result_stmt);
		while ($row = $result_stmt->fetch(PDO::FETCH_ASSOC)) {
			$ips[$row['id']] = $row['ip'] . ':' . $row['port'];
		}

		// Cache all configured domains
		$result_stmt = Database::prepare("SELECT `id`, `parentdomainid`, `letsencrypt` FROM `" . TABLE_PANEL_DOMAINS . "` ORDER BY `id` ASC");
		$ip_stmt = Database::prepare("SELECT `id_domain`, `id_ipandports` FROM `" . TABLE_DOMAINTOIP . "` WHERE `id_domain` = :domainid");
		Database::pexecute($result_stmt);
		while ($row = $result_stmt->fetch(PDO::FETCH_ASSOC)) {
			if ($row['parentdomainid'] == 0) {
				// All parentdomains by default have no ssl - ip/port
				$parentdomains[$row['id']] = false;
				Database::pexecute($ip_stmt, [
					'domainid' => $row['id']
				]);
				while ($iprow = $ip_stmt->fetch(PDO::FETCH_ASSOC)) {
					// If the parentdomain has an ip/port assigned which we know is SSL enabled, set the parentdomain to "true"
					if (array_key_exists($iprow['id_ipandports'], $ips)) {
						$parentdomains[$row['id']] = true;
					}
				}
			} elseif ($row['letsencrypt'] == 1) {
				// All subdomains with enabled letsencrypt enabled are stored
				if (!isset($subdomains[$row['parentdomainid']])) {
					$subdomains[$row['parentdomainid']] = [];
				}
				$subdomains[$row['parentdomainid']][] = $row['id'];
			}
		}

		// Check if every parentdomain with enabled letsencrypt as SSL enabled
		foreach ($parentdomains as $id => $sslavailable) {
			// This parentdomain has no subdomains
			if (!isset($subdomains[$id])) {
				continue;
			}
			// This parentdomain has SSL enabled, doesn't matter what status the subdomains have
			if ($sslavailable) {
				continue;
			}

			// At this point only parentdomains reside which have letsencrypt enabled subdomains
			if ($fix) {
				// We make a blanket update to all subdomains of this parentdomain, doesn't matter which one is wrong, all have to be disabled
				Database::pexecute($upd_stmt, [
					'domainid' => $id
				]);
				$this->log->logAction(FroxlorLogger::ADM_ACTION, LOG_WARNING,
					"found a subdomain with letsencrypt=1 but parent-domain has ssl=0, integrity check fixed this");
			} else {
				// It's just the check, let the function fail
				$this->log->logAction(FroxlorLogger::ADM_ACTION, LOG_NOTICE,
					"found a subdomain with letsencrypt=1 but parent-domain has ssl=0, integrity check can fix this");
				return false;
			}
		}

		if ($fix) {
			return $this->subdomainLetsencrypt();
		}
		return true;
	}

	/**
	 * check whether the webserveruser is in
	 * the customers groups when fcgid / php-fpm is used
	 *
	 * @param bool $fix fix member/groups
	 *
	 * @return bool
	 * @throws \Exception
	 */
	public function webserverGroupMemberForFcgidPhpFpm(bool $fix = false): bool
	{
		if (Settings::Get('system.mod_fcgid') == 0 && Settings::Get('phpfpm.enabled') == 0) {
			return true;
		}

		// get all customers that don't have the webserver-user in their group
		$cwg_stmt = Database::prepare("
	       SELECT `id` FROM `" . TABLE_FTP_GROUPS . "` WHERE NOT FIND_IN_SET(:webserveruser, `members`)
	    ");
		Database::pexecute($cwg_stmt, [
			'webserveruser' => Settings::Get('system.httpuser')
		]);

		if ($cwg_stmt->rowCount() > 0) {
			$this->log->logAction(FroxlorLogger::ADM_ACTION, LOG_NOTICE,
				"Customers are missing the webserver-user as group-member, integrity-check can fix that");
			if ($fix) {
				// prepare update statement
				$upd_stmt = Database::prepare("
	                UPDATE `" . TABLE_FTP_GROUPS . "` SET `members` = CONCAT(`members`, :additionaluser)
	                WHERE `id` = :id
	            ");
				$upd_data = [
					'additionaluser' => "," . Settings::Get('system.httpuser')
				];

				while ($cwg_row = $cwg_stmt->fetch()) {
					$upd_data['id'] = $cwg_row['id'];
					Database::pexecute($upd_stmt, $upd_data);
				}
				$this->log->logAction(FroxlorLogger::ADM_ACTION, LOG_NOTICE,
					"Customers were missing the webserver-user as group-member, integrity-check fixed that");
			} else {
				return false;
			}
		}

		if ($fix) {
			return $this->webserverGroupMemberForFcgidPhpFpm();
		}
		return true;
	}

	/**
	 * check whether the local froxlor user is in
	 * the customers groups when fcgid / php-fpm and
	 * fcgid/fpm in froxlor vhost is used
	 *
	 * @param bool $fix fix member/groups
	 *
	 * @return bool
	 * @throws \Exception
	 */
	public function froxlorLocalGroupMemberForFcgidPhpFpm(bool $fix = false): bool
	{
		if (Settings::Get('system.mod_fcgid') == 0 && Settings::Get('phpfpm.enabled') == 0) {
			return true;
		}

		if (Settings::get('system.mod_fcgid') == 1) {
			if (Settings::get('system.mod_fcgid_ownvhost') == 0) {
				return true;
			} else {
				$localuser = Settings::Get('system.mod_fcgid_httpuser');
			}
		}

		if (Settings::get('phpfpm.enabled') == 1) {
			if (Settings::get('phpfpm.enabled_ownvhost') == 0) {
				return true;
			} else {
				$localuser = Settings::Get('phpfpm.vhost_httpuser');
			}
		}

		// get all customers that don't have the webserver-user in their group
		$cwg_stmt = Database::prepare("
	       SELECT `id` FROM `" . TABLE_FTP_GROUPS . "` WHERE NOT FIND_IN_SET(:localuser, `members`)
	    ");
		Database::pexecute($cwg_stmt, [
			'localuser' => $localuser
		]);

		if ($cwg_stmt->rowCount() > 0) {
			$this->log->logAction(FroxlorLogger::ADM_ACTION, LOG_NOTICE,
				"Customers are missing the local froxlor-user as group-member, integrity-check can fix that");
			if ($fix) {
				// prepare update statement
				$upd_stmt = Database::prepare("
	                UPDATE `" . TABLE_FTP_GROUPS . "` SET `members` = CONCAT(`members`, :additionaluser)
	                WHERE `id` = :id
	            ");
				$upd_data = [
					'additionaluser' => "," . $localuser
				];

				while ($cwg_row = $cwg_stmt->fetch()) {
					$upd_data['id'] = $cwg_row['id'];
					Database::pexecute($upd_stmt, $upd_data);
				}
				$this->log->logAction(FroxlorLogger::ADM_ACTION, LOG_NOTICE,
					"Customers were missing the local froxlor-user as group-member, integrity-check fixed that");
			} else {
				return false;
			}
		}

		if ($fix) {
			return $this->froxlorLocalGroupMemberForFcgidPhpFpm();
		}
		return true;
	}
}
