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

namespace Froxlor\Domain;

use Froxlor\Cron\Http\LetsEncrypt\AcmeSh;
use Froxlor\Database\Database;
use Froxlor\FileDir;
use Froxlor\FroxlorLogger;
use Froxlor\Settings;
use PDO;

class Domain
{

	/**
	 * return all ip addresses associated with given domain,
	 * returns all ips if domain-id = 0 (froxlor.vhost)
	 *
	 * @param int $domain_id
	 * @return array
	 * @throws \Exception
	 */
	public static function getIpsOfDomain(int $domain_id = 0): array
	{
		if ($domain_id > 0) {
			$sel_stmt = Database::prepare("
				SELECT i.ip FROM `" . TABLE_PANEL_IPSANDPORTS . "` `i`
				LEFT JOIN `" . TABLE_DOMAINTOIP . "` `dip` ON dip.id_ipandports = i.id
				AND dip.id_domain = :domainid
				GROUP BY i.ip
			");
			$sel_param = [
				'domainid' => $domain_id
			];
		} else {
			// assuming froxlor.vhost (id = 0)
			$sel_stmt = Database::prepare("
				SELECT ip FROM `" . TABLE_PANEL_IPSANDPORTS . "`
				GROUP BY ip
			");
			$sel_param = [];
		}
		Database::pexecute($sel_stmt, $sel_param);
		$result = [];
		while ($ip = $sel_stmt->fetch(PDO::FETCH_ASSOC)) {
			$result[] = $ip['ip'];
		}
		return $result;
	}

	/**
	 * return an array of all enabled redirect-codes
	 *
	 * @return array array of enabled redirect-codes
	 */
	public static function getRedirectCodesArray(): array
	{
		$sql = "SELECT * FROM `" . TABLE_PANEL_REDIRECTCODES . "` WHERE `enabled` = '1' ORDER BY `id` ASC";
		$result_stmt = Database::query($sql);

		$codes = [];
		while ($rc = $result_stmt->fetch(PDO::FETCH_ASSOC)) {
			$codes[] = $rc;
		}

		return $codes;
	}

	/**
	 * returns the redirect-code for a given
	 * domain-id
	 *
	 * @param int $domainid id of the domain
	 *
	 * @return string redirect-code
	 * @throws \Exception
	 */
	public static function getDomainRedirectCode(int $domainid = 0): string
	{
		// get system default
		$default = '301';
		if (Settings::Get('customredirect.enabled') == '1') {
			$all_codes = self::getRedirectCodes(false);
			$_default = $all_codes[Settings::Get('customredirect.default')];
			$default = ($_default == '---') ? $default : $_default;
		}
		$code = $default;
		if ($domainid > 0) {
			$result_stmt = Database::prepare("
				SELECT `r`.`code` as `redirect`
				FROM `" . TABLE_PANEL_REDIRECTCODES . "` `r`, `" . TABLE_PANEL_DOMAINREDIRECTS . "` `rc`
				WHERE `r`.`id` = `rc`.`rid` and `rc`.`did` = :domainid
			");
			$result = Database::pexecute_first($result_stmt, [
				'domainid' => $domainid
			]);

			if (is_array($result) && isset($result['redirect'])) {
				$code = ($result['redirect'] == '---') ? $default : $result['redirect'];
			}
		}
		return $code;
	}

	/**
	 * return an array of all enabled redirect-codes
	 * for the settings form
	 *
	 * @param bool $add_desc optional, default true, add the code-description
	 *
	 * @return array array of enabled redirect-codes
	 */
	public static function getRedirectCodes(bool $add_desc = true): array
	{
		$sql = "SELECT * FROM `" . TABLE_PANEL_REDIRECTCODES . "` WHERE `enabled` = '1' ORDER BY `id` ASC";
		$result_stmt = Database::query($sql);

		$codes = [];
		while ($rc = $result_stmt->fetch(PDO::FETCH_ASSOC)) {
			$codes[$rc['id']] = $rc['code'];
			if ($add_desc) {
				$codes[$rc['id']] .= ' (' . lng('redirect_desc.' . $rc['desc']) . ')';
			}
		}

		return $codes;
	}

	/**
	 * returns the redirect-id for a given
	 * domain-id
	 *
	 * @param int $domainid id of the domain
	 *
	 * @return int redirect-code-id
	 * @throws \Exception
	 */
	public static function getDomainRedirectId(int $domainid = 0): int
	{
		$code = 1;
		if ($domainid > 0) {
			$result_stmt = Database::prepare("
				SELECT `r`.`id` as `redirect`
				FROM `" . TABLE_PANEL_REDIRECTCODES . "` `r`, `" . TABLE_PANEL_DOMAINREDIRECTS . "` `rc`
				WHERE `r`.`id` = `rc`.`rid` and `rc`.`did` = :domainid
			");
			$result = Database::pexecute_first($result_stmt, [
				'domainid' => $domainid
			]);

			if ($result && isset($result['redirect'])) {
				$code = (int)$result['redirect'];
			}
		}
		return $code;
	}

	/**
	 * adds a redirect-code for a domain
	 *
	 * @param int $domainid id of the domain to add the code for
	 * @param int $redirect selected redirect-id
	 *
	 * @return null
	 * @throws \Exception
	 */
	public static function addRedirectToDomain(int $domainid = 0, int $redirect = 1)
	{
		if ($domainid > 0) {
			$ins_stmt = Database::prepare("
				INSERT INTO `" . TABLE_PANEL_DOMAINREDIRECTS . "` SET `rid` = :rid, `did` = :did
			");
			Database::pexecute($ins_stmt, [
				'rid' => $redirect,
				'did' => $domainid
			]);
		}
	}

	/**
	 * updates the redirect-code of a domain
	 * if redirect-code is false, nothing happens
	 *
	 * @param int $domainid id of the domain to update
	 * @param int $redirect selected redirect-id
	 *
	 * @return null
	 * @throws \Exception
	 */
	public static function updateRedirectOfDomain(int $domainid = 0, int $redirect = 0)
	{
		if (!$redirect) {
			return;
		}

		if ($domainid > 0) {
			$del_stmt = Database::prepare("
				DELETE FROM `" . TABLE_PANEL_DOMAINREDIRECTS . "` WHERE `did` = :domainid
			");
			Database::pexecute($del_stmt, [
				'domainid' => $domainid
			]);

			$ins_stmt = Database::prepare("
				INSERT INTO `" . TABLE_PANEL_DOMAINREDIRECTS . "` SET `rid` = :rid, `did` = :did
			");
			Database::pexecute($ins_stmt, [
				'rid' => $redirect,
				'did' => $domainid
			]);
		}
	}

	/**
	 * get ids of domains that are main domains but a subdomain of another main domain (for DNS)
	 *
	 * @param int $id main-domain to check
	 *
	 * @return array
	 * @throws \Exception
	 */
	public static function getMainSubdomainIds(int $id): array
	{
		$result_stmt = Database::prepare("
			SELECT id
			FROM `" . TABLE_PANEL_DOMAINS . "`
			WHERE
			isbinddomain = 1 AND
			domain LIKE CONCAT('%.', ( SELECT d.domain FROM `" . TABLE_PANEL_DOMAINS . "` AS d WHERE d.id = :id ))
		");
		Database::pexecute($result_stmt, [
			'id' => $id
		]);
		$result = [];
		while ($entry = $result_stmt->fetch(PDO::FETCH_ASSOC)) {
			$result[] = $entry['id'];
		}
		return $result;
	}

	/**
	 * Check whether a given domain has an ssl-ip/port assigned
	 *
	 * @param int $domainid
	 *
	 * @return bool
	 * @throws \Exception
	 */
	public static function domainHasSslIpPort(int $domainid): bool
	{
		$result_stmt = Database::prepare("
			SELECT `dt`.* FROM `" . TABLE_DOMAINTOIP . "` `dt`, `" . TABLE_PANEL_IPSANDPORTS . "` `iap`
			WHERE `dt`.`id_ipandports` = `iap`.`id` AND `iap`.`ssl` = '1' AND `dt`.`id_domain` = :domainid;");
		Database::pexecute($result_stmt, [
			'domainid' => $domainid
		]);
		$result = $result_stmt->fetch(PDO::FETCH_ASSOC);

		if ($result && isset($result['id_ipandports'])) {
			return true;
		}
		return false;
	}

	/**
	 * returns true or false whether a given domain id
	 * is the std-subdomain of a customer
	 *
	 * @param int $did domain-id
	 *
	 * @return bool
	 * @throws \Exception
	 */
	public static function isCustomerStdSubdomain(int $did): bool
	{
		if ($did > 0) {
			$result_stmt = Database::prepare("
				SELECT `customerid` FROM `" . TABLE_PANEL_CUSTOMERS . "`
				WHERE `standardsubdomain` = :did
			");
			$result = Database::pexecute_first($result_stmt, [
				'did' => $did
			]);

			if ($result && isset($result['customerid'])) {
				return $result['customerid'] > 0;
			}
		}
		return false;
	}

	/**
	 * @param int $aliasDestinationDomainID
	 * @param FroxlorLogger $log
	 *
	 * @return void
	 * @throws \Exception
	 */
	public static function triggerLetsEncryptCSRForAliasDestinationDomain(
		int           $aliasDestinationDomainID,
		FroxlorLogger $log
	) {
		if ($aliasDestinationDomainID > 0) {
			$log->logAction(
				FroxlorLogger::ADM_ACTION,
				LOG_INFO,
				"LetsEncrypt CSR triggered for domain ID " . $aliasDestinationDomainID
			);
			$upd_stmt = Database::prepare("UPDATE
					`" . TABLE_PANEL_DOMAIN_SSL_SETTINGS . "`
				SET
					`validtodate` = null
				WHERE
					domainid = :domainid
			");
			Database::pexecute($upd_stmt, [
				'domainid' => $aliasDestinationDomainID
			]);
		}
	}

	/**
	 * @param string $domainname
	 * @return true
	 */
	public static function doLetsEncryptCleanUp(string $domainname): bool
	{
		// @ see \Froxlor\Cron\Http\LetsEncrypt\AcmeSh.php
		$acmesh = AcmeSh::getAcmeSh();
		if (file_exists($acmesh)) {
			$certificate_folder = AcmeSh::getWorkingDirFromEnv($domainname);
			$certificate_ecc_folder = AcmeSh::getWorkingDirFromEnv($domainname, true);
			if (file_exists($certificate_folder) || file_exists($certificate_ecc_folder)) {
				$params = " --remove -d " . $domainname;
				if (file_exists($certificate_ecc_folder)) {
					$params .= " --ecc";
				}
				// run remove command
				FileDir::safe_exec($acmesh . $params);
				// remove certificates directory
				if (file_exists($certificate_folder)) {
					FileDir::safe_exec('rm -rf ' . $certificate_folder);
				} elseif (file_exists($certificate_ecc_folder)) {
					FileDir::safe_exec('rm -rf ' . $certificate_ecc_folder);
				}
			}
		}
		return true;
	}

	/**
	 * checks give path for security issues
	 * and returns a string that can be appended
	 * to a line for an open_basedir directive
	 *
	 * @param string $path the path to check and append
	 * @param bool $first if true, no ':' will be prefixed to the path
	 *
	 * @return string
	 * @throws \Exception
	 */
	public static function appendOpenBasedirPath(string $path = '', bool $first = false): string
	{
		if ($path != '' && $path != '/' && (!preg_match("#^/dev#i", $path) || preg_match("#^/dev/urandom#i",
					$path)) && !preg_match("#^/proc#i", $path) && !preg_match("#^/etc#i",
				$path) && !preg_match("#^/sys#i", $path) && !preg_match("#:#", $path)) {
			if (preg_match("#^/dev/urandom#i", $path)) {
				$path = FileDir::makeCorrectFile($path);
			} else {
				$path = FileDir::makeCorrectDir($path);
			}

			// check for php-version that requires the trailing
			// slash to be removed as it does not allow the usage
			// of the sub-folders within the given folder, fixes #797
			if ((PHP_MINOR_VERSION == 2 && PHP_VERSION_ID >= 50216) || PHP_VERSION_ID >= 50304) {
				// check trailing slash
				if (substr($path, -1, 1) == '/') {
					// remove it
					$path = substr($path, 0, -1);
				}
			}

			if ($first) {
				return $path;
			}

			return ':' . $path;
		}
		return '';
	}
}
