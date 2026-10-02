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

namespace Froxlor\Cron\Http;

use Froxlor\Database\Database;
use Froxlor\Domain\Domain;
use Froxlor\Settings;
use PDO;

class WebserverBase
{

	/**
	 * returns an array with all entries required for all
	 * webserver-vhost-configs
	 *
	 * @return array
	 */
	public static function getVhostsToCreate()
	{
		$query = "SELECT `d`.*, `pd`.`domain` AS `parentdomain`, `c`.`loginname`,
				`d`.`phpsettingid`, `c`.`adminid`, `c`.`guid`, `c`.`email`,
				`c`.`documentroot` AS `customerroot`, `c`.`deactivated` as `customer_deactivated`,
				`c`.`phpenabled` AS `phpenabled_customer`,
				`d`.`phpenabled` AS `phpenabled_vhost`,
				`a`.`email` as `admin_email`
				FROM `" . TABLE_PANEL_DOMAINS . "` `d`

				LEFT JOIN `" . TABLE_PANEL_CUSTOMERS . "` `c` USING(`customerid`)
				LEFT JOIN `" . TABLE_PANEL_DOMAINS . "` `pd` ON (`pd`.`id` = `d`.`parentdomainid`)
				LEFT JOIN `" . TABLE_PANEL_ADMINS . "` `a` ON (`a`.`adminid` = `c`.`adminid`)

				WHERE `d`.`aliasdomain` IS NULL AND `d`.`email_only` <> '1'
				ORDER BY `d`.`parentdomainid` DESC, `d`.`iswildcarddomain`, `d`.`domain` ASC;
		";

		$result_domains_stmt = Database::query($query);

		// prepare IP statement
		$ip_stmt = Database::prepare("
			SELECT `di`.`id_domain` , `p`.`ssl`, `p`.`ssl_cert_file`, `p`.`ssl_key_file`, `p`.`ssl_ca_file`, `p`.`ssl_cert_chainfile`
			FROM `" . TABLE_DOMAINTOIP . "` `di`, `" . TABLE_PANEL_IPSANDPORTS . "` `p`
			WHERE `p`.`id` = `di`.`id_ipandports`
			AND `di`.`id_domain` = :domainid
			AND `p`.`ssl` = '1'
		");

		// prepare fpm-config select query
		$fpm_sel_stmt = Database::prepare("
			SELECT f.id FROM `" . TABLE_PANEL_FPMDAEMONS . "` f
			LEFT JOIN `" . TABLE_PANEL_PHPCONFIGS . "` p ON p.fpmsettingid = f.id
			WHERE p.id = :phpconfigid
		");

		$domains = [];
		while ($domain = $result_domains_stmt->fetch(PDO::FETCH_ASSOC)) {
			// set whole domain
			$domains[$domain['domain']] = $domain;
			// set empty-defaults for non-ssl
			$domains[$domain['domain']]['ssl'] = '';
			$domains[$domain['domain']]['ssl_cert_file'] = '';
			$domains[$domain['domain']]['ssl_key_file'] = '';
			$domains[$domain['domain']]['ssl_ca_file'] = '';
			$domains[$domain['domain']]['ssl_cert_chainfile'] = '';

			// now, if the domain has an ssl ip/port assigned, get
			// the corresponding information from the db
			if (Domain::domainHasSslIpPort($domain['id'])) {
				$ssl_ip = Database::pexecute_first($ip_stmt, [
					'domainid' => $domain['id']
				]);

				// set ssl info for domain
				$domains[$domain['domain']]['ssl'] = '1';
				$domains[$domain['domain']]['ssl_cert_file'] = $ssl_ip['ssl_cert_file'];
				$domains[$domain['domain']]['ssl_key_file'] = $ssl_ip['ssl_key_file'];
				$domains[$domain['domain']]['ssl_ca_file'] = $ssl_ip['ssl_ca_file'];
				$domains[$domain['domain']]['ssl_cert_chainfile'] = $ssl_ip['ssl_cert_chainfile'];
			}

			// read fpm-config-id if using fpm
			if ((int)Settings::Get('phpfpm.enabled') == 1) {
				$fpm_config = Database::pexecute_first($fpm_sel_stmt, [
					'phpconfigid' => $domain['phpsettingid']
				]);
				if ($fpm_config) {
					$domains[$domain['domain']]['fpm_config_id'] = $fpm_config['id'];
				} else {
					// fallback
					$domains[$domain['domain']]['fpm_config_id'] = 1;
				}
			}
		}

		return $domains;
	}
}
