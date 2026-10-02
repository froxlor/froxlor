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

namespace Froxlor\Cron\Dns;

use Froxlor\Database\Database;
use Froxlor\Domain\Domain;
use Froxlor\FileDir;
use Froxlor\FroxlorLogger;
use Froxlor\PhpHelper;
use Froxlor\Settings;
use PDO;

/**
 * Class DnsBase
 *
 * Base class for all DNS server configs
 */
abstract class DnsBase
{

	protected $logger = false;

	protected $ns = [];

	protected $mx = [];

	protected $axfr = [];

	public function __construct($logger)
	{
		$this->logger = $logger;

		$known_ns_ips = [];
		if (Settings::Get('system.nameservers') != '') {
			$nameservers = explode(',', Settings::Get('system.nameservers'));
			foreach ($nameservers as $nameserver) {
				$nameserver = trim($nameserver);
				// DNS servers might be multi homed; allow transfer from all ip
				// addresses of the DNS server
				$nameserver_ips = PhpHelper::gethostbynamel6($nameserver);
				// append dot to hostname
				if (substr($nameserver, -1, 1) != '.') {
					$nameserver .= '.';
				}
				// ignore invalid responses
				if (!is_array($nameserver_ips)) {
					// act like \Froxlor\PhpHelper::gethostbynamel6() and return unmodified hostname on error
					$nameserver_ips = [
						$nameserver
					];
				} else {
					$known_ns_ips = array_merge($known_ns_ips, $nameserver_ips);
				}
				$this->ns[] = [
					'hostname' => $nameserver,
					'ips' => $nameserver_ips
				];
			}
		}

		if (Settings::Get('system.mxservers') != '') {
			$mxservers = explode(',', Settings::Get('system.mxservers'));
			foreach ($mxservers as $mxserver) {
				if (substr($mxserver, -1, 1) != '.') {
					$mxserver .= '.';
				}
				$this->mx[] = $mxserver;
			}
		}

		// AXFR server #100
		if (Settings::Get('system.axfrservers') != '') {
			$axfrservers = explode(',', Settings::Get('system.axfrservers'));
			foreach ($axfrservers as $axfrserver) {
				if (!in_array(trim($axfrserver), $known_ns_ips)) {
					$this->axfr[] = trim($axfrserver);
				}
			}
		}
	}

	abstract public function writeConfigs();

	public function reloadDaemon()
	{
		// reload DNS daemon
		$cmd = Settings::Get('system.bindreload_command');
		$cmdStatus = 1;
		FileDir::safe_exec(escapeshellcmd($cmd), $cmdStatus);
		if ($cmdStatus === 0) {
			$this->logger->logAction(FroxlorLogger::CRON_ACTION, LOG_INFO, Settings::Get('system.dns_server') . ' daemon reloaded');
		} else {
			$this->logger->logAction(FroxlorLogger::CRON_ACTION, LOG_ERR, 'Error while running `' . $cmd . '`: exit code (' . $cmdStatus . ') - please check your system logs');
		}
	}

	protected function getDomainList()
	{
		$result_domains_stmt = Database::query("
			SELECT
				`d`.`id`,
				`d`.`domain`,
				`d`.`isemaildomain`,
				`d`.`iswildcarddomain`,
				`d`.`wwwserveralias`,
				`d`.`customerid`,
				`d`.`zonefile`,
				`d`.`bindserial`,
				`d`.`dkim`,
				`d`.`dkim_id`,
				`d`.`dkim_pubkey`,
				`c`.`loginname`,
				`c`.`guid`
			FROM
				`" . TABLE_PANEL_DOMAINS . "` `d`
			LEFT JOIN `" . TABLE_PANEL_CUSTOMERS . "` `c` USING(`customerid`)
			WHERE
				`d`.`isbinddomain` = '1'
			ORDER BY
				LENGTH(`d`.`domain`), `d`.`domain` ASC
		");

		$domains = [];
		// don't use fetchall() to be able to set the first column to the domain id and use it later on to set the rows'
		// array of direct children without having to search the outer array
		while ($domain = $result_domains_stmt->fetch(PDO::FETCH_ASSOC)) {
			$domains[$domain["id"]] = $domain;
		}

		// frolxor-hostname (#1090)
		if (Settings::get('system.dns_createhostnameentry') == 1) {
			$hostname_arr = [
				'id' => 'none',
				'domain' => Settings::Get('system.hostname'),
				'isbinddomain' => '1',
				'isemaildomain' => Settings::Get('system.dns_createmailentry'),
				'email_only' => '0',
				'customerid' => 'none',
				'loginname' => 'froxlor.panel',
				'bindserial' => date('Ymd') . '00',
				'dkim' => '0',
				'iswildcarddomain' => '1',
				'zonefile' => '',
				'froxlorhost' => '1'
			];
			$domains[0] = $hostname_arr;
		}

		if (empty($domains)) {
			return null;
		}

		// collect domain IDs of direct child domains as arrays in ['children'] column
		foreach (array_keys($domains) as $key) {
			if (!isset($domains[$key]['children'])) {
				$domains[$key]['children'] = [];
			}
			if (!isset($domains[$key]['is_child'])) {
				$domains[$key]['is_child'] = false;
			}
			$children = Domain::getMainSubdomainIds($key);
			if (count($children) > 0) {
				foreach ($children as $child) {
					if (isset($domains[$child])) {
						$domains[$key]['children'][] = $domains[$child]['id'];
						$domains[$child]['is_child'] = true;
					}
				}
			}
		}

		$this->logger->logAction(FroxlorLogger::CRON_ACTION, LOG_DEBUG, str_pad('domId', 9, ' ') . str_pad('domain', 40, ' ') . "list of child domain ids");
		foreach ($domains as $domain) {
			$logLine = str_pad($domain['id'], 9, ' ') . str_pad($domain['domain'], 40, ' ') . join(', ', $domain['children']);
			$this->logger->logAction(FroxlorLogger::CRON_ACTION, LOG_DEBUG, $logLine);
		}

		return $domains;
	}
}
