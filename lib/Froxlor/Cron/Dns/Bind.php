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

use Froxlor\Dns\Dns;
use Froxlor\FileDir;
use Froxlor\FroxlorLogger;
use Froxlor\Settings;
use Froxlor\Validate\Validate;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;

class Bind extends DnsBase
{

	private $bindconf_file = "";

	public function writeConfigs()
	{
		// tell the world what we are doing
		$this->logger->logAction(FroxlorLogger::CRON_ACTION, LOG_INFO, 'Task4 started - Rebuilding froxlor_bind.conf');

		// clean up
		$this->cleanZonefiles();

		// check for subfolder in bind-config-directory
		if (!file_exists(FileDir::makeCorrectDir(Settings::Get('system.bindconf_directory') . '/domains/'))) {
			$this->logger->logAction(FroxlorLogger::CRON_ACTION, LOG_NOTICE, 'mkdir ' . escapeshellarg(FileDir::makeCorrectDir(Settings::Get('system.bindconf_directory') . '/domains/')));
			FileDir::safe_exec('mkdir -p ' . escapeshellarg(FileDir::makeCorrectDir(Settings::Get('system.bindconf_directory') . '/domains/')));
		}

		$domains = $this->getDomainList();

		if (empty($domains)) {
			$this->logger->logAction(FroxlorLogger::CRON_ACTION, LOG_INFO, 'No domains found for nameserver-config, not creating any zones...');
			$this->bindconf_file = '';
		} else {
			$this->bindconf_file = '# ' . Settings::Get('system.bindconf_directory') . 'froxlor_bind.conf' . "\n" . '# Created ' . date('d.m.Y H:i') . "\n" . '# Do NOT manually edit this file, all changes will be deleted after the next domain change at the panel.' . "\n\n";
			foreach ($domains as $domain) {
				if ($domain['is_child']) {
					// domains that are subdomains to other main domains are handled by recursion within walkDomainList()
					continue;
				}
				$this->walkDomainList($domain, $domains);
			}
		}

		$bindconf_file_handler = fopen(FileDir::makeCorrectFile(Settings::Get('system.bindconf_directory') . '/froxlor_bind.conf'), 'w');
		fwrite($bindconf_file_handler, $this->bindconf_file);
		fclose($bindconf_file_handler);
		$this->logger->logAction(FroxlorLogger::CRON_ACTION, LOG_INFO, 'froxlor_bind.conf written');
		$this->reloadDaemon();
		$this->logger->logAction(FroxlorLogger::CRON_ACTION, LOG_INFO, 'Task4 finished');
	}

	private function cleanZonefiles()
	{
		$config_dir = FileDir::makeCorrectFile(Settings::Get('system.bindconf_directory') . '/domains/');

		$this->logger->logAction(FroxlorLogger::CRON_ACTION, LOG_INFO, 'Cleaning dns zone files from ' . $config_dir);

		// check directory
		if (@is_dir($config_dir)) {
			// create directory iterator
			$its = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($config_dir));

			// iterate through all subdirs, look for zone files and delete them
			foreach ($its as $it) {
				if ($it->isFile()) {
					// remove file
					FileDir::safe_exec('rm -f ' . escapeshellarg(FileDir::makeCorrectFile($its->getPathname())));
				}
			}
		}
	}

	private function walkDomainList($domain, $domains)
	{
		$zoneContent = '';
		$subzones = '';

		foreach ($domain['children'] as $child_domain_id) {
			$subzones .= $this->walkDomainList($domains[$child_domain_id], $domains);
		}

		if ($domain['zonefile'] == '') {
			// check for system-hostname
			$isFroxlorHostname = false;
			if (isset($domain['froxlorhost']) && $domain['froxlorhost'] == 1) {
				$isFroxlorHostname = true;
			}

			if (!$domain['is_child']) {
				$zoneContent = (string)Dns::createDomainZone(($domain['id'] == 'none') ? $domain : $domain['id'], $isFroxlorHostname);
				$domain['zonefile'] = 'domains/' . $domain['domain'] . '.zone';
				$zonefile_name = FileDir::makeCorrectFile(Settings::Get('system.bindconf_directory') . '/' . $domain['zonefile']);
				$zonefile_handler = fopen($zonefile_name, 'w');
				fwrite($zonefile_handler, $zoneContent . $subzones);
				fclose($zonefile_handler);
				$this->logger->logAction(FroxlorLogger::CRON_ACTION, LOG_INFO, '`' . $zonefile_name . '` written');
				$this->bindconf_file .= $this->generateDomainConfig($domain);
			} else {
				return (string)Dns::createDomainZone(($domain['id'] == 'none') ? $domain : $domain['id'], $isFroxlorHostname, true);
			}
		} else {
			$this->logger->logAction(FroxlorLogger::CRON_ACTION, LOG_INFO, 'Added zonefile ' . $domain['zonefile'] . ' for domain ' . $domain['domain'] . ' - Note that you will also have to handle ALL records for ALL subdomains.');
			$this->bindconf_file .= $this->generateDomainConfig($domain);
		}
	}

	private function generateDomainConfig($domain = [])
	{
		$this->logger->logAction(FroxlorLogger::CRON_ACTION, LOG_DEBUG, 'Generating dns config for ' . $domain['domain']);

		$bindconf_file = '# Domain ID: ' . $domain['id'] . ' - CustomerID: ' . $domain['customerid'] . ' - CustomerLogin: ' . $domain['loginname'] . "\n";
		$bindconf_file .= 'zone "' . $domain['domain'] . '" in {' . "\n";
		$bindconf_file .= '	type master;' . "\n";
		$bindconf_file .= '	file "' . FileDir::makeCorrectFile(Settings::Get('system.bindconf_directory') . '/' . $domain['zonefile']) . '";' . "\n";
		$bindconf_file .= '	allow-query { any; };' . "\n";

		if (count($this->ns) > 0 || count($this->axfr) > 0) {
			// open allow-transfer
			$bindconf_file .= '	allow-transfer {' . "\n";
			// put nameservers in allow-transfer
			if (count($this->ns) > 0) {
				foreach ($this->ns as $ns) {
					foreach ($ns["ips"] as $ip) {
						$ip = Validate::validate_ip2($ip, true, 'invalidip', true, true, true);
						if ($ip) {
							$bindconf_file .= '		' . $ip . ";\n";
						}
					}
				}
			}
			// AXFR server #100
			if (count($this->axfr) > 0) {
				foreach ($this->axfr as $axfrserver) {
					$bindconf_file .= '		' . $axfrserver . ';' . "\n";
				}
			}
			// close allow-transfer
			$bindconf_file .= '	};' . "\n";
		}

		$bindconf_file .= '};' . "\n";
		$bindconf_file .= "\n";

		return $bindconf_file;
	}
}
