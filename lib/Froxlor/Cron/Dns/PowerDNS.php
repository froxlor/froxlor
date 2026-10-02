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
use Froxlor\Dns\DnsZone;
use Froxlor\FroxlorLogger;
use Froxlor\Settings;
use PDO;

class PowerDNS extends DnsBase
{

	public function writeConfigs()
	{
		// tell the world what we are doing
		$this->logger->logAction(FroxlorLogger::CRON_ACTION, LOG_INFO, 'Task4 started - Refreshing DNS database');

		$domains = $this->getDomainList();

		// clean up
		$this->clearZoneTables($domains);

		if (empty($domains)) {
			$this->logger->logAction(FroxlorLogger::CRON_ACTION, LOG_INFO, 'No domains found for nameserver-config, not creating any zones...');
		} else {
			foreach ($domains as $domain) {
				if ($domain['is_child']) {
					// domains that are subdomains to other main domains are handled by recursion within walkDomainList()
					continue;
				}
				$this->walkDomainList($domain, $domains);
			}
		}
		$this->logger->logAction(FroxlorLogger::CRON_ACTION, LOG_INFO, 'PowerDNS database updated');
		$this->reloadDaemon();
		$this->logger->logAction(FroxlorLogger::CRON_ACTION, LOG_INFO, 'Task4 finished');
	}

	private function clearZoneTables($domains = null)
	{
		$this->logger->logAction(FroxlorLogger::CRON_ACTION, LOG_INFO, 'Cleaning dns zone entries from database');

		$pdns_domains_stmt = \Froxlor\Dns\PowerDNS::getDB()->prepare("SELECT `id`, `name` FROM `domains` WHERE `name` = :domain");

		$del_rec_stmt = \Froxlor\Dns\PowerDNS::getDB()->prepare("DELETE FROM `records` WHERE `domain_id` = :did");
		$del_meta_stmt = \Froxlor\Dns\PowerDNS::getDB()->prepare("DELETE FROM `domainmetadata` WHERE `domain_id` = :did");
		$del_dom_stmt = \Froxlor\Dns\PowerDNS::getDB()->prepare("DELETE FROM `domains` WHERE `id` = :did");

		foreach ($domains as $domain) {
			$pdns_domains_stmt->execute([
				'domain' => $domain['domain']
			]);
			$pdns_domain = $pdns_domains_stmt->fetch(PDO::FETCH_ASSOC);

			if ($pdns_domain && !empty($pdns_domain['id'])) {
				$del_rec_stmt->execute([
					'did' => $pdns_domain['id']
				]);
				$del_meta_stmt->execute([
					'did' => $pdns_domain['id']
				]);
				$del_dom_stmt->execute([
					'did' => $pdns_domain['id']
				]);
			}
		}
	}

	private function walkDomainList($domain, $domains)
	{
		$zoneContent = '';
		$subzones = [];

		foreach ($domain['children'] as $child_domain_id) {
			$subzones[] = $this->walkDomainList($domains[$child_domain_id], $domains);
		}

		if ($domain['zonefile'] == '') {
			// check for system-hostname
			$isFroxlorHostname = false;
			if (isset($domain['froxlorhost']) && $domain['froxlorhost'] == 1) {
				$isFroxlorHostname = true;
			}

			if (!$domain['is_child']) {
				$zoneContent = Dns::createDomainZone(($domain['id'] == 'none') ? $domain : $domain['id'], $isFroxlorHostname);
				if (count($subzones)) {
					foreach ($subzones as $subzone) {
						$zoneContent->records[] = $subzone;
					}
				}
				$pdnsDomId = $this->insertZone($zoneContent->origin, $zoneContent->serial);
				$this->insertRecords($pdnsDomId, $zoneContent->records, $zoneContent->origin);
				$this->insertAllowedTransfers($pdnsDomId);
				$this->logger->logAction(FroxlorLogger::CRON_ACTION, LOG_INFO, 'DB entries stored for zone `' . $domain['domain'] . '`');
			} else {
				return Dns::createDomainZone(($domain['id'] == 'none') ? $domain : $domain['id'], $isFroxlorHostname, true);
			}
		} else {
			$this->logger->logAction(FroxlorLogger::CRON_ACTION, LOG_ERR, 'Custom zonefiles are NOT supported when PowerDNS is selected as DNS daemon (triggered by: ' . $domain['domain'] . ')');
		}
	}

	private function insertZone($domainname, $serial = 0)
	{
		$ins_stmt = \Froxlor\Dns\PowerDNS::getDB()->prepare("
			INSERT INTO domains set `name` = :domainname, `notified_serial` = :serial, `type` = :type
		");
		$ins_stmt->execute([
			'domainname' => $domainname,
			'serial' => $serial,
			'type' => strtoupper(Settings::Get('system.powerdns_mode'))
		]);
		$lastid = \Froxlor\Dns\PowerDNS::getDB()->lastInsertId();
		return $lastid;
	}

	private function insertRecords($domainid = 0, $records = [], $origin = "")
	{
		$ins_stmt = \Froxlor\Dns\PowerDNS::getDB()->prepare("
			INSERT INTO records set
			`domain_id` = :did,
			`name` = :rec,
			`type` = :type,
			`content` = :content,
			`ttl` = :ttl,
			`prio` = :prio,
			`disabled` = '0'
		");

		foreach ($records as $record) {
			if ($record instanceof DnsZone) {
				$this->insertRecords($domainid, $record->records, $record->origin);
				continue;
			}

			if ($record->record == '@') {
				$_record = $origin;
			} else {
				$_record = $record->record . "." . $origin;
			}

			$ins_data = [
				'did' => $domainid,
				'rec' => $_record,
				'type' => $record->type,
				'content' => $record->content,
				'ttl' => $record->ttl,
				'prio' => $record->priority
			];
			$ins_stmt->execute($ins_data);
		}
	}

	private function insertAllowedTransfers($domainid)
	{
		$ins_stmt = \Froxlor\Dns\PowerDNS::getDB()->prepare("
			INSERT INTO domainmetadata set `domain_id` = :did, `kind` = 'ALLOW-AXFR-FROM', `content` = :value
		");

		$ins_data = [
			'did' => $domainid
		];

		if (count($this->ns) > 0 || count($this->axfr) > 0) {
			// put nameservers in allow-transfer
			if (count($this->ns) > 0) {
				foreach ($this->ns as $ns) {
					foreach ($ns["ips"] as $ip) {
						$ins_data['value'] = $ip;
						$ins_stmt->execute($ins_data);
					}
				}
			}
			// AXFR server #100
			if (count($this->axfr) > 0) {
				foreach ($this->axfr as $axfrserver) {
					$ins_data['value'] = $axfrserver;
					$ins_stmt->execute($ins_data);
				}
			}
		}
	}
}
