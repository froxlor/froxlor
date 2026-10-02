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

namespace Froxlor\Dns;

use Froxlor\Database\Database;
use Froxlor\Idna\IdnaWrapper;
use Froxlor\Settings;
use Froxlor\UI\Response;
use PDO;

class Dns
{
	/**
	 * @param int $domain_id
	 * @param string $area
	 * @param array $userinfo
	 *
	 * @return string|void
	 * @throws \Exception
	 */
	public static function getAllowedDomainEntry(int $domain_id, string $area = 'customer', array $userinfo = [])
	{
		$dom_data = [
			'did' => $domain_id
		];

		$where_clause = '';
		if ($area == 'admin') {
			if ((int)$userinfo['customers_see_all'] == 0) {
				$where_clause = '`adminid` = :uid AND ';
				$dom_data['uid'] = $userinfo['userid'];
			}
		} else {
			$where_clause = '`customerid` = :uid AND ';
			$dom_data['uid'] = $userinfo['userid'];
		}

		$dom_stmt = Database::prepare("
			SELECT domain, isbinddomain
			FROM `" . TABLE_PANEL_DOMAINS . "`
			WHERE " . $where_clause . " id = :did
		");
		$domain = Database::pexecute_first($dom_stmt, $dom_data);

		if ($domain) {
			if ($domain['isbinddomain'] != '1') {
				Response::standardError('dns_domain_nodns');
			}
			$idna_convert = new IdnaWrapper();
			return $idna_convert->decode($domain['domain']);
		}
		Response::standardError('dns_notfoundorallowed');
	}

	/**
	 * @param int|array $domain_id id of domain or in case of froxlorhostname, a domain-array with the needed data
	 * @param bool $froxlorhostname
	 * @param bool $isMainButSubTo
	 *
	 * @return DnsZone|void
	 * @throws \Exception
	 */
	public static function createDomainZone($domain_id, bool $froxlorhostname = false, bool $isMainButSubTo = false)
	{
		if (!$froxlorhostname) {
			// get domain-name
			$dom_stmt = Database::prepare("SELECT * FROM `" . TABLE_PANEL_DOMAINS . "` WHERE id = :did");
			$domain = Database::pexecute_first($dom_stmt, [
				'did' => $domain_id
			]);
		} else {
			$domain = $domain_id;
		}

		if (!isset($domain['isbinddomain']) || $domain['isbinddomain'] != '1') {
			return;
		}

		$dom_entries = [];
		if (!$froxlorhostname) {
			// select all entries
			$sel_stmt = Database::prepare("SELECT * FROM `" . TABLE_DOMAIN_DNS . "` WHERE domain_id = :did ORDER BY id ASC");
			Database::pexecute($sel_stmt, [
				'did' => $domain_id
			]);
			$dom_entries = $sel_stmt->fetchAll(PDO::FETCH_ASSOC);
		}

		// check for required records
		$required_entries = [];

		if ($domain['email_only'] == '0') {
			self::addRequiredEntry('@', 'A', $required_entries);
			self::addRequiredEntry('@', 'AAAA', $required_entries);
		}
		if (!$isMainButSubTo) {
			self::addRequiredEntry('@', 'NS', $required_entries);
		}
		if ($domain['isemaildomain'] == '1') {
			self::addRequiredEntry('@', 'MX', $required_entries);
			if (Settings::Get('system.dns_createmailentry')) {
				foreach (['imap', 'pop3', 'mail', 'smtp' ] as $record ) {
					foreach (['AAAA', 'A' ] as $type ) {
						self::addRequiredEntry($record, $type, $required_entries);
					}
				}
			}
		}

		// additional required records by setting
		if ($domain['email_only'] == '0') {
			if ($domain['iswildcarddomain'] == '1') {
				self::addRequiredEntry('*', 'A', $required_entries);
				self::addRequiredEntry('*', 'AAAA', $required_entries);
			} elseif ($domain['wwwserveralias'] == '1') {
				self::addRequiredEntry('www', 'A', $required_entries);
				self::addRequiredEntry('www', 'AAAA', $required_entries);
			}
		}

		if (!$froxlorhostname) {
			// additional required records for subdomains
			$subdomains_stmt = Database::prepare("
				SELECT `domain`, `iswildcarddomain`, `wwwserveralias`, `isemaildomain`, `email_only` FROM `" . TABLE_PANEL_DOMAINS . "`
				WHERE `parentdomainid` = :domainid
			");
			Database::pexecute($subdomains_stmt, [
				'domainid' => $domain_id
			]);

			while ($subdomain = $subdomains_stmt->fetch(PDO::FETCH_ASSOC)) {
				$sub_record = str_replace('.' . $domain['domain'], '', $subdomain['domain']);
				// Listing domains is enough as there currently is no support for choosing
				// different ips for a subdomain => use same IPs as toplevel
				if ($subdomain['email_only'] == '0') {
					self::addRequiredEntry($sub_record, 'A', $required_entries);
					self::addRequiredEntry($sub_record, 'AAAA', $required_entries);

					// Check whether to add a www.-prefix
					if ($subdomain['iswildcarddomain'] == '1') {
						self::addRequiredEntry('*.' . $sub_record, 'A', $required_entries);
						self::addRequiredEntry('*.' . $sub_record, 'AAAA', $required_entries);
					} elseif ($subdomain['wwwserveralias'] == '1') {
						self::addRequiredEntry('www.' . $sub_record, 'A', $required_entries);
						self::addRequiredEntry('www.' . $sub_record, 'AAAA', $required_entries);
					}
				}

				// check for email ability
				if ($subdomain['isemaildomain'] == '1') {
					if (Settings::Get('spf.use_spf') == '1') {
						// check for SPF content later
						self::addRequiredEntry('@SPF@.' . $sub_record, 'TXT', $required_entries);
					}
					if (Settings::Get('dmarc.use_dmarc') == '1') {
						// check for DMARC content later
						self::addRequiredEntry('@DMARC@.' . $sub_record, 'TXT', $required_entries);
					}
					if (Settings::Get('antispam.activated') == '1' && $domain['dkim'] == '1') {
						// check for DKIM content later
						self::addRequiredEntry('dkim' . $domain['dkim_id'] . '._domainkey.' . $sub_record, 'TXT', $required_entries);
					}
				}
			}
		}

		// additional required records for CAA if activated
		if (Settings::Get('system.dns_createcaaentry') && Settings::Get('system.use_ssl') == "1") {
			$result_stmt = Database::prepare("
				SELECT i.`ip`, i.`port`, i.`ssl`
				FROM " . TABLE_PANEL_IPSANDPORTS . " i
				LEFT JOIN " . TABLE_DOMAINTOIP . " dip ON dip.id_ipandports = i.id
				WHERE i.ssl = 1 AND dip.id_domain = :domainid
			");
			Database::pexecute($result_stmt, [
				'domainid' => $domain['id']
			]);

			$ssl_ipandports = [];
			while ($ssl_ipandport = $result_stmt->fetch(PDO::FETCH_ASSOC)) {
				$ssl_ipandports[] = $ssl_ipandport;
			}

			if (!empty($ssl_ipandports)) {
				// check for CAA content later
				self::addRequiredEntry('@CAA@', 'CAA', $required_entries);
			}
		}

		// additional required records for SPF and DKIM if activated
		if ($domain['isemaildomain'] == '1') {
			if (Settings::Get('spf.use_spf') == '1') {
				// check for SPF content later
				self::addRequiredEntry('@SPF@', 'TXT', $required_entries);
			}
			if (Settings::Get('dmarc.use_dmarc') == '1') {
				// check for DMARC content later
				self::addRequiredEntry('@DMARC@', 'TXT', $required_entries);
			}
			if (Settings::Get('antispam.activated') == '1' && $domain['dkim'] == '1') {
				// check for DKIM content later
				self::addRequiredEntry('dkim' . $domain['dkim_id'] . '._domainkey', 'TXT', $required_entries);
			}
		}

		$primary_ns = null;
		$zonerecords = [];

		// now generate all records and unset the required entries we have
		foreach ($dom_entries as $entry) {
			if (array_key_exists($entry['type'], $required_entries)
				&& array_key_exists( md5($entry['record']), $required_entries[$entry['type']])
			) {
				unset($required_entries[$entry['type']][md5($entry['record'])]);
			}
			if (Settings::Get('system.dns_createcaaentry') == '1'
				&& $entry['type'] == 'CAA'
				&& strtolower(substr($entry['content'], 0, 7 )) == '"v=caa1'
			) {
				// unset special CAA required-entry
				unset($required_entries[$entry['type']][md5("@CAA@")]);
			}
			if (Settings::Get('spf.use_spf') == '1'
				&& $entry['type'] == 'TXT'
				&& (strtolower(substr($entry['content'], 0, 7)) == '"v=spf1' || strtolower(substr($entry['content'], 0, 6)) == 'v=spf1')
			) {
				// unset special spf required-entry
				if ($entry['record'] == '@') {
					unset($required_entries[$entry['type']][md5("@SPF@")]);
				} else {
					// subdomain
					unset($required_entries[$entry['type']][md5("@SPF@." . $entry['record'])]);
				}
			}
			if (Settings::Get('dmarc.use_dmarc') == '1'
				&& $entry['type'] == 'TXT'
				&& ($entry['record'] == '_dmarc' || substr($entry['record'], 0, 7) == '_dmarc.')
				&& (strtolower(substr($entry['content'], 0, 9)) == '"v=dmarc1' || strtolower(substr($entry['content'], 0, 8)) == 'v=dmarc1')
			) {
				// unset special dmarc required-entry
				if ($entry['record'] == '_dmarc') {
					unset($required_entries[$entry['type']][md5("@DMARC@")]);
				} else {
					// subdomain
					unset($required_entries[$entry['type']][md5("@DMARC@" . substr($entry['record'], 6))]);
				}
			}
			if (empty($primary_ns) && $entry['record'] == '@' && $entry['type'] == 'NS') {
				// use the first NS entry pertaining to the current domain as primary ns
				$primary_ns = $entry['content'];
			}
			// check for CNAME on @, www- or wildcard-Alias and remove A/AAAA record accordingly
			foreach (['@', 'www', '*'] as $crecord) {
				if ($entry['type'] == 'CNAME'
					&& $entry['record'] == '@'
					&& (array_key_exists(md5($crecord), $required_entries['A']) || array_key_exists(md5($crecord), $required_entries['AAAA']))
				) {
					unset($required_entries['A'][md5($crecord)]);
					unset($required_entries['AAAA'][md5($crecord)]);
				}
			}
			// also allow overriding of auto-generated values (imap,pop3,mail,smtp) if enabled in the settings
			if (Settings::Get('system.dns_createmailentry')) {
				foreach (['imap', 'pop3', 'mail', 'smtp'] as $crecord) {
					if ($entry['type'] == 'CNAME'
						&& $entry['record'] == $crecord
						&& (array_key_exists(md5($crecord), $required_entries['A']) || array_key_exists(md5($crecord), $required_entries['AAAA']))
					) {
						unset($required_entries['A'][md5($crecord)]);
						unset($required_entries['AAAA'][md5($crecord)]);
					}
				}
			}
			$zonerecords[] = new DnsEntry($entry['record'], $entry['type'], $entry['content'], $entry['prio'] ?? 0, $entry['ttl']);
		}

		// add missing required entries
		if (!empty($required_entries)) {
			// A / AAAA records
			if (array_key_exists("A", $required_entries) || array_key_exists("AAAA", $required_entries)) {
				if ($froxlorhostname) {
					// use all available IP's for the froxlor-hostname
					$result_ip_stmt = Database::prepare("
						SELECT `ip` FROM `" . TABLE_PANEL_IPSANDPORTS . "` GROUP BY `ip`
					");
					Database::pexecute($result_ip_stmt);
				} else {
					$result_ip_stmt = Database::prepare("
						SELECT `p`.`ip` AS `ip`
						FROM `" . TABLE_PANEL_IPSANDPORTS . "` `p`, `" . TABLE_DOMAINTOIP . "` `di`
						WHERE `di`.`id_domain` = :domainid AND `p`.`id` = `di`.`id_ipandports`
						GROUP BY `p`.`ip`;
					");
					Database::pexecute($result_ip_stmt, [
						'domainid' => $domain_id
					]);
				}
				$all_ips = $result_ip_stmt->fetchAll(PDO::FETCH_ASSOC);

				foreach ($all_ips as $ip) {
					foreach ($required_entries as $type => $records) {
						foreach ($records as $record) {
							if ($type == 'A' && filter_var($ip['ip'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
								$zonerecords[] = new DnsEntry($record, 'A', $ip['ip']);
							} elseif ($type == 'AAAA' && filter_var($ip['ip'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) !== false) {
								$zonerecords[] = new DnsEntry($record, 'AAAA', $ip['ip']);
							}
						}
					}
				}
				unset($required_entries['A']);
				unset($required_entries['AAAA']);
			}

			// NS records
			if (array_key_exists("NS", $required_entries)) {
				if (Settings::Get('system.nameservers') != '') {
					$nameservers = explode(',', Settings::Get('system.nameservers'));
					foreach ($nameservers as $nameserver) {
						$nameserver = trim($nameserver);
						// append dot to hostname
						if (substr($nameserver, -1, 1) != '.') {
							$nameserver .= '.';
						}
						foreach ($required_entries as $type => $records) {
							if ($type == 'NS') {
								foreach ($records as $record) {
									if (empty($primary_ns)) {
										// use the first NS entry as primary ns
										$primary_ns = $nameserver;
									}
									$zonerecords[] = new DnsEntry($record, 'NS', $nameserver);
								}
							}
						}
					}
					unset($required_entries['NS']);
				}
			}

			// MX records
			if (array_key_exists("MX", $required_entries)) {
				if (Settings::Get('system.mxservers') != '') {
					$mxservers = explode(',', Settings::Get('system.mxservers'));
					foreach ($mxservers as $mxserver) {
						$mxserver = trim($mxserver);
						if (substr($mxserver, -1, 1) != '.') {
							$mxserver .= '.';
						}
						// split in prio and server
						$mx_details = explode(" ", $mxserver);
						if (count($mx_details) == 1) {
							$mx_details[1] = $mx_details[0];
							$mx_details[0] = 10;
						}
						foreach ($required_entries as $type => $records) {
							if ($type == 'MX') {
								foreach ($records as $record) {
									$zonerecords[] = new DnsEntry($record, 'MX', $mx_details[1], $mx_details[0]);
								}
							}
						}
					}
					unset($required_entries['MX']);
				}
			}

			// TXT (SPF and DKIM)
			if (array_key_exists("TXT", $required_entries)) {
				$dkim_entries = self::generateDkimEntries($domain);

				foreach ($required_entries as $type => $records) {
					if ($type == 'TXT') {
						foreach ($records as $record) {
							if ($record == '@SPF@') {
								// spf for main-domain
								$txt_content = Settings::Get('spf.spf_entry');
								$zonerecords[] = new DnsEntry('@', 'TXT', self::encloseTXTContent($txt_content));
							} elseif (strlen($record) > 6 && substr($record, 0, 6) == '@SPF@.') {
								// spf for subdomain
								$txt_content = Settings::Get('spf.spf_entry');
								$sub_record = substr($record, 6);
								$zonerecords[] = new DnsEntry($sub_record, 'TXT', self::encloseTXTContent($txt_content));
							} elseif ($record == '@DMARC@') {
								// dmarc for main-domain
								$txt_content = Settings::Get('dmarc.dmarc_entry');
								$zonerecords[] = new DnsEntry('_dmarc', 'TXT', self::encloseTXTContent($txt_content));
							} elseif (strlen($record) > 8 && substr($record, 0, 8) == '@DMARC@.') {
								// dmarc for subdomain
								$txt_content = Settings::Get('dmarc.dmarc_entry');
								$sub_record = substr($record, 8);
								$zonerecords[] = new DnsEntry('_dmarc.' . $sub_record, 'TXT', self::encloseTXTContent($txt_content));
							} elseif (!empty($dkim_entries)) {
								// DKIM entries
								$dkim_record = 'dkim' . $domain['dkim_id'] . '._domainkey';
								if ($record == $dkim_record) {
									// dkim for main-domain
									// check for multiline entry
									$multiline = false;
									if (substr($dkim_entries[0], 0, 1) == '(') {
										$multiline = true;
									}
									$zonerecords[] = new DnsEntry($record, 'TXT', self::encloseTXTContent($dkim_entries[0], $multiline));
								} elseif (strlen($record) > strlen($dkim_record) && substr($record, 0, strlen($dkim_record) + 1) == $dkim_record . '.') {
									// dkim for subdomain-domain
									// check for multiline entry
									$multiline = false;
									if (substr($dkim_entries[0], 0, 1) == '(') {
										$multiline = true;
									}
									$zonerecords[] = new DnsEntry($record, 'TXT', self::encloseTXTContent($dkim_entries[0], $multiline));
								}
							}
						}
					}
				}
			}

			// CAA
			if (array_key_exists("CAA", $required_entries)) {
				foreach ($required_entries as $type => $records) {
					if ($type == 'CAA') {
						foreach ($records as $record) {
							if ($record == '@CAA@') {
								$caa_entries = explode(PHP_EOL, Settings::Get('caa.caa_entry'));
								$caa_domain = "letsencrypt.org";
								if (Settings::Get('system.letsencryptca') == 'buypass' || Settings::Get('system.letsencryptca') == 'buypass_test') {
									$caa_domain = "buypass.com";
								}
								if ($domain['letsencrypt'] == 1) {
									if (Settings::Get('system.letsencryptca') == 'zerossl') {
										$caa_domains = [
											"sectigo.com",
											"trust-provider.com",
											"usertrust.com",
											"comodoca.com",
											"comodo.com"
										];
										foreach ($caa_domains as $caa_domain) {
											$le_entry = $domain['iswildcarddomain'] == '1' ? '0 issuewild "' . $caa_domain . '"' : '0 issue "' . $caa_domain . '"';
											array_push($caa_entries, $le_entry);
										}
									} else {
										$le_entry = $domain['iswildcarddomain'] == '1' ? '0 issuewild "' . $caa_domain . '"' : '0 issue "' . $caa_domain . '"';
										array_push($caa_entries, $le_entry);
									}
								}
								foreach ($caa_entries as $entry) {
									if (empty($entry)) {
										continue;
									}
									$zonerecords[] = new DnsEntry('@', 'CAA', $entry);
									// additional required records by subdomain setting
									if ($domain['wwwserveralias'] == '1') {
										$zonerecords[] = new DnsEntry('www', 'CAA', $entry);
									}
								}
							}
						}
					}
				}
			}
		}

		if (empty($primary_ns)) {
			// TODO log error: no NS given, use system-hostname
			$primary_ns = Settings::Get('system.hostname');
		}

		if (!$isMainButSubTo) {
			$date = date('Ymd');
			$domain['bindserial'] = (preg_match('/^' . $date . '/', $domain['bindserial']) ? $domain['bindserial'] + 1 : $date . '00');
			if (!$froxlorhostname) {
				$upd_stmt = Database::prepare("
					UPDATE `" . TABLE_PANEL_DOMAINS . "` SET
					`bindserial` = :serial
					 WHERE `id` = :id
				");
				Database::pexecute($upd_stmt, [
					'serial' => $domain['bindserial'],
					'id' => $domain['id']
				]);
			}

			// PowerDNS does not like multi-line-format
			$soa_email = Settings::Get('system.soaemail');
			if ($soa_email == "") {
				$soa_email = Settings::Get('panel.adminmail');
			}
			$soa_content = $primary_ns . " " . self::escapeSoaAdminMail($soa_email) . " ";
			$soa_content .= $domain['bindserial'] . " ";
			// TODO for now, dummy time-periods
			$soa_content .= "3600 900 1209600 1200";

			$soa_record = new DnsEntry('@', 'SOA', $soa_content);
			array_unshift($zonerecords, $soa_record);
		}

		$zone = new DnsZone(
			(int)Settings::Get('system.defaultttl'),
			$domain['domain'],
			$domain['bindserial'],
			$zonerecords
		);

		return $zone;
	}

	/**
	 * @param string $record
	 * @param string $type
	 * @param array $required
	 * @return void
	 */
	private static function addRequiredEntry(string $record = '@', string $type = 'A', array &$required = [])
	{
		if (!isset($required[$type])) {
			$required[$type] = [];
		}
		$required[$type][md5($record)] = $record;
	}

	/**
	 * @param array $domain
	 * @return array
	 */
	private static function generateDkimEntries(array $domain): array
	{
		$zone_dkim = [];

		if (Settings::Get('antispam.activated') == '1' && $domain['dkim'] == '1' && $domain['dkim_pubkey'] != '') {
			// start
			$dkim_txt = 'v=DKIM1;';
			// key
			$dkim_txt .= 'k=rsa;p=' . trim($domain['dkim_pubkey']) . ';';
			// dkim-entry
			$zone_dkim[] = $dkim_txt;
		}

		return $zone_dkim;
	}

	/**
	 * @param string $txt_content
	 * @param bool $isMultiLine
	 * @return string
	 */
	public static function encloseTXTContent(string $txt_content, bool $isMultiLine = false): string
	{
		// check that TXT content is enclosed in " "
		if (!$isMultiLine && Settings::Get('system.dns_server') != 'PowerDNS') {
			if (substr($txt_content, 0, 1) != '"') {
				$txt_content = '"' . $txt_content;
			}
			if (substr($txt_content, -1) != '"') {
				$txt_content .= '"';
			}
		}
		if (Settings::Get('system.dns_server') == 'PowerDNS') {
			// no quotation for PowerDNS
			if (substr($txt_content, 0, 1) == '"') {
				$txt_content = substr($txt_content, 1);
			}
			if (substr($txt_content, -1) == '"') {
				$txt_content = substr($txt_content, 0, -1);
			}
		}
		return $txt_content;
	}

	/**
	 * @param string $email
	 * @return string
	 */
	private static function escapeSoaAdminMail(string $email): string
	{
		$mail_parts = explode("@", $email);
		return str_replace(".", "\.", $mail_parts[0]) . "." . $mail_parts[1] . ".";
	}
}
