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

namespace Froxlor\Cron\Traffic;

/**
 * @author        Florian Lippert <flo@syscp.org> (2003-2009)
 * @author        Froxlor team <team@froxlor.org> (2010-)
 */

use Froxlor\Cron\Forkable;
use Froxlor\Cron\FroxlorCron;
use Froxlor\Database\Database;
use Froxlor\FileDir;
use Froxlor\Froxlor;
use Froxlor\FroxlorLogger;
use Froxlor\Http\Statistics;
use Froxlor\MailLogParser;
use Froxlor\Settings;
use PDO;

class TrafficCron extends FroxlorCron
{
	use Forkable;

	public static function run()
	{
		self::runFork([self::class, 'handle'], [true]);
	}

	public static function handle()
	{
		/**
		 * TRAFFIC AND DISKUSAGE MEASURE
		 */
		FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_INFO, 'Traffic run started...');
		$admin_traffic = [];
		$domainlist = [];
		$speciallogfile_domainlist = [];
		$result_domainlist_stmt = Database::query("
			SELECT `id`, `domain`, `customerid`, `parentdomainid`, `speciallogfile`
			FROM `" . TABLE_PANEL_DOMAINS . "` WHERE `aliasdomain` IS NULL AND `email_only` <> '1';
		");

		while ($row_domainlist = $result_domainlist_stmt->fetch(PDO::FETCH_ASSOC)) {
			if (!isset($domainlist[$row_domainlist['customerid']])) {
				$domainlist[$row_domainlist['customerid']] = [];
			}

			$domainlist[$row_domainlist['customerid']][$row_domainlist['id']] = $row_domainlist['domain'];

			if ($row_domainlist['parentdomainid'] == '0' && $row_domainlist['speciallogfile'] == '1') {
				if (!isset($speciallogfile_domainlist[$row_domainlist['customerid']])) {
					$speciallogfile_domainlist[$row_domainlist['customerid']] = [];
				}
				$speciallogfile_domainlist[$row_domainlist['customerid']][$row_domainlist['id']] = $row_domainlist['domain'];
			}
		}

		$mysqlusage_all = [];
		$databases_stmt = Database::query("SELECT * FROM " . TABLE_PANEL_DATABASES . " ORDER BY `dbserver`");
		$last_dbserver = 0;

		$databases_list = [];
		Database::needRoot(true);
		$databases_list_result_stmt = Database::query("SHOW DATABASES");
		while ($databases_list_row = $databases_list_result_stmt->fetch(PDO::FETCH_ASSOC)) {
			$databases_list[] = strtolower($databases_list_row['Database']);
		}

		while ($row_database = $databases_stmt->fetch(PDO::FETCH_ASSOC)) {
			if ($last_dbserver != $row_database['dbserver']) {
				Database::needRoot(true, $row_database['dbserver'], true);
				$last_dbserver = $row_database['dbserver'];

				$databases_list = [];
				$databases_list_result_stmt = Database::query("SHOW DATABASES");
				while ($databases_list_row = $databases_list_result_stmt->fetch(PDO::FETCH_ASSOC)) {
					$databases_list[] = strtolower($databases_list_row['Database']);
				}
			}

			if (in_array(strtolower($row_database['databasename']), $databases_list)) {
				// sum up data_length and index_length
				$mysql_usage_result_stmt = Database::prepare("
					SELECT SUM(data_length + index_length) AS customerusage
					FROM information_schema.TABLES
					WHERE table_schema = :database
					GROUP BY table_schema;
				");
				// get the result
				$mysql_usage_row = Database::pexecute_first($mysql_usage_result_stmt, [
					'database' => $row_database['databasename']
				]);
				// initialize counter for customer
				if (!isset($mysqlusage_all[$row_database['customerid']])) {
					$mysqlusage_all[$row_database['customerid']] = 0;
				}
				// sum up result
				if ($mysql_usage_row) {
					$mysqlusage_all[$row_database['customerid']] += floatval($mysql_usage_row['customerusage']);
				} else {
					FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_NOTICE, "Cannot get usage for database " . $row_database['databasename'] . ".");
				}
			} else {
				FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_WARNING, "Seems like the database " . $row_database['databasename'] . " had been removed manually.");
			}
		}

		Database::needRoot(false);

		// We are using the file-system quota, this will speed up the diskusage - collection
		if (Settings::Get('system.diskquota_enabled')) {
			$usedquota = FileDir::getFilesystemQuota();
		}

		/**
		 * MAIL-Traffic
		 */
		if (Settings::Get("system.mailtraffic_enabled")) {
			$mailTrafficCalc = new MailLogParser(Settings::Get("system.last_traffic_run"));
		}

		$result_stmt = Database::query("SELECT * FROM `" . TABLE_PANEL_CUSTOMERS . "` ORDER BY `customerid` ASC");

		$currentDate = date("Y-m-d");

		$current_stamp = time();
		$current_year = date('Y', $current_stamp);
		$current_month = date('m', $current_stamp);
		// @todo locale?
		$current_month_short = date('M', $current_stamp);
		$current_day = date('d', $current_stamp);

		while ($row = $result_stmt->fetch(PDO::FETCH_ASSOC)) {
			/**
			 * HTTP-Traffic
			 */
			FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_INFO, 'http traffic for ' . $row['loginname'] . ' started...');
			$httptraffic = 0;

			if (isset($domainlist[$row['customerid']]) && is_array($domainlist[$row['customerid']]) && count($domainlist[$row['customerid']]) != 0) {
				// Examining which caption to use for default webalizer stats...
				if ($row['standardsubdomain'] != '0' && isset($domainlist[$row['customerid']][$row['standardsubdomain']])) {
					// ... of course we'd prefer to use the standardsubdomain ...
					$caption = $domainlist[$row['customerid']][$row['standardsubdomain']];
				} else {
					// ... but if there is no standardsubdomain, we have to use the loginname ...
					$caption = $row['loginname'];

					// ... which results in non-usable links to files in the stats, so let's have a look if we find a domain which is not speciallogfiledomain
					foreach ($domainlist[$row['customerid']] as $domainid => $domain) {
						if (!isset($speciallogfile_domainlist[$row['customerid']]) || !isset($speciallogfile_domainlist[$row['customerid']][$domainid])) {
							$caption = $domain;
							break;
						}
					}
				}

				$httptraffic = 0;
				reset($domainlist[$row['customerid']]);

				$statsTool = Settings::Get('system.traffictool');

				if (isset($speciallogfile_domainlist[$row['customerid']]) && is_array($speciallogfile_domainlist[$row['customerid']]) && count($speciallogfile_domainlist[$row['customerid']]) != 0) {
					reset($speciallogfile_domainlist[$row['customerid']]);
					if ($statsTool != 'awstats') {
						foreach ($speciallogfile_domainlist[$row['customerid']] as $domainid => $domain) {
							if ($statsTool == 'goaccess') {
								$httptraffic += floatval(self::callGoaccessGetTraffic($row['customerid'], $row['loginname'] . '-' . $domain, $row['documentroot'] . '/goaccess/' . $domain . '/', $domain, ['month' => $current_month_short, 'year' => $current_year], $current_stamp));
							} else {
								$httptraffic += floatval(self::callWebalizerGetTraffic($row['loginname'] . '-' . $domain, $row['documentroot'] . '/webalizer/' . $domain . '/', $domain, $domainlist[$row['customerid']]));
							}
							// kind of a keep-alive-call as this unsets the link which leads to a new connection to the database
							Database::needRoot();
						}
					}
				}

				reset($domainlist[$row['customerid']]);

				// callAwstatsGetTraffic is called ONLY HERE and
				// *not* also in the special-logfiles-loop, because the function
				// will iterate through all customer-domains and the awstats-configs
				// know the logfile-name, #246
				if ($statsTool == 'awstats') {
					$httptraffic += floatval(self::callAwstatsGetTraffic($row['customerid'], $row['documentroot'] . '/awstats/', $domainlist[$row['customerid']], $current_stamp));
				} elseif ($statsTool == 'goaccess') {
					$httptraffic += floatval(self::callGoaccessGetTraffic($row['customerid'], $row['loginname'], $row['documentroot'] . '/goaccess/', $caption, ['month' => $current_month_short, 'year' => $current_year], $current_stamp));
				} else {
					$httptraffic += floatval(self::callWebalizerGetTraffic($row['loginname'], $row['documentroot'] . '/webalizer/', $caption, $domainlist[$row['customerid']]));
				}
				// kind of a keep-alive-call as this unsets the link which leads to a new connection to the database
				Database::needRoot();

				// make the stuff readable for the customer, #258
				Statistics::makeChownWithNewStats($row);
			}

			/**
			 * FTP-Traffic
			 */
			FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_INFO, 'ftp traffic for ' . $row['loginname'] . ' started...');
			$ftptraffic_stmt = Database::prepare("
				SELECT SUM(`up_bytes`) AS `up_bytes_sum`, SUM(`down_bytes`) AS `down_bytes_sum`
				FROM `" . TABLE_FTP_USERS . "` WHERE `customerid` = :customerid
			");
			$ftptraffic = Database::pexecute_first($ftptraffic_stmt, [
				'customerid' => $row['customerid']
			]);

			if (!is_array($ftptraffic)) {
				$ftptraffic = [
					'up_bytes_sum' => 0,
					'down_bytes_sum' => 0
				];
			}

			$upd_stmt = Database::prepare("
				UPDATE `" . TABLE_FTP_USERS . "` SET `up_bytes` = '0', `down_bytes` = '0' WHERE `customerid` = :customerid
			");
			Database::pexecute($upd_stmt, [
				'customerid' => $row['customerid']
			]);

			/**
			 * Mail-Traffic
			 */
			$mailtraffic = 0;
			if (Settings::Get("system.mailtraffic_enabled")) {
				FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_INFO, 'mail traffic usage for ' . $row['loginname'] . " started...");

				$domains_stmt = Database::prepare("SELECT domain FROM `" . TABLE_PANEL_DOMAINS . "` WHERE `customerid` = :cid");
				Database::pexecute($domains_stmt, [
					"cid" => $row['customerid']
				]);
				while ($domainRow = $domains_stmt->fetch(PDO::FETCH_ASSOC)) {
					$domainMailTraffic = $mailTrafficCalc->getDomainTraffic($domainRow["domain"]);
					if (!is_array($domainMailTraffic)) {
						continue;
					}

					foreach ($domainMailTraffic as $dateTraffic => $dayTraffic) {
						$dayTraffic = floatval($dayTraffic / 1024);

						[$year, $month, $day] = explode("-", $dateTraffic);
						if ($dateTraffic == $currentDate) {
							$mailtraffic = $dayTraffic;
						} else {
							// Check if an entry for the given day exists
							$stmt = Database::prepare("SELECT * FROM `" . TABLE_PANEL_TRAFFIC . "`
								WHERE `customerid` = :cid
								AND `year` = :year
								AND `month` = :month
								AND `day` = :day
							");
							$params = [
								"cid" => $row['customerid'],
								"year" => $year,
								"month" => $month,
								"day" => $day
							];
							Database::pexecute($stmt, $params);
							if ($stmt->rowCount() > 0) {
								$updRow = $stmt->fetch(PDO::FETCH_ASSOC);
								$upd_stmt = Database::prepare("UPDATE `" . TABLE_PANEL_TRAFFIC . "` SET
									`mail` = :mail
									WHERE `id` = :id
								");
								Database::pexecute($upd_stmt, [
									"mail" => $updRow['mail'] + $dayTraffic,
									"id" => $updRow['id']
								]);
							}
						}
					}
				}
			}

			/**
			 * Total Traffic
			 */
			FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_INFO, 'total traffic for ' . $row['loginname'] . ' started');
			$current_traffic = [];
			$current_traffic['http'] = floatval($httptraffic);
			$current_traffic['ftp_up'] = floatval(($ftptraffic['up_bytes_sum'] / 1024));
			$current_traffic['ftp_down'] = floatval(($ftptraffic['down_bytes_sum'] / 1024));
			$current_traffic['mail'] = floatval($mailtraffic);
			$current_traffic['all'] = $current_traffic['http'] + $current_traffic['ftp_up'] + $current_traffic['ftp_down'] + $current_traffic['mail'];

			$ins_data = [
				'customerid' => $row['customerid'],
				'year' => $current_year,
				'month' => $current_month,
				'day' => $current_day,
				'stamp' => $current_stamp,
				'http' => $current_traffic['http'],
				'ftp_up' => $current_traffic['ftp_up'],
				'ftp_down' => $current_traffic['ftp_down'],
				'mail' => $current_traffic['mail']
			];
			$ins_stmt = Database::prepare("
				INSERT INTO `" . TABLE_PANEL_TRAFFIC . "` SET
				`customerid` = :customerid,
				`year` = :year,
				`month` = :month,
				`day` = :day,
				`stamp` = :stamp,
				`http` = :http,
				`ftp_up` = :ftp_up,
				`ftp_down` = :ftp_down,
				`mail` = :mail
			");
			Database::pexecute($ins_stmt, $ins_data);

			$sum_month_traffic_stmt = Database::prepare("
				SELECT SUM(`http`) AS `http`, SUM(`ftp_up`) AS `ftp_up`, SUM(`ftp_down`) AS `ftp_down`, SUM(`mail`) AS `mail`
				FROM `" . TABLE_PANEL_TRAFFIC . "` WHERE `year` = :year AND `month` = :month AND `customerid` = :customerid
			");
			$sum_month_traffic = Database::pexecute_first($sum_month_traffic_stmt, [
				'year' => $current_year,
				'month' => $current_month,
				'customerid' => $row['customerid']
			]);
			$sum_month_traffic['all'] = $sum_month_traffic['http'] + $sum_month_traffic['ftp_up'] + $sum_month_traffic['ftp_down'] + $sum_month_traffic['mail'];

			if (!isset($admin_traffic[$row['adminid']]) || !is_array($admin_traffic[$row['adminid']])) {
				$admin_traffic[$row['adminid']]['http'] = 0;
				$admin_traffic[$row['adminid']]['ftp_up'] = 0;
				$admin_traffic[$row['adminid']]['ftp_down'] = 0;
				$admin_traffic[$row['adminid']]['mail'] = 0;
				$admin_traffic[$row['adminid']]['all'] = 0;
				$admin_traffic[$row['adminid']]['sum_month'] = 0;
			}

			$admin_traffic[$row['adminid']]['http'] += $current_traffic['http'];
			$admin_traffic[$row['adminid']]['ftp_up'] += $current_traffic['ftp_up'];
			$admin_traffic[$row['adminid']]['ftp_down'] += $current_traffic['ftp_down'];
			$admin_traffic[$row['adminid']]['mail'] += $current_traffic['mail'];
			$admin_traffic[$row['adminid']]['all'] += $current_traffic['all'];
			$admin_traffic[$row['adminid']]['sum_month'] += $sum_month_traffic['all'];

			/**
			 * WebSpace-Usage
			 */
			FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_INFO, 'calculating webspace usage for ' . $row['loginname']);
			$webspaceusage = 0;

			// Using repquota, it's faster using this tool than using du traversing the complete directory
			if (Settings::Get('system.diskquota_enabled') && isset($usedquota[$row['guid']]['block']['used']) && $usedquota[$row['guid']]['block']['used'] >= 1) {
				// We may use the array we created earlier, the used diskspace is stored in [<guid>][block][used]
				$webspaceusage = floatval($usedquota[$row['guid']]['block']['used']);
			} else {
				// Use the old fashioned way with "du"
				if (file_exists($row['documentroot']) && is_dir($row['documentroot'])) {
					$back = FileDir::safe_exec('du -sk ' . escapeshellarg($row['documentroot']));
					foreach ($back as $backrow) {
						$webspaceusage = explode(' ', $backrow);
					}

					$webspaceusage = floatval($webspaceusage['0']);
					unset($back);
				} else {
					FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_WARNING, 'documentroot ' . $row['documentroot'] . ' does not exist');
				}
			}

			/**
			 * MailSpace-Usage
			 */
			FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_INFO, 'calculating mailspace usage for ' . $row['loginname']);
			$emailusage = 0;

			$maildir = FileDir::makeCorrectDir(Settings::Get('system.vmail_homedir') . $row['loginname']);
			if (file_exists($maildir) && is_dir($maildir)) {
				$back = FileDir::safe_exec('du -sk ' . escapeshellarg($maildir));
				foreach ($back as $backrow) {
					$emailusage = explode(' ', $backrow);
				}

				$emailusage = floatval($emailusage['0']);
				unset($back);
			} else {
				FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_WARNING, 'maildir ' . $maildir . ' does not exist');
			}

			/**
			 * MySQLSpace-Usage
			 */
			FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_INFO, 'calculating mysqlspace usage for ' . $row['loginname']);
			$mysqlusage = 0;

			if (isset($mysqlusage_all[$row['customerid']])) {
				$mysqlusage = floatval($mysqlusage_all[$row['customerid']] / 1024);
			}

			$current_diskspace = [];
			$current_diskspace['webspace'] = floatval($webspaceusage);
			$current_diskspace['mail'] = floatval($emailusage);
			$current_diskspace['mysql'] = floatval($mysqlusage);
			$current_diskspace['all'] = $current_diskspace['webspace'] + $current_diskspace['mail'] + $current_diskspace['mysql'];

			$ins_data = [
				'customerid' => $row['customerid'],
				'year' => $current_year,
				'month' => $current_month,
				'day' => $current_day,
				'stamp' => $current_stamp,
				'webspace' => $current_diskspace['webspace'],
				'mail' => $current_diskspace['mail'],
				'mysql' => $current_diskspace['mysql']
			];
			$ins_stmt = Database::prepare("
				INSERT INTO `" . TABLE_PANEL_DISKSPACE . "` SET
				`customerid` = :customerid,
				`year` = :year,
				`month` = :month,
				`day` = :day,
				`stamp` = :stamp,
				`webspace` = :webspace,
				`mail` = :mail,
				`mysql` = :mysql
			");
			Database::pexecute($ins_stmt, $ins_data);

			if (!isset($admin_diskspace[$row['adminid']]) || !is_array($admin_diskspace[$row['adminid']])) {
				$admin_diskspace[$row['adminid']] = [];
				$admin_diskspace[$row['adminid']]['webspace'] = 0;
				$admin_diskspace[$row['adminid']]['mail'] = 0;
				$admin_diskspace[$row['adminid']]['mysql'] = 0;
				$admin_diskspace[$row['adminid']]['all'] = 0;
			}

			$admin_diskspace[$row['adminid']]['webspace'] += $current_diskspace['webspace'];
			$admin_diskspace[$row['adminid']]['mail'] += $current_diskspace['mail'];
			$admin_diskspace[$row['adminid']]['mysql'] += $current_diskspace['mysql'];
			$admin_diskspace[$row['adminid']]['all'] += $current_diskspace['all'];

			/**
			 * Total Usage
			 */
			$diskusage = floatval($webspaceusage + $emailusage + $mysqlusage);

			$upd_data = [
				'diskspace' => $current_diskspace['all'],
				'traffic' => $sum_month_traffic['all'],
				'customerid' => $row['customerid']
			];
			$upd_stmt = Database::prepare("
				UPDATE `" . TABLE_PANEL_CUSTOMERS . "` SET
				`diskspace_used` = :diskspace,
				`traffic_used` = :traffic
				WHERE `customerid` = :customerid
			");
			Database::pexecute($upd_stmt, $upd_data);

			/**
			 * Proftpd Quota
			 */
			$upd_data = [
				'biu' => ($current_diskspace['all'] * 1024),
				'loginname' => $row['loginname'],
				'loginnamelike' => $row['loginname'] . Settings::Get('customer.ftpprefix') . "%"
			];
			$upd_stmt = Database::prepare("
				UPDATE `" . TABLE_FTP_QUOTATALLIES . "` SET
				`bytes_in_used` = :biu WHERE `name` = :loginname OR `name` LIKE :loginnamelike
			");
			Database::pexecute($upd_stmt, $upd_data);

			/**
			 * Pureftpd Quota
			 */
			if (Settings::Get('system.ftpserver') == "pureftpd") {
				$result_quota_stmt = Database::prepare("
					SELECT homedir FROM `" . TABLE_FTP_USERS . "` WHERE customerid = :customerid
				");
				Database::pexecute($result_quota_stmt, [
					'customerid' => $row['customerid']
				]);

				// get correct user
				if ((Settings::Get('system.mod_fcgid') == 1 || Settings::Get('phpfpm.enabled') == 1) && $row['deactivated'] == '0') {
					$user = $row['loginname'];
					$group = $row['loginname'];
				} else {
					$user = $row['guid'];
					$group = $row['guid'];
				}

				while ($row_quota = $result_quota_stmt->fetch(PDO::FETCH_ASSOC)) {
					$quotafile = "" . $row_quota['homedir'] . ".ftpquota";
					$fh = fopen($quotafile, 'w');
					$stringdata = "0 " . $current_diskspace['all'] * 1024 . "";
					fwrite($fh, $stringdata);
					fclose($fh);
					FileDir::safe_exec('chown ' . $user . ':' . $group . ' ' . escapeshellarg($quotafile) . '');
				}
			}
		}

		/**
		 * Admin Usage
		 */
		$result_stmt = Database::query("SELECT `adminid` FROM `" . TABLE_PANEL_ADMINS . "` ORDER BY `adminid` ASC");

		while ($row = $result_stmt->fetch(PDO::FETCH_ASSOC)) {
			if (isset($admin_traffic[$row['adminid']])) {
				$ins_data = [
					'adminid' => $row['adminid'],
					'year' => $current_year,
					'month' => $current_month,
					'day' => $current_day,
					'stamp' => $current_stamp,
					'http' => $admin_traffic[$row['adminid']]['http'],
					'ftp_up' => $admin_traffic[$row['adminid']]['ftp_up'],
					'ftp_down' => $admin_traffic[$row['adminid']]['ftp_down'],
					'mail' => $admin_traffic[$row['adminid']]['mail']
				];
				$ins_stmt = Database::prepare("
					INSERT INTO `" . TABLE_PANEL_TRAFFIC_ADMINS . "` SET
					`adminid` = :adminid,
					`year` = :year,
					`month` = :month,
					`day` = :day,
					`stamp` = :stamp,
					`http` = :http,
					`ftp_up` = :ftp_up,
					`ftp_down` = :ftp_down,
					`mail` = :mail
				");
				Database::pexecute($ins_stmt, $ins_data);

				$upd_data = [
					'traffic' => $admin_traffic[$row['adminid']]['sum_month'],
					'adminid' => $row['adminid']
				];
				$upd_stmt = Database::prepare("
					UPDATE `" . TABLE_PANEL_ADMINS . "` SET
					`traffic_used` = :traffic
					WHERE `adminid` = :adminid
				");
				Database::pexecute($upd_stmt, $upd_data);
			}

			if (isset($admin_diskspace[$row['adminid']])) {
				$upd_data = [
					'diskspace' => $admin_diskspace[$row['adminid']]['all'],
					'adminid' => $row['adminid']
				];
				$upd_stmt = Database::prepare("
					UPDATE `" . TABLE_PANEL_ADMINS . "` SET
					`diskspace_used` = :diskspace
					WHERE `adminid` = :adminid
				");
				Database::pexecute($upd_stmt, $upd_data);
			}
		}

		Database::query("UPDATE `" . TABLE_PANEL_SETTINGS . "` SET `value` = UNIX_TIMESTAMP() WHERE `settinggroup` = 'system' AND `varname` = 'last_traffic_run'");
	}

	/**
	 * Run goaccess to create statistics and return used traffic since last run
	 *
	 * @param int $customerid
	 * @param string $logfile Name of logfile
	 * @param string $outputdir Place where stats should be build
	 * @param string $caption Caption for webalizer output
	 * @param array $monthyear_arr
	 * @param int $current_stamp
	 *
	 * @return int Used traffic
	 */
	private static function callGoaccessGetTraffic($customerid, $logfile, $outputdir, $caption, array $monthyear_arr = [], int $current_stamp = 0)
	{
		$returnval = 0;

		$logfile = FileDir::makeCorrectFile(Settings::Get('system.logfiles_directory') . $logfile . '-access.log');
		if (file_exists($logfile)) {
			$outputdir = FileDir::makeCorrectDir($outputdir);
			if (!file_exists($outputdir)) {
				FileDir::safe_exec('mkdir -p ' . escapeshellarg($outputdir));
			}

			if (file_exists($outputdir . '.tmp.json')) {
				@unlink($outputdir . '.tmp.json');
			}

			// goaccess <1.4
			$keep_params = '--keep-db-files --load-from-disk';
			$res = FileDir::safe_exec('goaccess --version');
			$ver_str = array_shift($res);
			$cGoVer = substr($ver_str, strrpos($ver_str, " ") + 1, -1);
			if (version_compare($cGoVer, '1.4', '>=')) {
				// at least 1.4
				$keep_params = '--persist --restore';
			}

			$format = (Settings::Get('system.logfiles_type') == '2' && Settings::Get('system.webserver') == 'apache2') ? 'VCOMBINED' : 'COMBINED';
			$monthyear = $monthyear_arr['month'] . '/' . $monthyear_arr['year'];
			$return_value = false;
			FileDir::safe_exec("grep '" . $monthyear . "' " . escapeshellarg($logfile) . " | goaccess " . $keep_params . " --db-path=" . escapeshellarg($outputdir) . " -o " . escapeshellarg($outputdir . '.tmp.json') . " -o " . escapeshellarg($outputdir . 'index.html') . " --html-report-title=" . escapeshellarg($caption) . " --log-format=" . $format . " --no-parsing-spinner --no-progress - ", $return_value, ['|']);

			if (file_exists($outputdir . '.tmp.json')) {
				// need jq here because of potentially LARGE json files
				$returnval = FileDir::safe_exec("jq -c '.general.bandwidth' " . escapeshellarg($outputdir . '.tmp.json'));
				$returnval = array_shift($returnval);
				// return KB as the others two do
				$returnval = floatval($returnval / 1024);
				@unlink($outputdir . '.tmp.json');
			}
		}

		if ($returnval > 0) {
			/**
			 * now, because this traffic is being saved daily, we have to
			 * subtract the values from all the month's values to return
			 * a sane value for our panel_traffic and to remain the whole stats
			 * (awstats overwrites the customers .html stats-files)
			 */
			if ($customerid !== false) {
				$result_stmt = Database::prepare("
					SELECT SUM(`http`) as `trafficmonth` FROM `" . TABLE_PANEL_TRAFFIC . "`
					WHERE `customerid` = :customerid
					AND `year` = :year AND `month` = :month
				");
				$result_data = [
					'customerid' => $customerid,
					'year' => date('Y', $current_stamp),
					'month' => date('m', $current_stamp)
				];
				$result = Database::pexecute_first($result_stmt, $result_data);

				if (is_array($result) && isset($result['trafficmonth'])) {
					$returnval = ($returnval - floatval($result['trafficmonth']));
				}
			}
		}
		return $returnval;
	}

	/**
	 * Function which make webalizer statistics and returns used traffic since last run
	 *
	 * @param string $logfile Name of logfile
	 * @param string $outputdir Place where stats should be build
	 * @param string $caption Caption for webalizer output
	 * @param array $usersdomainlist
	 *
	 * @return float Used traffic
	 */
	private static function callWebalizerGetTraffic($logfile, $outputdir, $caption, array $usersdomainlist = [])
	{
		$returnval = 0;

		$logfile = FileDir::makeCorrectFile(Settings::Get('system.logfiles_directory') . $logfile . '-access.log');
		if (file_exists($logfile)) {
			$domainargs = '';
			foreach ($usersdomainlist as $domain) {
				// hide referer
				$domainargs .= ' -r ' . escapeshellarg($domain);
			}

			$outputdir = FileDir::makeCorrectDir($outputdir);
			if (!file_exists($outputdir)) {
				FileDir::safe_exec('mkdir -p ' . escapeshellarg($outputdir));
			}

			if (file_exists($outputdir . 'webalizer.hist.1')) {
				@unlink($outputdir . 'webalizer.hist.1');
			}

			if (file_exists($outputdir . 'webalizer.hist') && !file_exists($outputdir . 'webalizer.hist.1')) {
				FileDir::safe_exec('cp ' . escapeshellarg($outputdir . 'webalizer.hist') . ' ' . escapeshellarg($outputdir . 'webalizer.hist.1'));
			}

			$verbosity = '';
			if (Settings::Get('system.webalizer_quiet') == '1') {
				$verbosity = '-q';
			} elseif (Settings::Get('system.webalizer_quiet') == '2') {
				$verbosity = '-Q';
			}

			$we = '/usr/bin/webalizer';

			// FreeBSD uses other paths, #140
			if (!file_exists($we)) {
				$we = '/usr/local/bin/webalizer';
			}

			FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_INFO, "Running webalizer for domain '" . $caption . "'");
			FileDir::safe_exec($we . ' ' . $verbosity . ' -p -o ' . escapeshellarg($outputdir) . ' -n ' . escapeshellarg($caption) . $domainargs . ' ' . escapeshellarg($logfile));

			/**
			 * Format of webalizer.hist-files:
			 * Month: $webalizer_hist_row['0']
			 * Year: $webalizer_hist_row['1']
			 * KB: $webalizer_hist_row['5']
			 */
			$httptraffic = [];
			$webalizer_hist = @file_get_contents($outputdir . 'webalizer.hist');
			FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_INFO, "Gathering traffic information from '" . $webalizer_hist . "'");

			$webalizer_hist_rows = explode("\n", $webalizer_hist);
			foreach ($webalizer_hist_rows as $webalizer_hist_row) {
				if ($webalizer_hist_row != '') {
					$webalizer_hist_row = explode(' ', $webalizer_hist_row);

					if (isset($webalizer_hist_row['0']) && isset($webalizer_hist_row['1']) && isset($webalizer_hist_row['5'])) {
						$month = intval($webalizer_hist_row['0']);
						$year = intval($webalizer_hist_row['1']);
						$traffic = floatval($webalizer_hist_row['5']);

						if (!isset($httptraffic[$year])) {
							$httptraffic[$year] = [];
						}

						$httptraffic[$year][$month] = $traffic;
					}
				}
			}

			reset($httptraffic);
			$httptrafficlast = [];
			$webalizer_lasthist = @file_get_contents($outputdir . 'webalizer.hist.1');
			FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_INFO, "Gathering traffic information from '" . $webalizer_lasthist . "'");

			$webalizer_lasthist_rows = explode("\n", $webalizer_lasthist);
			foreach ($webalizer_lasthist_rows as $webalizer_lasthist_row) {
				if ($webalizer_lasthist_row != '') {
					$webalizer_lasthist_row = explode(' ', $webalizer_lasthist_row);

					if (isset($webalizer_lasthist_row['0']) && isset($webalizer_lasthist_row['1']) && isset($webalizer_lasthist_row['5'])) {
						$month = intval($webalizer_lasthist_row['0']);
						$year = intval($webalizer_lasthist_row['1']);
						$traffic = floatval($webalizer_lasthist_row['5']);

						if (!isset($httptrafficlast[$year])) {
							$httptrafficlast[$year] = [];
						}

						$httptrafficlast[$year][$month] = $traffic;
					}
				}
			}

			reset($httptrafficlast);
			foreach ($httptraffic as $year => $months) {
				foreach ($months as $month => $traffic) {
					if (!isset($httptrafficlast[$year][$month])) {
						$returnval += $traffic;
					} elseif ($httptrafficlast[$year][$month] < $traffic) {
						$returnval += ($traffic - $httptrafficlast[$year][$month]);
					}
				}
			}
		}

		return floatval($returnval);
	}

	private static function callAwstatsGetTraffic($customerid, $outputdir, $usersdomainlist, $current_stamp)
	{
		$returnval = 0;

		foreach ($usersdomainlist as $singledomain) {
			// as we check for the config-model awstats will only parse
			// 'real' domains and no subdomains which are aliases in the
			// model-config-file.
			$returnval += self::awstatsDoSingleDomain($singledomain, $outputdir, $current_stamp);
			// kind of a keep-alive-call as this unsets the link which leads to a new connection to the database
			Database::needRoot();
		}

		/**
		 * as of #124, awstats traffic is saved in bytes instead
		 * of kilobytes (like webalizer does)
		 */
		$returnval = floatval($returnval / 1024);

		/**
		 * now, because this traffic is being saved daily, we have to
		 * subtract the values from all the month's values to return
		 * a sane value for our panel_traffic and to remain the whole stats
		 * (awstats overwrites the customers .html stats-files)
		 */
		if ($customerid !== false) {
			$result_stmt = Database::prepare("
				SELECT SUM(`http`) as `trafficmonth` FROM `" . TABLE_PANEL_TRAFFIC . "`
				WHERE `customerid` = :customerid
				AND `year` = :year AND `month` = :month
			");
			$result_data = [
				'customerid' => $customerid,
				'year' => date('Y', $current_stamp),
				'month' => date('m', $current_stamp)
			];
			$result = Database::pexecute_first($result_stmt, $result_data);

			if (is_array($result) && isset($result['trafficmonth'])) {
				$returnval = ($returnval - floatval($result['trafficmonth']));
			}
		}

		return floatval($returnval);
	}

	private static function awstatsDoSingleDomain($domain, $outputdir, $current_stamp)
	{
		$returnval = 0;

		$domainconfig = FileDir::makeCorrectFile(Settings::Get('system.awstats_conf') . '/awstats.' . $domain . '.conf');

		if (file_exists($domainconfig)) {
			$outputdir = FileDir::makeCorrectDir($outputdir . '/' . $domain);
			$staticOutputdir = FileDir::makeCorrectDir($outputdir . '/' . date('Y') . '-' . date('m'));

			if (!is_dir($staticOutputdir)) {
				FileDir::safe_exec('mkdir -p ' . escapeshellarg($staticOutputdir));
			}

			// check for correct path of awstats_buildstaticpages.pl
			$awbsp = FileDir::makeCorrectFile(Settings::Get('system.awstats_path') . '/awstats_buildstaticpages.pl');
			$awprog = FileDir::makeCorrectFile(Settings::Get('system.awstats_awstatspath') . '/awstats.pl');

			if (!file_exists($awbsp)) {
				echo "WANRING: Necessary awstats_buildstaticpages.pl script could not be found, no traffic is being calculated and no stats are generated. Please check your AWStats-Path setting";
				FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_WARNING, "Necessary awstats_buildstaticpages.pl script could not be found, no traffic is being calculated and no stats are generated. Please check your AWStats-Path setting");
				exit();
			}

			FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_INFO, "Running awstats_buildstaticpages.pl for domain '" . $domain . "' (Output: '" . $staticOutputdir . "')");
			FileDir::safe_exec($awbsp . ' -awstatsprog=' . escapeshellarg($awprog) . ' -update -month=' . date('m', $current_stamp) . ' -year=' . date('Y', $current_stamp) . ' -config=' . $domain . ' -dir=' . escapeshellarg($staticOutputdir));

			// update our awstats index files
			self::awstatsGenerateIndex($domain, $outputdir);

			// the default selection is 'current',
			// so link the latest dir to it
			$new_current = FileDir::makeCorrectFile($outputdir . '/current');
			FileDir::safe_exec('ln -fTs ' . escapeshellarg($staticOutputdir) . ' ' . escapeshellarg($new_current));

			// statistics file looks like: 'awstats[month][year].[domain].txt'
			$file = FileDir::makeCorrectFile($outputdir . '/awstats' . date('mY', time()) . '.' . $domain . '.txt');
			FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_INFO, "Gathering traffic information from '" . $file . "'");

			if (file_exists($file)) {
				$content = @file_get_contents($file);
				if ($content !== false) {
					$content_array = explode("\n", $content);

					$count_bdw = false;
					foreach ($content_array as $line) {
						// skip empty lines and comments
						if (trim($line) == '' || substr(trim($line), 0, 1) == '#') {
							continue;
						}

						$parts = explode(' ', $line);

						if (isset($parts[0]) && strtoupper($parts[0]) == 'BEGIN_DOMAIN') {
							$count_bdw = true;
						}

						if ($count_bdw) {
							if (isset($parts[0]) && strtoupper($parts[0]) == 'END_DOMAIN') {
								$count_bdw = false;
								break;
							} elseif (isset($parts[3])) {
								$returnval += floatval($parts[3]);
							}
						}
					}
				}
			}
		}
		return $returnval;
	}

	private static function awstatsGenerateIndex($domain, $outputdir)
	{
		// Generation header
		$header = "<!-- GENERATED BY FROXLOR -->\n";

		// Looking for {year}-{month} directories
		$entries = [];
		foreach (scandir($outputdir) as $a) {
			if (is_dir(FileDir::makeCorrectDir($outputdir . '/' . $a)) && preg_match('/^[0-9]{4}-[0-9]{2}$/', $a)) {
				array_push($entries, '<option value="' . $a . '">' . $a . '</option>');
			}
		}

		// These are the variables we will replace
		$regex = [
			'/\{SITE_DOMAIN\}/',
			'/\{SELECT_ENTRIES\}/'
		];

		$replace = [
			$domain,
			implode($entries)
		];

		// File names
		$index_file = Froxlor::getInstallDir() . '/templates/misc/awstats/index.html';
		$index_file = FileDir::makeCorrectFile($index_file);
		$nav_file = Froxlor::getInstallDir() . '/templates/misc/awstats/nav.html';
		$nav_file = FileDir::makeCorrectFile($nav_file);

		// Write the index file
		// 'index.html' used to be a symlink (ignore errors in case this is the first run and no index.html exists yet)
		@unlink(FileDir::makeCorrectFile($outputdir . '/' . 'index.html'));

		$awstats_index_file = fopen(FileDir::makeCorrectFile($outputdir . '/' . 'index.html'), 'w');
		$awstats_index_tpl = fopen($index_file, 'r');

		// Write the header
		fwrite($awstats_index_file, $header);

		// Write the configuration file
		while (($line = fgets($awstats_index_tpl, 4096)) !== false) {
			if (!preg_match('/^#/', $line) && trim($line) != '') {
				fwrite($awstats_index_file, preg_replace($regex, $replace, $line));
			}
		}
		fclose($awstats_index_file);
		fclose($awstats_index_tpl);

		// Write the nav file
		$awstats_nav_file = fopen(FileDir::makeCorrectFile($outputdir . '/' . 'nav.html'), 'w');
		$awstats_nav_tpl = fopen($nav_file, 'r');

		// Write the header
		fwrite($awstats_nav_file, $header);

		// Write the configuration file
		while (($line = fgets($awstats_nav_tpl, 4096)) !== false) {
			if (!preg_match('/^#/', $line) && trim($line) != '') {
				fwrite($awstats_nav_file, preg_replace($regex, $replace, $line));
			}
		}
		fclose($awstats_nav_file);
		fclose($awstats_nav_tpl);

		return;
	}
}
