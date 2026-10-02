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

namespace Froxlor\Cron;

use Froxlor\Database\Database;
use Froxlor\FileDir;
use Froxlor\Froxlor;
use Froxlor\Settings;
use PDO;

class CronConfig
{

	/**
	 * 1st: check for task of generation
	 * 2nd: if task found, generate cron.d-file
	 * 3rd: maybe restart cron?
	 */
	public static function checkCrondConfigurationFile()
	{
		// check for task
		Database::query("
			SELECT * FROM `" . TABLE_PANEL_TASKS . "` WHERE `type` = '99'
		");
		$num_results = Database::num_rows();

		// is there a task for re-generating the cron.d-file?
		if ($num_results > 0) {
			// get all crons and their intervals
			if (FileDir::isFreeBSD()) {
				// FreeBSD does not need a header as we are writing directly to the crontab
				$cronfile = "\n";
			} else {
				$cronfile = "# automatically generated cron-configuration by froxlor\n";
				$cronfile .= "# do not manually edit this file as it will be re-generated periodically.\n";
				$cronfile .= "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n#\n";
			}

			// get all the crons
			$result_stmt = Database::query("
				SELECT * FROM `" . TABLE_PANEL_CRONRUNS . "` WHERE `isactive` = '1'
			");

			$binpath = Settings::Get("system.croncmdline");
			// fallback as it is important
			if ($binpath === null) {
				$binpath = "/usr/bin/nice -n 5 /usr/bin/php -q";
			}

			$hour_delay = 0;
			$day_delay = 5;
			$month_delay = 7;
			while ($row_cronentry = $result_stmt->fetch(PDO::FETCH_ASSOC)) {
				// create cron.d-entry
				$matches = [];
				if (preg_match("/(\d+) (MINUTE|HOUR|DAY|WEEK|MONTH)/", $row_cronentry['interval'], $matches)) {
					if ($matches[1] == 1) {
						$minvalue = "*";
					} else {
						$minvalue = "*/" . $matches[1];
					}
					switch ($matches[2]) {
						case "MINUTE":
							$cronfile .= $minvalue . " * * * * ";
							break;
						case "HOUR":
							$cronfile .= $hour_delay . " " . $minvalue . " * * * ";
							$hour_delay += 3;
							break;
						case "DAY":
							if ($row_cronentry['cronfile'] == 'traffic') {
								// traffic at exactly 0:00 o'clock
								$cronfile .= "0 0 " . $minvalue . " * * ";
							} else {
								$cronfile .= $day_delay . " 0 " . $minvalue . " * * ";
								$day_delay += 5;
							}
							break;
						case "MONTH":
							$cronfile .= $month_delay . " 0 1 " . $minvalue . " * ";
							$month_delay += 7;
							break;
						case "WEEK":
							$cronfile .= $day_delay . " 0 " . ($matches[1] * 7) . " * * ";
							$day_delay += 5;
							break;
					}

					// create entry-line
					$cronfile .= "root " . $binpath . " " . FileDir::makeCorrectFile(Froxlor::getInstallDir() . "/bin/froxlor-cli") . " froxlor:cron " . escapeshellarg($row_cronentry['cronfile']) . " -q 1> /dev/null\n";
				}
			}

			// php sessionclean if enabled
			if ((int)Settings::Get('phpfpm.enabled') == 1) {
				$cronfile .= "# Look for and purge old sessions every 30 minutes" . PHP_EOL;
				$cronfile .= "09,39 * * * * root " . $binpath . " " . FileDir::makeCorrectFile(Froxlor::getInstallDir() . "/bin/froxlor-cli") . " froxlor:php-sessionclean 1> /dev/null" . PHP_EOL;
			}

			if (FileDir::isFreeBSD()) {
				// FreeBSD handles the cron-stuff in another way. We need to directly
				// write to the crontab file as there is not cron.d/froxlor file
				// (settings for system.cronconfig should be set correctly of course)
				$crontab = file_get_contents(Settings::Get("system.cronconfig"));

				if ($crontab === false) {
					die("Oh snap, we cannot read the crontab file. This should not happen.\nPlease check the path and permissions, the cron will keep trying if you don't stop the cron-service.\n\n");
				}

				// now parse out / replace our entries
				$crontablines = explode("\n", $crontab);
				$newcrontab = "";
				foreach ($crontablines as $ctl) {
					$ctl = trim($ctl);
					if (!empty($ctl) && !preg_match("/(.*)froxlor\:cron(.*)/", $ctl)) {
						$newcrontab .= $ctl . "\n";
					}
				}

				// re-assemble old-content + new froxlor-content
				$newcrontab .= $cronfile;

				// now continue with writing the file
				$cronfile = $newcrontab;
			}

			// write the file
			if (file_put_contents(Settings::Get("system.cronconfig"), $cronfile) === false) {
				// oh snap cannot create new crond-file
				die("Oh snap, we cannot create the cron-file. This should not happen.\nPlease check the path and permissions, the cron will keep trying if you don't stop the cron-service.\n\n");
			}
			// correct permissions
			chmod(Settings::Get("system.cronconfig"), 0640);

			// remove all re-generation tasks
			Database::query("DELETE FROM `" . TABLE_PANEL_TASKS . "` WHERE `type` = '99'");

			// run reload command
			FileDir::safe_exec(escapeshellcmd(Settings::Get('system.crondreload')));
		}
		return true;
	}
}
