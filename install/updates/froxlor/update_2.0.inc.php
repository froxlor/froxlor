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

use Froxlor\Database\Database;
use Froxlor\FileDir;
use Froxlor\Froxlor;
use Froxlor\Install\Update;
use Froxlor\Settings;

if (!defined('_CRON_UPDATE')) {
	if (!defined('AREA') || (defined('AREA') && AREA != 'admin') || !isset($userinfo['loginname']) || (isset($userinfo['loginname']) && $userinfo['loginname'] == '')) {
		header('Location: ../../../../index.php');
		exit();
	}
}

// last 0.10.x release
if (Froxlor::isFroxlorVersion('0.10.38.3')) {
	$update_to = '2.0.0-beta1';

	Update::showUpdateStep("Updating from 0.10.38.3 to " . $update_to, false);

	Update::showUpdateStep("Removing unused table");
	Database::query("DROP TABLE IF EXISTS `panel_sessions`;");
	Database::query("DROP TABLE IF EXISTS `panel_languages`;");
	Update::lastStepStatus(0);

	Update::showUpdateStep("Updating froxlor - theme");
	Database::query("UPDATE `" . TABLE_PANEL_ADMINS . "` SET `theme` = 'Froxlor' WHERE `theme` <> 'Froxlor';");
	Database::query("UPDATE `" . TABLE_PANEL_CUSTOMERS . "` SET `theme` = 'Froxlor' WHERE `theme` <> 'Froxlor';");
	Settings::Set('panel.default_theme', 'Froxlor');
	Update::lastStepStatus(0);

	Update::showUpdateStep("Creating new tables and fields");
	Database::query("DROP TABLE IF EXISTS `panel_usercolumns`;");
	$sql = "CREATE TABLE `panel_usercolumns` (
	`adminid` int(11) NOT NULL default '0',
	`customerid` int(11) NOT NULL default '0',
	`section` varchar(500) NOT NULL default '',
	`columns` text NOT NULL,
	UNIQUE KEY `user_section` (`adminid`, `customerid`, `section`),
	KEY adminid (adminid),
	KEY customerid (customerid)
	) ENGINE=InnoDB CHARSET=utf8 COLLATE=utf8_general_ci;";
	Database::query($sql);
	// new customer allowed_mysqlserver field
	Database::query("ALTER TABLE `" . TABLE_PANEL_CUSTOMERS . "` ROW_FORMAT=DYNAMIC;");
	Database::query("ALTER TABLE `" . TABLE_PANEL_CUSTOMERS . "` CHANGE COLUMN `customernumber` `customernumber` varchar(100) NOT NULL default '';");
	Database::query("ALTER TABLE `" . TABLE_PANEL_CUSTOMERS . "` CHANGE COLUMN `allowed_phpconfigs` `allowed_phpconfigs` text NOT NULL;");
	Database::query("ALTER TABLE `" . TABLE_PANEL_CUSTOMERS . "` ADD `allowed_mysqlserver` text NOT NULL;");
	$has_customer_table_update_200 = true;
	// ftp_users adjustments
	Database::query("ALTER TABLE `" . TABLE_FTP_USERS . "` CHANGE COLUMN `password` `password` varchar(255) NOT NULL default '';");
	Database::query("ALTER TABLE `" . TABLE_FTP_QUOTALIMITS . "` CHANGE COLUMN `name` `name` varchar(255) default NULL;");
	Database::query("ALTER TABLE `" . TABLE_FTP_QUOTATALLIES . "` CHANGE COLUMN `name` `name` varchar(255) default NULL;");
	// mail_users adjustments
	Database::query("ALTER TABLE `" . TABLE_MAIL_USERS . "` CHANGE COLUMN `password` `password` varchar(255) NOT NULL default '';");
	Database::query("ALTER TABLE `" . TABLE_MAIL_USERS . "` CHANGE COLUMN `password_enc` `password_enc` varchar(255) NOT NULL default '';");
	// drop domains_see_all field from panel_admins
	Database::query("ALTER TABLE `" . TABLE_PANEL_ADMINS . "` DROP COLUMN `domains_see_all`;");
	Update::lastStepStatus(0);

	Update::showUpdateStep("Checking for multiple mysql-servers to allow access to customers for existing databases");
	$dbservers_stmt = Database::query("
		SELECT `customerid`,
		GROUP_CONCAT(DISTINCT `dbserver` SEPARATOR ',') as allowed_mysqlserver
		FROM `" . TABLE_PANEL_DATABASES . "`
		GROUP BY `customerid`;
	");
	$upd_stmt = Database::prepare("UPDATE `" . TABLE_PANEL_CUSTOMERS . "` SET `allowed_mysqlserver` = :allowed_mysqlserver WHERE `customerid` = :customerid");
	while ($dbserver = $dbservers_stmt->fetch(PDO::FETCH_ASSOC)) {
		if (isset($dbserver['allowed_mysqlserver']) && !empty($dbserver['allowed_mysqlserver'])) {
			$allowed_mysqlserver = json_encode(explode(",", $dbserver['allowed_mysqlserver']));
			Database::pexecute($upd_stmt,
				['allowed_mysql_server' => $allowed_mysqlserver, 'customerid' => $dbserver['customerid']]);
		}
	}
	Update::lastStepStatus(0);

	$to_clean = array(
		"install/lib",
		"install/lng",
		"install/updates/froxlor/0.9",
		"install/updates/froxlor/0.10",
		"install/updates/preconfig/0.9",
		"install/updates/preconfig/0.10",
		"install/updates/preconfig.php",
		"templates/Sparkle",
		"lib/version.inc.php",
		"lng/czech.lng.php",
		"lng/dutch.lng.php",
		"lng/english.lng.php",
		"lng/french.lng.php",
		"lng/german.lng.php",
		"lng/italian.lng.php",
		"lng/lng_references.php",
		"lng/portugues.lng.php",
		"lng/swedish.lng.php",
		"scripts",
	);
	Update::cleanOldFiles($to_clean);

	Update::showUpdateStep("Adding new settings");
	$panel_settings_mode = isset($_POST['panel_settings_mode']) ? (int)$_POST['panel_settings_mode'] : 0;
	Settings::AddNew("panel.settings_mode", $panel_settings_mode);
	$system_distribution = isset($_POST['system_distribution']) ? $_POST['system_distribution'] : 'bullseye';
	Settings::AddNew("system.distribution", $system_distribution);
	Settings::AddNew("system.update_channel", 'stable');
	Settings::AddNew("system.updatecheck_data", '');
	Settings::AddNew("system.update_notify_last", $update_to);
	Settings::AddNew("panel.phpconfigs_hidesubdomains", '1');
	Update::lastStepStatus(0);

	Update::showUpdateStep("Adjusting existing settings");
	Settings::Set('system.passwordcryptfunc', PASSWORD_DEFAULT);
	// remap default-language
	$lang_map = [
		'Deutsch' => 'de',
		'English' => 'en',
		'Fran&ccedil;ais' => 'fr',
		'Portugu&ecirc;s' => 'pt',
		'Italiano' => 'it',
		'Nederlands' => 'nl',
		'Svenska' => 'se',
		'&#268;esk&aacute; republika' => 'cz'
	];
	// update user default languages
	$upd_adm_stmt = Database::prepare("UPDATE `" . TABLE_PANEL_ADMINS . "` SET `def_language` = :nv WHERE `def_language` = :ov");
	$upd_cus_stmt = Database::prepare("UPDATE `" . TABLE_PANEL_CUSTOMERS . "` SET `def_language` = :nv WHERE `def_language` = :ov");
	foreach ($lang_map as $old_val => $new_val) {
		Database::pexecute($upd_adm_stmt, ['nv' => $new_val, 'ov' => $old_val]);
		Database::pexecute($upd_cus_stmt, ['nv' => $new_val, 'ov' => $old_val]);
	}
	Settings::Set('panel.standardlanguage', $lang_map[Settings::Get('panel_standardlanguage')] ?? 'en');
	Database::query("DELETE FROM `" . TABLE_PANEL_SETTINGS . "` WHERE `settinggroup` = 'system' AND `varname` = 'debug_cron'");
	Database::query("DELETE FROM `" . TABLE_PANEL_SETTINGS . "` WHERE `settinggroup` = 'system' AND `varname` = 'letsencryptcountrycode'");
	Database::query("DELETE FROM `" . TABLE_PANEL_SETTINGS . "` WHERE `settinggroup` = 'system' AND `varname` = 'letsencryptstate'");
	Update::lastStepStatus(0);

	Update::showUpdateStep("Updating email account password-hashes");
	Database::query("UPDATE `" . TABLE_MAIL_USERS . "` SET `password_enc` = REPLACE(`password_enc`, '$1$', '{MD5-CRYPT}$1$') WHERE SUBSTRING(`password_enc`, 1, 3) = '$1$'");
	Database::query("UPDATE `" . TABLE_MAIL_USERS . "` SET `password_enc` = REPLACE(`password_enc`, '$5$', '{SHA256-CRYPT}$5$') WHERE SUBSTRING(`password_enc`, 1, 3) = '$5$'");
	Database::query("UPDATE `" . TABLE_MAIL_USERS . "` SET `password_enc` = REPLACE(`password_enc`, '$6$', '{SHA512-CRYPT}$6$') WHERE SUBSTRING(`password_enc`, 1, 3) = '$6$'");
	Database::query("UPDATE `" . TABLE_MAIL_USERS . "` SET `password_enc` = REPLACE(`password_enc`, '$2y$', '{BLF-CRYPT}$2y$') WHERE SUBSTRING(`password_enc`, 1, 4) = '$2y$'");
	Update::lastStepStatus(0);

	Froxlor::updateToVersion($update_to);
}

if (Froxlor::isDatabaseVersion('202112310')) {
	Update::showUpdateStep("Adjusting traffic tool settings");
	$traffic_tool = Settings::Get('system.awstats_enabled') == 1 ? 'awstats' : 'webalizer';
	Settings::AddNew("system.traffictool", $traffic_tool);
	Database::query("DELETE FROM `" . TABLE_PANEL_SETTINGS . "` WHERE `settinggroup` = 'system' AND `varname` = 'awstats_enabled'");
	Update::lastStepStatus(0);

	Froxlor::updateToDbVersion('202211030');
}

if (Froxlor::isDatabaseVersion('202211030')) {
	Update::showUpdateStep("Creating backward compatibility for cronjob");
	$disabled = explode(',', ini_get('disable_functions'));
	$exec_allowed = !in_array('exec', $disabled);
	// check whether old files could be deleted in previous updates and if not,
	// user should run cron to regenerate cron.d-file manually as he will run
	// the other commands manually only after the update so this file would be deleted too
	if ($exec_allowed) {
		$complete_filedir = Froxlor::getInstallDir() . '/scripts';
		mkdir($complete_filedir, 0750, true);
		$newCronBin = Froxlor::getInstallDir() . '/bin/froxlor-cli';
		$compCron = <<<EOF
<?php
chmod('$newCronBin', 0755);
// re-create cron.d configuration file
exec('$newCronBin froxlor:cron -r 99');
exit;
EOF;
		file_put_contents($complete_filedir . '/froxlor_master_cronjob.php', $compCron);
		Update::lastStepStatus(0);
	} else {
		$cron_run_cmd = 'chmod +x ' . FileDir::makeCorrectFile(Froxlor::getInstallDir() . '/bin/froxlor-cli') . PHP_EOL;
		$cron_run_cmd .= FileDir::makeCorrectFile(Froxlor::getInstallDir() . '/bin/froxlor-cli') . ' froxlor:cron -r 99';
		Update::lastStepStatus(1, 'manual commands needed',
			'Please run the following commands manually:<br><pre>' . $cron_run_cmd . '</pre>');
	}

	Froxlor::updateToDbVersion('202212060');
}

if (Froxlor::isFroxlorVersion('2.0.0-beta1')) {
	Update::showUpdateStep("Updating from 2.0.0-beta1 to 2.0.0", false);
	Froxlor::updateToVersion('2.0.0');
}

if (Froxlor::isFroxlorVersion('2.0.0')) {
	Update::showUpdateStep("Updating from 2.0.0 to 2.0.1", false);

	if (!isset($has_customer_table_update_200)) {
		Update::showUpdateStep("Creating new tables and fields");
		// new customer allowed_mysqlserver field
		Database::query("ALTER TABLE `" . TABLE_PANEL_CUSTOMERS . "` CHANGE COLUMN `allowed_mysqlserver` `allowed_mysqlserver` text NOT NULL;");
		Database::query("ALTER TABLE `" . TABLE_PANEL_CUSTOMERS . "` CHANGE COLUMN `allowed_phpconfigs` `allowed_phpconfigs` text NOT NULL;");
		Database::query("ALTER TABLE `" . TABLE_PANEL_CUSTOMERS . "` CHANGE COLUMN `customernumber` `customernumber` varchar(100) NOT NULL default '';");
		Update::lastStepStatus(0);
	}

	Froxlor::updateToVersion('2.0.1');
}

if (Froxlor::isFroxlorVersion('2.0.1')) {
	Update::showUpdateStep("Updating from 2.0.1 to 2.0.2", false);
	Froxlor::updateToVersion('2.0.2');
}

if (Froxlor::isFroxlorVersion('2.0.2')) {
	Update::showUpdateStep("Updating from 2.0.2 to 2.0.3", false);
	Froxlor::updateToVersion('2.0.3');
}

if (Froxlor::isFroxlorVersion('2.0.3')) {
	Update::showUpdateStep("Updating from 2.0.3 to 2.0.4", false);

	$complete_filedir = Froxlor::getInstallDir() . '/scripts';
	// check if compat. cronjob still exists (most likely didn't run successfully b/c of error from former 2.0 release)
	if (@file_exists($complete_filedir . '/froxlor_master_cronjob.php')) {
		Update::showUpdateStep("Adjusting backward compatibility for cronjob");
		$disabled = explode(',', ini_get('disable_functions'));
		$exec_allowed = !in_array('exec', $disabled);
		if ($exec_allowed) {
			$newCronBin = Froxlor::getInstallDir() . '/bin/froxlor-cli';
			$compCron = <<<EOF
<?php
chmod('$newCronBin', 0755);
// re-create cron.d configuration file
exec('$newCronBin froxlor:cron -r 99');
exit;
EOF;
			file_put_contents($complete_filedir . '/froxlor_master_cronjob.php', $compCron);
			Update::lastStepStatus(0);
		} else {
			$cron_run_cmd = 'chmod +x ' . FileDir::makeCorrectFile(Froxlor::getInstallDir() . '/bin/froxlor-cli') . PHP_EOL;
			$cron_run_cmd .= FileDir::makeCorrectFile(Froxlor::getInstallDir() . '/bin/froxlor-cli') . ' froxlor:cron -r 99';
			Update::lastStepStatus(1, 'manual commands needed',
				'Please run the following commands manually:<br><pre>' . $cron_run_cmd . '</pre>');
		}
	}
	Froxlor::updateToVersion('2.0.4');
}

if (Froxlor::isFroxlorVersion('2.0.4')) {
	Update::showUpdateStep("Updating from 2.0.4 to 2.0.5", false);
	Froxlor::updateToVersion('2.0.5');
}

if (Froxlor::isFroxlorVersion('2.0.5')) {
	Update::showUpdateStep("Updating from 2.0.5 to 2.0.6", false);

	Update::showUpdateStep("Updating possible missing email account password-hashes");
	Database::query("UPDATE `" . TABLE_MAIL_USERS . "` SET `password_enc` = REPLACE(`password_enc`, '$1$', '{MD5-CRYPT}$1$') WHERE SUBSTRING(`password_enc`, 1, 3) = '$1$'");
	Database::query("UPDATE `" . TABLE_MAIL_USERS . "` SET `password_enc` = REPLACE(`password_enc`, '$5$', '{SHA256-CRYPT}$5$') WHERE SUBSTRING(`password_enc`, 1, 3) = '$5$'");
	Database::query("UPDATE `" . TABLE_MAIL_USERS . "` SET `password_enc` = REPLACE(`password_enc`, '$6$', '{SHA512-CRYPT}$6$') WHERE SUBSTRING(`password_enc`, 1, 3) = '$6$'");
	Database::query("UPDATE `" . TABLE_MAIL_USERS . "` SET `password_enc` = REPLACE(`password_enc`, '$2y$', '{BLF-CRYPT}$2y$') WHERE SUBSTRING(`password_enc`, 1, 4) = '$2y$'");
	Update::lastStepStatus(0);

	Froxlor::updateToVersion('2.0.6');
}

if (Froxlor::isFroxlorVersion('2.0.6')) {
	Update::showUpdateStep("Updating from 2.0.6 to 2.0.7", false);

	Update::showUpdateStep("Correcting allowed_mysqlserver for customers");
	Database::query("UPDATE `" . TABLE_PANEL_CUSTOMERS . "` SET `allowed_mysqlserver` = '[0]' WHERE `allowed_mysqlserver` = ''");
	Update::lastStepStatus(0);

	Froxlor::updateToVersion('2.0.7');
}

if (Froxlor::isDatabaseVersion('202212060')) {
	Update::showUpdateStep("Validating acme.sh challenge path");
	$acmesh_challenge_dir = Settings::Get('system.letsencryptchallengepath');
	$system_letsencryptchallengepath_upd = isset($_POST['system_letsencryptchallengepath_upd']) ? $_POST['system_letsencryptchallengepath_upd'] : $acmesh_challenge_dir;
	if ($acmesh_challenge_dir != $system_letsencryptchallengepath_upd) {
		Settings::Set('system.letsencryptchallengepath', $system_letsencryptchallengepath_upd);
		if ((int)Settings::Get('system.leenabled') == 1) {
			// create JSON string for --apply
			$dist = Settings::Get('system.distribution');
			$webserver = Settings::Get('system.webserver');
			if ($webserver == 'apache2') {
				$webserver = 'apache22';
				if (Settings::Get('system.apache24')) {
					$webserver = 'apache24';
				}
			}
			$apply_json = '{"http":"' . $webserver . '","dns":"x","smtp":"x","mail":"x","ftp":"x","distro":"' . $dist . '","system":[]}';
			Update::lastStepStatus(1, 'manual commands needed',
				"Please reconfigure webserver service using <pre>bin/froxlor-cli froxlor:config-services --apply='" . $apply_json . "'</pre>" .
				'<br>or adjust the path manually in <pre>' . Settings::Get('system.letsencryptacmeconf') . '</pre>' .
				'<br><br>In case you already have certificates issued, run the following command to validate and correct the webroot used for renewal:<br>' .
				'<pre>bin/froxlor-cli froxlor:validate-acme-webroot</pre><br>'
			);
		} else {
			Update::lastStepStatus(0);
		}
	} else {
		Update::lastStepStatus(0);
	}

	Froxlor::updateToDbVersion('202301120');
}

if (Froxlor::isFroxlorVersion('2.0.7')) {
	Update::showUpdateStep("Updating from 2.0.7 to 2.0.8", false);

	// adjust file-logging to be set to froxlor/logs/
	$logtypes = explode(',', Settings::Get('logger.logtypes'));
	if (in_array('file', $logtypes)) {
		Update::showUpdateStep("Adjusting froxlor logfile for system-logging to be stored in logs/froxlor.log");
		Settings::Set('logger.logfile', 'froxlor.log');
		Update::lastStepStatus(0);
	}

	Froxlor::updateToVersion('2.0.8');
}

if (Froxlor::isDatabaseVersion('202301120')) {
	Update::showUpdateStep("Adding new setting for DNS resolver when using Let's Encrypt");
	$system_le_domain_dnscheck_resolver = isset($_POST['system_le_domain_dnscheck_resolver']) ? $_POST['system_le_domain_dnscheck_resolver'] : '1.1.1.1';
	Settings::AddNew("system.le_domain_dnscheck_resolver", $system_le_domain_dnscheck_resolver);
	Update::lastStepStatus(0);

	Froxlor::updateToDbVersion('202301180');
}

if (Froxlor::isFroxlorVersion('2.0.8')) {
	Update::showUpdateStep("Updating from 2.0.8 to 2.0.9", false);
	Froxlor::updateToVersion('2.0.9');
}

if (Froxlor::isFroxlorVersion('2.0.9')) {
	Update::showUpdateStep("Updating from 2.0.9 to 2.0.10", false);
	Froxlor::updateToVersion('2.0.10');
}

if (Froxlor::isDatabaseVersion('202301180')) {
	Update::showUpdateStep("Adding new setting for 'Allow API access' default value for new customers");
	Settings::AddNew("api.customer_default", "1");
	Update::lastStepStatus(0);

	Froxlor::updateToDbVersion('202302030');
}

if (Froxlor::isFroxlorVersion('2.0.10')) {
	Update::showUpdateStep("Updating from 2.0.10 to 2.0.11", false);
	Froxlor::updateToVersion('2.0.11');
}

if (Froxlor::isFroxlorVersion('2.0.11')) {
	Update::showUpdateStep("Updating from 2.0.11 to 2.0.12", false);
	Froxlor::updateToVersion('2.0.12');
}

if (Froxlor::isFroxlorVersion('2.0.12')) {
	Update::showUpdateStep("Updating from 2.0.12 to 2.0.13", false);
	Froxlor::updateToVersion('2.0.13');
}

if (Froxlor::isDatabaseVersion('202302030')) {
	Update::showUpdateStep("Correcting language mapping of templates created pre 2.0.x");
	// languages from 0.10.x
	$language_mapping_comp = [
		'de' => 'Deutsch',
		'en' => 'English',
		'fr' => 'Fran&ccedil;ais',
		'pt' => 'Portugu&ecirc;s',
		'it' => 'Italiano',
		'nl' => 'Nederlands',
		'se' => 'Svenska',
		'cz' => '&#268;esk&aacute; republika'
	];
	$upd_tpl_stmt = Database::prepare("UPDATE `" . TABLE_PANEL_TEMPLATES . "` SET `language` = :iso WHERE `language` = :lng");
	foreach ($language_mapping_comp as $iso => $lang) {
		Database::pexecute($upd_tpl_stmt, ['iso' => $iso, 'lng' => $lang]);
	}
	Update::lastStepStatus(0);

	Update::showUpdateStep("Enhancing ssl data table");
	Database::query("ALTER TABLE `" . TABLE_PANEL_DOMAIN_SSL_SETTINGS . "` CHANGE `expirationdate` `validtodate` datetime DEFAULT NULL;");
	Database::query("ALTER TABLE `" . TABLE_PANEL_DOMAIN_SSL_SETTINGS . "` ADD `validfromdate` datetime DEFAULT NULL AFTER `ssl_fullchain_file`;");
	Database::query("ALTER TABLE `" . TABLE_PANEL_DOMAIN_SSL_SETTINGS . "` ADD `issuer` varchar(255) NOT NULL default '' AFTER `validtodate`;");
	Update::lastStepStatus(0);

	Update::showUpdateStep("Filling new ssl data fields with existing certificate data");
	$crt_upd_stmt = Database::prepare("UPDATE `" . TABLE_PANEL_DOMAIN_SSL_SETTINGS . "` SET `validfromdate` = :validfromdate, `issuer` = :issuer WHERE `id` = :id");
	$crt_stmt = Database::prepare("SELECT * FROM `" . TABLE_PANEL_DOMAIN_SSL_SETTINGS . "`");
	Database::pexecute($crt_stmt);
	while ($cert = $crt_stmt->fetch(\PDO::FETCH_ASSOC)) {
		$cert_content = openssl_x509_parse($cert['ssl_cert_file']);
		if (is_array($cert_content)) {
			$validfromdate = empty($cert_content['validFrom_time_t']) ? null : date("Y-m-d H:i:s", $cert_content['validFrom_time_t']);
			$issuer = $cert_content['issuer']['O'] ?? "";
			Database::pexecute($crt_upd_stmt, ['validfromdate' => $validfromdate, 'issuer' => $issuer, 'id' => $cert['id']]);
		}
	}
	// clear possible user customized columns
	Database::query("DELETE FROM `" . TABLE_PANEL_USERCOLUMNS . "` WHERE `section` = 'sslcertificates_list'");
	Update::lastStepStatus(0);

	Froxlor::updateToDbVersion('202303150');
}

if (Froxlor::isFroxlorVersion('2.0.13')) {
	Update::showUpdateStep("Updating from 2.0.13 to 2.0.14", false);
	Froxlor::updateToVersion('2.0.14');
}

if (Froxlor::isFroxlorVersion('2.0.14')) {
	Update::showUpdateStep("Updating from 2.0.14 to 2.0.15", false);
	Froxlor::updateToVersion('2.0.15');
}

if (Froxlor::isDatabaseVersion('202303150')) {
	Update::showUpdateStep("Adding new request rate limit settings");
	Settings::AddNew("system.req_limit_per_interval", "60");
	Settings::AddNew("system.req_limit_interval", "60");
	Update::lastStepStatus(0);

	Froxlor::updateToDbVersion('202304260');
}

if (Froxlor::isFroxlorVersion('2.0.15')) {
	Update::showUpdateStep("Updating from 2.0.15 to 2.0.16", false);
	Froxlor::updateToVersion('2.0.16');
}

if (Froxlor::isFroxlorVersion('2.0.16')) {
	Update::showUpdateStep("Updating from 2.0.16 to 2.0.17", false);
	Froxlor::updateToVersion('2.0.17');
}

if (Froxlor::isFroxlorVersion('2.0.17')) {
	Update::showUpdateStep("Updating from 2.0.17 to 2.0.18", false);
	Froxlor::updateToVersion('2.0.18');
}

if (Froxlor::isFroxlorVersion('2.0.18')) {
	Update::showUpdateStep("Updating from 2.0.18 to 2.0.19", false);
	Froxlor::updateToVersion('2.0.19');
}

if (Froxlor::isFroxlorVersion('2.0.19')) {
	Update::showUpdateStep("Updating from 2.0.19 to 2.0.20", false);
	Froxlor::updateToVersion('2.0.20');
}

if (Froxlor::isFroxlorVersion('2.0.20')) {
	Update::showUpdateStep("Updating from 2.0.20 to 2.0.21", false);
	Froxlor::updateToVersion('2.0.21');
}

if (Froxlor::isFroxlorVersion('2.0.21')) {
	Update::showUpdateStep("Updating from 2.0.21 to 2.0.22", false);
	Froxlor::updateToVersion('2.0.22');
}

if (Froxlor::isFroxlorVersion('2.0.22')) {
	Update::showUpdateStep("Updating from 2.0.22 to 2.0.23", false);
	Froxlor::updateToVersion('2.0.23');
}

if (Froxlor::isFroxlorVersion('2.0.23')) {
	Update::showUpdateStep("Updating from 2.0.23 to 2.0.24", false);
	Froxlor::updateToVersion('2.0.24');
}
