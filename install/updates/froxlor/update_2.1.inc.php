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

if (Froxlor::isFroxlorVersion('2.0.24')) {
	Update::showUpdateStep("Cleaning domains table");
	Database::query("ALTER TABLE `" . TABLE_PANEL_DOMAINS . "` ROW_FORMAT=DYNAMIC;");
	Database::query("ALTER TABLE `" . TABLE_PANEL_DOMAINS . "` DROP COLUMN `ismainbutsubto`;");
	Update::lastStepStatus(0);

	Update::showUpdateStep("Creating new tables and fields");
	Database::query("DROP TABLE IF EXISTS `panel_loginlinks`;");
	$sql = "CREATE TABLE `panel_loginlinks` (
	  `hash` varchar(500) NOT NULL,
	  `loginname` varchar(50) NOT NULL,
	  `valid_until` int(15) NOT NULL,
	  `allowed_from` text NOT NULL,
	  UNIQUE KEY `loginname` (`loginname`)
	) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_general_ci;";
	Database::query($sql);
	Update::lastStepStatus(0);

	Update::showUpdateStep("Adding new settings");
	Settings::AddNew('panel.menu_collapsed', 1);
	Update::lastStepStatus(0);

	Update::showUpdateStep("Adjusting setting for deactivated webroot");
	$current_deactivated_webroot = Settings::Get('system.deactivateddocroot');
	if (empty($current_deactivated_webroot)) {
		Settings::Set('system.deactivateddocroot', FileDir::makeCorrectDir(Froxlor::getInstallDir() . '/templates/misc/deactivated/'));
		Update::lastStepStatus(0);
	} else {
		Update::lastStepStatus(1, 'Customized setting, not changing');
	}

	Update::showUpdateStep("Adjusting cronjobs");
	$cfupd_stmt = Database::prepare("
        UPDATE `" . TABLE_PANEL_CRONRUNS . "` SET
        `module`= 'froxlor/export',
        `cronfile` = 'export',
        `cronclass` = :cc,
        `interval` = '1 HOUR',
        `desc_lng_key` = 'cron_export'
        WHERE `module` = 'froxlor/backup'
    ");
	Database::pexecute($cfupd_stmt, [
		'cc' => '\\Froxlor\\Cron\\System\\ExportCron'
	]);
	Update::lastStepStatus(0);

	Update::showUpdateStep("Adjusting system for data-export function");
	Database::query("UPDATE `" . TABLE_PANEL_SETTINGS . "`SET `varname` = 'exportenabled' WHERE `settinggroup`= 'system' AND `varname`= 'backupenabled'");
	Database::query("UPDATE `" . TABLE_PANEL_SETTINGS . "`SET `value` = REPLACE(`value`, 'extras.backup', 'extras.export') WHERE `settinggroup` = 'panel' AND `varname` = 'customer_hide_options'");
	Database::query("DELETE FROM `" . TABLE_PANEL_USERCOLUMNS . "` WHERE `section` = 'backup_list'");
	Database::query("DELETE FROM `" . TABLE_PANEL_TASKS . "` WHERE `type` = '20'");
	Update::lastStepStatus(0);

	Froxlor::updateToDbVersion('202305240');
	Froxlor::updateToVersion('2.1.0-dev1');
}

if (Froxlor::isFroxlorVersion('2.1.0-dev1')) {
	Update::showUpdateStep("Updating from 2.1.0-dev1 to 2.1.0-beta1", false);
	Froxlor::updateToVersion('2.1.0-beta1');
}

if (Froxlor::isFroxlorVersion('2.1.0-beta1')) {
	Update::showUpdateStep("Updating from 2.1.0-beta1 to 2.1.0-beta2", false);

	Update::showUpdateStep("Removing unused table");
	Database::query("DROP TABLE IF EXISTS `panel_sessions`;");
	Update::lastStepStatus(0);

	Froxlor::updateToVersion('2.1.0-beta2');
}

if (Froxlor::isFroxlorVersion('2.1.0-beta2')) {
	Update::showUpdateStep("Updating from 2.1.0-beta2 to 2.1.0-rc1", false);
	Froxlor::updateToVersion('2.1.0-rc1');
}

if (Froxlor::isFroxlorVersion('2.1.0-rc1')) {
	Update::showUpdateStep("Updating from 2.1.0-rc1 to 2.1.0-rc2", false);

	Update::showUpdateStep("Adjusting setting spf_entry");
	$spf_entry = Settings::Get('spf.spf_entry');
	if (!preg_match('/^v=spf[a-z0-9:~?\s.-]+$/i', $spf_entry)) {
		Settings::Set('spf.spf_entry', 'v=spf1 a mx -all');
		Update::lastStepStatus(1, 'corrected');
	} else {
		Update::lastStepStatus(0);
	}

	Froxlor::updateToVersion('2.1.0-rc2');
}

if (Froxlor::isDatabaseVersion('202305240')) {

	Update::showUpdateStep("Adjusting file-template file extension setttings");
	$current_fileextension = Settings::Get('system.index_file_extension');
	Database::query("DELETE FROM `" . TABLE_PANEL_SETTINGS . "` WHERE `settinggroup`= 'system' AND `varname`= 'index_file_extension'");
	Database::query("ALTER TABLE `" . TABLE_PANEL_TEMPLATES . "` ADD `file_extension` varchar(50) NOT NULL default 'html';");
	if (!empty(trim($current_fileextension)) && strtolower(trim($current_fileextension)) != 'html') {
		$stmt = Database::prepare("UPDATE `" . TABLE_PANEL_TEMPLATES . "` SET `file_extension` = :ext WHERE `templategroup` = 'files'");
		Database::pexecute($stmt, ['ext' => strtolower(trim($current_fileextension))]);
	}
	Update::lastStepStatus(0);

	Froxlor::updateToDbVersion('202311260');
}

if (Froxlor::isFroxlorVersion('2.1.0-rc2')) {
	Update::showUpdateStep("Updating from 2.1.0-rc2 to 2.1.0-rc3", false);
	Froxlor::updateToVersion('2.1.0-rc3');
}

if (Froxlor::isDatabaseVersion('202311260')) {
	$to_clean = array(
		"install/updates/froxlor/update_2.x.inc.php",
		"install/updates/preconfig/preconfig_2.x.inc.php",
		"lib/Froxlor/Api/Commands/CustomerBackups.php",
		"lib/Froxlor/Cli/Action",
		"lib/Froxlor/Cli/Action.php",
		"lib/Froxlor/Cli/CmdLineHandler.php",
		"lib/Froxlor/Cli/ConfigServicesCmd.php",
		"lib/Froxlor/Cli/PhpSessioncleanCmd.php",
		"lib/Froxlor/Cli/SwitchServerIpCmd.php",
		"lib/Froxlor/Cli/UpdateCliCmd.php",
		"lib/Froxlor/Cron/System/BackupCron.php",
		"lib/formfields/customer/extras/formfield.backup.php",
		"lib/tablelisting/customer/tablelisting.backups.php",
		"templates/Froxlor/assets/mix-manifest.json",
		"templates/Froxlor/assets/css",
		"templates/Froxlor/assets/webfonts",
		"templates/Froxlor/assets/js/main.js",
		"templates/Froxlor/assets/js/main.js.LICENSE.txt",
		"templates/Froxlor/src",
		"templates/Froxlor/user/change_language.html.twig",
		"templates/Froxlor/user/change_password.html.twig",
		"templates/Froxlor/user/change_theme.html.twig",
		"tests/Backup/CustomerBackupsTest.php"
	);
	Update::cleanOldFiles($to_clean);

	Froxlor::updateToDbVersion('202312050');
}

if (Froxlor::isFroxlorVersion('2.1.0-rc3')) {
	Update::showUpdateStep("Updating from 2.1.0-rc3 to 2.1.0 stable", false);
	Froxlor::updateToVersion('2.1.0');
}

if (Froxlor::isFroxlorVersion('2.1.0')) {
	Update::showUpdateStep("Updating from 2.1.0 to 2.1.1", false);
	Froxlor::updateToVersion('2.1.1');
}

if (Froxlor::isDatabaseVersion('202312050')) {
	$to_clean = array(
		"lib/configfiles/centos7.xml",
		"lib/configfiles/centos8.xml",
		"lib/configfiles/stretch.xml",
		"lib/configfiles/xenial.xml",
		"lib/configfiles/buster.xml",
		"lib/configfiles/bionic.xml",
	);
	Update::cleanOldFiles($to_clean);

	Froxlor::updateToDbVersion('202312100');
}

if (Froxlor::isDatabaseVersion('202312100')) {

	Update::showUpdateStep("Adjusting table row format of larger tables");
	Database::query("ALTER TABLE `" . TABLE_PANEL_ADMINS . "` ROW_FORMAT=DYNAMIC;");
	Database::query("ALTER TABLE `" . TABLE_PANEL_DOMAINS . "` ROW_FORMAT=DYNAMIC;");
	Update::lastStepStatus(0);

	Froxlor::updateToDbVersion('202312120');
}

if (Froxlor::isFroxlorVersion('2.1.1')) {
	Update::showUpdateStep("Updating from 2.1.1 to 2.1.2", false);
	Froxlor::updateToVersion('2.1.2');
}

if (Froxlor::isFroxlorVersion('2.1.2')) {
	Update::showUpdateStep("Updating from 2.1.2 to 2.1.3", false);
	Froxlor::updateToVersion('2.1.3');
}

if (Froxlor::isFroxlorVersion('2.1.3')) {
	Update::showUpdateStep("Updating from 2.1.3 to 2.1.4", false);
	Froxlor::updateToVersion('2.1.4');
}

if (Froxlor::isFroxlorVersion('2.1.4')) {
	Update::showUpdateStep("Updating from 2.1.4 to 2.1.5", false);
	Froxlor::updateToVersion('2.1.5');
}

if (Froxlor::isFroxlorVersion('2.1.5')) {
	Update::showUpdateStep("Updating from 2.1.5 to 2.1.6", false);
	Froxlor::updateToVersion('2.1.6');
}

if (Froxlor::isFroxlorVersion('2.1.6')) {
	Update::showUpdateStep("Updating from 2.1.6 to 2.1.7", false);
	Froxlor::updateToVersion('2.1.7');
}

if (Froxlor::isFroxlorVersion('2.1.7')) {
	Update::showUpdateStep("Updating from 2.1.7 to 2.1.8", false);
	Froxlor::updateToVersion('2.1.8');
}

if (Froxlor::isFroxlorVersion('2.1.8')) {
	Update::showUpdateStep("Updating from 2.1.8 to 2.1.9", false);
	Froxlor::updateToVersion('2.1.9');
}
