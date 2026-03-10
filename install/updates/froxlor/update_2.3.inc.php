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
use Froxlor\Froxlor;
use Froxlor\Install\Update;
use Froxlor\Settings;

if (!defined('_CRON_UPDATE')) {
	if (!defined('AREA') || (defined('AREA') && AREA != 'admin') || !isset($userinfo['loginname']) || (isset($userinfo['loginname']) && $userinfo['loginname'] == '')) {
		header('Location: ../../../../index.php');
		exit();
	}
}

if (Froxlor::isDatabaseVersion('202412030')) {
	Update::showUpdateStep("Enhancing customer table");
	Database::query("ALTER TABLE `" . TABLE_PANEL_CUSTOMERS . "` ADD `shell_allowed` tinyint(1) NOT NULL DEFAULT 0;");
	Update::lastStepStatus(0);

	if (Settings::Get('system.allow_customer_shell') == '1') {
		Update::showUpdateStep("Allowing shell-usage to current customers as setting is globally enabled");
		Database::query("UPDATE `" . TABLE_PANEL_CUSTOMERS . "` SET `shell_allowed` = '1';");
		Update::lastStepStatus(0);
	}

	Froxlor::updateToDbVersion('202508310');

	Update::showUpdateStep("Updating from 2.2.8 to 2.3.0-dev1", false);
	Froxlor::updateToVersion('2.3.0-dev1');
}

if (Froxlor::isDatabaseVersion('202508310')) {
	Update::showUpdateStep("Remove old settings");
	Database::query("DELETE FROM `" . TABLE_PANEL_SETTINGS . "` WHERE `settinggroup` = 'system' AND `varname` = 'perl_path'");
	Update::lastStepStatus(0);

	if (Settings::Get('system.webserver') == 'lighttpd') {
		$system_alt_webserver = $_POST['system_alt_webserver'] ?? 'apache2';
		Update::showUpdateStep("Switching from lighttpd to " . $system_alt_webserver);
		Settings::Set('system.webserver', $system_alt_webserver);
		Settings::Set('system.apache24', 1);
		Update::lastStepStatus(0);
	}

	Froxlor::updateToDbVersion('202509010');
}

if (Froxlor::isDatabaseVersion('202509010')) {
	Update::showUpdateStep("Adding new table for user ssh-keys");
	Database::query("DROP TABLE IF EXISTS `panel_sshkeys`;");
	$sql = "CREATE TABLE `panel_sshkeys` (
	  `id` int(11) NOT NULL auto_increment,
	  `customerid` int(11) NOT NULL,
	  `ftp_user_id` int(20) NOT NULL,
	  `ssh_pubkey` text NOT NULL,
	  `description` varchar(255) NOT NULL DEFAULT '',
	  PRIMARY KEY  (id)
	) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_general_ci;";
	Database::query($sql);
	Update::lastStepStatus(0);

	Froxlor::updateToDbVersion('202509060');
}

if (Froxlor::isDatabaseVersion('202509060')) {
	Update::showUpdateStep("Disabling OCSP for Let's Encrypt enabled domains, as service is EOL");
	Database::query("UPDATE `" . TABLE_PANEL_DOMAINS . "` SET `ocsp_stapling` = '0' WHERE `letsencrypt` = '1';");
	Update::lastStepStatus(0);

	// clear templates cache
	Update::cleanOldFiles([
		'cache/*'
	]);

	Froxlor::updateToDbVersion('202509120');
}

if (Froxlor::isDatabaseVersion('202509120')) {
	Update::showUpdateStep("Adding new settings");
	Settings::AddNew("system.http3_support", "0");
	Update::lastStepStatus(0);

	Update::showUpdateStep("Adding http3 field to domain table");
	Database::query("ALTER TABLE `" . TABLE_PANEL_DOMAINS . "` ADD `http3` tinyint(1) NOT NULL default '0' AFTER `http2`;");
	Update::lastStepStatus(0);

	Froxlor::updateToDbVersion('202509210');
}

if (Froxlor::isDatabaseVersion('202509210')) {
	Update::showUpdateStep("Adding new table for email sender aliases");
	Database::query("DROP TABLE IF EXISTS `mail_sender_aliases`;");
	$sql = "CREATE TABLE `mail_sender_aliases` (
	  `id` int(11) NOT NULL auto_increment,
	  `email` varchar(255) NOT NULL,
	  `allowed_sender` varchar(255) NOT NULL,
	  PRIMARY KEY  (`id`),
	  UNIQUE KEY `email_sender` (`email`, `allowed_sender`)
	) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_general_ci;";
	Database::query($sql);
	$mail_enable_allow_sender = $_POST['mail_enable_allow_sender'] ?? 0;
	Settings::AddNew('mail.enable_allow_sender', $mail_enable_allow_sender);
	$mail_allow_external_domains = $_POST['mail_allow_external_domains'] ?? 0;
	Settings::AddNew('mail.allow_external_domains', $mail_allow_external_domains);
	Update::lastStepStatus(0);

	$to_clean = [
		'lib/configfiles/gentoo.xml',
	];
	Update::cleanOldFiles($to_clean);

	Froxlor::updateToDbVersion('202509270');
}

if (Froxlor::isDatabaseVersion('202509270')) {

	Settings::AddNew('system.distro_mismatch', '0');
	Froxlor::updateToDbVersion('202511020');
}

if (Froxlor::isFroxlorVersion('2.3.0-dev1')) {
	Update::showUpdateStep("Updating from 2.3.0-dev1 to 2.3.0-rc1", false);
	Froxlor::updateToVersion('2.3.0-rc1');
}

if (Froxlor::isFroxlorVersion('2.3.0-rc1')) {
	Update::showUpdateStep("Updating from 2.3.0-rc1 to 2.3.0", false);
	Froxlor::updateToVersion('2.3.0');
}

if (Froxlor::isDatabaseVersion('202511020')) {

	Settings::AddNew('system.report_web_bccadmin', '0');
	Froxlor::updateToDbVersion('202512090');
}

if (Froxlor::isDatabaseVersion('202512090')) {

	$to_clean = [
		'install/updates/froxlor/update_0.10.inc.php',
		'install/updates/preconfig/preconfig_0.10.inc.php',
		'lib/Froxlor/Cron/Http/Lighttpd.php',
		'lib/Froxlor/Cron/Http/LighttpdFcgi.php',
	];
	Update::cleanOldFiles($to_clean);

	Froxlor::updateToDbVersion('202512280');
}

if (Froxlor::isFroxlorVersion('2.3.0')) {
	Update::showUpdateStep("Updating from 2.3.0 to 2.3.1", false);
	Froxlor::updateToVersion('2.3.1');
}

if (Froxlor::isFroxlorVersion('2.3.1')) {
	Update::showUpdateStep("Updating from 2.3.1 to 2.3.2", false);
	Froxlor::updateToVersion('2.3.2');
}

if (Froxlor::isFroxlorVersion('2.3.2')) {
	Update::showUpdateStep("Updating from 2.3.2 to 2.3.3", false);
	Froxlor::updateToVersion('2.3.3');
}

if (Froxlor::isFroxlorVersion('2.3.3')) {
	Update::showUpdateStep("Updating from 2.3.3 to 2.3.4", false);
	Froxlor::updateToVersion('2.3.4');
}

if (Froxlor::isFroxlorVersion('2.3.4')) {
	Update::showUpdateStep("Updating from 2.3.4 to 2.3.5", false);
	Froxlor::updateToVersion('2.3.5');
}
