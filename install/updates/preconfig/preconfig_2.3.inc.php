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

use Froxlor\Install\Update;
use Froxlor\Settings;

$preconfig = [
	'title' => '2.3.x updates',
	'fields' => []
];
$return = [];

if (Update::versionInUpdate($current_db_version, '202509010')) {
	if (Settings::Get('system.webserver') == 'lighttpd') {
		$has_preconfig = true;
		$description = 'You seem to be using "lighttpd" as webserver, froxlor 2.3 no longer supports this webserver. Please select an alternative one. Remember to configure the service after the update!';
		$question = '<strong>Switch webserver to:</strong>&nbsp;';
		$return['system_alt_webserver'] = [
			'type' => 'select',
			'select_var' => [
				'apache2' => 'Apache 2.4',
				'nginx' => 'Nginx'
			],
			'selected' => 'apache2',
			'label' => $question,
			'prior_infotext' => $description
		];
	}
}

if (Update::versionInUpdate($current_db_version, '202509270')) {

	$has_preconfig = true;
	$description = 'It is now possible for customers to add "allowed sender" addresses for email-accounts to send from if enabled.';
	$question = '<strong>Enable "allowed sender" for customers?</strong>&nbsp;';
	$return['mail_enable_allow_sender'] = [
		'type' => 'checkbox',
		'value' => 1,
		'checked' => 0,
		'label' => $question,
		'prior_infotext' => $description
	];
	$description = 'By default, a customer cannot use domains that are not added to the account for the "allowed sender" feature. You can specify if you would like to allow adding addresses from external domains not managed by your installation.';
	$question = '<strong>Allow external domains for "allowed sender"?</strong>&nbsp;';
	$return['mail_allow_external_domains'] = [
		'type' => 'checkbox',
		'value' => 1,
		'checked' => 0,
		'label' => $question,
		'prior_infotext' => $description
	];
}

if (Update::versionInUpdate($current_db_version, '202603100')) {

	if (Settings::Get('system.webserver') == 'apache2') {
		$has_preconfig = true;
		$description = 'Select default value for the "ServerAdmin" value which is shown on webserver error pages (depending on ServerSignature setting).';
		$question = '<strong>Which email address should be shown in ServerAdmin directive?</strong>&nbsp;';
		$return['system_webserver_serveradmin'] = [
			'type' => 'select',
			'select_var' => [
				'customer' => 'Customer email address (default)',
				'admin' => 'Admin email address',
				'global' => 'Panel admin email address',
				'none' => 'No ServerAdmin'
			],
			'selected' => 'customer',
			'label' => $question,
			'prior_infotext' => $description
		];
	}
}

$preconfig['fields'] = $return;
return $preconfig;
