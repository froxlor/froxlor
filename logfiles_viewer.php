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

if (!defined('AREA')) {
	header("Location: index.php");
	exit();
}

use Froxlor\Api\Commands\SubDomains;
use Froxlor\Customer\Customer;
use Froxlor\FileDir;
use Froxlor\Settings;
use Froxlor\UI\Panel\UI;
use Froxlor\UI\Request;
use Froxlor\UI\Response;

// This file is being included in admin_domains and customer_domains
// and therefore does not need to require lib/init.php

$domain_id = (int)Request::any('domain_id');
$last_n = (int)Request::any('number_of_lines', 100);

// user's with logviewenabled = false
if (AREA != 'admin' && $userinfo['logviewenabled'] != '1') {
	// back to domain overview
	Response::redirectTo($filename, [
		'page' => 'domains'
	]);
}

if (function_exists('exec')) {
	// get domain-info
	try {
		$json_result = SubDomains::getLocal($userinfo, [
			'id' => $domain_id
		])->get();
	} catch (Exception $e) {
		Response::dynamicError($e->getMessage());
	}
	$domain = json_decode($json_result, true)['data'];

	if ($domain['email_only']) {
		Response::dynamicError("There are no webserver logfiles for email only domains.");
	}

	$speciallogfile = '';
	if ($domain['speciallogfile'] == '1') {
		if ($domain['parentdomainid'] == '0') {
			$speciallogfile = '-' . $domain['domain'];
		} else {
			$speciallogfile = '-' . $domain['parentdomain'];
		}
	}
	// The normal access/error - logging is enabled
	$error_log = FileDir::makeCorrectFile(Settings::Get('system.logfiles_directory') . Customer::getCustomerDetail($domain['customerid'], 'loginname') . $speciallogfile . '-error.log');
	$access_log = FileDir::makeCorrectFile(Settings::Get('system.logfiles_directory') . Customer::getCustomerDetail($domain['customerid'], 'loginname') . $speciallogfile . '-access.log');

	// error log
	if (file_exists($error_log)) {
		$result = FileDir::safe_exec('tail -n ' . $last_n . ' ' . escapeshellarg($error_log));
		$error_log_content = implode("\n", $result);
	} else {
		$error_log_content = "Error-Log" . (AREA == 'admin' ? " '" . $error_log . "'" : "") . " does not seem to exist";
	}

	// access log
	if (file_exists($access_log)) {
		$result = FileDir::safe_exec('tail -n ' . $last_n . ' ' . escapeshellarg($access_log));
		$access_log_content = implode("\n", $result);
	} else {
		$access_log_content = "Access-Log" . (AREA == 'admin' ? " '" . $access_log . "'" : "") . " does not seem to exist";
	}

	UI::view('user/logfiles.html.twig', [
		'error_log_content' => $error_log_content,
		'access_log_content' => $access_log_content,
		'actions_links' => [
			[
				'href' => $linker->getLink([
					'section' => 'domains',
					'page' => 'domains',
					'action' => 'edit',
					'id' => $domain_id
				]),
				'label' => lng('admin.domain_edit'),
				'icon' => 'fa-solid fa-pen'
			],
			[
				'href' => $linker->getLink(['section' => 'domains', 'page' => 'domains']),
				'label' => lng('panel.backtooverview'),
				'icon' => 'fa-solid fa-reply'
			]
		]
	]);
} else {
	if (AREA == 'admin') {
		Response::dynamicError('You need to allow the exec() function in the froxlor-vhost php-config');
	} else {
		Response::dynamicError('Required function exec() is not allowed. Please contact the system administrator.');
	}
}
