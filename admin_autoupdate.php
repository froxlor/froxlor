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

const AREA = 'admin';
require __DIR__ . '/lib/init.php';

use Froxlor\Froxlor;
use Froxlor\FroxlorLogger;
use Froxlor\FileDir;
use Froxlor\Install\AutoUpdate;
use Froxlor\Settings;
use Froxlor\UI\Panel\UI;
use Froxlor\UI\Request;
use Froxlor\UI\Response;

if ($page != 'error') {
	// check for webupdate to be enabled
	if (Settings::Config('enable_webupdate') != true) {
		Response::redirectTo($filename, [
			'page' => 'error',
			'errno' => 11
		]);
	}
}

// display initial version check
if ($page == 'overview') {
	// log our actions
	$log->logAction(FroxlorLogger::ADM_ACTION, LOG_NOTICE, "checking auto-update");

	// check for new version
	try {
		$result = AutoUpdate::checkVersion();
	} catch (Exception $e) {
		Response::dynamicError($e->getMessage());
	}

	if ($result == 1) {

		// anzeige über version-status mit ggfls. formular
		// zum update schritt #1 -> download
		$text = lng('admin.newerversionavailable') . ' ' . lng('admin.newerversiondetails', [AutoUpdate::getFromResult('version'), Froxlor::VERSION]);

		$upd_formfield = [
			'updates' => [
				'title' => lng('update.update'),
				'image' => 'fa-solid fa-download',
				'sections' => [
					'section_autoupd' => [
						'fields' => [
							'newversion' => ['type' => 'hidden', 'value' => AutoUpdate::getFromResult('version')]
						]
					]
				],
				'buttons' => [
					[
						'class' => 'btn-outline-secondary',
						'label' => lng('panel.cancel'),
						'type' => 'reset'
					],
					[
						'label' => lng('update.proceed')
					]
				]
			]
		];

		UI::view('user/form-note.html.twig', [
			'formaction' => $linker->getLink(['section' => 'autoupdate', 'page' => 'getdownload']),
			'formdata' => $upd_formfield['updates'],
			// alert
			'type' => 'warning',
			'alert_msg' => $text
		]);
	} else if ($result < 0 || $result > 1) {
		// remote errors
		if ($result < 0) {
			Response::dynamicError(AutoUpdate::getLastError());
		} else {
			Response::redirectTo($filename, [
				'page' => 'error',
				'errno' => $result
			]);
		}
	} else {
		// no new version
		Response::standardSuccess('update.noupdatesavail', (Settings::Get('system.update_channel') == 'testing' ? lng('serversettings.uc_testing') . ' ' : ''));
	}
} // download the new archive
elseif ($page == 'getdownload') {
	// retrieve the new version from the form
	$newversion = Request::post('newversion');

	$result = 6;
	// valid?
	if ($newversion !== null) {
		$result = AutoUpdate::downloadZip($newversion);
		if (!is_numeric($result)) {
			// to the next step
			Response::redirectTo($filename, [
				'page' => 'extract',
				'archive' => $result
			]);
		}
	}
	Response::redirectTo($filename, [
		'page' => 'error',
		'errno' => $result
	]);
} // extract and install new version
elseif ($page == 'extract') {
	if (Request::post('send') == 'send') {
		$toExtract = Request::post('archive');
		$localArchive = FileDir::makeCorrectFile(Froxlor::getInstallDir() . '/updates/' . $toExtract);
		$log->logAction(FroxlorLogger::ADM_ACTION, LOG_NOTICE, "Extracting " . $localArchive . " to " . Froxlor::getInstallDir());
		$result = AutoUpdate::extractZip($localArchive);
		if ($result > 0) {
			// error
			Response::redirectTo($filename, [
				'page' => 'error',
				'errno' => $result
			]);
		}
		if (function_exists('opcache_reset')) {
			@opcache_reset();
		}
		// redirect to update-page
		Response::redirectTo('admin_updates.php');
	} else {
		$toExtract = Request::get('archive');
		$localArchive = FileDir::makeCorrectFile(Froxlor::getInstallDir() . '/updates/' . $toExtract);
	}

	if (!file_exists($localArchive)) {
		Response::redirectTo($filename, [
			'page' => 'error',
			'errno' => 7
		]);
	}

	$text = lng('admin.extractdownloadedzip', [$toExtract]);

	$upd_formfield = [
		'updates' => [
			'title' => lng('update.update'),
			'image' => 'fa-solid fa-download',
			'sections' => [
				'section_autoupd' => [
					'fields' => [
						'archive' => ['type' => 'hidden', 'value' => $toExtract]
					]
				]
			],
			'buttons' => [
				[
					'class' => 'btn-outline-secondary',
					'label' => lng('panel.cancel'),
					'type' => 'reset'
				],
				[
					'label' => lng('update.proceed')
				]
			]
		]
	];

	UI::view('user/form-note.html.twig', [
		'formaction' => $linker->getLink(['section' => 'autoupdate', 'page' => 'extract']),
		'formdata' => $upd_formfield['updates'],
		// alert
		'type' => 'warning',
		'alert_msg' => $text
	]);
} // display error
elseif ($page == 'error') {
	// retrieve error-number via url-parameter
	$errno = Request::get('errno', 0);

	// 2 = no Zlib
	// 3 = custom version detected
	// 4 = could not store archive to local hdd
	// 5 = some weird value came from version.froxlor.org
	// 6 = download without valid version
	// 7 = local archive does not exist
	// 8 = could not extract archive
	// 9 = checksum mismatch
	// 10 = <php-7.4
	// 11 = enable_webupdate = false
	$errmsg = 'autoupdate_' . $errno;
	if ($errno == 3) {
		$errmsg = 'customized_version';
	}
	Response::standardError($errmsg);
}
