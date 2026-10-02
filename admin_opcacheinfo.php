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
 * @author     Janos Muzsi <muzsij@hypernics.hu>
 * @author     Andrew Collington <andy@amnuts.com>
 * @license    https://files.froxlor.org/misc/COPYING.txt GPLv2
 *
 * Based on https://github.com/amnuts/opcache-gui, which is
 * licensed under the MIT licence, which can be viewed
 * online at https://acollington.mit-license.org/
 */

const AREA = 'admin';
require __DIR__ . '/lib/init.php';

use Froxlor\FroxlorLogger;
use Froxlor\UI\HTML;
use Froxlor\UI\Panel\UI;
use Froxlor\UI\Request;
use Froxlor\UI\Response;

if ($action == 'reset' && function_exists('opcache_reset') && $userinfo['change_serversettings'] == '1') {
	if (Request::post('send') == 'send') {
		opcache_reset();
		$log->logAction(FroxlorLogger::ADM_ACTION, LOG_INFO, "reset OPcache");
		header('Location: ' . $linker->getLink([
				'section' => 'opcacheinfo',
				'page' => 'showinfo'
			]));
		exit();
	} else {
		HTML::askYesNo('cache_reallydelete', $filename, [
			'page' => $page,
			'action' => 'reset',
		], '', [
			'section' => 'opcacheinfo',
			'page' => 'showinfo'
		]);
	}
}

if (!extension_loaded('Zend OPcache')) {
	Response::standardError('no_opcacheinfo');
}

$ocEnabled = ini_get('opcache.enable');
if (empty($ocEnabled)) {
	Response::standardError('inactive_opcacheinfo');
}

if ($page == 'showinfo' && $userinfo['change_serversettings'] == '1') {
	$time = time();
	$log->logAction(FroxlorLogger::ADM_ACTION, LOG_NOTICE, "viewed OPcache info");

	$opcache = (new \Amnuts\Opcache\Service())->getData();

	UI::view('settings/opcacheinfo.html.twig', [
		'opcacheinfo' => [
			'version' => $opcache['version'],
			'overview' => $opcache['overview'],
			'files' => $opcache['files'],
			'preload' => $opcache['preload'],
			'directives' => $opcache['directives'],
			'blacklist' => $opcache['blacklist'],
			'functions' => $opcache['functions'],
		]
	]);
}
