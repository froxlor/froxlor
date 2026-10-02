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

use Froxlor\Froxlor;
use Froxlor\FileDir;
use Froxlor\FroxlorLogger;
use Froxlor\Settings;
use Froxlor\UI\Response;
use Froxlor\Database\IntegrityCheck;
use Froxlor\Install\Update;

if (!defined('_CRON_UPDATE')) {
	if (!defined('AREA') || (defined('AREA') && AREA != 'admin') || !isset($userinfo['loginname']) || (isset($userinfo['loginname']) && $userinfo['loginname'] == '')) {
		header('Location: ../index.php');
		exit();
	}
}

$filelog = FroxlorLogger::getInstanceOf(array(
	'loginname' => 'updater'
));

// if first writing does not work we'll stop, tell the user to fix it
// and then let him try again.
try {
	$filelog->logAction(FroxlorLogger::ADM_ACTION, LOG_WARNING, '-------------- START LOG --------------');
} catch (Exception $e) {
	Response::standardError('exception', $e->getMessage());
}

if (Froxlor::isFroxlor()) {

	include_once(FileDir::makeCorrectFile(dirname(__FILE__) . '/updates/froxlor/update_2.0.inc.php'));
	include_once(FileDir::makeCorrectFile(dirname(__FILE__) . '/updates/froxlor/update_2.1.inc.php'));
	include_once(FileDir::makeCorrectFile(dirname(__FILE__) . '/updates/froxlor/update_2.2.inc.php'));
	include_once(FileDir::makeCorrectFile(dirname(__FILE__) . '/updates/froxlor/update_2.3.inc.php'));

	// Check Froxlor - database integrity (only happens after all updates are done, so we know the db-layout is okay)
	Update::showUpdateStep("Checking database integrity");

	$integrity = new IntegrityCheck();
	if (!$integrity->checkAll()) {
		Update::lastStepStatus(1, 'Integrity could not be validated');
		Update::showUpdateStep("Trying to automatically restore integrity");
		if (!$integrity->fixAll()) {
			Update::lastStepStatus(2, 'failed', 'Check "database validation" as admin on the left-side menu to see where the problem is');
		} else {
			Update::lastStepStatus(0, 'Integrity restored');
		}
	} else {
		Update::lastStepStatus(0);
	}

	// reset cached version check
	Settings::Set('system.updatecheck_data', '');

	$filelog->logAction(FroxlorLogger::ADM_ACTION, LOG_WARNING, '--------------- END LOG ---------------');
	unset($filelog);
}
