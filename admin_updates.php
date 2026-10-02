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

use Froxlor\Cron\TaskId;
use Froxlor\Froxlor;
use Froxlor\FroxlorLogger;
use Froxlor\Install\Preconfig;
use Froxlor\Install\Update;
use Froxlor\Settings;
use Froxlor\System\Cronjob;
use Froxlor\UI\Panel\UI;
use Froxlor\UI\Request;
use Froxlor\UI\Response;
use Froxlor\User;

if ($page == 'overview') {
	$log->logAction(FroxlorLogger::ADM_ACTION, LOG_NOTICE, "viewed admin_updates");

	if (!Froxlor::isFroxlor()) {
		throw new Exception('SysCP/customized upgrades are not supported');
	}

	if (Froxlor::hasDbUpdates() || Froxlor::hasUpdates()) {
		$successful_update = false;
		$message = '';

		if (Request::post('send') == 'send') {
			if ((!empty(Request::post('update_preconfig')) && intval(Request::post('update_changesagreed', 0)) != 0) || empty(Request::post('update_preconfig'))) {
				include_once Froxlor::getInstallDir() . 'install/updatesql.php';

				User::updateCounters();
				Cronjob::inserttask(TaskId::REBUILD_VHOST);
				@chmod(Froxlor::getInstallDir() . '/lib/userdata.inc.php', 0400);

				UI::view('install/update.html.twig', [
					'checks' => Update::getUpdateTasks()
				]);
				exit;
			} else {
				$message = '<br><br><strong>You have to agree that you have read the update notifications.</strong>';
			}
		}

		$current_version = Settings::Get('panel.version');
		$current_db_version = Settings::Get('panel.db_version');
		if (empty($current_db_version)) {
			$current_db_version = "0";
		}
		$new_version = Froxlor::VERSION;
		$new_db_version = Froxlor::DBVERSION;

		if (Froxlor::VERSION != $current_version) {
			$replacer_currentversion = $current_version;
			$replacer_newversion = $new_version;
		} else {
			// show db version
			$replacer_currentversion = $current_db_version;
			$replacer_newversion = $new_db_version;
		}
		$ui_text = lng('update.update_information.part_a', [$replacer_newversion, $replacer_currentversion]);
		$ui_text .= lng('update.update_information.part_b');

		$upd_formfield = [
			'updates' => [
				'title' => lng('update.update'),
				'image' => 'fa-solid fa-download',
				'description' => lng('update.description'),
				'sections' => [],
				'buttons' => [
					[
						'label' => lng('update.proceed')
					]
				]
			]
		];

		$preconfig = Preconfig::getPreConfig();
		if (!empty($preconfig)) {
			$upd_formfield['updates']['sections'] = $preconfig;
		}

		UI::view('user/form-note.html.twig', [
			'formaction' => $linker->getLink(['section' => 'updates']),
			'formdata' => $upd_formfield['updates'],
			// alert
			'type' => !empty($message) ? 'danger' : 'info',
			'alert_msg' => $ui_text . $message
		]);
	} else {
		Response::standardSuccess('update.noupdatesavail', Settings::Get('system.update_channel') == 'testing' ? lng('serversettings.uc_testing') . ' ' : '');
	}
}
