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

use Froxlor\Api\Commands\Froxlor;
use Froxlor\Cron\TaskId;
use Froxlor\Database\Database;
use Froxlor\Database\IntegrityCheck;
use Froxlor\FroxlorLogger;
use Froxlor\PhpHelper;
use Froxlor\Settings;
use Froxlor\System\Cronjob;
use Froxlor\UI\Form;
use Froxlor\UI\HTML;
use Froxlor\UI\Listing;
use Froxlor\UI\Panel\UI;
use Froxlor\UI\Request;
use Froxlor\UI\Response;
use Froxlor\User;
use PHPMailer\PHPMailer\PHPMailer;

const AREA = 'admin';
require __DIR__ . '/lib/init.php';

if ($page == 'overview' && $userinfo['change_serversettings'] == '1') {
	$settings_data = PhpHelper::loadConfigArrayDir('./actions/admin/settings/');
	Settings::loadSettingsInto($settings_data);

	if (Request::post('send') == 'send') {
		$_part = Request::get('part', '');
		if ($_part == '') {
			$_part = Request::post('part', '');
		}

		if ($_part != '') {
			if ($_part == 'all') {
				$settings_all = true;
				$settings_part = false;
			} else {
				$settings_all = false;
				$settings_part = true;
			}
			$only_enabledisable = false;
		} else {
			$settings_all = false;
			$settings_part = false;
			$only_enabledisable = true;
		}

		// check if the session timeout is too low #815
		if (!empty(Request::post('session_sessiontimeout')) &&  intval(Request::post('session_sessiontimeout', 0)) < 60) {
			Response::standardError(['session_timeout', 'session_timeout_desc']);
		}

		try {
			if (Form::processForm($settings_data, Request::postAll(), [
				'filename' => $filename,
				'action' => $action,
				'page' => $page,
				'part' => $_part,
			], $_part, $settings_all, $settings_part, $only_enabledisable)) {
				$log->logAction(FroxlorLogger::ADM_ACTION, LOG_INFO, "rebuild configfiles due to changed setting");
				Cronjob::inserttask(TaskId::REBUILD_VHOST);
				// Using nameserver, insert a task which rebuilds the server config
				Cronjob::inserttask(TaskId::REBUILD_DNS);
				// cron.d file
				Cronjob::inserttask(TaskId::REBUILD_CRON);

				Response::standardSuccess('settingssaved', '', [
					'filename' => $filename,
					'action' => $action,
					'page' => $page
				]);
			}
		} catch (Exception $e) {
			Response::dynamicError($e->getMessage(), $e->getCode());
		}
	} else {
		$_part = Request::get('part', '');
		if ($_part == '') {
			$_part = Request::post('part', '');
		}

		$fields = Form::buildForm($settings_data, $_part);

		if ($_part == '' || $_part == 'all') {
			UI::view('settings/index.html.twig', ['fields' => $fields]);
		} else {
			$em = Request::any('em', '');
			UI::view('settings/detailpart.html.twig', [
				'fields' => $fields,
				'em' => $em,
				'part' => $_part,
				// alert-box
				'type' => 'warning',
				'heading' => lng('dns.nis2note.title'),
				'alert_msg' => lng('dns.nis2note.content')
			]);
		}
	}
} elseif ($page == 'phpinfo' && $userinfo['change_serversettings'] == '1') {
	ob_start();
	phpinfo();
	$phpinfo = [
		'phpinfo' => []
	];
	if (preg_match_all('#(?:<h2>(?:<a name=".*?">)?(.*?)(?:</a>)?</h2>)|(?:<tr(?: class=".*?")?><t[hd](?: class=".*?")?>(.*?)\s*</t[hd]>(?:<t[hd](?: class=".*?")?>(.*?)\s*</t[hd]>(?:<t[hd](?: class=".*?")?>(.*?)\s*</t[hd]>)?)?</tr>)#s', ob_get_clean(), $matches, PREG_SET_ORDER)) {
		foreach ($matches as $match) {
			$end = array_keys($phpinfo);
			$end = end($end);
			if (strlen($match[1])) {
				$phpinfo[$match[1]] = [];
			} elseif (isset($match[3])) {
				$phpinfo[$end][$match[2]] = isset($match[4]) ? [
					$match[3],
					$match[4]
				] : $match[3];
			} else {
				$phpinfo[$end][] = $match[2];
			}
		}
	} else {
		Response::standardError('error.no_phpinfo');
	}
	UI::view('settings/phpinfo.html.twig', [
		'phpversion' => PHP_VERSION,
		'phpinfo' => $phpinfo
	]);
} elseif ($page == 'rebuildconfigs' && $userinfo['change_serversettings'] == '1') {
	if (Request::post('send') == 'send') {
		$log->logAction(FroxlorLogger::ADM_ACTION, LOG_INFO, "rebuild configfiles");
		Cronjob::inserttask(TaskId::REBUILD_VHOST);
		Cronjob::inserttask(TaskId::CREATE_QUOTA);
		// Using nameserver, insert a task which rebuilds the server config
		Cronjob::inserttask(TaskId::REBUILD_DNS);
		// cron.d file
		Cronjob::inserttask(TaskId::REBUILD_CRON);

		Response::standardSuccess('rebuildingconfigs', '', [
			'filename' => 'admin_index.php'
		]);
	} else {
		HTML::askYesNo('admin_configs_reallyrebuild', $filename, [
			'page' => $page
		]);
	}
} elseif ($page == 'updatecounters' && $userinfo['change_serversettings'] == '1') {
	if (Request::post('send') == 'send') {
		$log->logAction(FroxlorLogger::ADM_ACTION, LOG_INFO, "updated resource-counters");
		$updatecounters = User::updateCounters(true);
		UI::view('user/resource-counter.html.twig', [
			'counters' => $updatecounters
		]);
	} else {
		HTML::askYesNo('admin_counters_reallyupdate', $filename, [
			'page' => $page
		]);
	}
} elseif ($page == 'wipecleartextmailpws' && $userinfo['change_serversettings'] == '1') {
	if (Request::post('send') == 'send') {
		$log->logAction(FroxlorLogger::ADM_ACTION, LOG_WARNING, "wiped all cleartext mail passwords");
		Database::query("UPDATE `" . TABLE_MAIL_USERS . "` SET `password` = '';");
		Database::query("UPDATE `" . TABLE_PANEL_SETTINGS . "` SET `value` = '0' WHERE `settinggroup` = 'system' AND `varname` = 'mailpwcleartext'");
		Response::redirectTo($filename);
	} else {
		HTML::askYesNo('admin_cleartextmailpws_reallywipe', $filename, [
			'page' => $page
		]);
	}
} elseif ($page == 'wipequotas' && $userinfo['change_serversettings'] == '1') {
	if (Request::post('send') == 'send') {
		$log->logAction(FroxlorLogger::ADM_ACTION, LOG_WARNING, "wiped all mailquotas");

		// Set the quota to 0 which means unlimited
		Database::query("UPDATE `" . TABLE_MAIL_USERS . "` SET `quota` = '0';");
		Database::query("UPDATE `" . TABLE_PANEL_CUSTOMERS . "` SET `email_quota_used` = '0'");
		Response::redirectTo($filename);
	} else {
		HTML::askYesNo('admin_quotas_reallywipe', $filename, [
			'page' => $page
		]);
	}
} elseif ($page == 'enforcequotas' && $userinfo['change_serversettings'] == '1') {
	if (Request::post('send') == 'send') {
		// Fetch all accounts
		$result_stmt = Database::query("SELECT `quota`, `customerid` FROM `" . TABLE_MAIL_USERS . "`");

		if (Database::num_rows() > 0) {
			$upd_stmt = Database::prepare("
				UPDATE `" . TABLE_PANEL_CUSTOMERS . "` SET
				`email_quota_used` = `email_quota_used` + :diff
				WHERE `customerid` = :customerid
			");

			while ($array = $result_stmt->fetch(PDO::FETCH_ASSOC)) {
				$difference = Settings::Get('system.mail_quota') - $array['quota'];
				Database::pexecute($upd_stmt, [
					'diff' => $difference,
					'customerid' => $customerid
				]);
			}
		}

		// Set the new quota
		$upd_stmt = Database::prepare("
			UPDATE `" . TABLE_MAIL_USERS . "` SET `quota` = :quota
		");
		Database::pexecute($upd_stmt, [
			'quota' => Settings::Get('system.mail_quota')
		]);

		// Update the Customer, if the used quota is bigger than the allowed quota
		Database::query("UPDATE `" . TABLE_PANEL_CUSTOMERS . "` SET `email_quota` = `email_quota_used` WHERE `email_quota` < `email_quota_used`");
		$log->logAction(FroxlorLogger::ADM_ACTION, LOG_WARNING, 'enforcing mailquota to all customers: ' . Settings::Get('system.mail_quota') . ' MB');
		Response::redirectTo($filename);
	} else {
		HTML::askYesNo('admin_quotas_reallyenforce', $filename, [
			'page' => $page
		]);
	}
} elseif ($page == 'integritycheck' && $userinfo['change_serversettings'] == '1') {
	$integrity = new IntegrityCheck();
	if (Request::post('send') == 'send') {
		$integrity->fixAll();
	} elseif (Request::get('action') == "fix") {
		HTML::askYesNo('admin_integritycheck_reallyfix', $filename, [
			'page' => $page
		]);
	}

	$integritycheck = [];
	foreach ($integrity->available as $id => $check) {
		$integritycheck[] = [
			'displayid' => $id + 1,
			'result' => $integrity->$check(),
			'checkdesc' => lng('integrity_check.' . $check)
		];
	}

	$integrity_list_data = include_once dirname(__FILE__) . '/lib/tablelisting/admin/tablelisting.integrity.php';
	$collection = [
		'data' => $integritycheck,
		'pagination' => []
	];

	UI::view('user/table.html.twig', [
		'listing' => Listing::formatFromArray($collection, $integrity_list_data['integrity_list'], 'integrity_list'),
		'actions_links' => [
			[
				'href' => $linker->getLink(['section' => 'settings', 'page' => $page, 'action' => 'fix']),
				'label' => lng('admin.integrityfix'),
				'icon' => 'fa-solid fa-screwdriver-wrench',
				'class' => 'btn-warning'
			]
		]
	]);
} elseif ($page == 'importexport' && $userinfo['change_serversettings'] == '1') {
	// check for json-stuff
	if (!extension_loaded('json')) {
		Response::standardError('jsonextensionnotfound');
	}

	if (Request::get('action') == "export") {
		// export
		try {
			$json_result = Froxlor::getLocal($userinfo)->exportSettings();
			$json_export = json_decode($json_result, true)['data'];
		} catch (Exception $e) {
			Response::dynamicError($e->getMessage());
		}
		header('Content-disposition: attachment; filename=Froxlor_settings-' . \Froxlor\Froxlor::VERSION . '-' . \Froxlor\Froxlor::DBVERSION . '_' . date('d.m.Y') . '.json');
		header('Content-type: application/json');
		echo $json_export;
		exit();
	} elseif (Request::get('action') == "import") {
		// import
		if (Request::post('send') == 'send') {
			// get uploaded file
			if (isset($_FILES["import_file"]["tmp_name"])) {
				$imp_content = file_get_contents($_FILES["import_file"]["tmp_name"]);
				try {
					Froxlor::getLocal($userinfo, [
						'json_str' => $imp_content
					])->importSettings();
				} catch (Exception $e) {
					Response::dynamicError($e->getMessage());
				}
				Response::standardSuccess('settingsimported', '', [
					'filename' => 'admin_settings.php'
				]);
			}
			Response::dynamicError("Upload failed");
		}
	} else {
		$settings_data = include_once dirname(__FILE__) . '/lib/formfields/admin/settings/formfield.settings_import.php';

		UI::view('user/form.html.twig', [
			'formaction' => $linker->getLink(['section' => 'settings', 'page' => $page, 'action' => 'import']),
			'formdata' => $settings_data['settings_import'],
			'actions_links' => [
				[
					'class' => 'btn-outline-primary',
					'href' => $linker->getLink(['section' => 'settings', 'page' => 'overview']),
					'label' => lng('admin.configfiles.overview'),
					'icon' => 'fa-solid fa-grip'
				],
				[
					'class' => 'btn-outline-secondary',
					'href' => $linker->getLink(['section' => 'settings', 'page' => $page, 'action' => 'export']),
					'label' => 'Download/export ' . lng('admin.serversettings'),
					'icon' => 'fa-solid fa-file-import'
				]
			]
		]);
	}
} elseif ($page == 'testmail') {
	$note_type = 'info';
	$note_msg = lng('admin.smtptestnote');

	if (Request::post('send') == 'send') {
		$test_addr = Request::post('test_addr');

		// Initialize the mailingsystem
		$testmail = new PHPMailer(true);
		$testmail->CharSet = "UTF-8";

		if (Settings::Get('system.mail_use_smtp')) {
			$testmail->isSMTP();
			$testmail->Host = Settings::Get('system.mail_smtp_host');
			$testmail->SMTPAuth = Settings::Get('system.mail_smtp_auth') == '1';
			$testmail->Username = Settings::Get('system.mail_smtp_user');
			$testmail->Password = Settings::Get('system.mail_smtp_passwd');
			if (Settings::Get('system.mail_smtp_usetls')) {
				$testmail->SMTPSecure = 'tls';
			} else {
				$testmail->SMTPAutoTLS = false;
			}
			$testmail->Port = Settings::Get('system.mail_smtp_port');
		}

		$_mailerror = false;
		if (PHPMailer::ValidateAddress(Settings::Get('panel.adminmail')) !== false) {
			// set return-to address and custom sender-name, see #76
			$testmail->SetFrom(Settings::Get('panel.adminmail'), Settings::Get('panel.adminmail_defname'));
			if (Settings::Get('panel.adminmail_return') != '') {
				$testmail->AddReplyTo(Settings::Get('panel.adminmail_return'), Settings::Get('panel.adminmail_defname'));
			}

			try {
				$testmail->Subject = "Froxlor Test-Mail";
				$mail_body = "Yay, this worked :)";
				$testmail->AltBody = $mail_body;
				$testmail->MsgHTML(str_replace("\n", "<br />", $mail_body));
				$testmail->AddAddress($test_addr);
				$testmail->Send();
			} catch (\PHPMailer\PHPMailer\Exception $e) {
				$note_type = 'danger';
				$note_msg = $e->getMessage();
				$_mailerror = true;
			} catch (Exception $e) {
				$note_type = 'danger';
				$note_msg = $e->getMessage();
				$_mailerror = true;
			}

			if (!$_mailerror) {
				// success
				$mail->ClearAddresses();
				Response::standardSuccess('testmailsent', '', [
					'filename' => 'admin_settings.php',
					'page' => 'testmail'
				]);
			}
		} else {
			// invalid sender e-mail
			$note_type = 'warning';
			$note_msg = "Invalid sender e-mail address: " . Settings::Get('panel.adminmail');
		}
	}

	$mailtest_add_data = include_once dirname(__FILE__) . '/lib/formfields/admin/settings/formfield.settings_mailtest.php';

	UI::view('user/form-note.html.twig', [
		'formaction' => $linker->getLink(['section' => 'settings']),
		'formdata' => $mailtest_add_data['mailtest'],
		'actions_links' => ($userinfo['change_serversettings'] == '1' ? [
			[
				'href' => $linker->getLink([
					'section' => 'settings',
					'page' => 'overview',
					'part' => 'system',
					'em' => 'system_mail_use_smtp'
				]),
				'label' => lng('admin.smtpsettings'),
				'icon' => 'fa-solid fa-gears',
				'class' => 'btn-outline-secondary'
			]
		] : []),
		// alert-box
		'type' => $note_type,
		'alert_msg' => $note_msg
	]);
} elseif ($page == 'toggleSettingsMode') {
	if ($userinfo['change_serversettings'] == '1') {
		$cmode = Settings::Get('panel.settings_mode');
		Settings::Set('panel.settings_mode', (int)(!(bool)$cmode));
	}
	Response::redirectTo($filename);
}
