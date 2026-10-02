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

use Froxlor\Database\Database;
use Froxlor\FroxlorLogger;
use Froxlor\Language;
use Froxlor\PhpHelper;
use Froxlor\Settings;
use Froxlor\UI\HTML;
use Froxlor\UI\Listing;
use Froxlor\UI\Panel\UI;
use Froxlor\UI\Request;
use Froxlor\UI\Response;
use Froxlor\Validate\Validate;
use Froxlor\CurrentUser;

$id = (int)Request::any('id');
$subjectid = intval(Request::any('subjectid'));
$mailbodyid = intval(Request::any('mailbodyid'));

$available_templates = [
	'createcustomer',
	'pop_success',
	'new_database_by_customer',
	'new_ftpaccount_by_customer',
	'password_reset'
];

// only show templates of features that are enabled #1191
if ((int)Settings::Get('system.report_enable') == 1) {
	array_push($available_templates, 'trafficmaxpercent', 'diskmaxpercent');
}
if (Settings::Get('panel.sendalternativemail') == 1) {
	array_push($available_templates, 'pop_success_alternative');
}

$file_templates = [
	'index_html',
	'unconfigured_html'
];

$languages = Language::getLanguages();

if ($action == '') {
	// email templates
	$log->logAction(FroxlorLogger::ADM_ACTION, LOG_NOTICE, "viewed admin_templates");

	$templates_array = [];
	$result_stmt = Database::prepare("
		SELECT `id`, `language`, `varname` FROM `" . TABLE_PANEL_TEMPLATES . "`
		WHERE `adminid` = :adminid AND `templategroup`='mails'
		ORDER BY `language`, `varname`
	");
	Database::pexecute($result_stmt, [
		'adminid' => $userinfo['adminid']
	]);

	while ($row = $result_stmt->fetch(PDO::FETCH_ASSOC)) {
		$parts = [];
		preg_match('/^([a-z]([a-z_]+[a-z])*)_(mailbody|subject)$/', $row['varname'], $parts);
		$templates_array[$row['language']][$parts[1]][$parts[3]] = $row['id'];
	}

	$templates = [];
	foreach ($templates_array as $language => $template_defs) {
		foreach ($template_defs as $action => $email) {
			$templates[] = [
				'subjectid' => $email['subject'],
				'mailbodyid' => $email['mailbody'],
				'template' => lng('admin.templates.' . $action),
				'language' => $language
			];
		}
	}

	$mail_actions_links = false;
	foreach ($languages as $language_file => $language_name) {
		$templates_done = [];
		$result_stmt = Database::prepare("
			SELECT `varname` FROM `" . TABLE_PANEL_TEMPLATES . "`
			WHERE `adminid` = :adminid AND `language`= :lang
			AND `templategroup` = 'mails' AND `varname` LIKE '%_subject'
		");
		Database::pexecute($result_stmt, [
			'adminid' => $userinfo['adminid'],
			'lang' => $language_name
		]);

		while ($row = $result_stmt->fetch(PDO::FETCH_ASSOC)) {
			$templates_done[] = str_replace('_subject', '', $row['varname']);
		}

		if (count(array_diff($available_templates, $templates_done)) > 0) {
			$mail_actions_links = [
				[
					'href' => $linker->getLink(['section' => 'templates', 'page' => $page, 'action' => 'add']),
					'label' => lng('admin.templates.template_add')
				]
			];
		}
	}

	$mailtpl_list_data = include_once dirname(__FILE__) . '/lib/tablelisting/admin/tablelisting.mailtemplates.php';
	$collection_mail = [
		'data' => $templates,
		'pagination' => []
	];

	// filetemplates
	$result_stmt = Database::prepare("
		SELECT `id`, `varname` FROM `" . TABLE_PANEL_TEMPLATES . "`
		WHERE `adminid` = :adminid AND `templategroup`='files'");
	Database::pexecute($result_stmt, [
		'adminid' => $userinfo['adminid']
	]);

	$filetemplates = [];
	while ($row = $result_stmt->fetch(PDO::FETCH_ASSOC)) {
		$filetemplates[] = [
			'id' => $row['id'],
			'template' => lng('admin.templates.' . $row['varname'])
		];
	}

	$file_actions_links = false;
	if (Database::num_rows() != count($file_templates)) {
		$file_actions_links = [
			[
				'href' => $linker->getLink([
					'section' => 'templates',
					'page' => $page,
					'action' => 'add',
					'files' => 'files'
				]),
				'label' => lng('admin.templates.template_fileadd')
			]
		];
	}

	$filetpl_list_data = include_once dirname(__FILE__) . '/lib/tablelisting/admin/tablelisting.filetemplates.php';
	$collection_file = [
		'data' => $filetemplates,
		'pagination' => []
	];

	if ($mail_actions_links === false) {
		$mail_actions_links = [];
	}
	if ($file_actions_links === false) {
		$file_actions_links = [];
	}

	UI::view('user/table-tpl.html.twig', [
		'maillisting' => Listing::formatFromArray($collection_mail, $mailtpl_list_data['mailtpl_list'], 'mailtpl_list'),
		'filelisting' => Listing::formatFromArray($collection_file, $filetpl_list_data['filetpl_list'], 'filetpl_list'),
		'actions_links' => array_merge($mail_actions_links, $file_actions_links)
	]);
} elseif ($action == 'delete' && $subjectid != 0 && $mailbodyid != 0) {
	// email templates
	$result_stmt = Database::prepare("
		SELECT `language`, `varname` FROM `" . TABLE_PANEL_TEMPLATES . "`
		WHERE `adminid` = :adminid AND `id` = :id");
	Database::pexecute($result_stmt, [
		'adminid' => $userinfo['adminid'],
		'id' => $subjectid
	]);
	$result = $result_stmt->fetch(PDO::FETCH_ASSOC);

	if ($result['varname'] != '') {
		if (Request::post('send') == 'send') {
			$del_stmt = Database::prepare("
				DELETE FROM `" . TABLE_PANEL_TEMPLATES . "`
				WHERE `adminid` = :adminid
				AND (`id` = :ida OR `id` = :idb)");
			Database::pexecute($del_stmt, [
				'adminid' => $userinfo['adminid'],
				'ida' => $subjectid,
				'idb' => $mailbodyid
			]);
			$log->logAction(FroxlorLogger::ADM_ACTION, LOG_INFO, "deleted template '" . $result['language'] . ' - ' . lng('admin.templates.' . str_replace('_subject', '', $result['varname'])) . "'");
			Response::redirectTo($filename, [
				'page' => $page
			]);
		} else {
			HTML::askYesNo('admin_template_reallydelete', $filename, [
				'subjectid' => $subjectid,
				'mailbodyid' => $mailbodyid,
				'page' => $page,
				'action' => $action
			], $result['language'] . ' - ' . lng('admin.templates.' . str_replace('_subject', '', $result['varname'])));
		}
	}
} elseif ($action == 'deletef' && $id != 0) {
	// file templates
	$result_stmt = Database::prepare("
		SELECT * FROM `" . TABLE_PANEL_TEMPLATES . "`
		WHERE `adminid` = :adminid AND `id` = :id");
	Database::pexecute($result_stmt, [
		'adminid' => $userinfo['adminid'],
		'id' => $id
	]);

	if (Database::num_rows() > 0) {
		$row = $result_stmt->fetch(PDO::FETCH_ASSOC);

		if (Request::post('send') == 'send') {
			$del_stmt = Database::prepare("
				DELETE FROM `" . TABLE_PANEL_TEMPLATES . "`
				WHERE `adminid` = :adminid AND `id` = :id");
			Database::pexecute($del_stmt, [
				'adminid' => $userinfo['adminid'],
				'id' => $id
			]);
			$log->logAction(FroxlorLogger::ADM_ACTION, LOG_INFO, "deleted template '" . lng('admin.templates.' . $row['varname']) . "'");
			Response::redirectTo($filename, [
				'page' => $page
			]);
		} else {
			HTML::askYesNo('admin_template_reallydelete', $filename, [
				'id' => $id,
				'page' => $page,
				'action' => $action
			], lng('admin.templates.' . $row['varname']));
		}
	} else {
		Response::standardError('templatenotfound');
	}
} elseif ($action == 'add') {
	if (Request::post('prepare') == 'prepare') {
		// email templates
		$language = htmlentities(Validate::validate(Request::post('language'), 'language', '/^[^\r\n\0"\']+$/', 'nolanguageselect'));
		if (!array_key_exists($language, $languages)) {
			Response::standardError('templatelanguageinvalid');
		}
		$template = Validate::validate(Request::post('template'), 'template');

		$result_stmt = Database::prepare("
			SELECT COUNT(*) as def FROM `" . TABLE_PANEL_TEMPLATES . "`
			WHERE `adminid` = :adminid AND `language` = :lang
			AND `templategroup` = 'mails' AND `varname` LIKE :template
		");
		$result = Database::pexecute_first($result_stmt, [
			'adminid' => $userinfo['adminid'],
			'lang' => $language,
			'template' => $template . '%'
		]);
		if ($result && $result['def'] > 0) {
			Response::standardError('templatelanguagecombodefined');
		}

		// set target language
		Language::setLanguage($language);

		$subject = lng('mails.' . $template . '.subject');
		$body = str_replace('\n', "\n", lng('mails.' . $template . '.mailbody'));

		// re set language to user
		Language::setLanguage(CurrentUser::getField('def_language'));

		$template_add_data = include_once dirname(__FILE__) . '/lib/formfields/admin/templates/formfield.template_add.php';

		UI::view('user/form-replacers.html.twig', [
			'formaction' => $linker->getLink(['section' => 'templates']),
			'formdata' => $template_add_data['template_add'],
			'replacers' => $template_add_data['template_replacers']
		]);
	} elseif (Request::post('send') == 'send' && empty(Request::post('filesend'))) {
		// email templates
		$language = htmlentities(Validate::validate(Request::post('language'), 'language', '/^[^\r\n\0"\']+$/', 'nolanguageselect'));
		if (!array_key_exists($language, $languages)) {
			Response::standardError('templatelanguageinvalid');
		}
		$template = Validate::validate(Request::post('template'), 'template');
		$subject = Validate::validate(Request::post('subject'), 'subject', '/^[^\r\n\0]+$/', 'nosubjectcreate');
		$mailbody = Validate::validate(Request::post('mailbody'), 'mailbody', '/^[^\0]+$/', 'nomailbodycreate');
		$templates = [];
		$result_stmt = Database::prepare("
			SELECT `varname` FROM `" . TABLE_PANEL_TEMPLATES . "`
			WHERE `adminid` = :adminid AND `language` = :lang
			AND `templategroup` = 'mails' AND `varname` LIKE '%_subject'");
		Database::pexecute($result_stmt, [
			'adminid' => $userinfo['adminid'],
			'lang' => $language
		]);

		while ($row = $result_stmt->fetch(PDO::FETCH_ASSOC)) {
			$templates[] = str_replace('_subject', '', $row['varname']);
		}

		$templates = array_diff($available_templates, $templates);
		if (!in_array($template, $templates)) {
			Response::standardError('templatenotfound');
		} else {
			$ins_stmt = Database::prepare("
				INSERT INTO `" . TABLE_PANEL_TEMPLATES . "` SET
					`adminid` = :adminid,
					`language` = :lang,
					`templategroup` = 'mails',
					`varname` = :var,
					`value` = :value");

			// mail-subject
			$ins_data = [
				'adminid' => $userinfo['adminid'],
				'lang' => $language,
				'var' => $template . '_subject',
				'value' => $subject
			];
			Database::pexecute($ins_stmt, $ins_data);

			// mail-body
			$ins_data = [
				'adminid' => $userinfo['adminid'],
				'lang' => $language,
				'var' => $template . '_mailbody',
				'value' => $mailbody
			];
			Database::pexecute($ins_stmt, $ins_data);

			$log->logAction(FroxlorLogger::ADM_ACTION, LOG_INFO, "added template '" . $language . ' - ' . $template . "'");
			Response::redirectTo($filename, [
				'page' => $page
			]);
		}
	} elseif (Request::post('filesend') == 'filesend') {
		// file templates
		$template = Validate::validate(Request::post('template'), 'template');
		$filecontent = Validate::validate(Request::post('filecontent'), 'filecontent', '/^[^\0]+$/', 'filecontentnotset');

		$ins_stmt = Database::prepare("
			INSERT INTO `" . TABLE_PANEL_TEMPLATES . "` SET
				`adminid` = :adminid,
				`language` = '',
				`templategroup` = 'files',
				`varname` = :var,
				`value` = :value");

		$ins_data = [
			'adminid' => $userinfo['adminid'],
			'var' => $template,
			'value' => $filecontent
		];
		Database::pexecute($ins_stmt, $ins_data);

		$log->logAction(FroxlorLogger::ADM_ACTION, LOG_INFO, "added template '" . $template . "'");
		Response::redirectTo($filename, [
			'page' => $page
		]);
	} elseif (empty(Request::get('files'))) {
		// email templates
		$add = false;
		$language_options = [];
		$template_options = [];

		foreach ($languages as $language_file => $language_name) {
			$templates = [];
			$result_stmt = Database::prepare("
				SELECT `varname` FROM `" . TABLE_PANEL_TEMPLATES . "`
				WHERE `adminid` = :adminid AND `language` = :lang
				AND `templategroup` = 'mails' AND `varname` LIKE '%_subject'");
			Database::pexecute($result_stmt, [
				'adminid' => $userinfo['adminid'],
				'lang' => $language_name
			]);

			while ($row = $result_stmt->fetch(PDO::FETCH_ASSOC)) {
				$templates[] = str_replace('_subject', '', $row['varname']);
			}

			if (count(array_diff($available_templates, $templates)) > 0) {
				$add = true;
				$language_options[$language_file] = $language_name;

				$templates = array_diff($available_templates, $templates);

				foreach ($templates as $template) {
					$template_options[$template] = lng('admin.templates.' . $template);
				}
			}
		}

		if ($add) {
			UI::view('user/form.html.twig', [
				'formaction' => $linker->getLink(['section' => 'templates']),
				'formdata' => [
					'title' => lng('admin.templates.template_add'),
					'image' => 'fa-solid fa-plus',
					'self_overview' => ['section' => 'templates', 'page' => 'email'],
					'sections' => [
						'section_a' => [
							'title' => lng('admin.templates.template_add'),
							'fields' => [
								'language' => [
									'label' => lng('login.language'),
									'type' => 'select',
									'select_var' => $language_options,
									'selected' => $userinfo['language']
								],
								'template' => [
									'label' => lng('admin.templates.action'),
									'type' => 'select',
									'select_var' => $template_options
								],
								'prepare' => [
									'type' => 'hidden',
									'value' => 'prepare'
								]
							]
						]
					]
				],
				'editid' => $id
			]);
		} else {
			Response::standardError('alltemplatesdefined');
		}
	} else {
		// filetemplates
		$result_stmt = Database::prepare("
			SELECT `id`, `varname` FROM `" . TABLE_PANEL_TEMPLATES . "`
			WHERE `adminid` = :adminid AND `templategroup`='files'");
		Database::pexecute($result_stmt, [
			'adminid' => $userinfo['adminid']
		]);

		if (Database::num_rows() == count($file_templates)) {
			Response::standardError('alltemplatesdefined');
		} else {
			$templatesdefined = [];
			$free_templates = [];

			while ($row = $result_stmt->fetch(PDO::FETCH_ASSOC)) {
				$templatesdefined[] = $row['varname'];
			}

			foreach (array_diff($file_templates, $templatesdefined) as $template) {
				$free_templates[$template] = lng('admin.templates.' . $template);
			}

			$filetemplate_add_data = include_once dirname(__FILE__) . '/lib/formfields/admin/templates/formfield.filetemplate_add.php';

			UI::view('user/form-replacers.html.twig', [
				'formaction' => $linker->getLink(['section' => 'templates']),
				'formdata' => $filetemplate_add_data['filetemplate_add'],
				'replacers' => $filetemplate_add_data['filetemplate_replacers']
			]);
		}
	}
} elseif ($action == 'edit' && $subjectid != 0 && $mailbodyid != 0) {
	// email templates
	$result_stmt = Database::prepare("
		SELECT `language`, `varname`, `value` FROM `" . TABLE_PANEL_TEMPLATES . "`
		WHERE `adminid` = :adminid AND `id` = :subjectid");
	Database::pexecute($result_stmt, [
		'adminid' => $userinfo['adminid'],
		'subjectid' => $subjectid
	]);
	$result = $result_stmt->fetch(PDO::FETCH_ASSOC);

	if ($result['varname'] != '') {
		if (Request::post('send') == 'send') {
			$subject = Validate::validate(Request::post('subject'), 'subject', '/^[^\r\n\0]+$/', 'nosubjectcreate');
			$mailbody = Validate::validate(Request::post('mailbody'), 'mailbody', '/^[^\0]+$/', 'nomailbodycreate');

			$upd_stmt = Database::prepare("
				UPDATE `" . TABLE_PANEL_TEMPLATES . "` SET
					`value` = :value
				WHERE `adminid` = :adminid AND `id` = :id");
			// subject
			Database::pexecute($upd_stmt, [
				'value' => $subject,
				'adminid' => $userinfo['adminid'],
				'id' => $subjectid
			]);
			// same query but mailbody
			Database::pexecute($upd_stmt, [
				'value' => $mailbody,
				'adminid' => $userinfo['adminid'],
				'id' => $mailbodyid
			]);

			$log->logAction(FroxlorLogger::ADM_ACTION, LOG_INFO, "edited template '" . $result['varname'] . "'");
			Response::redirectTo($filename, [
				'page' => $page
			]);
		} else {
			$result = PhpHelper::htmlentitiesArray($result);
			$template_name = lng('admin.templates.' . str_replace('_subject', '', $result['varname']));
			$subject = $result['value'];
			$result_stmt = Database::prepare("
				SELECT `language`, `varname`, `value`
				FROM `" . TABLE_PANEL_TEMPLATES . "`
				WHERE `adminid` = :adminid AND `id` = :id");
			Database::pexecute($result_stmt, [
				'adminid' => $userinfo['adminid'],
				'id' => $mailbodyid
			]);
			$result = $result_stmt->fetch(PDO::FETCH_ASSOC);

			$template = str_replace('_mailbody', '', $result['varname']);

			// don't escape the already escaped language-string so save up before htmlentities()
			$language = $result['language'];
			$result = PhpHelper::htmlentitiesArray($result);
			$mailbody = $result['value'];

			$template_edit_data = include_once dirname(__FILE__) . '/lib/formfields/admin/templates/formfield.template_edit.php';

			UI::view('user/form-replacers.html.twig', [
				'formaction' => $linker->getLink(['section' => 'templates']),
				'formdata' => $template_edit_data['template_edit'],
				'replacers' => $template_edit_data['template_replacers']
			]);
		}
	}
} elseif ($action == 'editf' && $id != 0) {
	// file templates
	$result_stmt = Database::prepare("
		SELECT * FROM `" . TABLE_PANEL_TEMPLATES . "`
		WHERE `adminid` = :adminid AND `id` = :id");
	Database::pexecute($result_stmt, [
		'adminid' => $userinfo['adminid'],
		'id' => $id
	]);

	if (Database::num_rows() > 0) {
		$row = $result_stmt->fetch(PDO::FETCH_ASSOC);

		// filetemplates
		if (Request::post('filesend') == 'filesend') {
			$filecontent = Validate::validate(Request::post('filecontent'), 'filecontent', '/^[^\0]+$/', 'filecontentnotset');
			$upd_stmt = Database::prepare("
				UPDATE `" . TABLE_PANEL_TEMPLATES . "` SET
					`value` = :value
				WHERE `adminid` = :adminid AND `id` = :id");
			Database::pexecute($upd_stmt, [
				'value' => $filecontent,
				'adminid' => $userinfo['adminid'],
				'id' => $id
			]);

			$log->logAction(FroxlorLogger::ADM_ACTION, LOG_INFO, "edited template '" . $row['varname'] . "'");
			Response::redirectTo($filename, [
				'page' => $page
			]);
		} else {
			$row = PhpHelper::htmlentitiesArray($row);

			$filetemplate_edit_data = include_once dirname(__FILE__) . '/lib/formfields/admin/templates/formfield.filetemplate_edit.php';

			UI::view('user/form-replacers.html.twig', [
				'formaction' => $linker->getLink(['section' => 'templates']),
				'formdata' => $filetemplate_edit_data['filetemplate_edit'],
				'replacers' => $filetemplate_edit_data['filetemplate_replacers'],
				'editid' => $id
			]);
		}
	} else {
		Response::standardError('templatenotfound');
	}
}
