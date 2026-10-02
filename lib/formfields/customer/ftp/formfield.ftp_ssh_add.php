<?php

/**
 * This file is part of the froxlor project.
 * Copyright (c) 2010 the froxlor Team (see authors).
 *
 * For the full copyright and license information, please view the COPYING
 * file that was distributed with this source code. You can also view the
 * COPYING file online at https://files.froxlor.org/misc/COPYING.txt
 *
 * @copyright  (c) the authors
 * @author         froxlor team <team@froxlor.org> (2010-)
 * @license        GPLv2 https://files.froxlor.org/misc/COPYING.txt
 * @package        Formfields
 */

return [
	'sshkey_add' => [
		'title' => lng('ftp.sshkey_add'),
		'image' => 'fa-solid fa-key',
		'self_overview' => ['section' => 'ftp', 'page' => 'sshkeys'],
		'sections' => [
			'section_a' => [
				'title' => lng('ftp.sshkey_add'),
				'fields' => [
					'description' => [
						'label' => lng('panel.sshkeydesc'),
						'type' => 'text'
					],
					'ftpuser' => [
						'label' => lng('panel.ftpuser'),
						'type' => 'select',
						'select_var' => $userList,
						'mandatory' => true
					],
					'ssh_pubkey' => [
						'label' => lng('panel.sshpubkey'),
						'placeholder' => lng('panel.sshpubkeyph'),
						'type' => 'textarea',
						'cols' => 60,
						'rows' => 12,
						'mandatory' => true
					],
				]
			]
		]
	]
];
