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
	'sshkey_edit' => [
		'title' => lng('ftp.sshkey_edit'),
		'image' => 'fa-solid fa-pen',
		'self_overview' => ['section' => 'ftp', 'page' => 'sshkeys'],
		'sections' => [
			'section_a' => [
				'title' => lng('ftp.sshkey_edit'),
				'fields' => [
					'username' => [
						'label' => lng('login.username'),
						'type' => 'label',
						'value' => $result['username']
					],
					'fingerprint' => [
						'label' => lng('panel.sshfingerprint'),
						'type' => 'label',
						'value' => $result['fingerprint']
					],
					'description' => [
						'label' => lng('panel.sshkeydesc'),
						'type' => 'text',
						'value' => $result['description']
					],
				]
			]
		]
	]
];
