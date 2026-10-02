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
use Froxlor\Config\ConfigParser;
use Froxlor\Install\Update;
use Froxlor\Settings;

$preconfig = [
	'title' => '2.0.x updates',
	'fields' => []
];
$return = [];

if (Update::versionInUpdate($current_version, '2.0.0-beta1')) {
	$description = 'We have rearranged the settings and split them into basic and advanced categories. This makes it easier for users who do not need all the detailed or very specific settings and options and gives a better overview of the basic/mostly used settings.';
	$question = '<strong>Chose settings mode (you can change that at any time)</strong>';
	$return['panel_settings_mode'] = [
		'type' => 'select',
		'select_var' => [
			0 => 'Basic',
			1 => 'Advanced'
		],
		'selected' => 1,
		'label' => $question,
		'prior_infotext' => $description
	];

	$description = 'The configuration page now can preselect a distribution, please select your current distribution';
	$question = '<strong>Select distribution</strong>';
	$config_dir = FileDir::makeCorrectDir(Froxlor::getInstallDir() . '/lib/configfiles/');
	// show list of available distro's
	$distros = glob($config_dir . '*.xml');
	// selection is required $distributions_select[''] = '-';
	// read in all the distros
	foreach ($distros as $_distribution) {
		// get configparser object
		$dist = new ConfigParser($_distribution);
		// store in tmp array
		$distributions_select[str_replace(".xml", "", strtolower(basename($_distribution)))] = $dist->getCompleteDistroName();
	}
	// sort by distribution name
	asort($distributions_select);
	$return['system_distribution'] = [
		'type' => 'select',
		'select_var' => $distributions_select,
		'selected' => '',
		'label' => $question,
		'prior_infotext' => $description
	];
}

if (Update::versionInUpdate($current_db_version, '202301120')) {
	$acmesh_challenge_dir = rtrim(FileDir::makeCorrectDir(Settings::Get('system.letsencryptchallengepath')), "/");
	$recommended = rtrim(FileDir::makeCorrectDir(Froxlor::getInstallDir()), "/");
	if ((int) Settings::Get('system.leenabled') == 1 && $acmesh_challenge_dir != $recommended) {
		$has_preconfig = true;
		$description = 'ACME challenge docroot from settings differs from the current installation directory.';
		$question = '<strong>Validate Let\'s Encrypt challenge path (recommended value: ' . $recommended . ')</strong>';
		$return['system_letsencryptchallengepath_upd'] = [
			'type' => 'text',
			'value' => $recommended,
			'placeholder' => $acmesh_challenge_dir,
			'label' => $question,
			'prior_infotext' => $description,
			'mandatory' => true,
		];
	}
}

if (Update::versionInUpdate($current_db_version, '202301180')) {
	if ((int) Settings::Get('system.leenabled') == 1) {
		$has_preconfig = true;
		$description = 'Froxlor now supports to set an external DNS resolver for the Let\'s Encrypt pre-check.';
		$question = '<strong>Specify a DNS resolver IP (recommended value: 1.1.1.1 or similar)</strong>';
		$return['system_le_domain_dnscheck_resolver'] = [
			'type' => 'text',
			'pattern' => '^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$|^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:))$|^\s*$',
			'value' => '1.1.1.1',
			'placeholder' => '1.1.1.1',
			'label' => $question,
			'prior_infotext' => $description,
		];
	}
}

$preconfig['fields'] = $return;
return $preconfig;
