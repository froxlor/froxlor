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

namespace Froxlor\UI\Callbacks;

use Froxlor\Settings;
use Froxlor\Idna\IdnaWrapper;
use Froxlor\UI\Panel\UI;

class PHPConf
{
	public static function domainList(array $attributes): string
	{
		$idna = new IdnaWrapper;
		$domains = "";
		$subdomains_count = count($attributes['fields']['subdomains']);
		foreach ($attributes['fields']['domains'] as $configdomain) {
			$domains .= $idna->decode($configdomain) . "<br>";
		}
		if ($subdomains_count == 0 && empty($domains)) {
			$domains = lng('admin.phpsettings.notused');
		} else {
			if (Settings::Get('panel.phpconfigs_hidesubdomains') == '1') {
				$domains .= !empty($subdomains_count) ? ((!empty($domains) ? '+ ' : '') . $subdomains_count . ' ' . lng('customer.subdomains')) : '';
			} else {
				foreach ($attributes['fields']['subdomains'] as $configdomain) {
					$domains .= $idna->decode($configdomain) . "<br>";
				}
			}
		}

		return $domains;
	}

	public static function configsList(array $attributes)
	{
		$configs = "";
		foreach ($attributes['fields']['configs'] as $configused) {
			$configs .= $configused . "<br>";
		}
		return $configs;
	}

	public static function isNotDefault(array $attributes)
	{
		if (UI::getCurrentUser()['change_serversettings']) {
			return $attributes['fields']['id'] != 1;
		}
		return false;
	}

	public static function fpmConfLink(array $attributes)
	{
		if (UI::getCurrentUser()['change_serversettings']) {
			$linker = UI::getLinker();
			return [
				'macro' => 'link',
				'data' => [
					'text' => $attributes['data'],
					'href' => $linker->getLink([
						'section' => 'phpsettings',
						'page' => 'fpmdaemons',
						'searchfield' => 'id',
						'searchtext' => $attributes['fields']['fpmsettingid'],
					]),
				]
			];
		}
		return $attributes['data'];
	}
}
