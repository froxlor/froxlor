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

use Froxlor\CurrentUser;
use Froxlor\Settings;

class Style
{
	public static function deactivated(array $attributes): string
	{
		return $attributes['fields']['deactivated'] ? 'table-danger' : '';
	}

	public static function loginDisabled(array $attributes): string
	{
		return $attributes['fields']['login_enabled'] == 'N' ? 'table-danger' : '';
	}

	public static function resultIntegrityBad(array $attributes): string
	{
		return $attributes['fields']['result'] ? '' : 'table-warning';
	}

	public static function invalidApiKey(array $attributes): string
	{
		// check whether the api key is not valid anymore
		$isValid = true;
		if ($attributes['fields']['valid_until'] >= 0) {
			if ($attributes['fields']['valid_until'] < time()) {
				$isValid = false;
			}
		}
		return $isValid ? '' : 'table-danger';
	}

	public static function resultDomainTerminatedOrDeactivated(array $attributes): string
	{
		$termination_date = str_replace("0000-00-00", "", $attributes['fields']['termination_date'] ?? '');
		$termination_css = '';
		if (!empty($termination_date)) {
			$cdate = strtotime($termination_date . " 23:59:59");
			$today = time();
			$termination_css = 'table-warning';
			if ($cdate < $today) {
				$termination_css = 'table-danger';
			}
		}
		$deactivated = $attributes['fields']['deactivated'] || (CurrentUser::isAdmin() && $attributes['fields']['customer_deactivated']);
		return $deactivated ? 'table-info' : $termination_css;
	}

	public static function resultCustomerLockedOrDeactivated(array $attributes): string
	{
		$row_css = '';
		if ((int)$attributes['fields']['deactivated'] == 1) {
			$row_css = 'table-info';
		} elseif ($attributes['fields']['loginfail_count'] >= Settings::Get('login.maxloginattempts')
			&& $attributes['fields']['lastlogin_fail'] > (time() - Settings::Get('login.deactivatetime'))
		) {
			$row_css = 'table-warning';
		}

		return $row_css;
	}

	public static function diskspaceWarning(array $attributes): string
	{
		return self::getWarningStyle('diskspace', $attributes['fields'], (int)Settings::Get('system.report_webmax'));
	}

	private static function getWarningStyle(string $field, array $attributes, int $report_max = 90): string
	{
		$style = '';
		if ((int)$attributes[$field] >= 0) {
			if (($attributes[$field] / 100) * $report_max < $attributes[$field . '_used']) {
				$style = 'table-danger';
			} elseif (($attributes[$field] / 100) * ($report_max - 15) < $attributes[$field . '_used']) {
				$style = 'table-warning';
			}
		}
		return $style;
	}

	public static function trafficWarning(array $attributes): string
	{
		return self::getWarningStyle('traffic', $attributes['fields'], (int)Settings::Get('system.report_trafficmax'));
	}
}
