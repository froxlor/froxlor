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

namespace Froxlor\Ajax;

use Froxlor\Api\Commands\Admins;
use Froxlor\Api\Commands\Customers;
use Froxlor\Api\Commands\Domains;
use Froxlor\Api\Commands\EmailDomains;
use Froxlor\Api\Commands\Emails;
use Froxlor\Api\Commands\FpmDaemons;
use Froxlor\Api\Commands\Ftps;
use Froxlor\Api\Commands\HostingPlans;
use Froxlor\Api\Commands\IpsAndPorts;
use Froxlor\Api\Commands\Mysqls;
use Froxlor\Api\Commands\PhpSettings;
use Froxlor\Api\Commands\SubDomains;
use Froxlor\Froxlor;
use Froxlor\PhpHelper;
use Froxlor\Settings;
use Froxlor\UI\Collection;

class GlobalSearch
{
	protected array $userinfo;

	public static function searchSettings(string $searchtext, array $userinfo): array
	{
		$result = [];
		if ($searchtext && strlen(trim($searchtext)) > 2) {
			$processed = [];
			$stparts = explode(" ", $searchtext);
			foreach ($stparts as $searchtext) {
				$searchtext = trim($searchtext);
				if (preg_match('/^([a-z]+):$/', $searchtext, $matches)) {
					// only search settings if specific search is 'settings', else skip
					if ($matches[1] == 'settings') {
						continue;
					} else {
						break;
					}
				}
				$settings_data = PhpHelper::loadConfigArrayDir(Froxlor::getInstallDir() . '/actions/admin/settings/');
				$results = [];
				if (!isset($processed['settings'])) {
					$processed['settings'] = [];
				}
				PhpHelper::recursive_array_search($searchtext, $settings_data, $results);
				foreach ($results as $pathkey) {
					$pk = explode(".", $pathkey);
					if (count($pk) > 4) {
						$settingkey = $pk[0] . '.' . $pk[1] . '.' . $pk[2] . '.' . $pk[3];
						if (isset($settings_data[$pk[0]][$pk[1]]['advanced_mode']) && $settings_data[$pk[0]][$pk[1]]['advanced_mode'] && (int)Settings::Get('panel.settings_mode') == 0) {
							continue;
						}
						if (is_array($processed['settings']) && !array_key_exists($settingkey, $processed['settings'])) {
							$processed['settings'][$settingkey] = true;
							$sresult = $settings_data[$pk[0]][$pk[1]][$pk[2]][$pk[3]];
							if (isset($sresult['advanced_mode']) && $sresult['advanced_mode'] && (int)Settings::Get('panel.settings_mode') == 0) {
								continue;
							}
							if ($sresult['type'] != 'hidden') {
								if (!isset($result['settings'])) {
									$result['settings'] = [];
								}
								$result['settings'][] = [
									'title' => (is_array($sresult['label']) ? $sresult['label']['title'] : $sresult['label']),
									'href' => 'admin_settings.php?page=overview&part=' . $pk[1] . '&em=' . $pk[3]
								];
							} // not hidden
						} // if not processed
					} // correct settingkey
				} // foreach
			} // foreach
		} // searchtext min 3 chars
		return $result;
	}

	/**
	 *
	 */
	public static function searchGlobal(string $searchtext, array $userinfo): array
	{
		$result = [];
		if ($searchtext && strlen(trim($searchtext)) > 2) {
			$processed = [];

			$stparts = explode(" ", $searchtext);
			$module = "";

			foreach ($stparts as $searchtext) {
				$searchtext = trim($searchtext);

				if (preg_match('/^([a-z]+):$/', $searchtext, $matches)) {
					$module = $matches[1];
					if ($matches[1] == 'settings') {
						break;
					} else {
						continue;
					}
				}

				// admin
				if (isset($userinfo['adminsession']) && $userinfo['adminsession'] == 1) {
					$toSearch = [
						// customers
						'customer' => [
							'class' => Customers::class,
							'searchfields' => [
								'c.loginname',
								'c.name',
								'c.firstname',
								'c.company',
								'c.street',
								'c.zipcode',
								'c.city',
								'c.email',
								'c.customernumber',
								'c.custom_notes'
							],
							'result_key' => 'loginname',
							'result_format' => [
								'title' => ['\\Froxlor\\User', 'getCorrectFullUserDetails'],
								'href' => 'admin_customers.php?page=customers&searchfield=c.loginname&searchtext='
							]
						],
						// domains
						'domains' => [
							'class' => Domains::class,
							'searchfields' => [
								'd.domain',
								'd.domain_ace',
								'd.documentroot'
							],
							'result_key' => 'domain_ace',
							'result_format' => [
								'title' => ['\\Froxlor\\Ajax\\GlobalSearch', 'getFieldFromResult'],
								'title_args' => 'domain_ace',
								'href' => 'admin_domains.php?page=domains&searchfield=d.domain_ace&searchtext='
							]
						],
						// ips and ports
						'ipsandports' => [
							'class' => IpsAndPorts::class,
							'searchfields' => [
								'ip',
								'vhostcontainer',
								'specialsettings'
							],
							'result_key' => 'ip',
							'result_groupkey' => 'ip',
							'result_format' => [
								'title' => ['\\Froxlor\\Ajax\\GlobalSearch', 'getFieldFromResult'],
								'title_args' => 'ip',
								'href' => 'admin_ipsandports.php?page=ipsandports&searchfield=ip&searchtext='
							]
						],
						// hosting-plans
						'hostingplans' => [
							'class' => HostingPlans::class,
							'searchfields' => [
								'p.name',
								'p.description'
							],
							'result_key' => 'id',
							'result_format' => [
								'title' => ['\\Froxlor\\Ajax\\GlobalSearch', 'getFieldFromResult'],
								'title_args' => 'name',
								'href' => 'admin_plans.php?page=overview&searchfield=id&searchtext='
							]
						],
						// PHP configs
						'phpconfigs' => [
							'class' => PhpSettings::class,
							'searchfields' => [
								'c.description',
								'fd.description',
								'c.binary'
							],
							'result_key' => 'id',
							'result_format' => [
								'title' => ['\\Froxlor\\Ajax\\GlobalSearch', 'getFieldFromResult'],
								'title_args' => 'description',
								'href' => 'admin_phpsettings.php?page=overview&searchfield=id&searchtext='
							]
						],
						// FPM daemons
						'fpmconfigs' => [
							'class' => FpmDaemons::class,
							'searchfields' => [
								'description',
								'reload_cmd'
							],
							'result_key' => 'id',
							'result_format' => [
								'title' => ['\\Froxlor\\Ajax\\GlobalSearch', 'getFieldFromResult'],
								'title_args' => 'description',
								'href' => 'admin_phpsettings.php?page=fpmdaemons&searchfield=id&searchtext='
							]
						]
					];

					if ((bool)$userinfo['change_serversettings']) {
						// admins
						$toSearch['admins'] = [
							'class' => Admins::class,
							'searchfields' => [
								'loginname',
								'name',
								'email',
								'custom_notes'
							],
							'result_key' => 'loginname',
							'result_format' => [
								'title' => ['\\Froxlor\\Ajax\\GlobalSearch', 'getFieldFromResult'],
								'title_args' => 'name',
								'href' => 'admin_admins.php?page=admins&searchfield=loginname&searchtext='
							]
						];
					}
				} else {
					$toSearch = [
						// (sub)domains
						'domains' => [
							'class' => SubDomains::class,
							'searchfields' => [
								'd.domain',
								'd.domain_ace',
								'd.documentroot'
							],
							'result_key' => 'domain_ace',
							'result_format' => [
								'title' => ['\\Froxlor\\Ajax\\GlobalSearch', 'getFieldFromResult'],
								'title_args' => 'domain_ace',
								'href' => 'customer_domains.php?page=domains&searchfield=d.domain_ace&searchtext='
							]
						],
						// email addresses
						'emails' => [
							'class' => Emails::class,
							'searchfields' => [
								'm.email',
								'm.email_full'
							],
							'result_key' => 'email',
							'result_format' => [
								'title' => ['\\Froxlor\\Ajax\\GlobalSearch', 'getFieldFromResult'],
								'title_args' => 'email',
								'href' => 'customer_email.php?page=email_domain&domainid={domainid}&searchfield=m.email&searchtext='
							]
						],
						// email-domains
						'email_domains' => [
							'class' => EmailDomains::class,
							'searchfields' => [
								'd.domain',
							],
							'result_key' => 'domain',
							'result_format' => [
								'title' => ['\\Froxlor\\Ajax\\GlobalSearch', 'getFieldFromResult'],
								'title_args' => 'domain',
								'href' => 'customer_email.php?page=emails&searchfield=d.domain&searchtext='
							]
						],
						// databases
						'databases' => [
							'class' => Mysqls::class,
							'searchfields' => [
								'databasename',
								'description'
							],
							'result_key' => 'databasename',
							'result_format' => [
								'title' => ['\\Froxlor\\Ajax\\GlobalSearch', 'getFieldFromResult'],
								'title_args' => 'databasename',
								'href' => 'customer_mysql.php?page=mysqls&searchfield=databasename&searchtext='
							]
						],
						// ftp user
						'ftpuser' => [
							'class' => Ftps::class,
							'searchfields' => [
								'username',
								'description'
							],
							'result_key' => 'username',
							'result_format' => [
								'title' => ['\\Froxlor\\Ajax\\GlobalSearch', 'getFieldFromResult'],
								'title_args' => 'username',
								'href' => 'customer_ftp.php?page=accounts&searchfield=username&searchtext='
							]
						]
					];
				}

				// module specific search
				if (!empty($module)) {
					$modSearch = $toSearch[$module] ?? [];
					$toSearch = [$module => $modSearch];
				}

				foreach ($toSearch as $entity => $edata) {
					$collection = (new Collection($edata['class'], $userinfo))
						->setInternal(true)
						->addParam([
							'sql_search' => [
								'_plainsql' => self::searchStringSql($edata['searchfields'], $searchtext)
							]
						]);
					if ($collection->count() > 0) {
						if (!isset($processed[$entity])) {
							$processed[$entity] = [];
						}
						$group_key = $edata['result_groupkey'] ?? $edata['result_key'];
						foreach ($collection->getList() as $cresult) {
							if (is_array($processed[$entity]) && !array_key_exists($cresult[$group_key], $processed[$entity])) {
								$processed[$entity][$cresult[$group_key]] = true;
								if (!isset($result[$entity])) {
									$result[$entity] = [];
								}
								// replacer from result in href
								$href_replacer = [];
								if (preg_match_all('/\{([a-z]+)\}/', $edata['result_format']['href'], $href_replacer) !== false) {
									foreach ($href_replacer[1] as $href_field) {
										$href_field_value = self::getFieldFromResult($cresult, $href_field);
										$edata['result_format']['href'] = str_replace('{' . $href_field . '}', $href_field_value, $edata['result_format']['href']);
									}
								}
								$result[$entity][] = [
									'title' => call_user_func($edata['result_format']['title'], $cresult, ($edata['result_format']['title_args'] ?? null)),
									'href' => $edata['result_format']['href'] . $cresult[$edata['result_key']]
								];
							}
						}
					}
				} // foreach entity

			} // foreach split search-term
		}
		return $result;
	}

	private static function searchStringSql(array $searchfields, $searchtext)
	{
		$result = ['sql' => [], 'values' => []];
		$result['sql'] = "(";
		foreach ($searchfields as $sf) {
			$result['sql'] .= $sf . " LIKE :searchtext OR ";
		}
		$result['sql'] = substr($result['sql'], 0, -3) . ")";
		$result['values'] = ['searchtext' => '%' . $searchtext . '%'];
		return $result;
	}

	private static function getFieldFromResult(array $resultset, ?string $field = null)
	{
		return $resultset[$field] ?? '';
	}
}
