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

namespace Froxlor\Cron\Http;

use Froxlor\Cron\Http\Php\PhpInterface;
use Froxlor\Database\Database;
use Froxlor\FileDir;
use Froxlor\Froxlor;
use Froxlor\Settings;

class NginxFcgi extends Nginx
{

	public function createOwnVhostStarter()
	{
		if (Settings::Get('phpfpm.enabled') == '1' && Settings::Get('phpfpm.enabled_ownvhost') == '1') {
			$mypath = Froxlor::getInstallDir();

			$user = Settings::Get('phpfpm.vhost_httpuser');
			$group = Settings::Get('phpfpm.vhost_httpgroup');

			// get fpm config
			$fpm_sel_stmt = Database::prepare("
				SELECT f.id FROM `" . TABLE_PANEL_FPMDAEMONS . "` f
				LEFT JOIN `" . TABLE_PANEL_PHPCONFIGS . "` p ON p.fpmsettingid = f.id
				WHERE p.id = :phpconfigid
			");
			$fpm_config = Database::pexecute_first($fpm_sel_stmt, [
				'phpconfigid' => Settings::Get('phpfpm.vhost_defaultini')
			]);

			$domain = [
				'id' => 'none',
				'domain' => Settings::Get('system.hostname'),
				'adminid' => 1, /* first admin-user (superadmin) */
				'mod_fcgid_starter' => -1,
				'mod_fcgid_maxrequests' => -1,
				'guid' => $user,
				'openbasedir' => 0,
				'email' => Settings::Get('panel.adminmail'),
				'loginname' => 'froxlor.panel',
				'documentroot' => $mypath,
				'customerroot' => $mypath,
				'fpm_config_id' => isset($fpm_config['id']) ? $fpm_config['id'] : 1
			];

			// all the files and folders have to belong to the local user
			// now because we also use fcgid for our own vhost
			FileDir::safe_exec('chown -R ' . $user . ':' . $group . ' ' . escapeshellarg($mypath));

			// get php.ini for our own vhost
			$php = new PhpInterface($domain);

			// get php-config
			if (Settings::Get('phpfpm.enabled') == '1') {
				// fpm
				$phpconfig = $php->getPhpConfig(Settings::Get('phpfpm.vhost_defaultini'));
			} else {
				// fcgid
				$phpconfig = $php->getPhpConfig(Settings::Get('system.mod_fcgid_defaultini_ownvhost'));
			}

			// create starter-file | config-file
			$php->getInterface()->createConfig($phpconfig);

			// create php.ini (fpm does nothing here, as it
			// defines ini-settings in its pool config)
			$php->getInterface()->createIniFile($phpconfig);
		}
	}

	protected function composePhpOptions(&$domain, $ssl_vhost = false)
	{
		$php_options_text = '';

		if ($domain['phpenabled_customer'] == 1 && $domain['phpenabled_vhost'] == '1') {
			$php = new PhpInterface($domain);
			$phpconfig = $php->getPhpConfig((int)$domain['phpsettingid']);

			$php_options_text = "\t" . 'location ~ ^(.+?\.php)(/.*)?$ {' . "\n";
			if ($domain['notryfiles'] != 1) {
				$php_options_text .= "\t\t" . 'try_files ' . $domain['nonexistinguri'] . ' @php;' . "\n";
				$php_options_text .= "\t" . '}' . "\n\n";

				$php_options_text .= "\t" . 'location @php {' . "\n";
				$php_options_text .= "\t\t" . 'try_files $1 =404;' . "\n\n";
			}
			$php_options_text .= "\t\t" . 'include ' . Settings::Get('nginx.fastcgiparams') . ";\n";
			$php_options_text .= "\t\t" . 'fastcgi_split_path_info ^(.+?\.php)(/.*)$;' . "\n";
			$php_options_text .= "\t\t" . 'fastcgi_param SCRIPT_FILENAME $request_filename;' . "\n";
			$php_options_text .= "\t\t" . 'set $path_info $fastcgi_path_info;' . "\n";
			$php_options_text .= "\t\t" . 'fastcgi_param PATH_INFO $path_info;' . "\n";
			if ($domain['ssl'] == '1' && $ssl_vhost) {
				$php_options_text .= "\t\t" . 'fastcgi_param HTTPS on;' . "\n";
			}
			$domain['fpm_socket'] = $php->getInterface()->getSocketFile();
			$php_options_text .= "\t\t" . 'fastcgi_pass unix:' . $domain['fpm_socket'] . ";\n";
			$php_options_text .= "\t\t" . 'fastcgi_index index.php;' . "\n";
			$php_options_text .= "\t}\n\n";

			// create starter-file | config-file
			$php->getInterface()->createConfig($phpconfig);

			// create php.ini (fpm does nothing here, as it
			// defines ini-settings in its pool config)
			$php->getInterface()->createIniFile($phpconfig);
		} else {
			$php_options_text .= '  # PHP is disabled for this vHost' . "\n";
		}

		return $php_options_text;
	}
}
