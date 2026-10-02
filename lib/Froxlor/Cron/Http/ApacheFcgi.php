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
use Froxlor\Customer\Customer;
use Froxlor\Database\Database;
use Froxlor\FileDir;
use Froxlor\Froxlor;
use Froxlor\Http\Directory;
use Froxlor\Settings;

/**
 * @author        Florian Lippert <flo@syscp.org> (2003-2009)
 * @author        Froxlor team <team@froxlor.org> (2010-)
 */
class ApacheFcgi extends Apache
{

	public function createOwnVhostStarter()
	{
		if (Settings::Get('system.mod_fcgid_ownvhost') == '1' || (Settings::Get('phpfpm.enabled') == '1' && Settings::Get('phpfpm.enabled_ownvhost') == '1')) {
			$mypath = Froxlor::getInstallDir();

			if (Settings::Get('system.mod_fcgid_ownvhost') == '1') {
				$user = Settings::Get('system.mod_fcgid_httpuser');
				$group = Settings::Get('system.mod_fcgid_httpgroup');
			} elseif (Settings::Get('phpfpm.enabled') == '1' && Settings::Get('phpfpm.enabled_ownvhost') == '1') {
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
			}

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

			if ((int)Settings::Get('phpfpm.enabled') == 1) {
				$srvName = 'fpm.external';
				if ($domain['ssl'] == 1 && $ssl_vhost) {
					$srvName = 'ssl-fpm.external';
				}
				// #1317 - perl is executed via apache and therefore, when using fpm, does not know the user
				// which perl is supposed to run as, hence the need for Suexec need
				if (Customer::customerHasPerlEnabled($domain['customerid'])) {
					$php_options_text .= '  SuexecUserGroup "' . $domain['loginname'] . '" "' . $domain['loginname'] . '"' . "\n";
				}

				$domain['fpm_socket'] = $php->getInterface()->getSocketFile();

				// mod_proxy stuff for apache-2.4
				if (Settings::Get('system.apache24') == '1' && Settings::Get('phpfpm.use_mod_proxy') == '1') {

					$php_options_text .= '  <Directory "' . FileDir::makeCorrectDir($domain['documentroot']) . '">' . "\n";

					$filesmatch = $phpconfig['fpm_settings']['limit_extensions'];
					$extensions = explode(" ", $filesmatch);
					$filesmatch = "";
					foreach ($extensions as $ext) {
						$filesmatch .= substr($ext, 1) . '|';
					}
					// start block, cut off last pipe and close block
					$filesmatch = '(' . str_replace(".", "\.", substr($filesmatch, 0, -1)) . ')';
					$php_options_text .= '  <FilesMatch \.' . $filesmatch . '$>' . "\n";
					$php_options_text .= '    <If "-f %{SCRIPT_FILENAME}">' . "\n";
					$php_options_text .= '      SetHandler proxy:unix:' . $domain['fpm_socket'] . '|fcgi://localhost' . "\n";
					$php_options_text .= '    </If>' . "\n";
					$php_options_text .= '  </FilesMatch>' . "\n";

					$mypath_dir = new Directory($domain['documentroot']);
					// only create the "require all granted" directive if there is no active directory-protection
					// for this path, as this would be the first require and therefore grant all access
					if ($mypath_dir->isUserProtected() == false) {
						if ($phpconfig['pass_authorizationheader'] == '1') {
							$php_options_text .= '    CGIPassAuth On' . "\n";
						}
						$php_options_text .= '    Require all granted' . "\n";
						$php_options_text .= '    AllowOverride All' . "\n";
					} elseif ($phpconfig['pass_authorizationheader'] == '1') {
						// allow Pass of Authorization header
						$php_options_text .= '    CGIPassAuth On' . "\n";
					}
					$php_options_text .= '  </Directory>' . "\n";
				} else {
					$addheader = "";
					if ($phpconfig['pass_authorizationheader'] == '1') {
						$addheader = " -pass-header Authorization";
					}
					$php_options_text .= '  FastCgiExternalServer ' . $php->getInterface()->getAliasConfigDir() . $srvName . ' -socket ' . $domain['fpm_socket'] . ' -idle-timeout ' . $phpconfig['fpm_settings']['idle_timeout'] . $addheader . "\n";
					$php_options_text .= '  <Directory "' . FileDir::makeCorrectDir($domain['documentroot']) . '">' . "\n";
					$filesmatch = $phpconfig['fpm_settings']['limit_extensions'];
					$extensions = explode(" ", $filesmatch);
					$filesmatch = "";
					foreach ($extensions as $ext) {
						$filesmatch .= substr($ext, 1) . '|';
					}
					// start block, cut off last pipe and close block
					$filesmatch = '(' . str_replace(".", "\.", substr($filesmatch, 0, -1)) . ')';
					$php_options_text .= '    <FilesMatch \.' . $filesmatch . '$>' . "\n";
					$php_options_text .= '      SetHandler php-fastcgi' . "\n";
					$php_options_text .= '      Action php-fastcgi /fastcgiphp' . "\n";
					$php_options_text .= '      Options +ExecCGI' . "\n";
					$php_options_text .= '    </FilesMatch>' . "\n";
					// >=apache-2.4 enabled?
					if (Settings::Get('system.apache24') == '1') {
						$mypath_dir = new Directory($domain['documentroot']);
						// only create the require all granted if there is not active directory-protection
						// for this path, as this would be the first require and therefore grant all access
						if ($mypath_dir->isUserProtected() == false) {
							$php_options_text .= '    Require all granted' . "\n";
							$php_options_text .= '    AllowOverride All' . "\n";
						}
					} else {
						$php_options_text .= '    Order allow,deny' . "\n";
						$php_options_text .= '    allow from all' . "\n";
					}
					$php_options_text .= '  </Directory>' . "\n";
					$php_options_text .= '  Alias /fastcgiphp ' . $php->getInterface()->getAliasConfigDir() . $srvName . "\n";
				}
			} else {
				$php_options_text .= '  FcgidIdleTimeout ' . Settings::Get('system.mod_fcgid_idle_timeout') . "\n";
				if ($phpconfig['pass_authorizationheader'] == '1') {
					$php_options_text .= '  FcgidPassHeader     Authorization' . "\n";
				}
				if ((int)Settings::Get('system.mod_fcgid_wrapper') == 0) {
					$php_options_text .= '  SuexecUserGroup "' . $domain['loginname'] . '" "' . $domain['loginname'] . '"' . "\n";
					$php_options_text .= '  ScriptAlias /php/ ' . $php->getInterface()->getConfigDir() . "\n";
				} else {
					$php_options_text .= '  SuexecUserGroup "' . $domain['loginname'] . '" "' . $domain['loginname'] . '"' . "\n";
					$php_options_text .= '  <Directory "' . FileDir::makeCorrectDir($domain['documentroot']) . '">' . "\n";
					$file_extensions = explode(' ', $phpconfig['file_extensions']);
					$php_options_text .= '    <FilesMatch "\.(' . implode('|', $file_extensions) . ')$">' . "\n";
					$php_options_text .= '      SetHandler fcgid-script' . "\n";
					foreach ($file_extensions as $file_extension) {
						$php_options_text .= '      FcgidWrapper ' . $php->getInterface()->getStarterFile() . ' .' . $file_extension . "\n";
					}
					$php_options_text .= '      Options +ExecCGI' . "\n";
					$php_options_text .= '    </FilesMatch>' . "\n";
					// >=apache-2.4 enabled?
					if (Settings::Get('system.apache24') == '1') {
						$mypath_dir = new Directory($domain['documentroot']);
						// only create the require all granted if there is not active directory-protection
						// for this path, as this would be the first require and therefore grant all access
						if ($mypath_dir->isUserProtected() == false) {
							$php_options_text .= '    Require all granted' . "\n";
							$php_options_text .= '    AllowOverride All' . "\n";
						}
					} else {
						$php_options_text .= '    Order allow,deny' . "\n";
						$php_options_text .= '    allow from all' . "\n";
					}
					$php_options_text .= '  </Directory>' . "\n";
				}
			}

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
