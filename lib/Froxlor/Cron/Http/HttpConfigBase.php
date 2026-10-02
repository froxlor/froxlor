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

use Froxlor\Cron\Http\LetsEncrypt\AcmeSh;
use Froxlor\Cron\Http\Php\Fpm;
use Froxlor\Database\Database;
use Froxlor\Domain\Domain;
use Froxlor\FileDir;
use Froxlor\Froxlor;
use Froxlor\FroxlorLogger;
use Froxlor\PhpHelper;
use Froxlor\Settings;
use Froxlor\System\Cronjob;
use PDO;

/**
 * Class HttpConfigBase
 *
 * Base class for all HTTP server configs
 */
class HttpConfigBase
{

	/**
	 * Pre-defined DHE groups to use as fallback if dhparams_file
	 * is given, but non-existent, see also https://github.com/froxlor/Froxlor/issues/1270
	 */
	const FFDHE4096 = <<<EOC
-----BEGIN DH PARAMETERS-----
MIICCAKCAgEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
ssbzSibBsu/6iGtCOGEfz9zeNVs7ZRkDW7w09N75nAI4YbRvydbmyQd62R0mkff3
7lmMsPrBhtkcrv4TCYUTknC0EwyTvEN5RPT9RFLi103TZPLiHnH1S/9croKrnJ32
nuhtK8UiNjoNq8Uhl5sN6todv5pC1cRITgq80Gv6U93vPBsg7j/VnXwl5B0rZp4e
8W5vUsMWTfT7eTDp5OWIV7asfV9C1p9tGHdjzx1VA0AEh/VbpX4xzHpxNciG77Qx
iu1qHgEtnmgyqQdgCpGBMMRtx3j5ca0AOAkpmaMzy4t6Gh25PXFAADwqTs6p+Y0K
zAqCkc3OyX3Pjsm1Wn+IpGtNtahR9EGC4caKAH5eZV9q//////////8CAQI=
-----END DH PARAMETERS-----
EOC;

	public function init()
	{
		// if Let's Encrypt is activated, run it before regeneration of webserver configfiles
		if (Settings::Get('system.leenabled') == 1) {
			FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_INFO, 'Running Let\'s Encrypt cronjob prior to regenerating webserver config files');
			AcmeSh::$no_inserttask = true;
			AcmeSh::run(true);
			// set last run timestamp of cronjob
			Cronjob::updateLastRunOfCron('letsencrypt');
		}
	}

	public function reload()
	{
		$called_class = get_called_class();
		if ((int)Settings::Get('phpfpm.enabled') == 1) {
			// get all start/stop commands
			$startstop_sel = Database::prepare("SELECT reload_cmd, config_dir FROM `" . TABLE_PANEL_FPMDAEMONS . "`");
			Database::pexecute($startstop_sel);
			$restart_cmds = $startstop_sel->fetchAll(PDO::FETCH_ASSOC);
			// restart all php-fpm instances
			foreach ($restart_cmds as $restart_cmd) {
				// check whether the config dir is empty (no domains uses this daemon)
				// so we need to create a dummy
				$_conffiles = glob(FileDir::makeCorrectFile($restart_cmd['config_dir'] . "/*.conf"));
				if ($_conffiles === false || empty($_conffiles)) {
					FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_INFO, $called_class . '::reload: fpm config directory "' . $restart_cmd['config_dir'] . '" is empty. Creating dummy.');
					Fpm::createDummyPool($restart_cmd['config_dir']);
				}
				FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_INFO, $called_class . '::reload: running ' . $restart_cmd['reload_cmd']);
				FileDir::safe_exec(escapeshellcmd($restart_cmd['reload_cmd']));
			}
		}
		FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_INFO, $called_class . '::reload: reloading ' . $called_class);
		FileDir::safe_exec(escapeshellcmd(Settings::Get('system.apachereload_command')));

		/**
		 * nginx does not auto-spawn fcgi-processes
		 */
		if (Settings::Get('system.webserver') == "nginx" && Settings::Get('system.phpreload_command') != '' && (int)Settings::Get('phpfpm.enabled') == 0) {
			FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_INFO, $called_class . '::reload: restarting php processes');
			FileDir::safe_exec(Settings::Get('system.phpreload_command'));
		}
	}

	/**
	 * process special config as template, by substituting {VARIABLE} with the
	 * respective value.
	 *
	 * The following variables are known at the moment:
	 *
	 * {DOMAIN} - domain name
	 * {IP} - IP for this domain
	 * {PORT} - Port for this domain
	 * {CUSTOMER} - customer name
	 * {IS_SSL} - evaluates to 'ssl' if domain/ip is ssl, otherwise it is an empty string
	 * {DOCROOT} - document root for this domain
	 *
	 * @param
	 *            $template
	 * @return string
	 */
	protected function processSpecialConfigTemplate($template, $domain, $ip, $port, $is_ssl_vhost)
	{
		$templateVars = [
			'DOMAIN' => $domain['domain'],
			'CUSTOMER' => $domain['loginname'],
			'IP' => $ip,
			'PORT' => $port,
			'SCHEME' => ($is_ssl_vhost) ? 'https' : 'http',
			'DOCROOT' => $domain['documentroot'],
			'FPMSOCKET' => ''
		];
		if ((int)Settings::Get('phpfpm.enabled') == 1 && isset($domain['fpm_socket']) && !empty($domain['fpm_socket'])) {
			$templateVars['FPMSOCKET'] = $domain['fpm_socket'];
		}
		return PhpHelper::replaceVariables($template, $templateVars);
	}

	protected function getMyPath($ip_port = null)
	{
		if (!empty($ip_port) && $ip_port['docroot'] == '') {
			if (Settings::Get('system.froxlordirectlyviahostname')) {
				$mypath = FileDir::makeCorrectDir(Froxlor::getInstallDir());
			} else {
				$mypath = FileDir::makeCorrectDir(dirname(Froxlor::getInstallDir()));
			}
		} else {
			// user-defined docroot, #417
			$mypath = FileDir::makeCorrectDir($ip_port['docroot']);
		}
		return $mypath;
	}

	protected function checkAlternativeSslPort()
	{
		// We must not check if our port differs from port 443,
		// but if there is a destination-port != 443
		$_sslport = '';
		// This returns the first port that is != 443 with ssl enabled,
		// ordered by ssl-certificate (if any) so that the ip/port combo
		// with certificate is used
		$ssldestport_stmt = Database::prepare("
			SELECT `ip`.`port` FROM " . TABLE_PANEL_IPSANDPORTS . " `ip`
			WHERE `ip`.`ssl` = '1'  AND `ip`.`port` != 443
			ORDER BY `ip`.`ssl_cert_file` DESC, `ip`.`port` LIMIT 1;
		");
		$ssldestport = Database::pexecute_first($ssldestport_stmt);

		if ($ssldestport && $ssldestport['port'] != '') {
			$_sslport = ":" . $ssldestport['port'];
		}

		return $_sslport;
	}

	protected function froxlorVhostHasLetsEncryptCert()
	{
		// check whether we have an entry with valid certificates which just does not need
		// updating yet, so we need to skip this here
		$froxlor_ssl_settings_stmt = Database::prepare("
			SELECT * FROM `" . TABLE_PANEL_DOMAIN_SSL_SETTINGS . "` WHERE `domainid` = '0'
		");
		$froxlor_ssl = Database::pexecute_first($froxlor_ssl_settings_stmt);
		if ($froxlor_ssl && !empty($froxlor_ssl['ssl_cert_file'])) {
			return true;
		}
		return false;
	}

	protected function froxlorVhostLetsEncryptNeedsRenew()
	{
		$froxlor_ssl_settings_stmt = Database::prepare("
			SELECT * FROM `" . TABLE_PANEL_DOMAIN_SSL_SETTINGS . "`
			WHERE `domainid` = '0' AND
			(`validtodate` < DATE_ADD(NOW(), INTERVAL 30 DAY) OR `validtodate` IS NULL)
		");
		$froxlor_ssl = Database::pexecute_first($froxlor_ssl_settings_stmt);
		if ($froxlor_ssl && !empty($froxlor_ssl['ssl_cert_file'])) {
			return true;
		}
		return false;
	}

	/**
	 * Get the filename for the virtualhost
	 */
	protected function getVhostFilename(array $domain, bool $ssl_vhost = false, bool $filename_only = false)
	{
		// number of dots in a domain specifies its position (and depth of subdomain) starting at 35 going downwards on higher depth
		$vhost_no = (string)(35 - substr_count($domain['domain'], ".") + 1);
		$filename = $vhost_no . '_froxlor_' . ($ssl_vhost ? 'ssl' : 'normal') . '_vhost_' . $domain['domain'] . '.conf';
		if ($filename_only) {
			return $filename;
		}
		return FileDir::makeCorrectFile(Settings::Get('system.apacheconf_vhost') . '/' . $filename);
	}

	protected function getCustomVhostFilename(string $name)
	{
		$vhosts_folder = FileDir::makeCorrectDir(dirname(Settings::Get('system.apacheconf_vhost')));
		if (is_dir(Settings::Get('system.apacheconf_vhost'))) {
			$vhosts_folder = FileDir::makeCorrectDir(Settings::Get('system.apacheconf_vhost'));
		}
		return FileDir::makeCorrectFile($vhosts_folder . '/' . $name);
	}
}
