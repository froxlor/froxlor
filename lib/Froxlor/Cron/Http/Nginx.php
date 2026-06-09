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
use Froxlor\Cron\TaskId;
use Froxlor\Customer\Customer;
use Froxlor\Database\Database;
use Froxlor\Domain\Domain;
use Froxlor\Froxlor;
use Froxlor\FileDir;
use Froxlor\FroxlorLogger;
use Froxlor\Http\Directory;
use Froxlor\Http\Statistics;
use Froxlor\Settings;
use Froxlor\System\Cronjob;
use Froxlor\Validate\Validate;
use Froxlor\System\Crypt;
use PDO;

class Nginx extends HttpConfigBase
{

	protected $nginx_data = [];

	// protected
	protected $needed_htpasswds = [];
	protected $http2_on_directive = false;
	protected $htpasswds_data = [];
	protected $known_htpasswdsfilenames = [];
	protected $vhost_root_autoindex = false;

	/**
	 * indicator whether a customer is deactivated or not
	 * if yes, only the webroot will be generated
	 *
	 * @var bool
	 */
	private $deactivated = false;

	public function __construct()
	{
		$nores = false;
		$res = FileDir::safe_exec('nginx -v 2>&1', $nores, ['>', '&']);
		$ver_str = array_shift($res);
		$cNginxVer = substr($ver_str, strrpos($ver_str, "/") + 1);
		if (version_compare($cNginxVer, '1.25.1', '>=')) {
			// at least 1.25.1
			$this->http2_on_directive = true;
		}
	}

	public function createVirtualHosts()
	{
		return;
	}

	public function createFileDirOptions()
	{
		return;
	}

	public function createIpPort()
	{
		$this->createLogformatEntry();

		$result_ipsandports_stmt = Database::query("
			SELECT * FROM `" . TABLE_PANEL_IPSANDPORTS . "` ORDER BY `ip` ASC, `port` ASC
		");

		while ($row_ipsandports = $result_ipsandports_stmt->fetch(PDO::FETCH_ASSOC)) {
			if (filter_var($row_ipsandports['ip'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
				$ip = '[' . $row_ipsandports['ip'] . ']';
			} else {
				$ip = $row_ipsandports['ip'];
			}
			$port = $row_ipsandports['port'];

			FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_INFO, 'nginx::createIpPort: creating ip/port settings for  ' . $ip . ":" . $port);
			$vhost_filename = FileDir::makeCorrectFile(Settings::Get('system.apacheconf_vhost') . '/10_froxlor_ipandport_' . trim(str_replace(':', '.', $row_ipsandports['ip']), '.') . '.' . $row_ipsandports['port'] . '.conf');

			if (!isset($this->nginx_data[$vhost_filename])) {
				$this->nginx_data[$vhost_filename] = '';
			}

			if ($row_ipsandports['vhostcontainer'] == '1') {
				$this->nginx_data[$vhost_filename] .= 'server { ' . "\n";

				$mypath = $this->getMyPath($row_ipsandports);

				// check for ssl before anything else so
				// we know whether it's an ssl vhost or not
				$ssl_vhost = false;
				if ($row_ipsandports['ssl'] == '1') {
					// check for required fallback
					if (($row_ipsandports['ssl_cert_file'] == '' || !file_exists($row_ipsandports['ssl_cert_file'])) && (Settings::Get('system.le_froxlor_enabled') == '0' || $this->froxlorVhostHasLetsEncryptCert() == false)) {
						$row_ipsandports['ssl_cert_file'] = Settings::Get('system.ssl_cert_file');
						if (!file_exists($row_ipsandports['ssl_cert_file'])) {
							FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_DEBUG, 'System certificate file "' . Settings::Get('system.ssl_cert_file') . '" does not seem to exist. Creating self-signed certificate...');
							Crypt::createSelfSignedCertificate();
						}
					}
					if ($row_ipsandports['ssl_key_file'] == '') {
						$row_ipsandports['ssl_key_file'] = Settings::Get('system.ssl_key_file');
						if (!file_exists($row_ipsandports['ssl_key_file'])) {
							// explicitly disable ssl for this vhost
							$row_ipsandports['ssl_cert_file'] = "";
							FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_DEBUG, 'System certificate key-file "' . Settings::Get('system.ssl_key_file') . '" does not seem to exist. Disabling SSL-vhost for "' . Settings::Get('system.hostname') . '"');
						}
					}
					if ($row_ipsandports['ssl_ca_file'] == '') {
						$row_ipsandports['ssl_ca_file'] = Settings::Get('system.ssl_ca_file');
					}
					if ($row_ipsandports['ssl_cert_file'] != '' && file_exists($row_ipsandports['ssl_cert_file'])) {
						$ssl_vhost = true;
					}

					$domain = [
						'id' => 0,
						'domain' => Settings::Get('system.hostname'),
						'adminid' => 1, /* first admin-user (superadmin) */
						'loginname' => 'froxlor.panel',
						'documentroot' => $mypath,
						'customerroot' => $mypath,
						'parentdomainid' => 0
					];

					// override corresponding array values
					$domain['ssl_cert_file'] = $row_ipsandports['ssl_cert_file'];
					$domain['ssl_key_file'] = $row_ipsandports['ssl_key_file'];
					$domain['ssl_ca_file'] = $row_ipsandports['ssl_ca_file'];
					$domain['ssl_cert_chainfile'] = $row_ipsandports['ssl_cert_chainfile'];

					// SSL STUFF
					$dssl = new DomainSSL();
					// this sets the ssl-related array-indices in the $domain array
					// if the domain has customer-defined ssl-certificates
					$dssl->setDomainSSLFilesArray($domain);

					if ($domain['ssl_cert_file'] != '' && file_exists($domain['ssl_cert_file'])) {
						// override corresponding array values
						$row_ipsandports['ssl_cert_file'] = $domain['ssl_cert_file'];
						$row_ipsandports['ssl_key_file'] = $domain['ssl_key_file'];
						$row_ipsandports['ssl_ca_file'] = $domain['ssl_ca_file'];
						$row_ipsandports['ssl_cert_chainfile'] = $domain['ssl_cert_chainfile'];
						$ssl_vhost = true;
					}
				}

				$http2 = $ssl_vhost == true && Settings::Get('system.http2_support') == '1';
				$http3 = $ssl_vhost == true && Settings::Get('system.http3_support') == '1';

				/**
				 * this HAS to be set for the default host in nginx or else no vhost will work
				 */
				$this->nginx_data[$vhost_filename] .= "\t" . 'listen    ' . $ip . ':' . $port . ' default_server' . ($ssl_vhost == true ? ' ssl' : '') . ($http2 && !$this->http2_on_directive ? ' http2' : '') . ';' . "\n";
				if ($http2 && $this->http2_on_directive) {
					$this->nginx_data[$vhost_filename] .= "\t" . 'http2 on;' . "\n";
				}
				if ($http3) {
					$this->nginx_data[$vhost_filename] .= "\t" . 'listen    ' . $ip . ':' . $port . ' default_server quic reuseport;' . "\n";
					$this->nginx_data[$vhost_filename] .= "\t" . 'http3 on;' . "\n";
					$this->nginx_data[$vhost_filename] .= "\t" . 'quic_gso on;' . "\n";
					$this->nginx_data[$vhost_filename] .= "\t" . 'quic_retry on;' . "\n";
					$this->nginx_data[$vhost_filename] .= "\t" . 'add_header Alt-Svc \'h3=":' . $port . '"; ma=86400\' always;' . "\n";
				}
				$this->nginx_data[$vhost_filename] .= "\t" . '# Froxlor default vhost' . "\n";

				$aliases = "";
				$froxlor_aliases = Settings::Get('system.froxloraliases');
				if (!empty($froxlor_aliases)) {
					$froxlor_aliases = explode(",", $froxlor_aliases);
					foreach ($froxlor_aliases as $falias) {
						if (Validate::validateDomain(trim($falias))) {
							$aliases .= trim($falias) . " ";
						}
					}
					$aliases = " " . trim($aliases);
				}
				$this->nginx_data[$vhost_filename] .= "\t" . 'server_name    ' . Settings::Get('system.hostname') . $aliases . ';' . "\n";

				$logtype = 'combined';
				if (Settings::Get('system.logfiles_format') != '') {
					$logtype = 'frx_custom';
				}
				$this->nginx_data[$vhost_filename] .= "\t" . 'access_log     /var/log/nginx/access.log ' . $logtype . ';' . "\n";

				if (Settings::Get('system.use_ssl') == '1' && Settings::Get('system.leenabled') == '1' && Settings::Get('system.le_froxlor_enabled') == '1') {
					$acmeConfFilename = Settings::Get('system.letsencryptacmeconf');
					$this->nginx_data[$vhost_filename] .= "\t" . 'include ' . $acmeConfFilename . ';' . "\n";
				}

				$is_redirect = false;
				// check for SSL redirect
				if ($row_ipsandports['ssl'] == '0' && Settings::Get('system.le_froxlor_redirect') == '1') {
					$is_redirect = true;
					// check whether froxlor uses Let's Encrypt and not cert is being generated yet
					// or a renewal is ongoing - disable redirect
					if (Settings::Get('system.leenabled') == '1' && Settings::Get('system.le_froxlor_enabled') && ($this->froxlorVhostHasLetsEncryptCert() == false || $this->froxlorVhostLetsEncryptNeedsRenew())) {
						$this->nginx_data[$vhost_filename] .= '# temp. disabled ssl-redirect due to Let\'s Encrypt certificate generation.' . PHP_EOL;
						$is_redirect = false;
						Cronjob::inserttask(TaskId::REBUILD_VHOST);
					} else {
						$_sslport = $this->checkAlternativeSslPort();
						$mypath = 'https://' . Settings::Get('system.hostname') . $_sslport;
						$this->nginx_data[$vhost_filename] .= "\t" . 'location / {' . "\n";
						$this->nginx_data[$vhost_filename] .= "\t\t" . 'return 301 ' . $mypath . '$request_uri;' . "\n";
						$this->nginx_data[$vhost_filename] .= "\t" . '}' . "\n";
					}
				}

				if (!$is_redirect) {
					$this->nginx_data[$vhost_filename] .= "\t" . 'root     ' . $mypath . ';' . "\n";
					$this->nginx_data[$vhost_filename] .= "\t" . 'index    index.php index.html index.htm;' . "\n\n";
					$this->nginx_data[$vhost_filename] .= "\t" . 'location / {' . "\n";
					$this->nginx_data[$vhost_filename] .= "\t" . '}' . "\n";

					if (Settings::Get('system.froxlordirectlyviahostname')) {
						$relpath = "/";
					} else {
						$relpath = "/".basename(Froxlor::getInstallDir());
					}
					// protect lib/userdata.inc.php
					$this->nginx_data[$vhost_filename] .= "\t" . 'location = ' . rtrim($relpath, "/") . '/lib/userdata.inc.php {' . "\n";
					$this->nginx_data[$vhost_filename] .= "\t" . '    deny all;' . "\n";
					$this->nginx_data[$vhost_filename] .= "\t" . '}' . "\n";

					// protect bin/
					$this->nginx_data[$vhost_filename] .= "\t" . 'location ~ ^' . rtrim($relpath, "/") . '/(bin|cache|logs|tests|vendor) {' . "\n";
					$this->nginx_data[$vhost_filename] .= "\t" . '    deny all;' . "\n";
					$this->nginx_data[$vhost_filename] .= "\t" . '}' . "\n";
				}

				if ($row_ipsandports['specialsettings'] != '' && ($row_ipsandports['ssl'] == '0' || ($row_ipsandports['ssl'] == '1' && Settings::Get('system.use_ssl') == '1' && $row_ipsandports['include_specialsettings'] == '1'))) {
					$this->nginx_data[$vhost_filename] .= $this->processSpecialConfigTemplate($row_ipsandports['specialsettings'], [
						'domain' => Settings::Get('system.hostname'),
						'loginname' => Settings::Get('phpfpm.vhost_httpuser'),
						'documentroot' => $mypath,
						'customerroot' => $mypath
					], $row_ipsandports['ip'], $row_ipsandports['port'], $row_ipsandports['ssl'] == '1') . "\n";
				}

				/**
				 * SSL config options
				 */
				if ($row_ipsandports['ssl'] == '1') {
					$row_ipsandports['domain'] = Settings::Get('system.hostname');
					$row_ipsandports['ssl_honorcipherorder'] = Settings::Get('system.honorcipherorder');
					$row_ipsandports['ssl_sessiontickets'] = Settings::Get('system.sessiontickets');
					$this->nginx_data[$vhost_filename] .= $this->composeSslSettings($row_ipsandports);
					if ($row_ipsandports['ssl_specialsettings'] != '') {
						$this->nginx_data[$vhost_filename] .= $this->processSpecialConfigTemplate($row_ipsandports['ssl_specialsettings'], [
							'domain' => Settings::Get('system.hostname'),
							'loginname' => Settings::Get('phpfpm.vhost_httpuser'),
							'documentroot' => $mypath,
							'customerroot' => $mypath
						], $row_ipsandports['ip'], $row_ipsandports['port'], $row_ipsandports['ssl'] == '1') . "\n";
					}
				}

				if (!$is_redirect) {
					$this->nginx_data[$vhost_filename] .= "\tlocation ~ \.php {\n";
					$this->nginx_data[$vhost_filename] .= "\t\tfastcgi_split_path_info ^(.+?\.php)(/.*)$;\n";
					$this->nginx_data[$vhost_filename] .= "\t\tinclude " . Settings::Get('nginx.fastcgiparams') . ";\n";
					$this->nginx_data[$vhost_filename] .= "\t\tfastcgi_param SCRIPT_FILENAME \$request_filename;\n";
					$this->nginx_data[$vhost_filename] .= "\t\ttry_files \$fastcgi_script_name =404;\n";
					$this->nginx_data[$vhost_filename] .= "\t\tset \$path_info \$fastcgi_path_info;\n";
					$this->nginx_data[$vhost_filename] .= "\t\tfastcgi_param PATH_INFO \$path_info;\n";


					if ($row_ipsandports['ssl'] == '1') {
						$this->nginx_data[$vhost_filename] .= "\t\tfastcgi_param HTTPS on;\n";
					}

					if ((int)Settings::Get('phpfpm.enabled') == 1 && (int)Settings::Get('phpfpm.enabled_ownvhost') == 1) {
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
							'guid' => Settings::Get('phpfpm.vhost_httpuser'),
							'openbasedir' => 0,
							'email' => Settings::Get('panel.adminmail'),
							'loginname' => 'froxlor.panel',
							'documentroot' => $mypath,
							'customerroot' => $mypath,
							'fpm_config_id' => isset($fpm_config['id']) ? $fpm_config['id'] : 1
						];

						$php = new PhpInterface($domain);
						$this->nginx_data[$vhost_filename] .= "\t\tfastcgi_pass unix:" . $php->getInterface()->getSocketFile() . ";\n";
					} else {
						$this->nginx_data[$vhost_filename] .= "\t\tfastcgi_pass " . Settings::Get('system.nginx_php_backend') . ";\n";
					}

					$this->nginx_data[$vhost_filename] .= "\t\tfastcgi_index index.php;\n";
					$this->nginx_data[$vhost_filename] .= "\t}\n";
				}

				$this->nginx_data[$vhost_filename] .= "}\n\n";
				// End of Froxlor server{}-part
			}
		}

		$this->createNginxHosts();

		/**
		 * standard error pages
		 */
		$this->createStandardErrorHandler();
	}

	private function createLogformatEntry()
	{
		if (Settings::Get('system.logfiles_format') != '') {
			$vhosts_folder = '';
			if (is_dir(Settings::Get('system.apacheconf_vhost'))) {
				$vhosts_folder = FileDir::makeCorrectDir(Settings::Get('system.apacheconf_vhost'));
			} else {
				$vhosts_folder = FileDir::makeCorrectDir(dirname(Settings::Get('system.apacheconf_vhost')));
			}

			$vhosts_filename = FileDir::makeCorrectFile($vhosts_folder . '/02_froxlor_logfiles_format.conf');

			if (!isset($this->nginx_data[$vhosts_filename])) {
				$this->nginx_data[$vhosts_filename] = '';
			}

			$logtype = 'frx_custom';
			$this->nginx_data[$vhosts_filename] = 'log_format ' . $logtype . ' ' . Settings::Get('system.logfiles_format') . ';' . "\n";
		}
	}

	protected function composeSslSettings($domain_or_ip)
	{
		$sslsettings = '';

		if ($domain_or_ip['ssl_cert_file'] == '' || !file_exists($domain_or_ip['ssl_cert_file'])) {
			$domain_or_ip['ssl_cert_file'] = Settings::Get('system.ssl_cert_file');
			if (!file_exists($domain_or_ip['ssl_cert_file'])) {
				// explicitly disable ssl for this vhost
				$domain_or_ip['ssl_cert_file'] = "";
				FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_DEBUG, 'System certificate file "' . Settings::Get('system.ssl_cert_file') . '" does not seem to exist. Disabling SSL-vhost for "' . $domain_or_ip['domain'] . '"');
			}
		}

		if ($domain_or_ip['ssl_key_file'] == '' || !file_exists($domain_or_ip['ssl_key_file'])) {
			// use fallback
			$domain_or_ip['ssl_key_file'] = Settings::Get('system.ssl_key_file');
			// check whether it exists
			if (!file_exists($domain_or_ip['ssl_key_file'])) {
				// explicitly disable ssl for this vhost
				$domain_or_ip['ssl_cert_file'] = "";
				FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_DEBUG, 'System certificate key-file "' . Settings::Get('system.ssl_key_file') . '" does not seem to exist. Disabling SSL-vhost for "' . $domain_or_ip['domain'] . '"');
			}
		}

		if ($domain_or_ip['ssl_ca_file'] == '') {
			$domain_or_ip['ssl_ca_file'] = Settings::Get('system.ssl_ca_file');
		}

		// #418
		if ($domain_or_ip['ssl_cert_chainfile'] == '') {
			$domain_or_ip['ssl_cert_chainfile'] = Settings::Get('system.ssl_cert_chainfile');
		}

		if ($domain_or_ip['ssl_cert_file'] != '') {
			// check for existence, #1485
			if (!file_exists($domain_or_ip['ssl_cert_file'])) {
				FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_ERR, $domain_or_ip['domain'] . ' :: certificate file "' . $domain_or_ip['ssl_cert_file'] . '" does not exist! Cannot create ssl-directives');
			} else {
				$ssl_protocols = (isset($domain_or_ip['override_tls']) && $domain_or_ip['override_tls'] == '1' && !empty($domain_or_ip['ssl_protocols'])) ? $domain_or_ip['ssl_protocols'] : Settings::Get('system.ssl_protocols');
				$ssl_cipher_list = (isset($domain_or_ip['override_tls']) && $domain_or_ip['override_tls'] == '1' && !empty($domain_or_ip['ssl_cipher_list'])) ? $domain_or_ip['ssl_cipher_list'] : Settings::Get('system.ssl_cipher_list');

				// obsolete: ssl on now belongs to the listen block as 'ssl' at the end
				// $sslsettings .= "\t" . 'ssl on;' . "\n";
				$sslsettings .= "\t" . 'ssl_protocols ' . str_replace(",", " ", $ssl_protocols) . ';' . "\n";
				$sslsettings .= "\t" . 'ssl_ciphers ' . $ssl_cipher_list . ';' . "\n";
				if (!empty(Settings::Get('system.dhparams_file'))) {
					$dhparams = FileDir::makeCorrectFile(Settings::Get('system.dhparams_file'));
					if (!file_exists($dhparams)) {
						file_put_contents($dhparams, self::FFDHE4096);
					}
					$sslsettings .= "\t" . 'ssl_dhparam ' . $dhparams . ';' . "\n";
				}
				// When <1.11.0: Defaults to prime256v1, similar to first curve recommendation by Mozilla.
				// (When specifyng just one, there's no fallback when specific curve is not supported by client.)
				// When >1.11.0: Defaults to auto, using recommended curves provided by OpenSSL.
				// see https://github.com/Froxlor/Froxlor/issues/652
				// $sslsettings .= "\t" . 'ssl_ecdh_curve secp384r1;' . "\n";
				$sslsettings .= "\t" . 'ssl_prefer_server_ciphers ' . (isset($domain_or_ip['ssl_honorcipherorder']) && $domain_or_ip['ssl_honorcipherorder'] == '1' ? 'on' : 'off') . ';' . "\n";
				if (Settings::Get('system.sessionticketsenabled') == '1') {
					$sslsettings .= "\t" . 'ssl_session_tickets ' . (isset($domain_or_ip['ssl_sessiontickets']) && $domain_or_ip['ssl_sessiontickets'] == '1' ? 'on' : 'off') . ';' . "\n";
				}
				$sslsettings .= "\t" . 'ssl_session_cache shared:SSL:10m;' . "\n";
				$sslsettings .= "\t" . 'ssl_certificate ' . FileDir::makeCorrectFile($domain_or_ip['ssl_cert_file']) . ';' . "\n";

				if ($domain_or_ip['ssl_key_file'] != '') {
					// check for existence, #1485
					if (!file_exists($domain_or_ip['ssl_key_file'])) {
						FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_ERR, $domain_or_ip['domain'] . ' :: certificate key file "' . $domain_or_ip['ssl_key_file'] . '" does not exist! Cannot create ssl-directives');
					} else {
						$sslsettings .= "\t" . 'ssl_certificate_key ' . FileDir::makeCorrectFile($domain_or_ip['ssl_key_file']) . ';' . "\n";
					}
				}

				if (isset($domain_or_ip['hsts']) && $domain_or_ip['hsts'] >= 0) {
					$sslsettings .= 'add_header Strict-Transport-Security "max-age=' . $domain_or_ip['hsts'];
					if ($domain_or_ip['hsts_sub'] == 1) {
						$sslsettings .= '; includeSubDomains';
					}
					if ($domain_or_ip['hsts_preload'] == 1) {
						$sslsettings .= '; preload';
					}
					$sslsettings .= '" always;' . "\n";
				}

				if ((isset($domain_or_ip['ocsp_stapling']) && $domain_or_ip['ocsp_stapling'] == "1")) {
					$sslsettings .= "\t" . 'ssl_stapling on;' . "\n";
					$sslsettings .= "\t" . 'ssl_stapling_verify on;' . "\n";
					$sslsettings .= "\t" . 'ssl_trusted_certificate ' . FileDir::makeCorrectFile($domain_or_ip['ssl_cert_file']) . ';' . "\n";
				}
			}
		}

		return $sslsettings;
	}

	/**
	 * create vhosts
	 */
	protected function createNginxHosts()
	{
		$domains = WebserverBase::getVhostsToCreate();
		foreach ($domains as $domain) {
			if (is_dir(Settings::Get('system.apacheconf_vhost'))) {
				FileDir::safe_exec('mkdir -p ' . escapeshellarg(FileDir::makeCorrectDir(Settings::Get('system.apacheconf_vhost'))));
			}

			$vhost_filename = $this->getVhostFilename($domain);

			if (!isset($this->nginx_data[$vhost_filename])) {
				$this->nginx_data[$vhost_filename] = '';
			}

			if ((empty($this->nginx_data[$vhost_filename]) && !is_dir(Settings::Get('system.apacheconf_vhost'))) || is_dir(Settings::Get('system.apacheconf_vhost'))) {
				$domain['nonexistinguri'] = '/' . md5(uniqid(microtime(), 1)) . '.htm';

				// Create non-ssl host
				$this->nginx_data[$vhost_filename] .= $this->getVhostContent($domain, false);
				if ($domain['ssl'] == '1' || $domain['ssl_redirect'] == '1') {
					$vhost_filename_ssl = $this->getVhostFilename($domain, true);
					if (!isset($this->nginx_data[$vhost_filename_ssl])) {
						$this->nginx_data[$vhost_filename_ssl] = '';
					}
					// Now enable ssl stuff
					$this->nginx_data[$vhost_filename_ssl] .= $this->getVhostContent($domain, true);
				}
			}
		}
	}

	protected function getVhostContent($domain, $ssl_vhost = false)
	{
		if ($ssl_vhost === true && $domain['ssl'] != '1' && $domain['ssl_redirect'] != '1') {
			return '';
		}

		// check whether the customer/domain is deactivated and NO docroot for deactivated users has been set#
		$ddr = Settings::Get('system.deactivateddocroot');
		if (($domain['deactivated'] == '1' || $domain['customer_deactivated'] == '1') && empty($ddr)) {
			return '# Customer deactivated and a docroot for deactivated users/domains hasn\'t been set.' . "\n";
		}

		$vhost_content = '';
		$_vhost_content = '';
		$has_http2_on = false;

		$query = "SELECT * FROM `" . TABLE_PANEL_IPSANDPORTS . "` `i`, `" . TABLE_DOMAINTOIP . "` `dip`
			WHERE dip.id_domain = :domainid AND i.id = dip.id_ipandports ";

		if ($ssl_vhost === true && ($domain['ssl'] == '1' || $domain['ssl_redirect'] == '1')) {
			// by ordering by cert-file the row with filled out SSL-Fields will be shown last,
			// thus it is enough to fill out 1 set of SSL-Fields
			$query .= "AND i.ssl = 1 ORDER BY i.ssl_cert_file ASC;";
		} else {
			$query .= "AND i.ssl = '0';";
		}

		// start vhost
		$vhost_content .= 'server { ' . "\n";

		$result_stmt = Database::prepare($query);
		Database::pexecute($result_stmt, [
			'domainid' => $domain['id']
		]);

		$http3 = $ssl_vhost == true && (isset($domain['http3']) && $domain['http3'] == '1' && Settings::Get('system.http3_support') == '1');
		while ($ipandport = $result_stmt->fetch(PDO::FETCH_ASSOC)) {
			$domain['ip'] = $ipandport['ip'];
			$domain['port'] = $ipandport['port'];
			if ($domain['ssl'] == '1') {
				$domain['ssl_cert_file'] = $ipandport['ssl_cert_file'];
				$domain['ssl_key_file'] = $ipandport['ssl_key_file'];
				$domain['ssl_ca_file'] = $ipandport['ssl_ca_file'];
				$domain['ssl_cert_chainfile'] = $ipandport['ssl_cert_chainfile'];

				// SSL STUFF
				$dssl = new DomainSSL();
				// this sets the ssl-related array-indices in the $domain array
				// if the domain has customer-defined ssl-certificates
				$dssl->setDomainSSLFilesArray($domain);
			}

			if (filter_var($domain['ip'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
				$ipport = '[' . $domain['ip'] . ']:' . $domain['port'];
			} else {
				$ipport = $domain['ip'] . ':' . $domain['port'];
			}

			if ($ipandport['default_vhostconf_domain'] != '' && ($ssl_vhost == false || ($ssl_vhost == true && $ipandport['include_default_vhostconf_domain'] == '1'))) {
				$_vhost_content .= $this->processSpecialConfigTemplate($ipandport['default_vhostconf_domain'], $domain, $domain['ip'], $domain['port'], $ssl_vhost) . "\n";
			}
			if ($ipandport['ssl_default_vhostconf_domain'] != '' && $ssl_vhost == true) {
				$_vhost_content .= $this->processSpecialConfigTemplate($ipandport['ssl_default_vhostconf_domain'], $domain, $domain['ip'], $domain['port'], $ssl_vhost) . "\n";
			}
			$http2 = $ssl_vhost == true && (isset($domain['http2']) && $domain['http2'] == '1' && Settings::Get('system.http2_support') == '1');

			$vhost_content .= "\t" . 'listen ' . $ipport . ($ssl_vhost == true ? ' ssl' : '') . ($http2 && !$this->http2_on_directive ? ' http2' : '') . ';' . "\n";
			if ($http2 && $this->http2_on_directive && !$has_http2_on) {
				$vhost_content .= "\t" . 'http2 on;' . "\n";
				$has_http2_on = true;
			}
			if ($http3) {
				$vhost_content .= "\t" . 'listen    ' . $ipport . ' quic;' . "\n";
			}
		}

		if ($http3) {
			$vhost_content .= "\t" . 'add_header Alt-Svc \'h3=":' . $domain['port'] . '"; ma=86400\' always;' . "\n";
			$vhost_content .= "\t" . 'http3 on;' . "\n";
			$vhost_content .= "\t" . 'quic_gso on;' . "\n";
			$vhost_content .= "\t" . 'quic_retry on;' . "\n";
		}

		// get all server-names
		$vhost_content .= $this->getServerNames($domain);

		// respect ssl_redirect settings, #542
		if ($ssl_vhost == false && $domain['ssl'] == '1' && $domain['ssl_redirect'] == '1') {
			// We must not check if our port differs from port 443,
			// but if there is a destination-port != 443
			$_sslport = '';
			// This returns the first port that is != 443 with ssl enabled, if any
			// ordered by ssl-certificate (if any) so that the ip/port combo
			// with certificate is used
			$ssldestport_stmt = Database::prepare("SELECT `ip`.`port` FROM " . TABLE_PANEL_IPSANDPORTS . " `ip`
				LEFT JOIN `" . TABLE_DOMAINTOIP . "` `dip` ON (`ip`.`id` = `dip`.`id_ipandports`)
				WHERE `dip`.`id_domain` = :domainid
				AND `ip`.`ssl` = '1'  AND `ip`.`port` != 443
				ORDER BY `ip`.`ssl_cert_file` DESC, `ip`.`port` LIMIT 1;");
			$ssldestport = Database::pexecute_first($ssldestport_stmt, [
				'domainid' => $domain['id']
			]);

			if ($ssldestport && $ssldestport['port'] != '') {
				$_sslport = ":" . $ssldestport['port'];
			}

			$domain['documentroot'] = 'https://$host' . $_sslport . '/';
		}

		// avoid using any whitespaces
		$domain['documentroot'] = trim($domain['documentroot']);

		// create ssl settings first since they are required for normal and redirect vhosts
		if ($ssl_vhost === true && $domain['ssl'] == '1' && Settings::Get('system.use_ssl') == '1') {
			$vhost_content .= "\n" . $this->composeSslSettings($domain) . "\n";
		}

		if (Settings::Get('system.use_ssl') == '1' && Settings::Get('system.leenabled') == '1') {
			$acmeConfFilename = Settings::Get('system.letsencryptacmeconf');
			$vhost_content .= "\t" . 'include ' . $acmeConfFilename . ';' . "\n";
		}

		// if the documentroot is an URL we just redirect
		if (preg_match('/^https?\:\/\//', $domain['documentroot'])) {
			$possible_deactivated_webroot = $this->getWebroot($domain);
			if ($this->deactivated == false) {
				if (($ssl_vhost == false && $domain['ssl'] == '1' && $domain['ssl_redirect'] == '1') || Validate::validateUrl($domain['documentroot'])) {
					$uri = $domain['documentroot'];
					if (substr($uri, -1) == '/') {
						$uri = substr($uri, 0, -1);
					}

					// Get domain's redirect code
					$code = Domain::getDomainRedirectCode($domain['id']);

					$vhost_content .= $this->getLogFiles($domain);
					$vhost_content .= "\t" . 'location / {' . "\n";
					$vhost_content .= "\t\t" . 'return ' . $code . ' ' . $uri . '$request_uri;' . "\n";
					$vhost_content .= "\t" . '}' . "\n";
				} else {
					$vhost_content .= "\t" . 'return 500 "misconfigured redirect url";' . "\n";
				}
			} elseif (Settings::Get('system.deactivateddocroot') != '') {
				$vhost_content .= $possible_deactivated_webroot;
			}
		} else {
			FileDir::mkDirWithCorrectOwnership($domain['customerroot'], $domain['documentroot'], $domain['guid'], $domain['guid'], true);

			$vhost_content .= $this->getLogFiles($domain);
			$vhost_content .= $this->getWebroot($domain);

			if ($this->deactivated == false) {
				$vhost_content = $this->mergeVhostCustom($vhost_content, $this->createPathOptions($domain)) . "\n";
				$vhost_content .= $this->composePhpOptions($domain, $ssl_vhost);

				$vhost_content .= isset($this->needed_htpasswds[$domain['id']]) ? $this->needed_htpasswds[$domain['id']] . "\n" : '';

				if ($domain['specialsettings'] != '' && ($ssl_vhost == false || ($ssl_vhost == true && $domain['include_specialsettings'] == 1))) {
					$vhost_content = $this->mergeVhostCustom($vhost_content, $this->processSpecialConfigTemplate($domain['specialsettings'], $domain, $domain['ip'], $domain['port'], $ssl_vhost));
				}

				if ($domain['ssl_specialsettings'] != '' && $ssl_vhost == true) {
					$vhost_content = $this->mergeVhostCustom($vhost_content, $this->processSpecialConfigTemplate($domain['ssl_specialsettings'], $domain, $domain['ip'], $domain['port'], $ssl_vhost));
				}

				if ($_vhost_content != '') {
					$vhost_content = $this->mergeVhostCustom($vhost_content, $_vhost_content);
				}

				if (Settings::Get('system.default_vhostconf') != '' && ($ssl_vhost == false || ($ssl_vhost == true && Settings::Get('system.include_default_vhostconf') == 1))) {
					$vhost_content = $this->mergeVhostCustom($vhost_content, $this->processSpecialConfigTemplate(Settings::Get('system.default_vhostconf'), $domain, $domain['ip'], $domain['port'], $ssl_vhost) . "\n");
				}

				if (Settings::Get('system.default_sslvhostconf') != '' && $ssl_vhost == true) {
					$vhost_content = $this->mergeVhostCustom($vhost_content, $this->processSpecialConfigTemplate(Settings::Get('system.default_sslvhostconf'), $domain, $domain['ip'], $domain['port'], $ssl_vhost) . "\n");
				}
			}
		}
		$vhost_content .= "\n}\n\n";

		return $vhost_content;
	}

	protected function getServerNames($domain)
	{
		$server_alias = '';

		if ($domain['iswildcarddomain'] == '1') {
			$server_alias = '*.' . $domain['domain'];
		} elseif ($domain['wwwserveralias'] == '1') {
			$server_alias = 'www.' . $domain['domain'];
		}

		$alias_domains_stmt = Database::prepare("
			SELECT `domain`, `iswildcarddomain`, `wwwserveralias`
			FROM `" . TABLE_PANEL_DOMAINS . "`
			WHERE `aliasdomain` = :domainid
		");
		Database::pexecute($alias_domains_stmt, [
			'domainid' => $domain['id']
		]);

		while (($alias_domain = $alias_domains_stmt->fetch(PDO::FETCH_ASSOC)) !== false) {
			$server_alias .= ' ' . $alias_domain['domain'];

			if ($alias_domain['iswildcarddomain'] == '1') {
				$server_alias .= ' *.' . $alias_domain['domain'];
			} elseif ($alias_domain['wwwserveralias'] == '1') {
				$server_alias .= ' www.' . $alias_domain['domain'];
			}
		}

		$servernames_text = "\t" . 'server_name    ' . $domain['domain'];
		if (trim($server_alias) != '') {
			$servernames_text .= ' ' . $server_alias;
		}
		$servernames_text .= ';' . "\n";

		return $servernames_text;
	}

	protected function getLogFiles($domain)
	{
		$logfiles_text = '';

		$speciallogfile = '';
		if ($domain['speciallogfile'] == '1') {
			if ($domain['parentdomainid'] == '0') {
				$speciallogfile = '-' . $domain['domain'];
			} else {
				$speciallogfile = '-' . $domain['parentdomain'];
			}
		}

		if ($domain['writeerrorlog']) {
			// The normal access/error - logging is enabled
			$error_log = FileDir::makeCorrectFile(Settings::Get('system.logfiles_directory') . $domain['loginname'] . $speciallogfile . '-error.log');
			// Create the logfile if it does not exist (fixes #46)
			touch($error_log);
			chmod($error_log, 0640);
			chown($error_log, Settings::Get('system.httpuser'));
			chgrp($error_log, Settings::Get('system.httpgroup'));
		} else {
			$error_log = '/dev/null';
		}

		if ($domain['writeaccesslog']) {
			$access_log = FileDir::makeCorrectFile(Settings::Get('system.logfiles_directory') . $domain['loginname'] . $speciallogfile . '-access.log');
			// Create the logfile if it does not exist (fixes #46)
			touch($access_log);
			chmod($access_log, 0640);
			chown($access_log, Settings::Get('system.httpuser'));
			chgrp($access_log, Settings::Get('system.httpgroup'));
		} else {
			$access_log = '/dev/null';
		}

		$logtype = 'combined';
		if (Settings::Get('system.logfiles_format') != '') {
			$logtype = 'frx_custom';
		}

		$logfiles_text .= "\t" . 'access_log    ' . $access_log . ' ' . $logtype . ';' . "\n";
		$logfiles_text .= "\t" . 'error_log    ' . $error_log . ' ' . Settings::Get('system.errorlog_level') . ';' . "\n";

		if (Settings::Get('system.traffictool') == 'awstats') {
			if ((int)$domain['parentdomainid'] == 0) {
				// prepare the aliases and subdomains for stats config files
				$server_alias = '';
				$alias_domains_stmt = Database::prepare("
					SELECT `domain`, `iswildcarddomain`, `wwwserveralias`
					FROM `" . TABLE_PANEL_DOMAINS . "`
					WHERE `aliasdomain` = :domainid OR `parentdomainid` = :domainid
				");
				Database::pexecute($alias_domains_stmt, [
					'domainid' => $domain['id']
				]);

				while (($alias_domain = $alias_domains_stmt->fetch(PDO::FETCH_ASSOC)) !== false) {
					$server_alias .= ' ' . $alias_domain['domain'] . ' ';

					if ($alias_domain['iswildcarddomain'] == '1') {
						$server_alias .= '*.' . $domain['domain'];
					} else {
						if ($alias_domain['wwwserveralias'] == '1') {
							$server_alias .= 'www.' . $alias_domain['domain'];
						} else {
							$server_alias .= '';
						}
					}
				}

				$alias = '';
				if ($domain['iswildcarddomain'] == '1') {
					$alias = '*.' . $domain['domain'];
				} elseif ($domain['wwwserveralias'] == '1') {
					$alias = 'www.' . $domain['domain'];
				}

				// After inserting the AWStats information,
				// be sure to build the awstats conf file as well
				// and chown it using $awstats_params, #258
				// Bug 960 + Bug 970 : Use full $domain instead of custom $awstats_params as following classes depend on the information
				Statistics::createAWStatsConf(Settings::Get('system.logfiles_directory') . $domain['loginname'] . $speciallogfile . '-access.log', $domain['domain'], $alias . $server_alias, $domain['customerroot'], $domain);
			}
		}

		return $logfiles_text;
	}

	protected function getWebroot($domain)
	{
		$webroot_text = '';

		if (($domain['deactivated'] == '1' || $domain['customer_deactivated'] == '1' ) && Settings::Get('system.deactivateddocroot') != '') {
			$webroot_text .= "\t" . '# Using docroot for deactivated users/domains...' . "\n";
			$webroot_text .= "\t" . 'root     ' . FileDir::makeCorrectDir(Settings::Get('system.deactivateddocroot')) . ';' . "\n";
			$this->deactivated = true;
		} else {
			$webroot_text .= "\t" . 'root     ' . FileDir::makeCorrectDir($domain['documentroot']) . ';' . "\n";
			$this->deactivated = false;
		}

		$webroot_text .= "\n\t" . 'location / {' . "\n";

		if ($domain['phpenabled_customer'] == 1 && $domain['phpenabled_vhost'] == '1') {
			$webroot_text .= "\t" . 'index    index.php index.html index.htm;' . "\n";
			if ($domain['notryfiles'] != 1) {
				$webroot_text .= "\t\t" . 'try_files $uri $uri/ @rewrites;' . "\n";
			}
		} else {
			$webroot_text .= "\t" . 'index    index.html index.htm;' . "\n";
		}

		if ($this->vhost_root_autoindex) {
			$webroot_text .= "\t\t" . 'autoindex on;' . "\n";
			$this->vhost_root_autoindex = false;
		}

		$webroot_text .= "\t" . '}' . "\n\n";
		if ($domain['phpenabled_customer'] == 1 && $domain['phpenabled_vhost'] == '1' && $domain['notryfiles'] != 1) {
			$webroot_text .= "\tlocation @rewrites {\n";
			$webroot_text .= "\t\trewrite ^ /index.php last;\n";
			$webroot_text .= "\t}\n\n";
		}

		return $webroot_text;
	}

	protected function mergeVhostCustom($vhost_frx, $vhost_usr)
	{
		// Clean froxlor defined settings
		$vhost_frx = $this->cleanVhostStruct($vhost_frx);
		// Clean user defined settings
		$vhost_usr = $this->cleanVhostStruct($vhost_usr);

		// Cycle through the user defined settings
		$currentBlock = [];
		$blockLevel = 0;
		foreach ($vhost_usr as $line) {
			$line = trim($line);
			$currentBlock[] = $line;

			if (strpos($line, "{") !== false) {
				$blockLevel++;
			}
			if (strpos($line, "}") !== false && $blockLevel > 0) {
				$blockLevel--;
			}

			if ($line == "}" && $blockLevel == 0) {
				if (in_array($currentBlock[0], $vhost_frx)) {
					// Add to existing block
					$pos = array_search($currentBlock[0], $vhost_frx);
					do {
						$pos++;
					} while ($vhost_frx[$pos] != "}");

					for ($i = 1; $i < count($currentBlock) - 1; $i++) {
						array_splice($vhost_frx, $pos + $i - 1, 0, $currentBlock[$i]);
					}
				} else {
					// Add to end
					array_splice($vhost_frx, count($vhost_frx), 0, $currentBlock);
				}
				$currentBlock = [];
			} elseif ($blockLevel == 0) {
				array_splice($vhost_frx, count($vhost_frx), 0, $currentBlock);
				$currentBlock = [];
			}
		}

		$nextLevel = 0;
		for ($i = 0; $i < count($vhost_frx); $i++) {
			if (substr_count($vhost_frx[$i], "}") != 0 && substr_count($vhost_frx[$i], "{") == 0) {
				$nextLevel -= 1;
				$vhost_frx[$i] .= "\n";
			}
			if ($nextLevel > 0) {
				for ($j = 0; $j < $nextLevel; $j++) {
					$vhost_frx[$i] = "	" . $vhost_frx[$i];
				}
			}
			if (substr_count($vhost_frx[$i], "{") != 0 && substr_count($vhost_frx[$i], "}") == 0) {
				$nextLevel += 1;
			}
		}

		return implode("\n", $vhost_frx);
	}

	private function cleanVhostStruct($vhost = null)
	{
		// Remove windows linebreaks
		$vhost = str_replace("\r", "\n", $vhost);
		// remove comments
		$vhost = implode("\n", preg_replace('/^(\s+)?#(.*)$/', '', explode("\n", $vhost)));
		// Break blocks into lines
		$vhost = preg_replace("/^(\s+)?location(.+)\{(.+)\}$/misU", "location $2 {\n $3 \n}", $vhost);
		// Break into array items
		$vhost = explode("\n", preg_replace('/[ \t]+/', ' ', trim(preg_replace('/\t+/', '', $vhost))));
		// Remove empty lines
		$vhost = array_filter($vhost, function ($a) {
			return preg_match("#\S#", $a);
		});

		// remove unnecessary whitespaces
		$vhost = array_map("trim", $vhost);
		// re-number array keys
		$vhost = array_values($vhost);
		return $vhost;
	}

	protected function createPathOptions($domain)
	{
		$result_stmt = Database::prepare("
			SELECT * FROM " . TABLE_PANEL_HTACCESS . "
			WHERE `path` LIKE :docroot
		");
		Database::pexecute($result_stmt, [
			'docroot' => $domain['documentroot'] . '%'
		]);

		$path_options = '';
		$htpasswds = $this->getHtpasswds($domain);

		// for each entry in the htaccess table
		while ($row = $result_stmt->fetch(PDO::FETCH_ASSOC)) {
			if (!empty($row['error404path'])) {
				$defhandler = $row['error404path'];
				if (!Validate::validateUrl($defhandler)) {
					$defhandler = FileDir::makeCorrectFile($defhandler);
				}
				$path_options .= "\t" . 'error_page   404    ' . $defhandler . ';' . "\n";
			}

			if (!empty($row['error403path'])) {
				$defhandler = $row['error403path'];
				if (!Validate::validateUrl($defhandler)) {
					$defhandler = FileDir::makeCorrectFile($defhandler);
				}
				$path_options .= "\t" . 'error_page   403    ' . $defhandler . ';' . "\n";
			}

			if (!empty($row['error500path'])) {
				$defhandler = $row['error500path'];
				if (!Validate::validateUrl($defhandler)) {
					$defhandler = FileDir::makeCorrectFile($defhandler);
				}
				$path_options .= "\t" . 'error_page   500 502 503 504    ' . $defhandler . ';' . "\n";
			}

			// if ($row['options_indexes'] != '0') {
			$path = FileDir::makeCorrectDir(substr($row['path'], strlen($domain['documentroot']) - 1));

			FileDir::mkDirWithCorrectOwnership($domain['documentroot'], $row['path'], $domain['guid'], $domain['guid']);

			$path_options .= "\t" . '# ' . $path . "\n";
			if ($path == '/') {
				if ($row['options_indexes'] != '0') {
					$this->vhost_root_autoindex = true;
				}
				$path_options .= "\t" . 'location ' . FileDir::makeCorrectDir($path) . ' {' . "\n";
				if ($this->vhost_root_autoindex) {
					$path_options .= "\t\t" . 'autoindex  on;' . "\n";
					$this->vhost_root_autoindex = false;
				}

				// check if we have a htpasswd for this path
				// (damn nginx does not like more than one
				// 'location'-part with the same path)
				if (count($htpasswds) > 0) {
					foreach ($htpasswds as $idx => $single) {
						switch ($single['path']) {
							case '/awstats/':
							case '/webalizer/':
							case '/goaccess/':
								// no stats-alias in "location /"-context
								break;
							default:
								if ($single['path'] == '/') {
									$path_options .= "\t\t" . 'auth_basic            "' . $single['authname'] . '";' . "\n";
									$path_options .= "\t\t" . 'auth_basic_user_file  ' . FileDir::makeCorrectFile($single['usrf']) . ';' . "\n";
									if ($domain['phpenabled_customer'] == 1 && $domain['phpenabled_vhost'] == '1') {
										$path_options .= "\t\t" . 'index    index.php index.html index.htm;' . "\n";
									} else {
										$path_options .= "\t\t" . 'index    index.html index.htm;' . "\n";
									}
									// remove already used entries so we do not have doubles
									unset($htpasswds[$idx]);
								}
						}
					}
				}
				$path_options .= "\t" . '}' . "\n";

				$this->vhost_root_autoindex = false;
			} else {
				$path_options .= "\t" . 'location ^~ ' . FileDir::makeCorrectFile($path) . ' {' . "\n";
				if ($this->vhost_root_autoindex || $row['options_indexes'] != '0') {
					$path_options .= "\t\t" . 'autoindex  on;' . "\n";
					$this->vhost_root_autoindex = false;
				}
				$path_options .= "\t" . '} ' . "\n";
			}
			// }

			/**
			 * Perl support
			 * required the fastCGI wrapper to be running to receive the CGI requests.
			 */
			if (Customer::customerHasPerlEnabled($domain['customerid']) && $row['options_cgi'] != '0') {
				$path = FileDir::makeCorrectDir(substr($row['path'], strlen($domain['documentroot']) - 1));
				FileDir::mkDirWithCorrectOwnership($domain['documentroot'], $row['path'], $domain['guid'], $domain['guid']);

				// We need to remove the last slash, otherwise the regex wouldn't work
				if ($row['path'] != $domain['documentroot']) {
					$path = substr($path, 0, -1);
				}
				$path_options .= "\t" . 'location ~ \(.pl|.cgi)$ {' . "\n";
				$path_options .= "\t\t" . 'gzip off; #gzip makes scripts feel slower since they have to complete before getting gzipped' . "\n";
				$path_options .= "\t\t" . 'fastcgi_pass  ' . Settings::Get('system.perl_server') . ';' . "\n";
				$path_options .= "\t\t" . 'fastcgi_index index.cgi;' . "\n";
				$path_options .= "\t\t" . 'include ' . Settings::Get('nginx.fastcgiparams') . ';' . "\n";
				$path_options .= "\t" . '}' . "\n";
			}
		}

		// now the rest of the htpasswds
		if (count($htpasswds) > 0) {
			foreach ($htpasswds as $idx => $single) {
				// if ($single['path'] != '/') {
				switch ($single['path']) {
					case '/awstats/':
					case '/webalizer/':
					case '/goaccess/':
						$path_options .= $this->getStats($domain, $single);
						unset($htpasswds[$idx]);
						break;
					default:
						if ($single['path'] == '/') {
							$path_options .= "\t" . 'location ' . FileDir::makeCorrectDir($single['path']) . ' {' . "\n";
						} else {
							$path_options .= "\t" . 'location ^~ ' . FileDir::makeCorrectFile($single['path']) . ' {' . "\n";
						}
						$path_options .= "\t\t" . 'auth_basic            "' . $single['authname'] . '";' . "\n";
						$path_options .= "\t\t" . 'auth_basic_user_file  ' . FileDir::makeCorrectFile($single['usrf']) . ';' . "\n";
						if ($domain['phpenabled_customer'] == 1 && $domain['phpenabled_vhost'] == '1') {
							$path_options .= "\t\t" . 'index    index.php index.html index.htm;' . "\n";
							if ($domain['notryfiles'] != 1) {
								$path_options .= "\t\t" . 'location ~ ^(.+?\.php)(/.*)?$ {' . "\n";
								$path_options .= "\t\t\t" . 'try_files ' . $domain['nonexistinguri'] . ' @php;' . "\n";
								$path_options .= "\t\t" . '}' . "\n\n";
							}
						} else {
							$path_options .= "\t\t" . 'index    index.html index.htm;' . "\n";
						}
						$path_options .= "\t" . '}' . "\n";
				}
				// }
				unset($htpasswds[$idx]);
			}
		}

		return $path_options;
	}

	protected function getHtpasswds($domain)
	{
		$result_stmt = Database::prepare("
			SELECT a.*
			FROM `" . TABLE_PANEL_HTPASSWDS . "` AS a
			JOIN `" . TABLE_PANEL_DOMAINS . "` AS b USING (`customerid`)
			LEFT JOIN `" . TABLE_PANEL_CUSTOMERS . "` c ON c.customerid = b.customerid
			WHERE b.customerid = :customerid AND b.domain = :domain
			AND (a.path = CONCAT(c.documentroot, :ttool, '/') OR INSTR(a.path, b.documentroot));
		");
		Database::pexecute($result_stmt, [
			'customerid' => $domain['customerid'],
			'domain' => $domain['domain'],
			'ttool' => Settings::Get('system.traffictool')
		]);

		$returnval = [];
		$x = 0;
		while ($row_htpasswds = $result_stmt->fetch(PDO::FETCH_ASSOC)) {
			if (count($row_htpasswds) > 0) {
				$htpasswd_filename = FileDir::makeCorrectFile(Settings::Get('system.apacheconf_htpasswddir') . '/' . $row_htpasswds['customerid'] . '-' . md5($row_htpasswds['path']) . '.htpasswd');

				// ensure we can write to the array with index $htpasswd_filename
				if (!isset($this->htpasswds_data[$htpasswd_filename])) {
					$this->htpasswds_data[$htpasswd_filename] = '';
				}

				$this->htpasswds_data[$htpasswd_filename] .= $row_htpasswds['username'] . ':' . $row_htpasswds['password'] . "\n";

				// if the domains and their web contents are located in a subdirectory of
				// the nginx user, we have to evaluate the right path which is to protect
				if (stripos($row_htpasswds['path'], $domain['documentroot']) !== false) {
					// if the website contents is located in the user directory
					$path = FileDir::makeCorrectDir(substr($row_htpasswds['path'], strlen($domain['documentroot']) - 1));
				} else {
					// if the website contents is located in a subdirectory of the user
					$matches = [];
					preg_match('/^([\/[:print:]]*\/)([[:print:]\/]+){1}$/i', $row_htpasswds['path'], $matches);
					$path = FileDir::makeCorrectDir(substr($row_htpasswds['path'], strlen($matches[1]) - 1));
				}

				$returnval[$x]['path'] = $path;
				$returnval[$x]['root'] = FileDir::makeCorrectDir($domain['documentroot']);

				// Ensure there is only one auth name per password block, otherwise
				// the directives are inserted multiple times -> invalid config
				$authname = $row_htpasswds['authname'];
				for ($i = 0; $i < $x; $i++) {
					if ($returnval[$i]['usrf'] == $htpasswd_filename) {
						$authname = $returnval[$i]['authname'];
						break;
					}
				}
				$returnval[$x]['authname'] = $authname;

				$returnval[$x]['usrf'] = $htpasswd_filename;
				$x++;
			}
		}

		// Remove duplicate entries
		$returnval = array_map("unserialize", array_unique(array_map("serialize", $returnval)));

		return $returnval;
	}

	protected function getStats($domain, $single)
	{
		$stats_text = '';

		$statTool = Settings::Get('system.traffictool');
		$statDomain = "";
		if ($statTool == 'awstats') {
			// awstats generates for each domain regardless of speciallogfile
			$statDomain = "/" . $domain['domain'];
		}
		if ($domain['speciallogfile'] == '1') {
			$statDomain = "/" . (($domain['parentdomainid'] == '0') ? $domain['domain'] : $domain['parentdomain']);
		}
		$statDocroot = FileDir::makeCorrectFile($domain['customerroot'] . '/' . $statTool . $statDomain);

		$stats_text .= "\t" . 'location ^~ /'.$statTool.' {' . "\n";
		$stats_text .= "\t\t" . 'alias ' . $statDocroot . '/;' . "\n";
		$stats_text .= "\t\t" . 'auth_basic            "' . $single['authname'] . '";' . "\n";
		$stats_text .= "\t\t" . 'auth_basic_user_file  ' . FileDir::makeCorrectFile($single['usrf']) . ';' . "\n";
		$stats_text .= "\t" . '}' . "\n\n";

		// awstats special requirement for icons
		if ($statTool == 'awstats') {
			$stats_text .= "\t" . 'location ~ ^/awstats-icon/(.*)$ {' . "\n";
			$stats_text .= "\t\t" . 'alias ' . FileDir::makeCorrectDir(Settings::Get('system.awstats_icons')) . '$1;' . "\n";
			$stats_text .= "\t" . '}' . "\n\n";
		}

		return $stats_text;
	}

	protected function composePhpOptions(&$domain, $ssl_vhost = false)
	{
		$phpopts = '';
		if ($domain['phpenabled_customer'] == 1 && $domain['phpenabled_vhost'] == '1') {
			$phpopts = "\t" . 'location ~ ^(.+?\.php)(/.*)?$ {' . "\n";
			if ($domain['notryfiles'] != 1) {
				$phpopts .= "\t\t" . 'try_files ' . $domain['nonexistinguri'] . ' @php;' . "\n";
				$phpopts .= "\t" . '}' . "\n\n";

				$phpopts .= "\tlocation @php {\n";
				$phpopts .= "\t\t" . 'try_files $1 =404;' . "\n\n";
			}
			$phpopts .= "\t\tfastcgi_split_path_info ^(.+?\.php)(/.*)$;\n";
			$phpopts .= "\t\tinclude " . Settings::Get('nginx.fastcgiparams') . ";\n";
			$phpopts .= "\t\tfastcgi_param SCRIPT_FILENAME \$request_filename;\n";
			$phpopts .= "\t\tset \$path_info \$fastcgi_path_info;\n";
			$phpopts .= "\t\tfastcgi_param PATH_INFO \$path_info;\n";
			$phpopts .= "\t\tfastcgi_pass " . Settings::Get('system.nginx_php_backend') . ";\n";
			$phpopts .= "\t\tfastcgi_index index.php;\n";
			if ($domain['ssl'] == '1' && $ssl_vhost) {
				$phpopts .= "\t\tfastcgi_param HTTPS on;\n";
			}
			$phpopts .= "\t}\n\n";
		}
		return $phpopts;
	}

	/**
	 * define a default ErrorDocument-statement, bug #unknown-yet
	 */
	private function createStandardErrorHandler()
	{
		if (Settings::Get('defaultwebsrverrhandler.enabled') == '1' && (Settings::Get('defaultwebsrverrhandler.err401') != '' || Settings::Get('defaultwebsrverrhandler.err403') != '' || Settings::Get('defaultwebsrverrhandler.err404') != '' || Settings::Get('defaultwebsrverrhandler.err500') != '')) {
			$vhosts_filename = $this->getCustomVhostFilename('05_froxlor_default_errorhandler.conf');

			if (!isset($this->nginx_data[$vhosts_filename])) {
				$this->nginx_data[$vhosts_filename] = '';
			}

			$statusCodes = [
				'401',
				'403',
				'404',
				'500'
			];
			foreach ($statusCodes as $statusCode) {
				if (Settings::Get('defaultwebsrverrhandler.err' . $statusCode) != '') {
					$defhandler = Settings::Get('defaultwebsrverrhandler.err' . $statusCode);
					if (!Validate::validateUrl($defhandler)) {
						$defhandler = FileDir::makeCorrectFile($defhandler);
					}
					$this->nginx_data[$vhosts_filename] .= 'error_page ' . $statusCode . ' ' . $defhandler . ';' . "\n";
				}
			}
		}
	}

	public function createOwnVhostStarter()
	{
		return;
	}

	public function writeConfigs()
	{
		FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_INFO, "nginx::writeConfigs: rebuilding " . Settings::Get('system.apacheconf_vhost'));

		$vhostDir = new Directory(Settings::Get('system.apacheconf_vhost'));
		if (!$vhostDir->isConfigDir()) {
			// Save one big file
			$vhosts_file = '';

			// sort by filename so the order is:
			// 1. subdomains
			// 2. subdomains as main-domains
			// 3. main-domains
			ksort($this->nginx_data);

			foreach ($this->nginx_data as $vhosts_filename => $vhost_content) {
				$vhosts_file .= $vhost_content . "\n\n";
			}

			$vhosts_filename = Settings::Get('system.apacheconf_vhost');

			// Apply header
			$vhosts_file = '# ' . basename($vhosts_filename) . "\n" . '# Created ' . date('d.m.Y H:i') . "\n" . '# Do NOT manually edit this file, all changes will be deleted after the next domain change at the panel.' . "\n" . "\n" . $vhosts_file;
			$vhosts_file_handler = fopen($vhosts_filename, 'w');
			fwrite($vhosts_file_handler, $vhosts_file);
			fclose($vhosts_file_handler);
		} else {
			if (!file_exists(Settings::Get('system.apacheconf_vhost'))) {
				FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_NOTICE, 'nginx::writeConfigs: mkdir ' . escapeshellarg(FileDir::makeCorrectDir(Settings::Get('system.apacheconf_vhost'))));
				FileDir::safe_exec('mkdir -p ' . escapeshellarg(FileDir::makeCorrectDir(Settings::Get('system.apacheconf_vhost'))));
			}

			// Write a single file for every vhost
			foreach ($this->nginx_data as $vhosts_filename => $vhosts_file) {
				// Apply header
				$vhosts_file = '# ' . basename($vhosts_filename) . "\n" . '# Created ' . date('d.m.Y H:i') . "\n" . '# Do NOT manually edit this file, all changes will be deleted after the next domain change at the panel.' . "\n" . "\n" . $vhosts_file;

				if (!empty($vhosts_filename)) {
					$vhosts_file_handler = fopen($vhosts_filename, 'w');
					fwrite($vhosts_file_handler, $vhosts_file);
					fclose($vhosts_file_handler);
				}
			}
		}

		// htaccess stuff
		if (count($this->htpasswds_data) > 0) {
			if (!file_exists(Settings::Get('system.apacheconf_htpasswddir'))) {
				$umask = umask();
				umask(0000);
				mkdir(Settings::Get('system.apacheconf_htpasswddir'), 0751);
				umask($umask);
			} elseif (!is_dir(Settings::Get('system.apacheconf_htpasswddir'))) {
				FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_WARNING, 'WARNING!!! ' . Settings::Get('system.apacheconf_htpasswddir') . ' is not a directory. htpasswd directory protection is disabled!!!');
			}

			if (is_dir(Settings::Get('system.apacheconf_htpasswddir'))) {
				foreach ($this->htpasswds_data as $htpasswd_filename => $htpasswd_file) {
					$this->known_htpasswdsfilenames[] = basename($htpasswd_filename);
					$htpasswd_file_handler = fopen($htpasswd_filename, 'w');
					// Filter duplicate pairs of username and password
					$htpasswd_file = implode("\n", array_unique(explode("\n", $htpasswd_file)));
					fwrite($htpasswd_file_handler, $htpasswd_file);
					fclose($htpasswd_file_handler);
				}
			}
		}
	}
}
