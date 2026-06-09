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
use Froxlor\FileDir;
use Froxlor\FroxlorLogger;
use Froxlor\Http\Directory;
use Froxlor\Http\Statistics;
use Froxlor\PhpHelper;
use Froxlor\Settings;
use Froxlor\System\Cronjob;
use Froxlor\System\Crypt;
use Froxlor\Validate\Validate;
use PDO;

class Apache extends HttpConfigBase
{

	// protected
	protected $known_diroptionsfilenames = [];

	protected $known_htpasswdsfilenames = [];

	protected $virtualhosts_data = [];

	protected $diroptions_data = [];

	protected $htpasswds_data = [];

	/**
	 * indicator whether a customer is deactivated or not
	 * if yes, only the webroot will be generated
	 *
	 * @var bool
	 */
	private $deactivated = false;

	public function createIpPort()
	{
		$result_ipsandports_stmt = Database::query("SELECT * FROM `" . TABLE_PANEL_IPSANDPORTS . "` ORDER BY `ip` ASC, `port` ASC");

		while ($row_ipsandports = $result_ipsandports_stmt->fetch(PDO::FETCH_ASSOC)) {
			if (filter_var($row_ipsandports['ip'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
				$ipport = '[' . $row_ipsandports['ip'] . ']:' . $row_ipsandports['port'];
			} else {
				$ipport = $row_ipsandports['ip'] . ':' . $row_ipsandports['port'];
			}

			FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_INFO, 'apache::createIpPort: creating ip/port settings for  ' . $ipport);
			$vhosts_filename = FileDir::makeCorrectFile(Settings::Get('system.apacheconf_vhost') . '/10_froxlor_ipandport_' . trim(str_replace(':', '.', $row_ipsandports['ip']), '.') . '.' . $row_ipsandports['port'] . '.conf');

			if (!isset($this->virtualhosts_data[$vhosts_filename])) {
				$this->virtualhosts_data[$vhosts_filename] = '';
			}

			if ($row_ipsandports['listen_statement'] == '1') {
				$this->virtualhosts_data[$vhosts_filename] .= 'Listen ' . $ipport . "\n";
				FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_DEBUG, $ipport . ' :: inserted listen-statement');
			}

			if ($row_ipsandports['namevirtualhost_statement'] == '1') {
				// >=apache-2.4 enabled?
				if (Settings::Get('system.apache24') == '1') {
					FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_NOTICE, $ipport . ' :: namevirtualhost-statement no longer needed for apache-2.4');
				} else {
					$this->virtualhosts_data[$vhosts_filename] .= 'NameVirtualHost ' . $ipport . "\n";
					FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_DEBUG, $ipport . ' :: inserted namevirtualhost-statement');
				}
			}

			if ($row_ipsandports['vhostcontainer'] == '1') {
				$without_vhost = $this->virtualhosts_data[$vhosts_filename];
				$close_vhost = true;

				$this->virtualhosts_data[$vhosts_filename] .= '<VirtualHost ' . $ipport . '>' . "\n";

				$mypath = $this->getMyPath($row_ipsandports);

				$this->virtualhosts_data[$vhosts_filename] .= 'DocumentRoot "' . rtrim($mypath, "/") . '"' . "\n";

				if ($row_ipsandports['vhostcontainer_servername_statement'] == '1') {
					$this->virtualhosts_data[$vhosts_filename] .= ' ServerName ' . Settings::Get('system.hostname') . "\n";

					$froxlor_aliases = Settings::Get('system.froxloraliases');
					if (!empty($froxlor_aliases)) {
						$froxlor_aliases = explode(",", $froxlor_aliases);
						$aliases = "";
						foreach ($froxlor_aliases as $falias) {
							if (Validate::validateDomain(trim($falias))) {
								$aliases .= trim($falias) . " ";
							}
						}
						$aliases = trim($aliases);
						if (!empty($aliases)) {
							$this->virtualhosts_data[$vhosts_filename] .= ' ServerAlias ' . $aliases . "\n";
						}
					}
				}

				$is_redirect = false;
				// check for SSL redirect
				if ($row_ipsandports['ssl'] == '0' && Settings::Get('system.le_froxlor_redirect') == '1') {
					$is_redirect = true;
					// check whether froxlor uses Let's Encrypt and not cert is being generated yet
					// or a renewal is ongoing - disable redirect
					if (Settings::Get('system.leenabled') == '1' && Settings::Get('system.le_froxlor_enabled') && ($this->froxlorVhostHasLetsEncryptCert() == false || $this->froxlorVhostLetsEncryptNeedsRenew())) {
						$this->virtualhosts_data[$vhosts_filename] .= '# temp. disabled ssl-redirect due to Let\'s Encrypt certificate generation.' . PHP_EOL;
						$is_redirect = false;
						Cronjob::inserttask(TaskId::REBUILD_VHOST);
					} else {
						$_sslport = $this->checkAlternativeSslPort();

						$mypath = 'https://' . Settings::Get('system.hostname') . $_sslport . '/';
						$code = '301';
						$modrew_red = ' [R=' . $code . ';L,NE]';

						// redirect everything, not only root-directory, #541
						$this->virtualhosts_data[$vhosts_filename] .= '  <IfModule mod_rewrite.c>' . "\n";
						$this->virtualhosts_data[$vhosts_filename] .= '    RewriteEngine On' . "\n";
						$this->virtualhosts_data[$vhosts_filename] .= '    RewriteCond %{HTTPS} off' . "\n";
						if (Settings::Get('system.leenabled') == '1' && Settings::Get('system.le_froxlor_enabled') == '1') {
							$this->virtualhosts_data[$vhosts_filename] .= '    RewriteCond %{REQUEST_URI} !^/\.well-known/acme-challenge' . "\n";
						}
						$this->virtualhosts_data[$vhosts_filename] .= '    RewriteRule ^/(.*) ' . $mypath . '$1' . $modrew_red . "\n";
						$this->virtualhosts_data[$vhosts_filename] .= '  </IfModule>' . "\n";
						$this->virtualhosts_data[$vhosts_filename] .= '  <IfModule !mod_rewrite.c>' . "\n";
						$this->virtualhosts_data[$vhosts_filename] .= '    Redirect ' . $code . ' / ' . $mypath . "\n";
						$this->virtualhosts_data[$vhosts_filename] .= '  </IfModule>' . "\n";
					}
				}

				if (!$is_redirect) {
					// protect lib/userdata.inc.php
					$this->virtualhosts_data[$vhosts_filename] .= '  <Directory "' . rtrim($mypath, "/") . '/lib/">' . "\n";
					$this->virtualhosts_data[$vhosts_filename] .= '    <Files "userdata.inc.php">' . "\n";
					if (Settings::Get('system.apache24') == '1') {
						$this->virtualhosts_data[$vhosts_filename] .= '    Require all denied' . "\n";
					} else {
						$this->virtualhosts_data[$vhosts_filename] .= '    Order deny,allow' . "\n";
						$this->virtualhosts_data[$vhosts_filename] .= '    deny from all' . "\n";
					}
					$this->virtualhosts_data[$vhosts_filename] .= '    </Files>' . "\n";
					$this->virtualhosts_data[$vhosts_filename] .= '  </Directory>' . "\n";
					// protect bin/
					$this->virtualhosts_data[$vhosts_filename] .= '  <DirectoryMatch "^' . rtrim($mypath, "/") . '/(bin|cache|logs|tests|vendor)/">' . "\n";
					if (Settings::Get('system.apache24') == '1') {
						$this->virtualhosts_data[$vhosts_filename] .= '    Require all denied' . "\n";
					} else {
						$this->virtualhosts_data[$vhosts_filename] .= '    Order deny,allow' . "\n";
						$this->virtualhosts_data[$vhosts_filename] .= '    deny from all' . "\n";
					}
					$this->virtualhosts_data[$vhosts_filename] .= '  </DirectoryMatch>' . "\n";

					// create fcgid <Directory>-Part (starter is created in apache_fcgid)
					if (Settings::Get('system.mod_fcgid_ownvhost') == '1' && Settings::Get('system.mod_fcgid') == '1') {
						$configdir = FileDir::makeCorrectDir(Settings::Get('system.mod_fcgid_configdir') . '/froxlor.panel/' . Settings::Get('system.hostname'));
						$this->virtualhosts_data[$vhosts_filename] .= '  FcgidIdleTimeout ' . Settings::Get('system.mod_fcgid_idle_timeout') . "\n";
						if ((int)Settings::Get('system.mod_fcgid_wrapper') == 0) {
							$this->virtualhosts_data[$vhosts_filename] .= '  SuexecUserGroup "' . Settings::Get('system.mod_fcgid_httpuser') . '" "' . Settings::Get('system.mod_fcgid_httpgroup') . '"' . "\n";
							$this->virtualhosts_data[$vhosts_filename] .= '  ScriptAlias /php/ ' . $configdir . "\n";
						} else {
							$domain = [
								'id' => 'none',
								'domain' => Settings::Get('system.hostname'),
								'adminid' => 1, /* first admin-user (superadmin) */
								'mod_fcgid_starter' => -1,
								'mod_fcgid_maxrequests' => -1,
								'guid' => Settings::Get('system.mod_fcgid_httpuser'),
								'openbasedir' => 0,
								'email' => Settings::Get('panel.adminmail'),
								'loginname' => 'froxlor.panel',
								'documentroot' => $mypath,
								'customerroot' => $mypath
							];
							$php = new PhpInterface($domain);
							$phpconfig = $php->getPhpConfig(Settings::Get('system.mod_fcgid_defaultini_ownvhost'));
							if ($phpconfig['pass_authorizationheader'] == '1') {
								$this->virtualhosts_data[$vhosts_filename] .= '  FcgidPassHeader     Authorization' . "\n";
							}
							$starter_filename = FileDir::makeCorrectFile($configdir . '/php-fcgi-starter');
							$this->virtualhosts_data[$vhosts_filename] .= '  SuexecUserGroup "' . Settings::Get('system.mod_fcgid_httpuser') . '" "' . Settings::Get('system.mod_fcgid_httpgroup') . '"' . "\n";
							$this->virtualhosts_data[$vhosts_filename] .= '  <Directory "' . $mypath . '">' . "\n";
							$file_extensions = explode(' ', $phpconfig['file_extensions']);
							$this->virtualhosts_data[$vhosts_filename] .= '    <FilesMatch "\.(' . implode('|', $file_extensions) . ')$">' . "\n";
							$this->virtualhosts_data[$vhosts_filename] .= '      SetHandler fcgid-script' . "\n";
							foreach ($file_extensions as $file_extension) {
								$this->virtualhosts_data[$vhosts_filename] .= '      FcgidWrapper ' . $starter_filename . ' .' . $file_extension . "\n";
							}
							$this->virtualhosts_data[$vhosts_filename] .= '      Options +ExecCGI' . "\n";
							$this->virtualhosts_data[$vhosts_filename] .= '    </FilesMatch>' . "\n";
							// >=apache-2.4 enabled?
							if (Settings::Get('system.apache24') == '1') {
								$mypath_dir = new Directory($mypath);
								// only create the require all granted if there is not active directory-protection
								// for this path, as this would be the first require and therefore grant all access
								if ($mypath_dir->isUserProtected() == false) {
									$this->virtualhosts_data[$vhosts_filename] .= '    Require all granted' . "\n";
									$this->virtualhosts_data[$vhosts_filename] .= '    AllowOverride All' . "\n";
								}
							} else {
								$this->virtualhosts_data[$vhosts_filename] .= '    Order allow,deny' . "\n";
								$this->virtualhosts_data[$vhosts_filename] .= '    allow from all' . "\n";
							}
							$this->virtualhosts_data[$vhosts_filename] .= '  </Directory>' . "\n";
						}
					} elseif (Settings::Get('phpfpm.enabled') == '1' && (int)Settings::Get('phpfpm.enabled_ownvhost') == 1) {
						// get fpm config
						$fpm_sel_stmt = Database::prepare("
							SELECT f.id FROM `" . TABLE_PANEL_FPMDAEMONS . "` f
							LEFT JOIN `" . TABLE_PANEL_PHPCONFIGS . "` p ON p.fpmsettingid = f.id
							WHERE p.id = :phpconfigid
						");
						$fpm_config = Database::pexecute_first($fpm_sel_stmt, [
							'phpconfigid' => Settings::Get('phpfpm.vhost_defaultini')
						]);
						// create php-fpm <Directory>-Part (config is created in apache_fcgid)
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

						$php = new phpinterface($domain);
						$phpconfig = $php->getPhpConfig(Settings::Get('phpfpm.vhost_defaultini'));
						$srvName = substr(md5($ipport), 0, 4) . '.fpm.external';
						if ($row_ipsandports['ssl']) {
							$srvName = substr(md5($ipport), 0, 4) . '.ssl-fpm.external';
						}

						$this->virtualhosts_data[$vhosts_filename] .= '  <Directory "' . $mypath . '">' . "\n";
						// mod_proxy stuff for apache-2.4
						if (Settings::Get('system.apache24') == '1' && Settings::Get('phpfpm.use_mod_proxy') == '1') {
							$filesmatch = $phpconfig['fpm_settings']['limit_extensions'];
							$extensions = explode(" ", $filesmatch);
							$filesmatch = "";
							foreach ($extensions as $ext) {
								$filesmatch .= substr($ext, 1) . '|';
							}
							// start block, cut off last pipe and close block
							$filesmatch = '(' . str_replace(".", "\.", substr($filesmatch, 0, -1)) . ')';
							$this->virtualhosts_data[$vhosts_filename] .= '  <FilesMatch \.' . $filesmatch . '$>' . "\n";
							$this->virtualhosts_data[$vhosts_filename] .= '    <If "-f %{SCRIPT_FILENAME}">' . "\n";
							$this->virtualhosts_data[$vhosts_filename] .= '  	SetHandler proxy:unix:' . $php->getInterface()->getSocketFile() . '|fcgi://localhost' . "\n";
							$this->virtualhosts_data[$vhosts_filename] .= '    </If>' . "\n";
							$this->virtualhosts_data[$vhosts_filename] .= '  </FilesMatch>' . "\n";
							if ($phpconfig['pass_authorizationheader'] == '1') {
								$this->virtualhosts_data[$vhosts_filename] .= '    CGIPassAuth On' . "\n";
							}
						} else {
							$addheader = "";
							if ($phpconfig['pass_authorizationheader'] == '1') {
								$addheader = " -pass-header Authorization";
							}
							$this->virtualhosts_data[$vhosts_filename] .= '  FastCgiExternalServer ' . $php->getInterface()->getAliasConfigDir() . $srvName . ' -socket ' . $php->getInterface()->getSocketFile() . ' -idle-timeout ' . $phpconfig['fpm_settings']['idle_timeout'] . $addheader . "\n";
							$filesmatch = $phpconfig['fpm_settings']['limit_extensions'];
							$extensions = explode(" ", $filesmatch);
							$filesmatch = "";
							foreach ($extensions as $ext) {
								$filesmatch .= substr($ext, 1) . '|';
							}
							// start block, cut off last pipe and close block
							$filesmatch = '(' . str_replace(".", "\.", substr($filesmatch, 0, -1)) . ')';
							$this->virtualhosts_data[$vhosts_filename] .= '   <FilesMatch \.' . $filesmatch . '$>' . "\n";
							$this->virtualhosts_data[$vhosts_filename] .= '     AddHandler php-fastcgi .php' . "\n";
							$this->virtualhosts_data[$vhosts_filename] .= '     Action php-fastcgi /fastcgiphp' . "\n";
							$this->virtualhosts_data[$vhosts_filename] .= '      Options +ExecCGI' . "\n";
							$this->virtualhosts_data[$vhosts_filename] .= '    </FilesMatch>' . "\n";
							$this->virtualhosts_data[$vhosts_filename] .= '  Alias /fastcgiphp ' . $php->getInterface()->getAliasConfigDir() . $srvName . "\n";
						}
						// >=apache-2.4 enabled?
						if (Settings::Get('system.apache24') == '1') {
							$this->virtualhosts_data[$vhosts_filename] .= '    Require all granted' . "\n";
							$this->virtualhosts_data[$vhosts_filename] .= '    AllowOverride All' . "\n";
						} else {
							$this->virtualhosts_data[$vhosts_filename] .= '    Order allow,deny' . "\n";
							$this->virtualhosts_data[$vhosts_filename] .= '    allow from all' . "\n";
						}
						$this->virtualhosts_data[$vhosts_filename] .= '  </Directory>' . "\n";
					} else {
						// mod_php
						$domain = [
							'id' => 'none',
							'domain' => Settings::Get('system.hostname'),
							'adminid' => 1, /* first admin-user (superadmin) */
							'guid' => Settings::Get('system.httpuser'),
							'openbasedir' => 0,
							'email' => Settings::Get('panel.adminmail'),
							'loginname' => 'froxlor.panel',
							'documentroot' => $mypath,
							'customerroot' => $mypath
						];
					}
					// end of ssl-redirect check
				} else {
					// fallback of froxlor domain-data for processSpecialConfigTemplate()
					$domain = [
						'domain' => Settings::Get('system.hostname'),
						'loginname' => 'froxlor.panel',
						'documentroot' => $mypath,
						'customerroot' => $mypath
					];
				}

				/**
				 * dirprotection, see #72
				 *
				 * @todo deferred until 0.9.5, needs more testing
				 *       $this->virtualhosts_data[$vhosts_filename] .= "\t<Directory \"'.$mypath.'(images|packages|templates)\">\n";
				 *       $this->virtualhosts_data[$vhosts_filename] .= "\t\tAllow from all\n";
				 *       $this->virtualhosts_data[$vhosts_filename] .= "\t\tOptions -Indexes\n";
				 *       $this->virtualhosts_data[$vhosts_filename] .= "\t</Directory>\n";
				 *
				 *       $this->virtualhosts_data[$vhosts_filename] .= "\t<Directory \"'.$mypath.'*\">\n";
				 *       $this->virtualhosts_data[$vhosts_filename] .= "\t\tOrder Deny,Allow\n";
				 *       $this->virtualhosts_data[$vhosts_filename] .= "\t\tDeny from All\n";
				 *       $this->virtualhosts_data[$vhosts_filename] .= "\t</Directory>\n";
				 *       end of dirprotection
				 */

				if ($row_ipsandports['specialsettings'] != '' && ($row_ipsandports['ssl'] == '0' || ($row_ipsandports['ssl'] == '1' && Settings::Get('system.use_ssl') == '1' && $row_ipsandports['include_specialsettings'] == '1'))) {
					$this->virtualhosts_data[$vhosts_filename] .= $this->processSpecialConfigTemplate($row_ipsandports['specialsettings'], $domain, $row_ipsandports['ip'], $row_ipsandports['port'], $row_ipsandports['ssl'] == '1') . "\n";
				}

				if ($row_ipsandports['ssl'] == '1' && Settings::Get('system.use_ssl') == '1') {
					if ($row_ipsandports['ssl_specialsettings'] != '') {
						$this->virtualhosts_data[$vhosts_filename] .= $this->processSpecialConfigTemplate($row_ipsandports['ssl_specialsettings'], $domain, $row_ipsandports['ip'], $row_ipsandports['port'], $row_ipsandports['ssl'] == '1') . "\n";
					}

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

					// #418
					if ($row_ipsandports['ssl_cert_chainfile'] == '') {
						$row_ipsandports['ssl_cert_chainfile'] = Settings::Get('system.ssl_cert_chainfile');
					}

					$domain = [
						'id' => 0,
						'domain' => Settings::Get('system.hostname'),
						'adminid' => 1, /* first admin-user (superadmin) */
						'loginname' => 'froxlor.panel',
						'documentroot' => $mypath,
						'customerroot' => $mypath,
						'parentdomainid' => 0,
						'ssl_honorcipherorder' => Settings::Get('system.honorcipherorder'),
						'ssl_sessiontickets' => Settings::Get('system.sessiontickets')
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

					if ($domain['ssl_cert_file'] != '') {
						// check for existence, #1485
						if (!file_exists($domain['ssl_cert_file'])) {
							FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_ERR, $ipport . ' :: certificate file "' . $domain['ssl_cert_file'] . '" does not exist! Cannot create ssl-directives');
						} else {
							$this->virtualhosts_data[$vhosts_filename] .= ' SSLEngine On' . "\n";
							$this->virtualhosts_data[$vhosts_filename] .= ' SSLProtocol -ALL +' . str_replace(",", " +", Settings::Get('system.ssl_protocols')) . "\n";
							if (Settings::Get('system.apache24') == '1') {
								if (Settings::Get('system.http2_support') == '1') {
									$this->virtualhosts_data[$vhosts_filename] .= ' Protocols h2 http/1.1' . "\n";
								}
								if (!empty(Settings::Get('system.dhparams_file'))) {
									$dhparams = FileDir::makeCorrectFile(Settings::Get('system.dhparams_file'));
									if (!file_exists($dhparams)) {
										file_put_contents($dhparams, self::FFDHE4096);
									}
									$this->virtualhosts_data[$vhosts_filename] .= ' SSLOpenSSLConfCmd DHParameters "' . $dhparams . '"' . "\n";
								}
								$this->virtualhosts_data[$vhosts_filename] .= ' SSLCompression Off' . "\n";
								if (Settings::Get('system.sessionticketsenabled') == '1') {
									$this->virtualhosts_data[$vhosts_filename] .= ' SSLSessionTickets ' . ($domain['ssl_sessiontickets'] == '1' ? 'on' : 'off') . "\n";
								}
							}

							$this->virtualhosts_data[$vhosts_filename] .= ' SSLHonorCipherOrder ' . ($domain['ssl_honorcipherorder'] == '1' ? 'on' : 'off') . "\n";
							$this->virtualhosts_data[$vhosts_filename] .= ' SSLCipherSuite ' . Settings::Get('system.ssl_cipher_list') . "\n";
							$protocols = array_map('trim', explode(",", Settings::Get('system.ssl_protocols')));
							if (in_array("TLSv1.3", $protocols) && !empty(Settings::Get('system.tlsv13_cipher_list')) && Settings::Get('system.apache24') == 1) {
								$this->virtualhosts_data[$vhosts_filename] .= ' SSLCipherSuite TLSv1.3 ' . Settings::Get('system.tlsv13_cipher_list') . "\n";
							}
							$this->virtualhosts_data[$vhosts_filename] .= ' SSLVerifyDepth 10' . "\n";
							$this->virtualhosts_data[$vhosts_filename] .= ' SSLCertificateFile ' . FileDir::makeCorrectFile($domain['ssl_cert_file']) . "\n";

							if ($domain['ssl_key_file'] != '') {
								// check for existence, #1485
								if (!file_exists($domain['ssl_key_file'])) {
									FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_ERR, $ipport . ' :: certificate key file "' . $domain['ssl_key_file'] . '" does not exist! Cannot create ssl-directives');
								} else {
									$this->virtualhosts_data[$vhosts_filename] .= ' SSLCertificateKeyFile ' . FileDir::makeCorrectFile($domain['ssl_key_file']) . "\n";
								}
							}

							if ($domain['ssl_ca_file'] != '') {
								// check for existence, #1485
								if (!file_exists($domain['ssl_ca_file'])) {
									FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_ERR, $ipport . ' :: certificate CA file "' . $domain['ssl_ca_file'] . '" does not exist! Cannot create ssl-directives');
								} else {
									$this->virtualhosts_data[$vhosts_filename] .= ' SSLCACertificateFile ' . FileDir::makeCorrectFile($domain['ssl_ca_file']) . "\n";
								}
							}

							// #418
							if ($domain['ssl_cert_chainfile'] != '') {
								// check for existence, #1485
								if (!file_exists($domain['ssl_cert_chainfile'])) {
									FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_ERR, $ipport . ' :: certificate chain file "' . $domain['ssl_cert_chainfile'] . '" does not exist! Cannot create ssl-directives');
								} else {
									$this->virtualhosts_data[$vhosts_filename] .= ' SSLCertificateChainFile ' . FileDir::makeCorrectFile($domain['ssl_cert_chainfile']) . "\n";
								}
							}
						}
					} else {
						// if there is no cert-file specified but we are generating a ssl-vhost,
						// we should return an empty string because this vhost would suck dick, ref #1583
						FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_ERR, $domain['domain'] . ' :: empty certificate file! Cannot create ssl-directives');
						$this->virtualhosts_data[$vhosts_filename] = $without_vhost;
						$this->virtualhosts_data[$vhosts_filename] .= '# no ssl-certificate was specified for this domain, therefore no explicit vhost-container is being generated';
						$close_vhost = false;
					}
				}

				if ($close_vhost) {
					$this->virtualhosts_data[$vhosts_filename] .= '</VirtualHost>' . "\n";
				}
				FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_DEBUG, $ipport . ' :: inserted vhostcontainer');
			}
			unset($vhosts_filename);
		}

		/**
		 * bug #32
		 */
		$this->createStandardDirectoryEntry();

		/**
		 * bug #unknown-yet
		 */
		$this->createStandardErrorHandler();
	}

	/**
	 * define a standard <Directory>-statement, bug #32
	 */
	private function createStandardDirectoryEntry()
	{
		$vhosts_filename = $this->getCustomVhostFilename('05_froxlor_dirfix_nofcgid.conf');

		if (!isset($this->virtualhosts_data[$vhosts_filename])) {
			$this->virtualhosts_data[$vhosts_filename] = '';
		}

		$this->virtualhosts_data[$vhosts_filename] .= '  <Directory "' . FileDir::makeCorrectDir(Settings::Get('system.documentroot_prefix')) . '">' . "\n";

		// check for custom values, see #1638
		$custom_opts = Settings::Get('system.apacheglobaldiropt');
		if (!empty($custom_opts)) {
			$this->virtualhosts_data[$vhosts_filename] .= $custom_opts . "\n";
		} else {
			// >=apache-2.4 enabled?
			if (Settings::Get('system.apache24') == '1') {
				$this->virtualhosts_data[$vhosts_filename] .= '    Require all granted' . "\n";
				$this->virtualhosts_data[$vhosts_filename] .= '    AllowOverride All' . "\n";
			} else {
				$this->virtualhosts_data[$vhosts_filename] .= '    Order allow,deny' . "\n";
				$this->virtualhosts_data[$vhosts_filename] .= '    allow from all' . "\n";
			}
		}
		$this->virtualhosts_data[$vhosts_filename] .= '  </Directory>' . "\n";

		$ocsp_cache_filename = $this->getCustomVhostFilename('03_froxlor_ocsp_cache.conf');
		if (Settings::Get('system.use_ssl') == '1' && Settings::Get('system.apache24') == 1) {
			$this->virtualhosts_data[$ocsp_cache_filename] = 'SSLStaplingCache ' . Settings::Get('system.apache24_ocsp_cache_path') . "\n";
		} else {
			if (file_exists($ocsp_cache_filename)) {
				FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_NOTICE, 'apache::_createStandardDirectoryEntry: unlinking ' . basename($ocsp_cache_filename));
				unlink(FileDir::makeCorrectFile($ocsp_cache_filename));
			}
		}
	}

	/**
	 * define a default ErrorDocument-statement, bug #unknown-yet
	 */
	private function createStandardErrorHandler()
	{
		if (Settings::Get('defaultwebsrverrhandler.enabled') == '1' && (Settings::Get('defaultwebsrverrhandler.err401') != '' || Settings::Get('defaultwebsrverrhandler.err403') != '' || Settings::Get('defaultwebsrverrhandler.err404') != '' || Settings::Get('defaultwebsrverrhandler.err500') != '')) {
			$vhosts_filename = $this->getCustomVhostFilename('05_froxlor_default_errorhandler.conf');

			if (!isset($this->virtualhosts_data[$vhosts_filename])) {
				$this->virtualhosts_data[$vhosts_filename] = '';
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
						if (substr($defhandler, 0, 1) != '"' && substr($defhandler, -1, 1) != '"') {
							$defhandler = '"' . FileDir::makeCorrectFile($defhandler) . '"';
						}
					}
					$this->virtualhosts_data[$vhosts_filename] .= 'ErrorDocument ' . $statusCode . ' ' . $defhandler . "\n";
				}
			}
		}
	}

	public function createOwnVhostStarter()
	{
		return;
	}

	/**
	 * We compose the virtualhost entries for the domains
	 */
	public function createVirtualHosts()
	{
		$domains = WebserverBase::getVhostsToCreate();
		foreach ($domains as $domain) {
			FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_INFO, 'apache::createVirtualHosts: creating vhost container for domain ' . $domain['id'] . ', customer ' . $domain['loginname']);
			$vhosts_filename = $this->getVhostFilename($domain);

			// Apply header
			$this->virtualhosts_data[$vhosts_filename] = '# Domain ID: ' . $domain['id'] . ' - CustomerID: ' . $domain['customerid'] . ' - CustomerLogin: ' . $domain['loginname'] . "\n";

			$ddr = Settings::Get('system.deactivateddocroot');
			if (($domain['deactivated'] == '1' || $domain['customer_deactivated'] == '1') && empty($ddr)) {
				$this->virtualhosts_data[$vhosts_filename] .= '# Customer/domain deactivated and a docroot for deactivated users hasn\'t been set.' . "\n";
			} else {
				// Create vhost without ssl
				$this->virtualhosts_data[$vhosts_filename] .= $this->getVhostContent($domain, false);

				if ($domain['ssl_enabled'] == '1' && ($domain['ssl'] == '1' || $domain['ssl_redirect'] == '1')) {
					// Adding ssl stuff if enabled
					$vhosts_filename_ssl = $this->getVhostFilename($domain, true);
					$this->virtualhosts_data[$vhosts_filename_ssl] = '# Domain ID: ' . $domain['id'] . ' (SSL) - CustomerID: ' . $domain['customerid'] . ' - CustomerLogin: ' . $domain['loginname'] . "\n";
					$this->virtualhosts_data[$vhosts_filename_ssl] .= $this->getVhostContent($domain, true);
				}
			}
		}
	}

	/**
	 * We compose the virtualhost entry for one domain
	 */
	protected function getVhostContent($domain, $ssl_vhost = false)
	{
		if ($ssl_vhost === true && ($domain['ssl_redirect'] != '1' && $domain['ssl'] != '1')) {
			return '';
		}

		$query = "SELECT * FROM `" . TABLE_PANEL_IPSANDPORTS . "` `i`, `" . TABLE_DOMAINTOIP . "` `dip`
			WHERE dip.id_domain = :domainid AND i.id = dip.id_ipandports ";

		if ($ssl_vhost === true && ($domain['ssl'] == '1' || $domain['ssl_redirect'] == '1')) {
			// by ordering by cert-file the row with filled out SSL-Fields will be shown last, thus it is enough to fill out 1 set of SSL-Fields
			$query .= "AND i.ssl = '1' ORDER BY i.ssl_cert_file ASC;";
		} else {
			$query .= "AND i.ssl = '0';";
		}

		$vhost_content = '';
		$result_stmt = Database::prepare($query);
		Database::pexecute($result_stmt, [
			'domainid' => $domain['id']
		]);

		$ipportlist = '';
		$_vhost_content = '';
		while ($ipandport = $result_stmt->fetch(PDO::FETCH_ASSOC)) {
			$ipport = '';
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
				$ipport = '[' . $domain['ip'] . ']:' . $domain['port'] . ' ';
			} else {
				$ipport = $domain['ip'] . ':' . $domain['port'] . ' ';
			}

			if ($ipandport['default_vhostconf_domain'] != '' && ($ssl_vhost == false || ($ssl_vhost == true && $ipandport['include_default_vhostconf_domain'] == '1'))) {
				$_vhost_content .= $this->processSpecialConfigTemplate($ipandport['default_vhostconf_domain'], $domain, $domain['ip'], $domain['port'], $ssl_vhost) . "\n";
			}
			if ($ipandport['ssl_default_vhostconf_domain'] != '' && $ssl_vhost == true) {
				$_vhost_content .= $this->processSpecialConfigTemplate($ipandport['ssl_default_vhostconf_domain'], $domain, $domain['ip'], $domain['port'], $ssl_vhost) . "\n";
			}
			$ipportlist .= $ipport;
		}

		$vhost_content .= '<VirtualHost ' . trim($ipportlist) . '>' . "\n";
		$vhost_content .= $this->getServerNames($domain);

		$domain['documentroot_norewrite'] = $domain['documentroot'];
		if (($ssl_vhost == false && $domain['ssl'] == '1' && $domain['ssl_redirect'] == '1')) {
			// We must not check if our port differs from port 443,
			// but if there is a destination-port != 443
			$_sslport = '';
			// This returns the first port that is != 443 with ssl enabled, if any
			// ordered by ssl-certificate (if any) so that the ip/port combo
			// with certificate is used
			$ssldestport_stmt = Database::prepare("
				SELECT `ip`.`port` FROM " . TABLE_PANEL_IPSANDPORTS . " `ip`
				LEFT JOIN `" . TABLE_DOMAINTOIP . "` `dip` ON (`ip`.`id` = `dip`.`id_ipandports`)
				WHERE `dip`.`id_domain` = :domainid
				AND `ip`.`ssl` = '1'  AND `ip`.`port` != 443
				ORDER BY `ip`.`ssl_cert_file` DESC, `ip`.`port` LIMIT 1;
			");
			$ssldestport = Database::pexecute_first($ssldestport_stmt, [
				'domainid' => $domain['id']
			]);

			if ($ssldestport && $ssldestport['port'] != '') {
				$_sslport = ":" . $ssldestport['port'];
			}

			$domain['documentroot'] = 'https://%{HTTP_HOST}' . $_sslport . '/';
			$domain['documentroot_norewrite'] = 'https://' . $domain['domain'] . $_sslport . '/';
		}

		if ($ssl_vhost === true && $domain['ssl'] == '1' && Settings::Get('system.use_ssl') == '1') {
			if ($domain['ssl_cert_file'] == '' || !file_exists($domain['ssl_cert_file'])) {
				$domain['ssl_cert_file'] = Settings::Get('system.ssl_cert_file');
				if (!file_exists($domain['ssl_cert_file'])) {
					// explicitly disable ssl for this vhost
					$domain['ssl_cert_file'] = "";
					FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_DEBUG, 'System certificate file "' . Settings::Get('system.ssl_cert_file') . '" does not seem to exist. Disabling SSL-vhost for "' . $domain['domain'] . '"');
				}
			}

			if ($domain['ssl_key_file'] == '' || !file_exists($domain['ssl_key_file'])) {
				$domain['ssl_key_file'] = Settings::Get('system.ssl_key_file');
				if (!file_exists($domain['ssl_key_file'])) {
					// explicitly disable ssl for this vhost
					$domain['ssl_cert_file'] = "";
					FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_DEBUG, 'System certificate key-file "' . Settings::Get('system.ssl_key_file') . '" does not seem to exist. Disabling SSL-vhost for "' . $domain['domain'] . '"');
				}
			}

			if ($domain['ssl_ca_file'] == '') {
				$domain['ssl_ca_file'] = Settings::Get('system.ssl_ca_file');
			}

			if ($domain['ssl_cert_chainfile'] == '') {
				$domain['ssl_cert_chainfile'] = Settings::Get('system.ssl_cert_chainfile');
			}

			if ($domain['ssl_cert_file'] != '') {
				$ssl_protocols = ($domain['override_tls'] == '1' && !empty($domain['ssl_protocols'])) ? $domain['ssl_protocols'] : Settings::Get('system.ssl_protocols');
				$ssl_cipher_list = ($domain['override_tls'] == '1' && !empty($domain['ssl_cipher_list'])) ? $domain['ssl_cipher_list'] : Settings::Get('system.ssl_cipher_list');
				$tlsv13_cipher_list = ($domain['override_tls'] == '1' && !empty($domain['tlsv13_cipher_list'])) ? $domain['tlsv13_cipher_list'] : Settings::Get('system.tlsv13_cipher_list');

				$vhost_content .= '  SSLEngine On' . "\n";
				$vhost_content .= '  SSLProtocol -ALL +' . str_replace(",", " +", $ssl_protocols) . "\n";
				if (Settings::Get('system.apache24') == '1') {
					if (isset($domain['http2']) && $domain['http2'] == '1' && Settings::Get('system.http2_support') == '1') {
						$vhost_content .= '  Protocols h2 http/1.1' . "\n";
					}
					if (!empty(Settings::Get('system.dhparams_file'))) {
						$dhparams = FileDir::makeCorrectFile(Settings::Get('system.dhparams_file'));
						if (!file_exists($dhparams)) {
							file_put_contents($dhparams, self::FFDHE4096);
						}
						$vhost_content .= '  SSLOpenSSLConfCmd DHParameters "' . $dhparams . '"' . "\n";
					}
					$vhost_content .= '  SSLCompression Off' . "\n";
					if (Settings::Get('system.sessionticketsenabled') == '1') {
						$vhost_content .= '  SSLSessionTickets ' . ($domain['ssl_sessiontickets'] == '1' ? 'on' : 'off') . "\n";
					}
				}
				$vhost_content .= '  SSLHonorCipherOrder ' . ($domain['ssl_honorcipherorder'] == '1' ? 'on' : 'off') . "\n";
				$vhost_content .= '  SSLCipherSuite ' . $ssl_cipher_list . "\n";
				$protocols = array_map('trim', explode(",", $ssl_protocols));
				if (in_array("TLSv1.3", $protocols) && !empty($tlsv13_cipher_list) && Settings::Get('system.apache24') == 1) {
					$vhost_content .= '  SSLCipherSuite TLSv1.3 ' . $tlsv13_cipher_list . "\n";
				}
				$vhost_content .= '  SSLVerifyDepth 10' . "\n";
				$vhost_content .= '  SSLCertificateFile ' . FileDir::makeCorrectFile($domain['ssl_cert_file']) . "\n";

				if ($domain['ssl_key_file'] != '') {
					$vhost_content .= '  SSLCertificateKeyFile ' . FileDir::makeCorrectFile($domain['ssl_key_file']) . "\n";
				}

				if ($domain['ssl_ca_file'] != '') {
					$vhost_content .= '  SSLCACertificateFile ' . FileDir::makeCorrectFile($domain['ssl_ca_file']) . "\n";
				}

				if ($domain['ssl_cert_chainfile'] != '') {
					$vhost_content .= '  SSLCertificateChainFile ' . FileDir::makeCorrectFile($domain['ssl_cert_chainfile']) . "\n";
				}

				if (Settings::Get('system.apache24') == '1' && isset($domain['ocsp_stapling']) && $domain['ocsp_stapling'] == '1') {
					$vhost_content .= '  SSLUseStapling on' . PHP_EOL;
				}

				if ($domain['hsts'] >= 0) {
					$vhost_content .= '  <IfModule mod_headers.c>' . "\n";
					$vhost_content .= '    Header always set Strict-Transport-Security "max-age=' . $domain['hsts'];
					if ($domain['hsts_sub'] == 1) {
						$vhost_content .= '; includeSubDomains';
					}
					if ($domain['hsts_preload'] == 1) {
						$vhost_content .= '; preload';
					}
					$vhost_content .= '"' . "\n";
					$vhost_content .= '  </IfModule>' . "\n";
				}
			} else {
				// if there is no cert-file specified but we are generating a ssl-vhost,
				// we should return an empty string because this vhost would suck dick, ref #1583
				FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_ERR, $domain['domain'] . ' :: empty certificate file! Cannot create ssl-directives');
				return '# no ssl-certificate was specified for this domain, therefore no explicit vhost is being generated';
			}
		}

		// avoid using any whitespaces
		$domain['documentroot'] = trim($domain['documentroot']);

		if (preg_match('/^https?\:\/\//', $domain['documentroot'])) {
			$possible_deactivated_webroot = $this->getWebroot($domain);
			if ($this->deactivated == false) {
				if (($ssl_vhost == false && $domain['ssl'] == '1' && $domain['ssl_redirect'] == '1') || Validate::validateUrl($domain['documentroot'])) {
					$corrected_docroot = $domain['documentroot'];

					// Get domain's redirect code
					$code = Domain::getDomainRedirectCode($domain['id']);
					$modrew_red = '';
					if ($code != '') {
						$modrew_red = ' [R=' . $code . ';L,NE]';
					}

					$vhost_content .= $this->getLogfiles($domain);
					// redirect everything, not only root-directory, #541
					$vhost_content .= '  <IfModule mod_rewrite.c>' . "\n";
					$vhost_content .= '    RewriteEngine On' . "\n";
					if (!$ssl_vhost) {
						$vhost_content .= '    RewriteCond %{HTTPS} off' . "\n";
					}
					if ($domain['letsencrypt'] == '1') {
						$vhost_content .= '    RewriteCond %{REQUEST_URI} !^/\.well-known/acme-challenge' . "\n";
					}
					$vhost_content .= '    RewriteRule ^/(.*) ' . $corrected_docroot . '$1' . $modrew_red . "\n";
					$vhost_content .= '  </IfModule>' . "\n";
					$vhost_content .= '  <IfModule !mod_rewrite.c>' . "\n";
					$vhost_content .= '    Redirect ' . $code . ' / ' . $domain['documentroot_norewrite'] . "\n";
					$vhost_content .= '  </IfModule>' . "\n";
				} else {
					$vhost_content .= '  <IfModule !mod_rewrite.c>' . "\n";
					$vhost_content .= '  	RedirectMatch 500 ^/' . "\n";
					$vhost_content .= '  </IfModule>' . "\n";
					$vhost_content .= 'ErrorDocument 500 "misconfigured redirect url"' . "\n";
					$vhost_content .= '  <IfModule mod_rewrite.c>' . "\n";
					$vhost_content .= '    RewriteEngine On' . "\n";
					$vhost_content .= '    RewriteRule ^ - [R=500,L]' . "\n";
					$vhost_content .= '  </IfModule>' . "\n";
				}
			} elseif (Settings::Get('system.deactivateddocroot') != '') {
				$vhost_content .= $possible_deactivated_webroot;
			}
		} else {
			FileDir::mkDirWithCorrectOwnership($domain['customerroot'], $domain['documentroot'], $domain['guid'], $domain['guid'], true, true);
			$vhost_content .= $this->getWebroot($domain);
			if ($this->deactivated == false) {
				$vhost_content .= $this->composePhpOptions($domain, $ssl_vhost);
				$vhost_content .= $this->getStats($domain);
			}
			$vhost_content .= $this->getLogfiles($domain);

			if ($this->deactivated == false) {
				if ($domain['specialsettings'] != '' && ($ssl_vhost == false || ($ssl_vhost == true && $domain['include_specialsettings'] == 1))) {
					$vhost_content .= $this->processSpecialConfigTemplate($domain['specialsettings'], $domain, $domain['ip'], $domain['port'], $ssl_vhost) . "\n";
				}

				if ($domain['ssl_specialsettings'] != '' && $ssl_vhost == true) {
					$vhost_content .= $this->processSpecialConfigTemplate($domain['ssl_specialsettings'], $domain, $domain['ip'], $domain['port'], $ssl_vhost) . "\n";
				}

				if ($_vhost_content != '') {
					$vhost_content .= $_vhost_content;
				}

				if (Settings::Get('system.default_vhostconf') != '' && ($ssl_vhost == false || ($ssl_vhost == true && Settings::Get('system.include_default_vhostconf') == 1))) {
					$vhost_content .= $this->processSpecialConfigTemplate(Settings::Get('system.default_vhostconf'), $domain, $domain['ip'], $domain['port'], $ssl_vhost) . "\n";
				}

				if (Settings::Get('system.default_sslvhostconf') != '' && $ssl_vhost == true) {
					$vhost_content .= $this->processSpecialConfigTemplate(Settings::Get('system.default_sslvhostconf'), $domain, $domain['ip'], $domain['port'], $ssl_vhost) . "\n";
				}
			}
		}

		$vhost_content .= '</VirtualHost>' . "\n";

		return $vhost_content;
	}

	/**
	 * We collect all servernames and Aliases
	 */
	protected function getServerNames($domain)
	{
		$servernames_text = '  ServerName ' . $domain['domain'] . "\n";

		$server_alias = '';
		if ($domain['iswildcarddomain'] == '1') {
			$server_alias = '*.' . $domain['domain'];
		} elseif ($domain['wwwserveralias'] == '1') {
			$server_alias = 'www.' . $domain['domain'];
		}

		if (trim($server_alias) != '') {
			$servernames_text .= '  ServerAlias ' . $server_alias . "\n";
		}

		$alias_domains_stmt = Database::prepare("
			SELECT `domain`, `iswildcarddomain`, `wwwserveralias`
			FROM `" . TABLE_PANEL_DOMAINS . "`
			WHERE `aliasdomain`= :domainid
		");
		Database::pexecute($alias_domains_stmt, [
			'domainid' => $domain['id']
		]);

		while (($alias_domain = $alias_domains_stmt->fetch(PDO::FETCH_ASSOC)) !== false) {
			$server_alias = '  ServerAlias ' . $alias_domain['domain'];

			if ($alias_domain['iswildcarddomain'] == '1') {
				$server_alias .= ' *.' . $alias_domain['domain'];
			} else {
				if ($alias_domain['wwwserveralias'] == '1') {
					$server_alias .= ' www.' . $alias_domain['domain'];
				}
			}

			$servernames_text .= $server_alias . "\n";
		}

		switch (Settings::Get('system.webserver_serveradmin')) {
			case 'customer':
				$servernames_text .= '  ServerAdmin ' . $domain['email'] . "\n";
				break;
			case 'admin':
				$servernames_text .= '  ServerAdmin ' . $domain['admin_email'] . "\n";
				break;
			case 'global':
				$servernames_text .= '  ServerAdmin ' . Settings::Get('panel.adminmail') . "\n";
				break;
			case 'none':
			default:
				// empty
		}

		return $servernames_text;
	}

	/**
	 * Let's get the webroot
	 */
	protected function getWebroot($domain)
	{
		$webroot_text = '';
		$domain['customerroot'] = FileDir::makeCorrectDir($domain['customerroot']);
		$domain['documentroot'] = FileDir::makeCorrectDir($domain['documentroot']);

		if (($domain['deactivated'] == '1' || $domain['customer_deactivated'] == '1') && Settings::Get('system.deactivateddocroot') != '') {
			$webroot_text .= '  # Using docroot for deactivated users/domains...' . "\n";
			$webroot_text .= '  DocumentRoot "' . rtrim(FileDir::makeCorrectDir(Settings::Get('system.deactivateddocroot')), "/") . "\"\n";
			$webroot_text .= '  <Directory "' . FileDir::makeCorrectDir(Settings::Get('system.deactivateddocroot')) . '">' . "\n";
			// >=apache-2.4 enabled?
			if (Settings::Get('system.apache24') == '1') {
				$webroot_text .= '    Require all granted' . "\n";
				$webroot_text .= '    AllowOverride All' . "\n";
			} else {
				$webroot_text .= '    Order allow,deny' . "\n";
				$webroot_text .= '    allow from all' . "\n";
			}
			$webroot_text .= '  </Directory>' . "\n";
			$this->deactivated = true;
		} else {
			$webroot_text .= '  DocumentRoot "' . rtrim($domain['documentroot'], "/") . "\"\n";
			$this->deactivated = false;
		}

		return $webroot_text;
	}

	/**
	 * We put together the needed php options in the virtualhost entries
	 *
	 * @param array $domain
	 * @param bool $ssl_vhost
	 *
	 * @return string
	 */
	protected function composePhpOptions(&$domain, $ssl_vhost = false)
	{
		$php_options_text = '';

		if ($domain['phpenabled_customer'] == 1 && $domain['phpenabled_vhost'] == '1') {
			// This vHost has PHP enabled and we are using the regular mod_php
			$cmail = Customer::getCustomerDetail($domain['customerid'], 'email');
			$php_options_text .= '  php_admin_value sendmail_path "/usr/sbin/sendmail -t -f ' . $cmail . '"' . PHP_EOL;

			if ($domain['openbasedir'] == '1') {
				if ($domain['openbasedir_path'] == '1' || strstr($domain['documentroot'], ":") !== false) {
					$_phpappendopenbasedir = Domain::appendOpenBasedirPath($domain['customerroot'], true);
				} else if ($domain['openbasedir_path'] == '2' && strpos(dirname($domain['documentroot']) . '/', $domain['customerroot']) !== false) {
					$_phpappendopenbasedir = Domain::appendOpenBasedirPath(dirname($domain['documentroot']) . '/', true);
				} else {
					$_phpappendopenbasedir = Domain::appendOpenBasedirPath($domain['documentroot'], true);
				}

				$_custom_openbasedir = explode(':', Settings::Get('system.phpappendopenbasedir'));
				foreach ($_custom_openbasedir as $cobd) {
					$_phpappendopenbasedir .= Domain::appendOpenBasedirPath($cobd);
				}

				$php_options_text .= '  php_admin_value open_basedir "' . $_phpappendopenbasedir . '"' . "\n";
			}
		} else {
			$php_options_text .= '  # PHP is disabled for this vHost' . "\n";
			$php_options_text .= '  php_flag engine off' . "\n";
		}

		/**
		 * check for apache-itk-support, #1400
		 * why is this here? Because it only works with mod_php
		 */
		if (Settings::get('system.apacheitksupport') == 1) {
			$php_options_text .= '  <IfModule mpm_itk_module>' . "\n";
			$php_options_text .= '    AssignUserID ' . $domain['loginname'] . ' ' . $domain['loginname'] . "\n";
			$php_options_text .= '  </IfModule>' . "\n";
		}

		return $php_options_text;
	}

	/**
	 * Lets set the text part for the stats software
	 */
	protected function getStats($domain)
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

		$stats_text .= '  Alias /' . $statTool . ' "' . $statDocroot . '"' . "\n";
		// awstats special requirement for icons
		if ($statTool == 'awstats') {
			$stats_text .= '  Alias /awstats-icon "' . FileDir::makeCorrectDir(Settings::Get('system.awstats_icons')) . '"' . "\n";
		}

		return $stats_text;
	}

	/**
	 * Lets set the logfiles
	 */
	protected function getLogfiles($domain)
	{
		$logfiles_text = '';

		if ($domain['speciallogfile'] == '1') {
			if ($domain['parentdomainid'] == '0') {
				$speciallogfile = '-' . $domain['domain'];
			} else {
				$speciallogfile = '-' . $domain['parentdomain'];
			}
		} else {
			$speciallogfile = '';
		}

		if ($domain['writeerrorlog']) {
			// The normal access/error - logging is enabled
			$error_log = FileDir::makeCorrectFile(Settings::Get('system.logfiles_directory') . $domain['loginname'] . $speciallogfile . '-error.log');
			// Create the logfile if it does not exist (fixes #46)
			touch($error_log);
			chmod($error_log, 0640);
			chown($error_log, Settings::Get('system.httpuser'));
			chgrp($error_log, Settings::Get('system.httpgroup'));
			// set error log log-level
			$logfiles_text .= '  LogLevel ' . Settings::Get('system.errorlog_level') . "\n";
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
			$logfiles_text .= '  LogFormat ' . Settings::Get('system.logfiles_format') . ' ' . $logtype . "\n";
		}
		if (Settings::Get('system.logfiles_type') == '2' && Settings::Get('system.logfiles_format') == '') {
			$logtype = 'vhost_combined';
		}

		if (Settings::Get('system.logfiles_piped') == '1' && Settings::Get('system.logfiles_script') != '') {
			if ($domain['writeerrorlog']) {
				// replace for error_log
				$command = PhpHelper::replaceVariables(Settings::Get('system.logfiles_script'), [
					'LOGFILE' => $error_log,
					'DOMAIN' => $domain['domain'],
					'CUSTOMER' => $domain['loginname']
				]);
				$logfiles_text .= '  ErrorLog "|' . $command . "\"\n";
			} else {
				$logfiles_text .= '  ErrorLog "' . $error_log . '"' . "\n";
			}
			if ($domain['writeaccesslog']) {
				// replace for access_log
				$command = PhpHelper::replaceVariables(Settings::Get('system.logfiles_script'), [
					'LOGFILE' => $access_log,
					'DOMAIN' => $domain['domain'],
					'CUSTOMER' => $domain['loginname']
				]);
				$logfiles_text .= '  CustomLog "|' . $command . '" ' . $logtype . "\n";
			} else {
				$logfiles_text .= '  CustomLog "' . $access_log . '" ' . $logtype . "\n";
			}
		} else {
			$logfiles_text .= '  ErrorLog "' . $error_log . '"' . "\n";
			$logfiles_text .= '  CustomLog "' . $access_log . '" ' . $logtype . "\n";
		}

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
						$server_alias .= '*.' . $alias_domain['domain'];
					} elseif ($alias_domain['wwwserveralias'] == '1') {
						$server_alias .= 'www.' . $alias_domain['domain'];
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

	/**
	 * We compose the diroption entries for the paths
	 */
	public function createFileDirOptions()
	{
		$result_stmt = Database::query("
			SELECT `htac`.*, `c`.`guid`, `c`.`documentroot` AS `customerroot`
			FROM `" . TABLE_PANEL_HTACCESS . "` `htac`
			LEFT JOIN `" . TABLE_PANEL_CUSTOMERS . "` `c` USING (`customerid`)
			ORDER BY `htac`.`path`
		");
		$diroptions = [];

		while ($row_diroptions = $result_stmt->fetch(PDO::FETCH_ASSOC)) {
			if ($row_diroptions['customerid'] != 0 && isset($row_diroptions['customerroot']) && $row_diroptions['customerroot'] != '') {
				$diroptions[$row_diroptions['path']] = $row_diroptions;
				$diroptions[$row_diroptions['path']]['htpasswds'] = [];
			}
		}

		$result_stmt = Database::query("
			SELECT `htpw`.*, `c`.`guid`, `c`.`documentroot` AS `customerroot`
			FROM `" . TABLE_PANEL_HTPASSWDS . "` `htpw`
			LEFT JOIN `" . TABLE_PANEL_CUSTOMERS . "` `c` USING (`customerid`)
			ORDER BY `htpw`.`path`, `htpw`.`username`
		");

		while ($row_htpasswds = $result_stmt->fetch(PDO::FETCH_ASSOC)) {
			if ($row_htpasswds['customerid'] != 0 && isset($row_htpasswds['customerroot']) && $row_htpasswds['customerroot'] != '') {
				if (!isset($diroptions[$row_htpasswds['path']]) || !is_array($diroptions[$row_htpasswds['path']])) {
					$diroptions[$row_htpasswds['path']] = [];
				}

				$diroptions[$row_htpasswds['path']]['path'] = $row_htpasswds['path'];
				$diroptions[$row_htpasswds['path']]['guid'] = $row_htpasswds['guid'];
				$diroptions[$row_htpasswds['path']]['customerroot'] = $row_htpasswds['customerroot'];
				$diroptions[$row_htpasswds['path']]['customerid'] = $row_htpasswds['customerid'];
				$diroptions[$row_htpasswds['path']]['htpasswds'][] = $row_htpasswds;
			}
		}

		foreach ($diroptions as $row_diroptions) {
			$row_diroptions['path'] = FileDir::makeCorrectDir($row_diroptions['path']);
			FileDir::mkDirWithCorrectOwnership($row_diroptions['customerroot'], $row_diroptions['path'], $row_diroptions['guid'], $row_diroptions['guid']);
			$diroptions_filename = FileDir::makeCorrectFile(Settings::Get('system.apacheconf_diroptions') . '/40_froxlor_diroption_' . md5($row_diroptions['path']) . '.conf');

			if (!isset($this->diroptions_data[$diroptions_filename])) {
				$this->diroptions_data[$diroptions_filename] = '';
			}

			if (is_dir($row_diroptions['path'])) {
				$cperlenabled = Customer::customerHasPerlEnabled($row_diroptions['customerid']);

				$this->diroptions_data[$diroptions_filename] .= '<Directory "' . $row_diroptions['path'] . '">' . "\n";

				if (isset($row_diroptions['options_indexes']) && $row_diroptions['options_indexes'] == '1') {
					$this->diroptions_data[$diroptions_filename] .= '  Options +Indexes';

					// add perl options if enabled
					if ($cperlenabled && isset($row_diroptions['options_cgi']) && $row_diroptions['options_cgi'] == '1') {
						$this->diroptions_data[$diroptions_filename] .= ' +ExecCGI -MultiViews +SymLinksIfOwnerMatch +FollowSymLinks' . "\n";
					} else {
						$this->diroptions_data[$diroptions_filename] .= "\n";
					}
					FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_INFO, 'Setting Options +Indexes for ' . $row_diroptions['path']);
				}

				if (isset($row_diroptions['options_indexes']) && $row_diroptions['options_indexes'] == '0') {
					$this->diroptions_data[$diroptions_filename] .= '  Options -Indexes';

					// add perl options if enabled
					if ($cperlenabled && isset($row_diroptions['options_cgi']) && $row_diroptions['options_cgi'] == '1') {
						$this->diroptions_data[$diroptions_filename] .= ' +ExecCGI -MultiViews +SymLinksIfOwnerMatch +FollowSymLinks' . "\n";
					} else {
						$this->diroptions_data[$diroptions_filename] .= "\n";
					}
					FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_INFO, 'Setting Options -Indexes for ' . $row_diroptions['path']);
				}

				$statusCodes = [
					'404',
					'403',
					'500'
				];
				foreach ($statusCodes as $statusCode) {
					if (isset($row_diroptions['error' . $statusCode . 'path']) && $row_diroptions['error' . $statusCode . 'path'] != '') {
						$defhandler = $row_diroptions['error' . $statusCode . 'path'];
						if (!Validate::validateUrl($defhandler)) {
							if (substr($defhandler, 0, 1) != '"' && substr($defhandler, -1, 1) != '"') {
								$defhandler = '"' . FileDir::makeCorrectFile($defhandler) . '"';
							}
						}
						$this->diroptions_data[$diroptions_filename] .= '  ErrorDocument ' . $statusCode . ' ' . $defhandler . "\n";
					}
				}

				if ($cperlenabled && isset($row_diroptions['options_cgi']) && $row_diroptions['options_cgi'] == '1') {
					$this->diroptions_data[$diroptions_filename] .= '  AllowOverride None' . "\n";
					$this->diroptions_data[$diroptions_filename] .= '  AddHandler cgi-script .cgi .pl' . "\n";
					// >=apache-2.4 enabled?
					if (Settings::Get('system.apache24') == '1') {
						$mypath_dir = new Directory($row_diroptions['path']);
						// only create the' require all granted' if there is no active directory-protection
						// for this path, as this would be the first require and therefore grant all access
						if ($mypath_dir->isUserProtected() == false) {
							$this->diroptions_data[$diroptions_filename] .= '  Require all granted' . "\n";
							// $this->diroptions_data[$diroptions_filename] .= ' AllowOverride All' . "\n";
						}
					} else {
						$this->diroptions_data[$diroptions_filename] .= '  Order allow,deny' . "\n";
						$this->diroptions_data[$diroptions_filename] .= '  Allow from all' . "\n";
					}
					FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_INFO, 'Enabling perl execution for ' . $row_diroptions['path']);

					// check for suexec-workaround, #319
					if ((int)Settings::Get('perl.suexecworkaround') == 1) {
						// symlink this directory to suexec-safe-path
						$loginname = Customer::getCustomerDetail($row_diroptions['customerid'], 'loginname');
						$suexecpath = FileDir::makeCorrectDir(Settings::Get('perl.suexecpath') . '/' . $loginname . '/' . md5($row_diroptions['path']) . '/');

						if (!file_exists($suexecpath)) {
							FileDir::safe_exec('mkdir -p ' . escapeshellarg($suexecpath));
							FileDir::safe_exec('chown -R ' . escapeshellarg($row_diroptions['guid']) . ':' . escapeshellarg($row_diroptions['guid']) . ' ' . escapeshellarg($suexecpath));
						}

						// symlink to {$givenpath}/cgi-bin
						// NOTE: symlinks are FILES, so do not append a / here
						$perlsymlink = FileDir::makeCorrectFile($row_diroptions['path'] . '/cgi-bin');
						if (!file_exists($perlsymlink)) {
							FileDir::safe_exec('ln -s ' . escapeshellarg($suexecpath) . ' ' . escapeshellarg($perlsymlink));
						}
						FileDir::safe_exec('chown -h ' . escapeshellarg($row_diroptions['guid']) . ':' . escapeshellarg($row_diroptions['guid']) . ' ' . escapeshellarg($perlsymlink));
					}
				} else {
					// if no perl-execution is enabled but the workaround is,
					// we have to remove the symlink and folder in suexecpath
					if ((int)Settings::Get('perl.suexecworkaround') == 1) {
						$loginname = Customer::getCustomerDetail($row_diroptions['customerid'], 'loginname');
						$suexecpath = FileDir::makeCorrectDir(Settings::Get('perl.suexecpath') . '/' . $loginname . '/' . md5($row_diroptions['path']) . '/');
						$perlsymlink = FileDir::makeCorrectFile($row_diroptions['path'] . '/cgi-bin');

						// remove symlink
						if (file_exists($perlsymlink)) {
							FileDir::safe_exec('rm -f ' . escapeshellarg($perlsymlink));
						}
						// remove folder in suexec-path
						if (file_exists($suexecpath)) {
							FileDir::safe_exec('rm -rf ' . escapeshellarg($suexecpath));
						}
					}
				}

				if (count($row_diroptions['htpasswds']) > 0) {
					$htpasswd_filename = FileDir::makeCorrectFile(Settings::Get('system.apacheconf_htpasswddir') . '/' . $row_diroptions['customerid'] . '-' . md5($row_diroptions['path']) . '.htpasswd');

					if (!isset($this->htpasswds_data[$htpasswd_filename])) {
						$this->htpasswds_data[$htpasswd_filename] = '';
					}

					foreach ($row_diroptions['htpasswds'] as $row_htpasswd) {
						$this->htpasswds_data[$htpasswd_filename] .= $row_htpasswd['username'] . ':' . $row_htpasswd['password'] . "\n";
					}

					$this->diroptions_data[$diroptions_filename] .= '  AuthType Basic' . "\n";
					$this->diroptions_data[$diroptions_filename] .= '  AuthName "' . $row_htpasswd['authname'] . '"' . "\n";
					$this->diroptions_data[$diroptions_filename] .= '  AuthUserFile ' . $htpasswd_filename . "\n";
					$this->diroptions_data[$diroptions_filename] .= '  require valid-user' . "\n";
				}

				$this->diroptions_data[$diroptions_filename] .= '</Directory>' . "\n";
			}
		}
	}

	/**
	 * We write the configs
	 */
	public function writeConfigs()
	{
		// Write diroptions
		FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_INFO, "apache::writeConfigs: rebuilding " . Settings::Get('system.apacheconf_diroptions'));

		if (count($this->diroptions_data) > 0) {
			$optsDir = new Directory(Settings::Get('system.apacheconf_diroptions'));
			if (!$optsDir->isConfigDir()) {
				// Save one big file
				$diroptions_file = '';

				foreach ($this->diroptions_data as $diroptions_filename => $diroptions_content) {
					$diroptions_file .= $diroptions_content . "\n\n";
				}

				$diroptions_filename = Settings::Get('system.apacheconf_diroptions');

				// Apply header
				$diroptions_file = '# ' . basename($diroptions_filename) . "\n" . '# Created ' . date('d.m.Y H:i') . "\n" . '# Do NOT manually edit this file, all changes will be deleted after the next domain change at the panel.' . "\n" . "\n" . $diroptions_file;
				$diroptions_file_handler = fopen($diroptions_filename, 'w');
				fwrite($diroptions_file_handler, $diroptions_file);
				fclose($diroptions_file_handler);
			} else {
				if (!file_exists(Settings::Get('system.apacheconf_diroptions'))) {
					FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_NOTICE, 'apache::writeConfigs: mkdir ' . escapeshellarg(FileDir::makeCorrectDir(Settings::Get('system.apacheconf_diroptions'))));
					FileDir::safe_exec('mkdir ' . escapeshellarg(FileDir::makeCorrectDir(Settings::Get('system.apacheconf_diroptions'))));
				}

				// Write a single file for every diroption
				foreach ($this->diroptions_data as $diroptions_filename => $diroptions_file) {
					$this->known_diroptionsfilenames[] = basename($diroptions_filename);

					// Apply header
					$diroptions_file = '# ' . basename($diroptions_filename) . "\n" . '# Created ' . date('d.m.Y H:i') . "\n" . '# Do NOT manually edit this file, all changes will be deleted after the next domain change at the panel.' . "\n" . "\n" . $diroptions_file;
					$diroptions_file_handler = fopen($diroptions_filename, 'w');
					fwrite($diroptions_file_handler, $diroptions_file);
					fclose($diroptions_file_handler);
				}
			}
		}

		// Write htpasswds
		FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_INFO, "apache::writeConfigs: rebuilding " . Settings::Get('system.apacheconf_htpasswddir'));

		if (count($this->htpasswds_data) > 0) {
			if (!file_exists(Settings::Get('system.apacheconf_htpasswddir'))) {
				$umask = umask();
				umask(0000);
				mkdir(Settings::Get('system.apacheconf_htpasswddir'), 0751);
				umask($umask);
			}

			$htpasswdDir = new Directory(Settings::Get('system.apacheconf_htpasswddir'));
			if ($htpasswdDir->isConfigDir(true)) {
				foreach ($this->htpasswds_data as $htpasswd_filename => $htpasswd_file) {
					$this->known_htpasswdsfilenames[] = basename($htpasswd_filename);
					$htpasswd_file_handler = fopen($htpasswd_filename, 'w');
					fwrite($htpasswd_file_handler, $htpasswd_file);
					fclose($htpasswd_file_handler);
				}
			} else {
				FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_WARNING, 'WARNING!!! ' . Settings::Get('system.apacheconf_htpasswddir') . ' is not a directory. htpasswd directory protection is disabled!!!');
			}
		}

		// Write virtualhosts
		FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_INFO, "apache::writeConfigs: rebuilding " . Settings::Get('system.apacheconf_vhost'));

		if (count($this->virtualhosts_data) > 0) {
			$vhostDir = new Directory(Settings::Get('system.apacheconf_vhost'));
			if (!$vhostDir->isConfigDir()) {
				// Save one big file
				$vhosts_file = '';

				// sort by filename so the order is:
				// 1. subdomains x-29
				// 2. subdomains as main-domains 30
				// 3. main-domains 35
				// #437
				ksort($this->virtualhosts_data);

				foreach ($this->virtualhosts_data as $vhosts_filename => $vhost_content) {
					$vhosts_file .= $vhost_content . "\n\n";
				}

				// Include diroptions file in case it exists
				if (file_exists(Settings::Get('system.apacheconf_diroptions'))) {
					$vhosts_file .= "\n" . 'Include ' . Settings::Get('system.apacheconf_diroptions') . "\n\n";
				}

				$vhosts_filename = Settings::Get('system.apacheconf_vhost');

				// Apply header
				$vhosts_file = '# ' . basename($vhosts_filename) . "\n" . '# Created ' . date('d.m.Y H:i') . "\n" . '# Do NOT manually edit this file, all changes will be deleted after the next domain change at the panel.' . "\n" . "\n" . $vhosts_file;
				$vhosts_file_handler = fopen($vhosts_filename, 'w');
				fwrite($vhosts_file_handler, $vhosts_file);
				fclose($vhosts_file_handler);
			} else {
				if (!file_exists(Settings::Get('system.apacheconf_vhost'))) {
					FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_NOTICE, 'apache::writeConfigs: mkdir ' . escapeshellarg(FileDir::makeCorrectDir(Settings::Get('system.apacheconf_vhost'))));
					FileDir::safe_exec('mkdir ' . escapeshellarg(FileDir::makeCorrectDir(Settings::Get('system.apacheconf_vhost'))));
				}

				// Write a single file for every vhost
				foreach ($this->virtualhosts_data as $vhosts_filename => $vhosts_file) {
					// Apply header
					$vhosts_file = '# ' . basename($vhosts_filename) . "\n" . '# Created ' . date('d.m.Y H:i') . "\n" . '# Do NOT manually edit this file, all changes will be deleted after the next domain change at the panel.' . "\n" . "\n" . $vhosts_file;
					$vhosts_file_handler = fopen($vhosts_filename, 'w');
					fwrite($vhosts_file_handler, $vhosts_file);
					fclose($vhosts_file_handler);
				}
			}
		}
	}
}
