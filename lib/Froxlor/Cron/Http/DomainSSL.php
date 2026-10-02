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

use Froxlor\Database\Database;
use Froxlor\FileDir;
use Froxlor\FroxlorLogger;
use Froxlor\Settings;

class DomainSSL
{

	/**
	 * read domain-related (or if empty, parentdomain-related) ssl-certificates from the database
	 * and (if not empty) set the corresponding array-indices (ssl_cert_file, ssl_key_file,
	 * ssl_ca_file and ssl_cert_chainfile).
	 * Hence the parameter as reference.
	 *
	 * @param array $domain
	 *            domain-array as reference so we can set the corresponding array-indices
	 *
	 * @return null
	 * @throws \Exception
	 */
	public function setDomainSSLFilesArray(?array &$domain = null)
	{
		// check if the domain itself has a certificate defined
		$dom_certs_stmt = Database::prepare("
			SELECT s.*, d.domain
			FROM `" . TABLE_PANEL_DOMAIN_SSL_SETTINGS . "` s
			LEFT JOIN `" . TABLE_PANEL_DOMAINS . "` d ON d.id = s.domainid
			WHERE s.`domainid` = :domid
		");
		$dom_certs = Database::pexecute_first($dom_certs_stmt, [
			'domid' => $domain['id']
		]);

		$parent_certificate = false;
		if (!is_array($dom_certs) || !isset($dom_certs['ssl_cert_file']) || $dom_certs['ssl_cert_file'] == '') {
			// maybe its parent?
			if (isset($domain['parentdomainid']) && $domain['parentdomainid'] != 0) {
				$dom_certs = Database::pexecute_first($dom_certs_stmt, [
					'domid' => $domain['parentdomainid']
				]);
				$parent_certificate = true;
			}
		}

		// check if it's an array and if the most important field is set
		if (is_array($dom_certs) && isset($dom_certs['ssl_cert_file']) && $dom_certs['ssl_cert_file'] != '') {
			// get destination path
			$sslcertpath = FileDir::makeCorrectDir(Settings::Get('system.customer_ssl_path'));
			// create path if it does not exist
			if (!file_exists($sslcertpath)) {
				FileDir::safe_exec('mkdir -p ' . escapeshellarg($sslcertpath));
			}
			// make correct files for the certificates
			$ssl_files = [
				'ssl_cert_file' => FileDir::makeCorrectFile($sslcertpath . '/' . ($parent_certificate ? $dom_certs['domain'] : $domain['domain']) . '.crt'),
				'ssl_key_file' => FileDir::makeCorrectFile($sslcertpath . '/' . ($parent_certificate ? $dom_certs['domain'] : $domain['domain']) . '.key')
			];

			if (!$this->validateCertificate($dom_certs)) {
				FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_ERR, 'Given SSL private key for ' . $domain['domain'] . ' does not seem to match the certificate. Cannot create ssl-directives');
				return;
			}

			// initialize optional files
			$ssl_files['ssl_ca_file'] = '';
			$ssl_files['ssl_cert_chainfile'] = '';
			// set them if they are != empty
			if ($dom_certs['ssl_ca_file'] != '') {
				$ssl_files['ssl_ca_file'] = FileDir::makeCorrectFile($sslcertpath . '/' . ($parent_certificate ? $dom_certs['domain'] : $domain['domain']) . '_CA.pem');
			}
			if ($dom_certs['ssl_cert_chainfile'] != '') {
				if (Settings::Get('system.webserver') == 'nginx') {
					// put ca.crt in my.crt, as nginx does not support a separate chain file.
					$dom_certs['ssl_cert_file'] = trim($dom_certs['ssl_cert_file']) . "\n" . trim($dom_certs['ssl_cert_chainfile']) . "\n";
				} else {
					$ssl_files['ssl_cert_chainfile'] = FileDir::makeCorrectFile($sslcertpath . '/' . ($parent_certificate ? $dom_certs['domain'] : $domain['domain']) . '_chain.pem');
				}
			}
			// will only be generated to be used externally, froxlor does not need this
			if ($dom_certs['ssl_fullchain_file'] != '') {
				$ssl_files['ssl_fullchain_file'] = FileDir::makeCorrectFile($sslcertpath . '/' . ($parent_certificate ? $dom_certs['domain'] : $domain['domain']) . '_fullchain.pem');
			}
			// create them on the filesystem
			foreach ($ssl_files as $type => $filename) {
				if ($filename != '') {
					touch($filename);
					$_fh = fopen($filename, 'w');
					fwrite($_fh, $dom_certs[$type]);
					fclose($_fh);
					if ($type == 'ssl_key_file') {
						chmod($filename, 0600);
					} else {
						chmod($filename, 0644);
					}
				}
			}
			// override corresponding array values
			$domain['ssl_cert_file'] = $ssl_files['ssl_cert_file'];
			$domain['ssl_key_file'] = $ssl_files['ssl_key_file'];
			$domain['ssl_ca_file'] = $ssl_files['ssl_ca_file'];
			$domain['ssl_cert_chainfile'] = $ssl_files['ssl_cert_chainfile'];
		}

		return;
	}

	private function validateCertificate($dom_certs = []): bool
	{
		return openssl_x509_check_private_key($dom_certs['ssl_cert_file'], $dom_certs['ssl_key_file']);
	}
}
