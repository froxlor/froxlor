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

namespace Froxlor\System;

use Froxlor\Database\Database;
use Froxlor\Froxlor;
use Froxlor\Settings;
use Froxlor\Validate\Validate;

class Crypt
{

	/**
	 * Generates a random password
	 *
	 * @param int $length optional, will be read from settings if not given
	 * @param bool $isSalt optional, default false, do not include special characters
	 *
	 * @return string
	 */
	public static function generatePassword(int $length = 0, bool $isSalt = false): string
	{
		$alpha_lower = 'abcdefghijklmnopqrstuvwxyz';
		$alpha_upper = strtoupper($alpha_lower);
		$numeric = '0123456789';
		$special = Settings::Get('panel.password_special_char');
		if (empty($length)) {
			$length = Settings::Get('panel.password_min_length') > 3 ? Settings::Get('panel.password_min_length') : 10;
		}

		$pw = self::specialShuffle($alpha_lower);
		$n = floor(($length) / 4);

		if (Settings::Get('panel.password_alpha_upper')) {
			$pw .= mb_substr(self::specialShuffle($alpha_upper), 0, $n);
		}

		if (Settings::Get('panel.password_numeric')) {
			$pw .= mb_substr(self::specialShuffle($numeric), 0, $n);
		}

		if (Settings::Get('panel.password_special_char_required') && !$isSalt) {
			$pw .= mb_substr(self::specialShuffle($special), 0, $n);
		}

		$pw = mb_substr($pw, -$length);

		return self::specialShuffle($pw);
	}

	/**
	 * multibyte-character safe shuffle function
	 *
	 * @param string $str
	 *
	 * @return string
	 */
	private static function specialShuffle(string $str): string
	{
		$len = mb_strlen($str);
		$sploded = [];
		while ($len-- > 0) {
			$sploded[] = mb_substr($str, $len, 1);
		}
		shuffle($sploded);
		return join('', $sploded);
	}

	/**
	 * return an array of available hashes
	 *
	 * @return array
	 */
	public static function getAvailablePasswordHashes(): array
	{
		// get available pwd-hases
		$available_pwdhashes = [
			PASSWORD_DEFAULT => lng('serversettings.systemdefault')
		];
		if (defined('PASSWORD_BCRYPT')) {
			$available_pwdhashes[PASSWORD_BCRYPT] = 'Bcrypt/Blowfish' . (PASSWORD_DEFAULT == PASSWORD_BCRYPT ? ' (' . lng('serversettings.systemdefault') . ')' : '');
		}
		if (defined('PASSWORD_ARGON2I')) {
			$available_pwdhashes[PASSWORD_ARGON2I] = 'Argon2i' . (PASSWORD_DEFAULT == PASSWORD_ARGON2I ? ' (' . lng('serversettings.systemdefault') . ')' : '');
		}
		if (defined('PASSWORD_ARGON2ID')) {
			$available_pwdhashes[PASSWORD_ARGON2ID] = 'Argon2id' . (PASSWORD_DEFAULT == PASSWORD_ARGON2ID ? ' (' . lng('serversettings.systemdefault') . ')' : '');
		}

		return $available_pwdhashes;
	}

	/**
	 * Function validatePassword
	 *
	 * if password-min-length is set in settings
	 * we check against the length, if not matched
	 * an error message will be output and 'exit' is called
	 *
	 * @param string $password the password to validate
	 * @param bool $json_response
	 *
	 * @return string either the password or an errormessage+exit
	 */
	public static function validatePassword(string $password, bool $json_response = false): string
	{
		if (Settings::Get('panel.password_min_length') > 0) {
			$password = Validate::validate($password, Settings::Get('panel.password_min_length'),
				'/^.{' . (int)Settings::Get('panel.password_min_length') . ',}$/D', 'notrequiredpasswordlength', [],
				$json_response);
		}

		if (Settings::Get('panel.password_regex') != '') {
			$password = Validate::validate($password, Settings::Get('panel.password_regex'),
				Settings::Get('panel.password_regex'), 'notrequiredpasswordcomplexity', [], $json_response);
		} else {
			if (Settings::Get('panel.password_alpha_lower')) {
				$password = Validate::validate($password, '/.*[a-z]+.*/', '/.*[a-z]+.*/',
					'notrequiredpasswordcomplexity', [], $json_response);
			}
			if (Settings::Get('panel.password_alpha_upper')) {
				$password = Validate::validate($password, '/.*[A-Z]+.*/', '/.*[A-Z]+.*/',
					'notrequiredpasswordcomplexity', [], $json_response);
			}
			if (Settings::Get('panel.password_numeric')) {
				$password = Validate::validate($password, '/.*[0-9]+.*/', '/.*[0-9]+.*/',
					'notrequiredpasswordcomplexity', [], $json_response);
			}
			if (Settings::Get('panel.password_special_char_required')) {
				$password = Validate::validate($password,
					'/.*[' . preg_quote(Settings::Get('panel.password_special_char'), '/') . ']+.*/',
					'/.*[' . preg_quote(Settings::Get('panel.password_special_char'), '/') . ']+.*/',
					'notrequiredpasswordcomplexity', [], $json_response);
			}
		}

		return $password;
	}

	/**
	 * Function validatePasswordLogin
	 *
	 * compare user password-hash with given user-password
	 * and check if they are the same
	 * additionally it updates the hash if the system settings changed
	 * or if the very old md5() sum is used
	 *
	 * @param array $userinfo user-data from table
	 * @param string $password the password to validate
	 * @param string $table either panel_customers or panel_admins
	 * @param string $uid user-id-field in $table
	 *
	 * @return bool
	 * @throws \Exception
	 */
	public static function validatePasswordLogin(
		array $userinfo,
		string $password,
		string $table = 'panel_customers',
		string $uid = 'customerid'
	): bool {
		$algo = Settings::Get('system.passwordcryptfunc') !== null ? Settings::Get('system.passwordcryptfunc') : PASSWORD_DEFAULT;
		if (is_numeric($algo)) {
			// old setting format
			$algo = PASSWORD_DEFAULT;
			Settings::Set('system.passwordcryptfunc', $algo);
		}
		$pwd_hash = $userinfo['password'];

		$update_hash = false;
		$pwd_check = "";
		// check for good'ole md5
		if (strlen($pwd_hash) == 32 && ctype_xdigit($pwd_hash)) {
			$pwd_check = md5($password);
			$update_hash = true;
		}

		if ($pwd_hash === $pwd_check || password_verify($password, $pwd_hash)) {
			// check for update of hash (only if our database is ready to handle the bigger string)
			$is_ready = Froxlor::versionCompare2("0.9.33", Froxlor::getVersion()) <= 0;
			if ((password_needs_rehash($pwd_hash, $algo) || $update_hash) && $is_ready) {
				$upd_stmt = Database::prepare("
					UPDATE " . $table . " SET `password` = :newpasswd WHERE `" . $uid . "` = :uid
				");
				$params = [
					'newpasswd' => self::makeCryptPassword($password),
					'uid' => $userinfo[$uid]
				];
				Database::pexecute($upd_stmt, $params);
			}
			return true;
		}
		return false;
	}

	/**
	 * Make encrypted password from clear text password
	 *
	 * @param string $password Password to be encrypted
	 * @param bool $htpasswd optional whether to generate a bcrypt password for directory protection
	 * @param bool $ftpd optional generates sha256 password strings for proftpd/pureftpd
	 *
	 * @return string encrypted password
	 */
	public static function makeCryptPassword(string $password, bool $htpasswd = false, bool $ftpd = false): string
	{
		if ($htpasswd || $ftpd) {
			if ($ftpd) {
				// sha256 compatible for proftpd and pure-ftpd
				return crypt($password, '$5$' . self::generatePassword(16, true) . '$');
			}
			// bcrypt hash for dir-protection
			return password_hash($password, PASSWORD_BCRYPT);
		}
		// crypt using the specified crypt-algorithm or system default
		$algo = Settings::Get('system.passwordcryptfunc') !== null ? Settings::Get('system.passwordcryptfunc') : PASSWORD_DEFAULT;
		return password_hash($password, $algo);
	}

	/**
	 * creates a self-signed ECC-certificate for the froxlor-vhost
	 * and sets the content to the corresponding files set in the
	 * settings for ssl-certificate-file and ssl-certificate-key
	 *
	 * @return void
	 */
	public static function createSelfSignedCertificate()
	{
		// validate that we have file names in the settings
		$certFile = Settings::Get('system.ssl_cert_file');
		$keyFile = Settings::Get('system.ssl_key_file');
		if (empty($certFile)) {
			$certFile = '/etc/ssl/froxlor_selfsigned.pem';
			Settings::Set('system.ssl_cert_file', $certFile);
		}
		if (empty($keyFile)) {
			$keyFile = '/etc/ssl/froxlor_selfsigned.key';
			Settings::Set('system.ssl_key_file', $keyFile);
		}

		// certificate info
		$dn = [
			"countryName" => "DE",
			"stateOrProvinceName" => "Hessen",
			"localityName" => "Frankfurt am Main",
			"organizationName" => "froxlor",
			"organizationalUnitName" => "froxlor Server Management Panel",
			"commonName" => Settings::Get('system.hostname'),
			"emailAddress" => Settings::Get('panel.adminmail')
		];
		// create private key
		$privkey = openssl_pkey_new([
			"private_key_type" => OPENSSL_KEYTYPE_EC,
			"curve_name" => 'prime256v1',
		]);
		// create signing request
		$csr = openssl_csr_new($dn, $privkey, array('digest_alg' => 'sha384'));
		// sign csr
		$x509 = openssl_csr_sign($csr, null, $privkey, 365, array('digest_alg' => 'sha384'));
		// export to files
		openssl_x509_export_to_file($x509, $certFile);
		openssl_pkey_export_to_file($privkey, $keyFile);
	}
}
