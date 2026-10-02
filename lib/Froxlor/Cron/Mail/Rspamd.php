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

namespace Froxlor\Cron\Mail;

use Exception;
use Froxlor\Database\Database;
use Froxlor\FileDir;
use Froxlor\FroxlorLogger;
use Froxlor\Settings;

class Rspamd
{
	const DEFAULT_MARK_LVL = 7.0;
	const DEFAULT_REJECT_LVL = 14.0;

	private string $frx_settings_file = "";

	protected FroxlorLogger $logger;

	public function __construct(FroxlorLogger $logger)
	{
		$this->logger = $logger;
	}

	/**
	 * @throws Exception
	 */
	public function writeConfigs()
	{
		// tell the world what we are doing
		$this->logger->logAction(FroxlorLogger::CRON_ACTION, LOG_INFO, 'Task9 started - Rebuilding antispam configuration');

		// get all email addresses
		$antispam_stmt = Database::prepare("
			SELECT email, spam_tag_level, rewrite_subject, spam_kill_level, bypass_spam, policy_greylist, iscatchall
			FROM `" . TABLE_MAIL_VIRTUAL . "`
			ORDER BY email
		");
		Database::pexecute($antispam_stmt);

		$this->frx_settings_file = "#\n# Automatically generated file by froxlor. DO NOT EDIT manually as it will be overwritten!\n# Generated: " . date('d.m.Y H:i') . "\n#\n\n";
		while ($email = $antispam_stmt->fetch(\PDO::FETCH_ASSOC)) {
			$this->generateEmailAddrConfig($email);
		}

		$antispam_cfg_file = FileDir::makeCorrectFile(Settings::Get('antispam.config_file'));
		file_put_contents($antispam_cfg_file, $this->frx_settings_file);
		$this->logger->logAction(FroxlorLogger::CRON_ACTION, LOG_INFO, $antispam_cfg_file . ' written');
		$this->writeDkimConfigs();
		$this->reloadDaemon();
		$this->logger->logAction(FroxlorLogger::CRON_ACTION, LOG_INFO, 'Task9 finished');
	}

	/**
	 * # local.d/dkim_signing.conf
	 * try_fallback = true;
	 * path = "/var/lib/rspamd/dkim/$domain.$selector.key";
	 * selector_map = "/etc/rspamd/dkim_selectors.map";
	 *
	 * @return void
	 * @throws Exception
	 */
	public function writeDkimConfigs()
	{
		$this->logger->logAction(FroxlorLogger::CRON_ACTION, LOG_INFO, 'Writing DKIM key-pairs');

		$dkim_selector_map = "";
		$result_domains_stmt = Database::query("
				SELECT `id`, `domain`, `dkim`, `dkim_id`, `dkim_pubkey`, `dkim_privkey`
				FROM `" . TABLE_PANEL_DOMAINS . "`
				WHERE `dkim` = '1'
				ORDER BY `id` ASC
			");

		while ($domain = $result_domains_stmt->fetch(\PDO::FETCH_ASSOC)) {

			if ($domain['dkim_privkey'] == '' || $domain['dkim_pubkey'] == '') {
				$max_dkim_id_stmt = Database::query("SELECT MAX(`dkim_id`) as `max_dkim_id` FROM `" . TABLE_PANEL_DOMAINS . "`");
				$max_dkim_id = $max_dkim_id_stmt->fetch(\PDO::FETCH_ASSOC);
				$domain['dkim_id'] = (int)$max_dkim_id['max_dkim_id'] + 1;

				$privkey_filename = FileDir::makeCorrectFile('/var/lib/rspamd/dkim/' . $domain['domain'] . '.dkim' . $domain['dkim_id'] . '.key');
				$pubkey_filename = FileDir::makeCorrectFile('/var/lib/rspamd/dkim/' . $domain['domain'] . '.dkim' . $domain['dkim_id'] . '.txt');

				$this->logger->logAction(FroxlorLogger::CRON_ACTION, LOG_INFO, 'Generating DKIM keys for "' . $domain['domain'] . '"');
				$rsret = [];
				FileDir::safe_exec(
					'rspamadm dkim_keygen -d ' . escapeshellarg($domain['domain']) . ' -k ' . $privkey_filename . ' -s dkim' . $domain['dkim_id'] . ' -b ' . Settings::Get('antispam.dkim_keylength') . ' -o plain > ' . escapeshellarg($pubkey_filename),
					$rsret,
					['>']
				);
				if (!file_exists($privkey_filename) || !file_exists($pubkey_filename)) {
					$this->logger->logAction(FroxlorLogger::CRON_ACTION, LOG_ERR, 'DKIM Keypair for domain "' . $domain['domain'] . '" was not generated successfully.');
					continue;
				}
				$domain['dkim_privkey'] = file_get_contents($privkey_filename);
				FileDir::safe_exec("chmod 0640 " . escapeshellarg($privkey_filename));
				FileDir::safe_exec("chown _rspamd:_rspamd " . escapeshellarg($privkey_filename));
				$domain['dkim_pubkey'] = file_get_contents($pubkey_filename);
				FileDir::safe_exec("chmod 0664 " . escapeshellarg($pubkey_filename));
				FileDir::safe_exec("chown _rspamd:_rspamd " . escapeshellarg($pubkey_filename));
				$upd_stmt = Database::prepare("
						UPDATE `" . TABLE_PANEL_DOMAINS . "` SET
						`dkim_id` = :dkimid,
						`dkim_privkey` = :privkey,
						`dkim_pubkey` = :pubkey
						WHERE `id` = :id
					");
				$upd_data = [
					'dkimid' => $domain['dkim_id'],
					'privkey' => $domain['dkim_privkey'],
					'pubkey' => $domain['dkim_pubkey'],
					'id' => $domain['id']
				];
				Database::pexecute($upd_stmt, $upd_data);
			} else {
				$privkey_filename = FileDir::makeCorrectFile('/var/lib/rspamd/dkim/' . $domain['domain'] . '.dkim' . $domain['dkim_id'] . '.key');
				$pubkey_filename = FileDir::makeCorrectFile('/var/lib/rspamd/dkim/' . $domain['domain'] . '.dkim' . $domain['dkim_id'] . '.txt');
			}

			if (!file_exists($privkey_filename) && $domain['dkim_privkey'] != '') {
				file_put_contents($privkey_filename, $domain['dkim_privkey']);
				FileDir::safe_exec("chmod 0640 " . escapeshellarg($privkey_filename));
				FileDir::safe_exec("chown _rspamd:_rspamd " . escapeshellarg($privkey_filename));
			}

			if (!file_exists($pubkey_filename) && $domain['dkim_pubkey'] != '') {
				file_put_contents($pubkey_filename, $domain['dkim_pubkey']);
				FileDir::safe_exec("chmod 0644 " . escapeshellarg($pubkey_filename));
				FileDir::safe_exec("chown _rspamd:_rspamd " . escapeshellarg($pubkey_filename));
			}

			$dkim_selector_map .= $domain['domain'] . " dkim" . $domain['dkim_id'] . "\n";
		}

		$dkim_selector_file = FileDir::makeCorrectFile('/etc/rspamd/dkim_selectors.map');
		file_put_contents($dkim_selector_file, $dkim_selector_map);
	}

	private function generateEmailAddrConfig(array $email): void
	{
		$this->logger->logAction(FroxlorLogger::CRON_ACTION, LOG_DEBUG, 'Generating antispam config for ' . $email['email']);

		$email['spam_tag_level'] = floatval($email['spam_tag_level']);
		$email['spam_kill_level'] = $email['spam_kill_level'] == -1 ? "null" : floatval($email['spam_kill_level']);
		$email_id = md5($email['email']);

		$this->frx_settings_file .= '# Email: ' . $email['email'] . "\n";
		foreach (['rcpt', 'from'] as $type) {
			$this->frx_settings_file .= 'frx_' . $email_id . '_' . $type . ' {' . "\n";
			$this->frx_settings_file .= '	id = "frx_' . $email_id . '_' . $type . '";' . "\n";
			if ($email['iscatchall']) {
				$this->frx_settings_file .= '	priority = low;' . "\n";
				$this->frx_settings_file .= '	' . $type . ' = "' . substr($email['email'], strpos($email['email'], '@')) . '";' . "\n";
			} else {
				$this->frx_settings_file .= '	priority = medium;' . "\n";
				$this->frx_settings_file .= '	' . $type . ' = "' . $email['email'] . '";' . "\n";
			}
			if ((int)$email['bypass_spam'] == 1) {
				$this->frx_settings_file .= '	want_spam = yes;' . "\n";
			} else {
				$this->frx_settings_file .= '	apply {' . "\n";
				$this->frx_settings_file .= '		actions {' . "\n";
				$this->frx_settings_file .= '			"add header" = ' . $email['spam_tag_level'] . ';' . "\n";
				if ((int)$email['rewrite_subject'] == 1) {
					$this->frx_settings_file .= '			rewrite_subject = ' . ($email['spam_tag_level'] + 0.01) . ';' . "\n";
				}
				$this->frx_settings_file .= '			reject = ' . $email['spam_kill_level'] . ';' . "\n";
				if ($type == 'rcpt' && (int)$email['policy_greylist'] == 0) {
					$this->frx_settings_file .= '			greylist = null;' . "\n";
				}
				$this->frx_settings_file .= '		}' . "\n";
				$this->frx_settings_file .= '	}' . "\n";
				if ($type == 'rcpt' && (int)$email['policy_greylist'] == 0) {
					$this->frx_settings_file .= '	symbols [ "DONT_GREYLIST" ]' . "\n";
				}
			}
			$this->frx_settings_file .= '}' . "\n";
		}
		$this->frx_settings_file .= "\n";
	}

	public function reloadDaemon()
	{
		// reload DNS daemon
		$cmd = Settings::Get('antispam.reload_command');
		$cmdStatus = 1;
		FileDir::safe_exec(escapeshellcmd($cmd), $cmdStatus);
		if ($cmdStatus === 0) {
			$this->logger->logAction(FroxlorLogger::CRON_ACTION, LOG_INFO, 'Antispam daemon reloaded');
		} else {
			$this->logger->logAction(FroxlorLogger::CRON_ACTION, LOG_ERR, 'Error while running `' . $cmd . '`: exit code (' . $cmdStatus . ') - please check your system logs');
		}
	}
}
