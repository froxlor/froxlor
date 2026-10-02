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

namespace Froxlor\Cli;

use Froxlor\Cron\TaskId;
use Froxlor\Database\Database;
use Froxlor\FileDir;
use Froxlor\Froxlor;
use Froxlor\Settings;
use Froxlor\System\Cronjob;
use PDO;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Question\ConfirmationQuestion;
use Symfony\Component\Console\Style\SymfonyStyle;

final class ValidateAcmeWebroot extends CliCommand
{

	protected function configure()
	{
		$this->setName('froxlor:validate-acme-webroot');
		$this->setDescription('Validates the Le_Webroot value is correct for froxlor managed domains with Let\'s Encrypt certificate.');
		$this->addOption('yes-to-all', 'A', InputOption::VALUE_NONE, 'Do not ask for confirmation, update files if necessary');
	}

	/**
	 * @throws \Exception
	 */
	protected function execute(InputInterface $input, OutputInterface $output): int
	{
		$result = $this->validateRequirements($output, true);

		$io = new SymfonyStyle($input, $output);

		if ((int)Settings::Get('system.leenabled') == 0) {
			$io->info("Let's Encrypt not activated in froxlor settings.");
			$result = self::INVALID;
		}

		if ($result == self::SUCCESS) {
			$yestoall = $input->getOption('yes-to-all') !== false;
			$helper = $this->getHelper('question');
			$count_changes = 0;
			// get all Let's Encrypt enabled domains
			$sel_stmt = Database::prepare("SELECT id, domain FROM panel_domains WHERE `letsencrypt` = '1' AND aliasdomain IS NULL ORDER BY id ASC");
			Database::pexecute($sel_stmt);
			$domains = $sel_stmt->fetchAll(PDO::FETCH_ASSOC);
			// check for froxlor-vhost
			if (Settings::Get('system.le_froxlor_enabled') == '1') {
				$domains[] = [
					'id' => 0,
					'domain' => Settings::Get('system.hostname')
				];
			}
			$upd_stmt = Database::prepare("UPDATE domain_ssl_settings SET `validtodate`=NULL WHERE `domainid` = :did");
			$acmesh_dir = dirname(Settings::Get('system.acmeshpath'));
			$acmesh_challenge_dir = rtrim(FileDir::makeCorrectDir(Settings::Get('system.letsencryptchallengepath')), "/");
			$recommended = rtrim(FileDir::makeCorrectDir(Froxlor::getInstallDir()), "/");

			if ($acmesh_challenge_dir != $recommended) {
				$io->warning([
					"ACME challenge docroot from settings differs from the current installation directory.",
					"Settings: '" . $acmesh_challenge_dir . "'",
					"Default/recommended value: '" . $recommended . "'",
				]);
				$question = new ConfirmationQuestion('Fix ACME challenge docroot setting? [yes] ', true, '/^(y|j)/i');
				if ($yestoall || $helper->ask($input, $output, $question)) {
					Settings::Set('system.letsencryptchallengepath', $recommended);
					$former_value = $acmesh_challenge_dir;
					$acmesh_challenge_dir = $recommended;
					// need to update the corresponding acme-alias config-file
					$acme_alias_file = Settings::Get('system.letsencryptacmeconf');
					$sed_params = "s@" . $former_value . "@" . $acmesh_challenge_dir . "@";
					FileDir::safe_exec('sed -i -e "' . $sed_params . '" ' . escapeshellarg($acme_alias_file));
					$count_changes++;
				}
			}

			foreach ($domains as $domain_arr) {
				$domain = $domain_arr['domain'];
				$acme_domain_conf = FileDir::makeCorrectFile($acmesh_dir . '/' . $domain . '/' . $domain . '.conf');
				if (file_exists($acme_domain_conf)) {
					$io->text("Getting info from " . $acme_domain_conf);
					$conf_content = file_get_contents($acme_domain_conf);
				} else {
					$acme_domain_conf = FileDir::makeCorrectFile($acmesh_dir . '/' . $domain . '_ecc/' . $domain . '.conf');
					if (file_exists($acme_domain_conf)) {
						$io->text("Getting info from " . $acme_domain_conf);
						$conf_content = file_get_contents($acme_domain_conf);
					} else {
						$io->info("No domain configuration file found in '" . $acmesh_dir . "'");
						continue;
					}
				}
				if (!empty($conf_content)) {
					$lines = explode("\n", $conf_content);
					foreach ($lines as $line) {
						$val_key = explode("=", $line);
						if ($val_key[0] == 'Le_Webroot') {
							$domain_webroot = trim(trim($val_key[1], "'"), '"');
							if ($domain_webroot != $acmesh_challenge_dir) {
								$io->warning("Domain '" . $domain . "' has old/wrong Le_Webroot setting: '" . $domain_webroot . ' <> ' . $acmesh_challenge_dir . "'");
								$question = new ConfirmationQuestion('Fix Le_Webroot? [yes] ', true, '/^(y|j)/i');
								if ($yestoall || $helper->ask($input, $output, $question)) {
									$sed_params = "s@Le_Webroot=.*@Le_Webroot='" . $acmesh_challenge_dir . "'@";
									FileDir::safe_exec('sed -i -e "' . $sed_params . '" ' . escapeshellarg($acme_domain_conf));
									Database::pexecute($upd_stmt, ['did' => $domain_arr['id']]);
									$io->success("Correction of Le_Webroot successful");
									$count_changes++;
								} else {
									continue;
								}
							} else {
								$io->info("Domain '" . $domain . "' Le_Webroot value is correct");
							}
							break;
						}
					}
				}
			}
			if ($count_changes > 0) {
				if (Froxlor::hasUpdates() || Froxlor::hasDbUpdates()) {
					$io->info("Changes detected but froxlor has been updated. Inserting task to rebuild vhosts after update.");
					Cronjob::inserttask(TaskId::REBUILD_VHOST);
				} else {
					$question = new ConfirmationQuestion('Changes detected. Force cronjob to refresh certificates? [yes] ', true, '/^(y|j)/i');
					if ($yestoall || $helper->ask($input, $output, $question)) {
						passthru(FileDir::makeCorrectFile(Froxlor::getInstallDir() . '/bin/froxlor-cli') . ' froxlor:cron -f -d');
					}
				}
			} else {
				$io->success("No changes necessary.");
			}
		}

		return $result;
	}

}
