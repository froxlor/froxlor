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

use Exception;
use Froxlor\Database\Database;
use Froxlor\FileDir;
use Froxlor\Froxlor;
use Froxlor\Install\AutoUpdate;
use Froxlor\Install\Preconfig;
use Froxlor\Install\Update;
use Froxlor\Settings;
use Froxlor\System\Mailer;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Question\ChoiceQuestion;
use Symfony\Component\Console\Question\ConfirmationQuestion;
use Symfony\Component\Console\Question\Question;
use Symfony\Component\Console\Style\SymfonyStyle;

final class UpdateCommand extends CliCommand
{

	protected function configure()
	{
		$this->setName('froxlor:update');
		$this->setDescription('Check for newer version and update froxlor');
		$this->addOption('check-only', 'c', InputOption::VALUE_NONE, 'Only check for newer version and exit')
			->addOption('show-update-options', 'o', InputOption::VALUE_NONE, 'Show possible update option parameter for the update if any. Only usable in combination with "check-only".')
			->addOption('update-options', 'O', InputOption::VALUE_IS_ARRAY | InputOption::VALUE_REQUIRED, 'Parameter list of update options.')
			->addOption('database', 'd', InputOption::VALUE_NONE, 'Only run database updates in case updates are done via apt or manually.')
			->addOption('mail-notify', 'm', InputOption::VALUE_NONE, 'Additionally inform administrator via email if a newer version was found')
			->addOption('yes-to-all', 'A', InputOption::VALUE_NONE, 'Do not ask for download, extract and database-update, just do it (if not --check-only is set)')
			->addOption('integer-return', 'i', InputOption::VALUE_NONE, 'Return integer whether a new version is available or not (implies --check-only). Useful for programmatic use.');
	}

	protected function execute(InputInterface $input, OutputInterface $output)
	{
		$result = self::SUCCESS;

		// database update only
		if ($input->getOption('database')) {
			$result = $this->validateRequirements($output, true);
			if ($result == self::SUCCESS) {
				require Froxlor::getInstallDir() . '/lib/functions.php';
				if (Froxlor::hasUpdates() || Froxlor::hasDbUpdates()) {
					$output->writeln('<info>' . lng('update.dbupdate_required') . '</>');
					if ($input->getOption('check-only')) {
						$output->writeln('<comment>Doing nothing because of "check-only" flag.</>');
						$this->askUpdateOptions($input, $output, null, false);
					} else {
						$yestoall = $input->getOption('yes-to-all') !== false;
						$helper = $this->getHelper('question');

						$this->askUpdateOptions($input, $output, $helper, $yestoall);

						$question = new ConfirmationQuestion('Update database? [no] ', false, '/^(y|j)/i');
						if ($yestoall || $helper->ask($input, $output, $question)) {
							$result = $this->runUpdate($output, true);
						}
					}
					return $result;
				}
				$output->writeln('<info>' . lng('update.noupdatesavail', [(Settings::Get('system.update_channel') == 'testing' ? lng('serversettings.uc_testing') . ' ' : '')]) . '</>');
			}
			return $result;
		}

		$result = $this->validateRequirements($output);

		if ($result != self::SUCCESS) {
			// requirements failed, exit
			return $result;
		}

		require Froxlor::getInstallDir() . '/lib/functions.php';

		// version check
		$newversionavail = false;
		if ($result == self::SUCCESS) {
			try {
				$aucheck = AutoUpdate::checkVersion();

				if ($aucheck == 1) {
					$this->mailNotify($input, $output);
					if ($input->getOption('integer-return')) {
						$output->write(1);
						return self::SUCCESS;
					}
					// there is a new version
					if ($input->getOption('check-only')) {
						$text = lng('update.uc_newinfo', [(Settings::Get('system.update_channel') != 'stable' ? Settings::Get('system.update_channel') . ' ' : ''), AutoUpdate::getFromResult('version'), Froxlor::VERSION]);
					} else {
						$text = lng('admin.newerversionavailable') . ' ' . lng('admin.newerversiondetails', [AutoUpdate::getFromResult('version'), Froxlor::VERSION]);
					}
					$text = str_replace("<br/>", " ", $text);
					$text = str_replace("<b>", "<info>", $text);
					$text = str_replace("</b>", "</info>", $text);
					$newversionavail = true;
					$output->writeln('<comment>' . $text . '</>');
					$result = self::SUCCESS;
				} elseif ($aucheck < 0 || $aucheck > 1) {
					if ($input->getOption('integer-return')) {
						$output->write(-1);
						return self::INVALID;
					}
					// errors
					if ($aucheck < 0) {
						$output->writeln('<error>' . AutoUpdate::getLastError() . '</>');
					} else {
						$errmsg = 'error.autoupdate_' . $aucheck;
						if ($aucheck == 3) {
							$errmsg = 'error.customized_version';
						}
						$output->writeln('<error>' . lng($errmsg) . '</>');
					}
					$result = self::INVALID;
				} else {
					if ($input->getOption('integer-return')) {
						$output->write(0);
						return self::SUCCESS;
					}
					// no new version
					$output->writeln('<info>' . AutoUpdate::getFromResult('info') . '</>');
					$result = self::SUCCESS;
				}
			} catch (Exception $e) {
				if ($input->getOption('integer-return')) {
					$output->write(-1);
					return self::FAILURE;
				}
				$output->writeln('<error>' . $e->getMessage() . '</>');
				$result = self::FAILURE;
			}
		}

		// if there's a newer version, proceed
		if ($result == self::SUCCESS && $newversionavail) {

			// check whether we only wanted to check
			if ($input->getOption('check-only')) {
				//$output->writeln('<comment>Not proceeding as "check-only" is specified</>');
				$this->askUpdateOptions($input, $output, null, false);
				return $result;
			} else {
				$yestoall = $input->getOption('yes-to-all') !== false;

				$helper = $this->getHelper('question');

				// ask download
				$question = new ConfirmationQuestion('Download newer version? [no] ', false, '/^(y|j)/i');
				if ($yestoall || $helper->ask($input, $output, $question)) {
					// do download
					$output->writeln('Downloading...');
					$audl = AutoUpdate::downloadZip(AutoUpdate::getFromResult('version'));
					if (!is_numeric($audl)) {
						// ask extract
						$question = new ConfirmationQuestion('Extract downloaded archive? [no] ', false, '/^(y|j)/i');
						if ($yestoall || $helper->ask($input, $output, $question)) {
							// do extract
							$output->writeln('Extracting...');
							$auex = AutoUpdate::extractZip(Froxlor::getInstallDir() . '/updates/' . $audl);
							if ($auex == 0) {
								$output->writeln("<info>Froxlor files updated successfully.</>");
								$result = self::SUCCESS;

								// restart fpm if used to clear opcache
								if ((int)Settings::Get('phpfpm.enabled') == 1 && Settings::Get('phpfpm.enabled_ownvhost') == '1') {
									// get fpm restart cmd
									$startstop_sel = Database::prepare("
										SELECT f.reload_cmd, f.config_dir
										FROM `" . TABLE_PANEL_FPMDAEMONS . "` f
										LEFT JOIN `" . TABLE_PANEL_PHPCONFIGS . "` p ON p.fpmsettingid = f.id
										WHERE p.id = :phpconfigid
									");
									$restart_cmd = Database::pexecute_first($startstop_sel, [
										'phpconfigid' => Settings::Get('phpfpm.vhost_defaultini')
									]);
									// restart php-fpm instance
									FileDir::safe_exec(escapeshellcmd($restart_cmd['reload_cmd']));
								}

								$this->askUpdateOptions($input, $output, $helper, $yestoall);

								$question = new ConfirmationQuestion('Update database? [no] ', false, '/^(y|j)/i');
								if ($yestoall || $helper->ask($input, $output, $question)) {
									// run in separate process to ensure the use of newly unpacked files
									passthru(Froxlor::getInstallDir() . '/bin/froxlor-cli froxlor:update -dA', $result);
								}
							} else {
								$errmsg = 'error.autoupdate_' . $auex;
								$output->writeln('<error>' . lng($errmsg) . '</>');
								$result = self::FAILURE;
							}
						}
					} else {
						$errmsg = 'error.autoupdate_' . $audl;
						$output->writeln('<error>' . lng($errmsg) . '</>');
						$result = self::FAILURE;
					}
				}
			}
		}
		return $result;
	}

	/**
	 * @param InputInterface $input
	 * @param OutputInterface $output
	 * @param $helper
	 * @param bool $yestoall
	 * @return void
	 */
	private function askUpdateOptions(InputInterface $input, OutputInterface $output, $helper, bool $yestoall = false)
	{
		// check for preconfigs
		$preconfig = Preconfig::getPreConfig(true);
		$show_options_only = $input->getOption('show-update-options') !== false;
		if (!is_null($helper) && $show_options_only) {
			$output->writeln('<comment>Unsetting "show-update-options" due to not being called with "check-only".</>');
			$show_options_only = false;
		}
		$update_options = [];
		// set parameters
		$uOptions = $input->getOption('update-options');
		if (!empty($uOptions)) {
			$options_value = [];
			foreach ($uOptions as $givenOption) {
				$optVal = explode("=", $givenOption);
				if (count($optVal) == 2) {
					$options_value[$optVal[0]] = $optVal[1];
				}
			}
		}
		if (!empty($preconfig)) {
			krsort($preconfig);
			foreach ($preconfig as $section) {
				if (!$show_options_only) {
					$output->writeln("<info>Updater questions for " . $section['title'] . "</>");
				}
				foreach ($section['fields'] as $update_field => $metainfo) {
					if (isset($options_value[$update_field])) {
						$output->writeln('Setting given parameter "' . $update_field . '" to "' . $options_value[$update_field] . '"');
						$_POST[$update_field] = $options_value[$update_field];
						continue;
					}
					$default = null;
					$question_text = html_entity_decode(strip_tags($metainfo['label']), ENT_QUOTES | ENT_IGNORE, "UTF-8");
					if ($metainfo['type'] == 'checkbox') {
						$default = (int)$metainfo['checked'];
						if ($show_options_only) {
							$update_options[] = [
								'name' => $update_field,
								'question' => $question_text,
								'default' => $default,
								'choices' => '0: No' . PHP_EOL . '1: Yes' . PHP_EOL
							];
						} else {
							$question = new ConfirmationQuestion($question_text . ' [' . ($metainfo['checked'] ? 'yes' : 'no') . '] ', (bool)$metainfo['checked'], '/^(y|j)/i');
						}
					} elseif ($metainfo['type'] == 'select') {
						$default = $metainfo['selected'];
						$choices = "";
						foreach (array_values($metainfo['select_var'] ?? []) as $index => $choice) {
							$choices .= $index . ': ' . $choice . PHP_EOL;
						}
						if ($show_options_only) {
							$update_options[] = [
								'name' => $update_field,
								'question' => $question_text,
								'default' => !empty($default) ? $default : '-',
								'choices' => $choices
							];
						} else {
							$question = new ChoiceQuestion(
								$question_text,
								array_values($metainfo['select_var'] ?? []),
								$metainfo['selected']
							);
							$question->setValidator(function ($answer) use ($metainfo): string {
								$key = array_keys($metainfo['select_var'])[(int)$answer] ?? false; // Find the key based on the selected value
								if ($key === false) {
									throw new \RuntimeException('Invalid selection.');
								}
								return $key;
							});
						}
					} elseif ($metainfo['type'] == 'text') {
						$default = $metainfo['value'] ?? '';
						if ($show_options_only) {
							$update_options[] = [
								'name' => $update_field,
								'question' => $question_text,
								'default' => $default,
								'choices' => PHP_EOL
							];
						} else {
							$question = new Question($question_text . (!empty($metainfo['value']) ? ' [' . $metainfo['value'] . ']' : ''), $default);
							$question->setValidator(function (string $answer) use ($metainfo): string {
								if (($metainfo['mandatory'] ?? false) && empty($answer)) {
									throw new \RuntimeException(
										'Answer cannot be empty'
									);
								}
								if (!empty($metainfo['pattern'] ?? "") && !preg_match("/" . $metainfo['pattern'] . "/", $answer)) {
									throw new \RuntimeException('Answer does not seem to be in valid format');
								}
								return $answer;
							});
						}
					} else {
						$output->writeln("<error>Unknown type " . $metainfo['type'] . "</error>");
						continue;
					}

					if (!$show_options_only) {
						if ($yestoall) {
							$_POST[$update_field] = $default;
						} else {
							$_POST[$update_field] = $helper->ask($input, $output, $question);
						}
					}
				}
			}

			if ($show_options_only) {
				$io = new SymfonyStyle($input, $output);
				$io->table(
					['Parameter', 'Description', 'Default', 'Choices'],
					$update_options
				);
			}
		}
	}

	private function mailNotify(InputInterface $input, OutputInterface $output)
	{
		if ($input->getOption('mail-notify')) {
			$last_check_version = Settings::Get('system.update_notify_last');
			if (Update::versionInUpdate($last_check_version, AutoUpdate::getFromResult('version'))) {
				$text = lng('update.uc_newinfo', [(Settings::Get('system.update_channel') != 'stable' ? Settings::Get('system.update_channel') . ' ' : ''), AutoUpdate::getFromResult('version'), Froxlor::VERSION]);
				$mail = new Mailer(true);
				$mail->Body = $text;
				$mail->Subject = "[froxlor] " . lng('update.notify_subject');
				$mail->AddAddress(Settings::Get('panel.adminmail'), Settings::Get('panel.adminmail_defname'));
				if (!$mail->Send() && $input->getOption('integer-return') == null) {
					$output->writeln('<error>' . $mail->ErrorInfo . '</>');
				}
				Settings::Set('system.update_notify_last', AutoUpdate::getFromResult('version'));
			}
		}
	}
}
