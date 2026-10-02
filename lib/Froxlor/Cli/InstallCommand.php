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
use Froxlor\Config\ConfigParser;
use Froxlor\Database\Database;
use Froxlor\Froxlor;
use Froxlor\Install\Install;
use Froxlor\Install\Install\Core;
use Froxlor\Settings;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Helper\Table;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

final class InstallCommand extends Command
{

	private $io = null;

	private $formfielddata = [];

	protected function configure()
	{
		$this->setName('froxlor:install');
		$this->setDescription('Installation process to use instead of web-ui');
		$this->addArgument('input-file', InputArgument::OPTIONAL, 'Optional JSON array file to use for unattended installations');
		$this->addOption('print-example-file', 'p', InputOption::VALUE_NONE, 'Outputs an example JSON content to be used with the input file parameter')
			->addOption('create-userdata-from-str', 'c', InputOption::VALUE_REQUIRED, 'Creates lib/userdata.inc.php file from string created by web-install process')
			->addOption('show-sysinfo', 's', InputOption::VALUE_NONE, 'Outputs system information about your froxlor installation');
	}

	/**
	 * @throws Exception
	 */
	protected function execute(InputInterface $input, OutputInterface $output): int
	{
		$result = self::SUCCESS;

		if ($input->getOption('create-userdata-from-str') !== null) {
			$ud_str = $input->getOption('create-userdata-from-str');
			$ud_dec = @json_decode(@base64_decode($ud_str), true);
			if (is_array($ud_dec) && !empty($ud_dec) && count($ud_dec) == 8) {
				$core = new Core($ud_dec);
				$core->createUserdataConf();
				return $result;
			}
			$output->writeln("<error>Invalid parameter value.</>");
			return self::INVALID;
		}

		if ($input->getOption('show-sysinfo') !== false) {
			if (!file_exists(Froxlor::getInstallDir() . '/lib/userdata.inc.php')) {
				$output->writeln("<error>Could not find froxlor's userdata.inc.php file. You can use this parameter only with an installed froxlor system.</>");
				return self::INVALID;
			}
			$this->printSysInfo($output);
			return self::SUCCESS;
		}

		session_start();

		require __DIR__ . '/install.functions.php';

		// set a few defaults CLI cannot know
		$_SERVER['SERVER_SOFTWARE'] = 'apache';
		$host = [];
		exec('hostname -f', $host);
		$_SERVER['SERVER_NAME'] = $host[0] ?? '';
		$ips = [];
		exec('hostname -I', $ips);
		$ips = explode(" ", $ips[0] ?? "");
		// ipv4 address?
		$_SERVER['SERVER_ADDR'] = filter_var($ips[0] ?? "", FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ? ($ips[0] ?? '') : '';
		if (empty($_SERVER['SERVER_ADDR'])) {
			// possible ipv6 address?
			$_SERVER['SERVER_ADDR'] = filter_var($ips[0] ?? "", FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? ($ips[0] ?? '') : '';
		}

		if ($input->getOption('print-example-file') !== false) {
			$this->printExampleFile($output);
			return self::SUCCESS;
		}

		if (file_exists(Froxlor::getInstallDir() . '/lib/userdata.inc.php')) {
			$output->writeln("<error>froxlor seems to be installed already.</>");
			return self::INVALID;
		}

		$this->io = new SymfonyStyle($input, $output);
		$this->io->title('Froxlor installation');

		if ($input->getArgument('input-file')) {
			$inputFile = $input->getArgument('input-file');
			if (strtoupper(substr($inputFile, 0, 4)) == 'HTTP') {
				$output->writeln("Input file seems to be an URL, trying to download");
				$target = "/tmp/froxlor-install-" . time() . ".json";
				if (@file_exists($target)) {
					@unlink($target);
				}
				$this->downloadFile($inputFile, $target);
				$inputFile = $target;
			}
			if (!is_file($inputFile)) {
				$output->writeln('<error>Given input file is not a file</>');
				return self::INVALID;
			} elseif (!file_exists($inputFile)) {
				$output->writeln('<error>Given input file cannot be found (' . $inputFile . ')</>');
				return self::INVALID;
			} elseif (!is_readable($inputFile)) {
				$output->writeln('<error>Given input file cannot be read (' . $inputFile . ')</>');
				return self::INVALID;
			}

			$inputcontent = file_get_contents($inputFile);
			$decoded_input = json_decode($inputcontent, true) ?? [];
			$extended = true;

			if (empty($decoded_input)) {
				$output->writeln('<error>Given input file seems to be invalid JSON</>');
				return self::INVALID;
			}
			$this->io->info('Running unattended installation');
		} else {
			$extended = $this->io->confirm('Use advanced installation mode?', false);
			$decoded_input = [];
		}

		return $this->showStep(0, $extended, $decoded_input);
	}

	/**
	 * @throws Exception
	 */
	private function showStep(int $step = 0, bool $extended = false, array $decoded_input = []): int
	{
		$result = self::SUCCESS;
		$inst = new Install(['step' => $step, 'extended' => $extended]);
		switch ($step) {
			case 0:
				$this->io->section(lng('install.preflight'));
				$crresult = $inst->checkRequirements();
				$this->io->info($crresult['text']);
				if (!empty($crresult['criticals'])) {
					foreach ($crresult['criticals'] as $ctype => $critical) {
						if (!empty($ctype) && $ctype == 'wrong_ownership') {
							$this->io->error(lng('install.errors.' . $ctype, [$critical['user'], $critical['group']]));
						} elseif (!empty($ctype) && $ctype == 'missing_extensions') {
							$this->io->error([
								lng('install.errors.' . $ctype),
								implode("\n", $critical)
							]);
						} else {
							$this->io->error($critical);
						}
					}
					$result = self::FAILURE;
				}
				if (!empty($crresult['suggestions'])) {
					foreach ($crresult['suggestions'] as $ctype => $suggestion) {
						if ($ctype == 'missing_extensions') {
							$this->io->warning([
								lng('install.errors.suggestedextensions'),
								implode("\n", $suggestion)
							]);
						} else {
							$this->io->warning($suggestion);
						}
					}
				}
				if ($result == self::SUCCESS) {
					return $this->showStep(++$step, $extended, $decoded_input);
				}
				break;
			case 1:
			case 2:
			case 3:
				$section = $inst->formfield['install']['sections']['step' . $step] ?? [];
				$this->io->section($section['title']);
				if (empty($decoded_input)) {
					$this->io->note($section['description']);
				}
				foreach ($section['fields'] as $fieldname => $fielddata) {
					if ($extended == false && isset($fielddata['advanced']) && $fielddata['advanced'] == true) {
						if ($fieldname == 'httpuser' || $fieldname == 'httpgroup') {
							// overwrite posix_getgrgid(posix_getgid())['name'] as it would result in 'root'
							$this->formfielddata[$fieldname] = 'www-data';
						} else {
							$this->formfielddata[$fieldname] = $fielddata['value'];
						}
						continue;
					}
					$ask_field = true;
					// preset from input-file
					if (!empty($decoded_input) && isset($decoded_input[$fieldname])) {
						$this->formfielddata[$fieldname] = $decoded_input[$fieldname];
						$ask_field = false;
					}
					$fielddata['value'] = $this->formfielddata[$fieldname] ?? ($fielddata['value'] ?? null);
					$fielddata['label'] = $this->cliTextFormat($fielddata['label'], " ");
					if ($ask_field) {
						if ($fielddata['type'] == 'password') {
							$this->formfielddata[$fieldname] = $this->io->askHidden($fielddata['label'], function ($value) use ($fielddata) {
								if (isset($fielddata['mandatory']) && $fielddata['mandatory'] && empty($value)) {
									throw new \RuntimeException('You must enter a value.');
								}
								return $value;
							});
						} elseif ($fielddata['type'] == 'checkbox') {
							$this->formfielddata[$fieldname] = $this->io->confirm($fielddata['label'], $fielddata['value'] ?? false);
						} elseif ($fielddata['type'] == 'select') {
							$this->formfielddata[$fieldname] = $this->io->choice($fielddata['label'], $fielddata['select_var'], $fielddata['selected'] ?? '');
						} else {
							$this->formfielddata[$fieldname] = $this->io->ask($fielddata['label'], $fielddata['value'] ?? '', function ($value) use ($fielddata) {
								if (isset($fielddata['mandatory']) && $fielddata['mandatory'] && empty($value)) {
									throw new \RuntimeException('You must enter a value.');
								}
								return $value;
							});
						}
					} else {
						$this->io->text("Setting field '" . $fieldname . "' to value '" . ($fielddata['type'] == 'password' ? '*hidden*' : $fielddata['value']) . "'");
						if (isset($fielddata['mandatory']) && $fielddata['mandatory'] && empty($fielddata['value'])) {
							$this->io->error("Mandatory field '" . $fieldname . "' not specified/empty value in input file");
							return self::FAILURE;
						}
					}
				}

				try {
					if ($step == 1) {
						$inst->checkDatabase($this->formfielddata);
					} elseif ($step == 2) {
						$inst->checkAdminUser($this->formfielddata);
					} elseif ($step == 3) {
						$inst->checkSystem($this->formfielddata);
					}
				} catch (Exception $e) {
					$this->io->error($e->getMessage());
					if ($this->io->confirm('Retry?', empty($decoded_input))) {
						return $this->showStep($step, $extended, $decoded_input);
					}
					return self::FAILURE;
				}
				if ($step == 3) {
					// do actual install with data from $this->formfielddata
					$core = new Core($this->formfielddata);
					$core->doInstall(false);
					$core->createUserdataConf();
				}
				return $this->showStep(++$step, $extended, $decoded_input);
				break;
			case 4:
				$section = $inst->formfield['install']['sections']['step' . $step] ?? [];
				$this->io->section($section['title']);
				$this->io->note($this->cliTextFormat($section['description']));
				$cmdfield = $section['fields']['system'];
				$this->io->success([
					$cmdfield['label'],
					$cmdfield['value']
				]);
				if (!isset($decoded_input['manual_config']) || (bool)$decoded_input['manual_config'] === false) {
					if (!empty($decoded_input) || $this->io->confirm('Execute command now?', false)) {
						passthru($cmdfield['value']);
					}
				}
				break;
		}
		return $result;
	}

	private function printExampleFile(OutputInterface $output)
	{
		// show list of available distro's
		$distros = glob(dirname(__DIR__, 3) . '/lib/configfiles/*.xml');
		// read in all the distros
		foreach ($distros as $distribution) {
			// get configparser object
			$dist = new ConfigParser($distribution);
			// store in tmp array
			$supportedOS[str_replace(".xml", "", strtolower(basename($distribution)))] = $dist->getCompleteDistroName();
		}
		// sort by distribution name
		asort($supportedOS);
		$webserverBackend = [
			'php-fpm' => 'PHP-FPM',
			'fcgid' => 'FCGID',
			'mod_php' => 'mod_php (not recommended)',
		];
		$guessedDistribution = "";
		$guessedWebserver = "";
		$fields = include dirname(dirname(__DIR__)) . '/formfields/install/formfield.install.php';
		$json_output = [];
		foreach ($fields['install']['sections'] as $section => $section_fields) {
			foreach ($section_fields['fields'] as $name => $field) {
				if ($name == 'system' || $name == 'target_servername') {
					continue;
				}
				if ($field['type'] == 'text' || $field['type'] == 'email') {
					if ($name == 'httpuser' || $name == 'httpgroup') {
						$fieldval = 'www-data';
					} else {
						$fieldval = $field['value'] ?? "";
					}
				} elseif ($field['type'] == 'password') {
					$fieldval = '******';
				} elseif ($field['type'] == 'select') {
					$fieldval = implode("|", array_keys($field['select_var']));
				} elseif ($field['type'] == 'checkbox') {
					$fieldval = "1|0";
				} else {
					$fieldval = "?";
				}
				$json_output[$name] = $fieldval;
			}
		}
		$output->writeln(json_encode($json_output, JSON_PRETTY_PRINT));
	}

	private function downloadFile($src, $dest)
	{
		set_time_limit(0);
		// This is the file where we save the information
		$fp = fopen($dest, 'w+');
		// Here is the file we are downloading, replace spaces with %20
		$ch = curl_init(str_replace(" ", "%20", $src));
		curl_setopt($ch, CURLOPT_TIMEOUT, 50);
		curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
		// write curl response to file
		curl_setopt($ch, CURLOPT_FILE, $fp);
		curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
		// get curl response
		curl_exec($ch);
		fclose($fp);
	}

	private function printSysInfo(OutputInterface $output)
	{

		$php_sapi = 'mod_php';
		$php_version = phpversion();
		if (Settings::Get('system.mod_fcgid') == '1') {
			$php_sapi = 'FCGID';
			if (Settings::Get('system.mod_fcgid_ownvhost') == '1') {
				$php_sapi .= ' (+ froxlor)';
			}
		} elseif (Settings::Get('phpfpm.enabled') == '1') {
			$php_sapi = 'PHP-FPM';
			if (Settings::Get('phpfpm.enabled_ownvhost') == '1') {
				$php_sapi .= ' (+ froxlor)';
			}
		}

		$kernel = 'unknown';
		if (function_exists('posix_uname')) {
			$kernel_nfo = posix_uname();
			$kernel = $kernel_nfo['release'] . ' (' . $kernel_nfo['machine'] . ')';
		}

		$ips = [];
		$ips_stmt = Database::query("SELECT CONCAT(`ip`, ' (', `port`, ')') as ipaddr FROM `" . TABLE_PANEL_IPSANDPORTS . "` ORDER BY `id`");
		while ($ip = $ips_stmt->fetch(\PDO::FETCH_ASSOC)) {
			$ips[] = $ip['ipaddr'];
		}

		$table = new Table($output);
		$table
			->setHeaders([
				'Key', 'Value'
			])
			->setRows([
				['Froxlor', Froxlor::getVersionString()],
				['Update-channel', Settings::Get('system.update_channel')],
				['Hostname', Settings::Get('system.hostname')],
				['Install-dir', Froxlor::getInstallDir()],
				['PHP CLI', $php_version],
				['PHP SAPI', $php_sapi],
				['Webserver', Settings::Get('system.webserver')],
				['Kernel', $kernel],
				['Database', Database::getAttribute(\PDO::ATTR_SERVER_VERSION)],
				['Distro config', Settings::Get('system.distribution')],
				['IP addresses', implode("\n", $ips)],
			]);
		$table->setStyle('box');
		$table->render();
	}

	private function cliTextFormat(string $text, string $nl_char = "\n"): string
	{
		$text = str_replace(['<br>', '<br/>', '<br />'], [$nl_char, $nl_char, $nl_char], $text);
		return strip_tags($text);
	}
}
