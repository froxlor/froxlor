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

namespace Froxlor;

use Exception;
use Froxlor\Database\Database;
use PDO;

class MailLogParser
{
	private $startTime;
	private $domainTraffic = [];
	private $myDomains = [];
	private $mails = [];

	/**
	 * constructor
	 *
	 * @param
	 *            string logFile
	 * @param
	 *            int startTime
	 * @param
	 *            string logFileExim
	 */
	public function __construct($startTime = 0)
	{
		$this->startTime = $startTime;

		// Get all domains from Database
		$stmt = Database::prepare("SELECT domain FROM `" . TABLE_PANEL_DOMAINS . "`");
		Database::pexecute($stmt, []);
		while ($domain_row = $stmt->fetch(PDO::FETCH_ASSOC)) {
			$this->myDomains[] = $domain_row["domain"];
		}

		// Parse MTA traffic
		if (Settings::Get("system.mtaserver") == "postfix") {
			$this->parsePostfixLog(Settings::Get("system.mtalog"));
			$this->parsePostfixLog(Settings::Get("system.mtalog") . ".1");
		} elseif (Settings::Get("system.mtaserver") == "exim4") {
			$this->parseExim4Log(Settings::Get("system.mtalog"));
		}

		// Parse MDA traffic
		if (Settings::Get("system.mdaserver") == "dovecot") {
			$this->parseDovecotLog(Settings::Get("system.mdalog"));
			$this->parseDovecotLog(Settings::Get("system.mdalog") . ".1");
		} elseif (Settings::Get("system.mdaserver") == "courier") {
			$this->parseCourierLog(Settings::Get("system.mdalog"));
			$this->parseCourierLog(Settings::Get("system.mdalog") . ".1");
		}
	}

	/**
	 * parsePostfixLog
	 * parses the traffic from a postfix logfile
	 *
	 * @param string $logFile
	 *            logFile
	 */
	private function parsePostfixLog($logFile)
	{
		// Check if file exists
		if (!file_exists($logFile)) {
			return false;
		}

		// Open the log file
		try {
			$file_handle = fopen($logFile, "r");
			if (!$file_handle) {
				throw new Exception("Could not open the file!");
			}
		} catch (Exception $e) {
			echo "Error (File: " . $e->getFile() . ", line " . $e->getLine() . "): " . $e->getMessage();
			return false;
		}

		while (!feof($file_handle)) {
			unset($matches);
			$line = fgets($file_handle);

			if (strpos($line, 'postfix') === false) {
				continue;
			}

			$timestamp = $this->getLogTimestamp($line);
			if ($this->startTime < $timestamp) {
				if (preg_match("/postfix\/qmgr.*(?::|\])\s([A-Z\d]+).*from=<?(?:.*\@([a-zA-Z\d\.\-]+))?>?, size=(\d+),/", $line, $matches)) {
					// Postfix from
					$this->mails[$matches[1]] = [
						"domainFrom" => strtolower($matches[2]),
						"size" => $matches[3]
					];
				} elseif (preg_match("/postfix\/(?:pipe|smtp|lmtp).*(?::|\])\s([A-Z\d]+).*to=<?(?:.*\@([a-zA-Z\d\.\-]+))?>?,/", $line, $matches)) {
					// Postfix to
					if (array_key_exists($matches[1], $this->mails)) {
						$this->mails[$matches[1]]["domainTo"] = strtolower($matches[2]);

						// Only mails from/to outside the system should be added
						$mail = $this->mails[$matches[1]];
						if (in_array($mail["domainFrom"], $this->myDomains) || in_array($mail["domainTo"], $this->myDomains)) {
							// Outgoing traffic
							if (array_key_exists("domainFrom", $mail)) {
								$this->addDomainTraffic($mail["domainFrom"], $mail["size"], $timestamp);
							}

							// Incoming traffic
							if (array_key_exists("domainTo", $mail) && in_array($mail["domainTo"], $this->myDomains)) {
								$this->addDomainTraffic($mail["domainTo"], $mail["size"], $timestamp);
							}
						}
						unset($mail);
					}
				}
			}
		}
		fclose($file_handle);
		return true;
	}

	/**
	 * getLogTimestamp
	 *
	 * @param
	 *            string line
	 *            return int
	 */
	private function getLogTimestamp($line)
	{
		$matches = null;
		if (preg_match("/((?:[A-Z]{3}\s{1,2}\d{1,2}|\d{4}-\d{2}-\d{2}).\d{2}:\d{2}:\d{2})/i", $line, $matches)) {
			$timestamp = strtotime($matches[1]);
			if ($timestamp > ($this->startTime + 60 * 60 * 24)) {
				return strtotime($matches[1] . " -1 year");
			} else {
				return strtotime($matches[1]);
			}
		} else {
			return 0;
		}
	}

	/**
	 * _addDomainTraffic
	 * adds the traffic to the domain array if we own the domain
	 *
	 * @param
	 *            string domain
	 * @param
	 *            int traffic
	 */
	private function addDomainTraffic($domain, $traffic, $timestamp)
	{
		$date = date("Y-m-d", $timestamp);
		if (in_array($domain, $this->myDomains)) {
			if (array_key_exists($domain, $this->domainTraffic) && array_key_exists($date, $this->domainTraffic[$domain])) {
				$this->domainTraffic[$domain][$date] += (int)$traffic;
			} else {
				if (!array_key_exists($domain, $this->domainTraffic)) {
					$this->domainTraffic[$domain] = [];
				}
				$this->domainTraffic[$domain][$date] = (int)$traffic;
			}
		}
	}

	/**
	 * parseExim4Log
	 * parses the smtp traffic from a exim4 logfile
	 *
	 * @param string $logFile
	 *            logFile
	 */
	private function parseExim4Log($logFile)
	{
		// Check if file exists
		if (!file_exists($logFile)) {
			return false;
		}

		// Open the log file
		try {
			$file_handle = fopen($logFile, "r");
			if (!$file_handle) {
				throw new Exception("Could not open the file!");
			}
		} catch (Exception $e) {
			echo "Error (File: " . $e->getFile() . ", line " . $e->getLine() . "): " . $e->getMessage();
			return false;
		}

		while (!feof($file_handle)) {
			unset($matches);
			$line = fgets($file_handle);

			$timestamp = $this->getLogTimestamp($line);
			if ($this->startTime < $timestamp) {
				if (preg_match("/<= .*@([a-z0-9.\-]+) .*S=(\d+)/i", $line, $matches)) {
					// Outgoing traffic
					$this->addDomainTraffic($matches[1], $matches[2], $timestamp);
				} elseif (preg_match("/=> .*<?.*@([a-z0-9.\-]+)>? .*S=(\d+)/i", $line, $matches)) {
					// Incoming traffic
					$this->addDomainTraffic($matches[1], $matches[2], $timestamp);
				}
			}
		}
		fclose($file_handle);
		return true;
	}

	/**
	 * parseDovecotLog
	 * parses the dovecot imap/pop3 traffic from logfile
	 *
	 * @param string $logFile
	 *            logFile
	 */
	private function parseDovecotLog($logFile)
	{
		// Check if file exists
		if (!file_exists($logFile)) {
			return false;
		}

		// Open the log file
		try {
			$file_handle = fopen($logFile, "r");
			if (!$file_handle) {
				throw new Exception("Could not open the file!");
			}
		} catch (Exception $e) {
			echo "Error (File: " . $e->getFile() . ", line " . $e->getLine() . "): " . $e->getMessage();
			return false;
		}

		while (!feof($file_handle)) {
			unset($matches);
			$line = fgets($file_handle);

			if (strpos($line, 'dovecot') === false) {
				continue;
			}

			$timestamp = $this->getLogTimestamp($line);
			if ($this->startTime < $timestamp) {
				if (preg_match("/dovecot.*(?::|\]) imap\(.*@([a-z0-9\.\-]+)\)(<\d+><[a-z0-9+\/=]+>)?:.*(?:in=(\d+) out=(\d+)|bytes=(\d+)\/(\d+))/i", $line, $matches)) {
					// Dovecot IMAP
					$this->addDomainTraffic($matches[1], (int)$matches[3] + (int)$matches[4], $timestamp);
				} elseif (preg_match("/dovecot.*(?::|\]) pop3\(.*@([a-z0-9\.\-]+)\)(<\d+><[a-z0-9+\/=]+>)?:.*in=(\d+).*out=(\d+)/i", $line, $matches)) {
					// Dovecot POP3
					$this->addDomainTraffic($matches[1], (int)$matches[3] + (int)$matches[4], $timestamp);
				}
			}
		}
		fclose($file_handle);
		return true;
	}

	/**
	 * parseCourierLog
	 * parses the dovecot imap/pop3 traffic from logfile
	 *
	 * @param string $logFile
	 *            logFile
	 */
	private function parseCourierLog($logFile)
	{
		// Check if file exists
		if (!file_exists($logFile)) {
			return false;
		}

		// Open the log file
		try {
			$file_handle = fopen($logFile, "r");
			if (!$file_handle) {
				throw new Exception("Could not open the file!");
			}
		} catch (Exception $e) {
			echo "Error (File: " . $e->getFile() . ", line " . $e->getLine() . "): " . $e->getMessage();
			return false;
		}

		while (!feof($file_handle)) {
			unset($matches);
			$line = fgets($file_handle);

			$timestamp = $this->getLogTimestamp($line);
			if ($this->startTime < $timestamp) {
				if (preg_match("/(?:imapd|pop3d)(?:-ssl)?.*(?::|\]).*user=.*@([a-z0-9\.\-]+),.*rcvd=(\d+), sent=(\d+),/i", $line, $matches)) {
					// Courier IMAP & POP3
					$this->addDomainTraffic($matches[1], (int)$matches[2] + (int)$matches[3], $timestamp);
				}
			}
		}
		fclose($file_handle);
		return true;
	}

	/**
	 * getDomainTraffic
	 * returns the traffic of a given domain or 0 if the domain has no traffic
	 *
	 * @param
	 *            string domain
	 *            return array
	 */
	public function getDomainTraffic($domain)
	{
		if (array_key_exists($domain, $this->domainTraffic)) {
			return $this->domainTraffic[$domain];
		} else {
			return 0;
		}
	}
}
