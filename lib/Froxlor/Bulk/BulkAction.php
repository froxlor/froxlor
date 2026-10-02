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

namespace Froxlor\Bulk;

use Exception;
use Froxlor\FileDir;

/**
 * Abstract Class BulkAction to mass-import entities
 *
 * @author Michael Kaufmann (d00p) <d00p@froxlor.org>
 *
 */
abstract class BulkAction
{

	/**
	 * logged in user
	 *
	 * @var array
	 */
	protected $userinfo = [];
	/**
	 * complete path including filename of file to be imported
	 *
	 * @var string
	 */
	private $impFile = null;
	/**
	 * api-function to call for addingg entity
	 *
	 * @var string
	 */
	private $api_call = null;
	/**
	 * api-function parameter names, read from import-file (first line)
	 *
	 * @var array
	 */
	private $api_params = null;
	/**
	 * errors while importing
	 *
	 * @var array
	 */
	private $errors = [];

	/**
	 * class constructor, optionally sets file and customer-id
	 *
	 * @param string $import_file
	 * @param array $userinfo
	 *
	 * @return object BulkAction instance
	 */
	protected function __construct(?string $import_file = null, array $userinfo = [])
	{
		if (!empty($import_file)) {
			$this->impFile = FileDir::makeCorrectFile($import_file);
		}
		$this->userinfo = $userinfo;
	}

	/**
	 * import the parsed import file data with an optional separator other then semicolon
	 * and offset (maybe for header-line in csv or similar)
	 *
	 * @param string $separator
	 * @param int $offset
	 *
	 * @return array 'all' => amount of records processed, 'imported' => number of imported records
	 */
	abstract public function doImport(string $separator = ";", int $offset = 0);

	/**
	 * setter for import-file
	 *
	 * @param string $import_file
	 *
	 * @return void
	 */
	public function setImportFile($import_file = null)
	{
		$this->impFile = FileDir::makeCorrectFile($import_file);
	}

	/**
	 * return the list of errors
	 *
	 * @return array
	 */
	public function getErrors()
	{
		return $this->errors;
	}

	/**
	 * setter for api_call
	 *
	 * @param string $api_call
	 *
	 * @return void
	 */
	protected function setApiCall($api_call = "")
	{
		$this->api_call = $api_call;
	}

	protected function importEntity($data_array = null)
	{
		if (empty($data_array)) {
			return null;
		}

		$module = '\\Froxlor\\Api\\Commands\\' . substr($this->api_call, 0, strpos($this->api_call, "."));
		$function = substr($this->api_call, strpos($this->api_call, ".") + 1);

		$new_data = [];
		foreach ($this->api_params as $idx => $param) {
			if (isset($data_array[$idx])) {
				$new_data[$param] = $data_array[$idx];
			}
		}

		$result = null;
		try {
			$json_result = $module::getLocal($this->userinfo, $new_data)->$function();
			$result = json_decode($json_result, true)['data'];
		} catch (Exception $e) {
			$this->errors[] = $e->getMessage();
		}
		return !empty($result);
	}

	/**
	 * reads in the csv import file and returns an array with
	 * all the entities to be imported
	 *
	 * @param string $separator
	 *
	 * @return array
	 */
	protected function parseImportFile($separator = ";")
	{
		if (empty($this->impFile)) {
			throw new Exception("No file was given for import");
		}

		if (!file_exists($this->impFile)) {
			throw new Exception("The file '" . $this->impFile . "' could not be found");
		}

		if (!is_readable($this->impFile)) {
			throw new Exception("Unable to read file '" . $this->impFile . "'");
		}

		if (empty($separator) || strlen($separator) != 1) {
			throw new Exception("Invalid separator specified: '" . $separator . "'");
		}

		$file_data = [];
		$is_params_line = true;
		$fh = @fopen($this->impFile, "r");
		if ($fh) {
			while (($line = fgets($fh)) !== false) {
				$tmp_arr = explode($separator, $line);
				$data_arr = [];
				foreach ($tmp_arr as $idx => $data) {
					if ($is_params_line) {
						$this->api_params[$idx] = $data;
					} else {
						$data_arr[$idx] = $data;
					}
				}
				if ($is_params_line) {
					$is_params_line = false;
					continue;
				}
				$file_data[] = array_map("trim", $data_arr);
			}
			$this->api_params = array_map("trim", $this->api_params);
		} else {
			throw new Exception("Unable to open file '" . $this->impFile . "'");
		}
		fclose($fh);

		return $file_data;
	}

}
