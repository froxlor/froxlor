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

class FroxlorAPI
{
    private string $url;
    private string $key;
    private string $secret;
    private ?array $lastError = null;
    private ?string $lastStatusCode = null;

    public function __construct($url, $key, $secret)
    {
        $this->url = $url;
        $this->key = $key;
        $this->secret = $secret;
    }

    public function request($command, array $data = [])
    {
        $payload = [
            'command' => $command,
            'params' => $data
        ];

        $ch = curl_init($this->url);
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
        curl_setopt($ch, CURLOPT_HEADER, 0);
        curl_setopt($ch, CURLOPT_USERPWD, $this->key . ":" . $this->secret);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($payload));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $result = curl_exec($ch);

        $this->lastStatusCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

        return json_decode($result ?? curl_error($ch), true);
    }

    public function getLastStatusCode(): ?string
    {
        return $this->lastStatusCode;
    }
}
