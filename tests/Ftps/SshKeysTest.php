<?php
use PHPUnit\Framework\TestCase;

use Froxlor\Api\Commands\Customers;
use Froxlor\Api\Commands\Ftps;
use Froxlor\Api\Commands\SshKeys;
use phpseclib3\Crypt\RSA;

/**
 * Regression tests for GHSA-p3v3-74gc-jh5f: SshKeys::add() validated the submitted
 * key with PublicKeyLoader::loadPublicKey(), which only parses the first OpenSSH key
 * token and folds everything after the first newline into the key comment. A
 * multi-line value therefore validated successfully and was stored verbatim, and the
 * root-run cron later wrote it byte-for-byte into authorized_keys, turning the
 * "extra" lines into independent, fully honored entries (arbitrary
 * command=/from=/environment= directives, additional keys).
 *
 * Uses a dedicated ftp-user/customer session so it doesn't depend on fixtures from
 * FtpsTest.php (which creates and deletes its own ftp-users within that same file).
 *
 * @covers \Froxlor\Api\Commands\SshKeys
 */
class SshKeysTest extends TestCase
{
	private static $ftpUsername;
	private static $customerId;

	public static function setUpBeforeClass(): void
	{
		global $admin_userdata;

		$customer_userdata = json_decode(Customers::getLocal($admin_userdata, [
			'loginname' => 'test1'
		])->get(), true)['data'];
		self::$customerId = $customer_userdata['customerid'];

		$json_result = Ftps::getLocal($admin_userdata, [
			'customerid' => self::$customerId,
			'ftp_password' => 'h4xXx0r!Test',
			'path' => '/',
			'ftp_description' => 'sshkeys regression test user',
			'sendinfomail' => 0
		])->add();
		$result = json_decode($json_result, true)['data'];
		self::$ftpUsername = $result['username'];
	}

	public static function tearDownAfterClass(): void
	{
		global $admin_userdata;
		try {
			Ftps::getLocal($admin_userdata, ['username' => self::$ftpUsername])->delete();
		} catch (Exception $e) {
			// ignore - best-effort cleanup
		}
	}

	private static function generatePublicKey(string $comment): string
	{
		return RSA::createKey(2048)->getPublicKey()->toString('OpenSSH', ['comment' => $comment]);
	}

	public function testAddRejectsMultiLineKeyWithInjectedDirective()
	{
		global $admin_userdata;

		$payload = self::generatePublicKey('legit') . "\n"
			. 'command="/bin/sh -c id>/tmp/pwn",no-pty ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIATTACKER attacker';

		$this->expectExceptionMessage('Given SSH-key does not seem to be a valid public key');
		SshKeys::getLocal($admin_userdata, [
			'customerid' => self::$customerId,
			'ftpuser' => self::$ftpUsername,
			'ssh_pubkey' => $payload
		])->add();
	}

	public function testAddRejectsMultiLineKeyWithSecondFullKey()
	{
		global $admin_userdata;

		// two otherwise entirely valid keys, just joined by a raw newline
		$payload = self::generatePublicKey('first') . "\n" . self::generatePublicKey('second');

		$this->expectExceptionMessage('Given SSH-key does not seem to be a valid public key');
		SshKeys::getLocal($admin_userdata, [
			'customerid' => self::$customerId,
			'ftpuser' => self::$ftpUsername,
			'ssh_pubkey' => $payload
		])->add();
	}

	public function testAddRejectsKeyWithCarriageReturn()
	{
		global $admin_userdata;

		$payload = self::generatePublicKey('legit') . "\r\n" . 'environment="LD_PRELOAD=/tmp/evil.so" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIATTACKER attacker';

		$this->expectExceptionMessage('Given SSH-key does not seem to be a valid public key');
		SshKeys::getLocal($admin_userdata, [
			'customerid' => self::$customerId,
			'ftpuser' => self::$ftpUsername,
			'ssh_pubkey' => $payload
		])->add();
	}

	/**
	 * a single-line key, including one with a harmless trailing newline (the common
	 * case when a key is pasted from a file), must continue to be accepted
	 */
	public function testAddAcceptsLegitimateSingleLineKey()
	{
		global $admin_userdata;

		$pubkey = self::generatePublicKey('legit-single-line');
		$json_result = SshKeys::getLocal($admin_userdata, [
			'customerid' => self::$customerId,
			'ftpuser' => self::$ftpUsername,
			'ssh_pubkey' => $pubkey . "\n"
		])->add();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals(trim($pubkey), $result['ssh_pubkey']);

		// cleanup so a re-run / later test in this class doesn't hit
		// "This SSH-key already exists for the given user"
		SshKeys::getLocal($admin_userdata, ['customerid' => self::$customerId, 'id' => $result['id']])->delete();
	}
}
