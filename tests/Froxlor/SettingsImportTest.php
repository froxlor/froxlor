<?php

use Froxlor\Api\Commands\Froxlor;
use Froxlor\Database\Database;
use Froxlor\FroxlorLogger;
use Froxlor\Settings;
use Froxlor\UI\Form;
use Froxlor\Validate\Check;
use PHPUnit\Framework\TestCase;

/**
 * A settings import must report what went wrong instead of rendering a page and
 * terminating, and must not claim success when it failed.
 */
class SettingsImportTest extends TestCase
{
	/**
	 * Plausibility check used by the form tests below: always rejects.
	 *
	 * @return array
	 */
	public static function alwaysRejects($fieldname, $fielddata, $newfieldvalue, $allnewfieldvalues)
	{
		return [Check::FORMFIELDS_PLAUSIBILITY_CHECK_ERROR, 'invalidcharacters'];
	}

	protected function tearDown(): void
	{
		Form::setNonInteractive(false);
	}

	public function testAFailedCheckThrowsInsteadOfRenderingWhenNobodyIsWatching(): void
	{
		// Without this the form renders an alert page and calls exit(), which
		// leaves an API or CLI caller with HTML on stdout and a dead process.
		$form = $this->formWith([self::class, 'alwaysRejects']);
		$input = ['somefield' => 'newvalue'];

		Form::setNonInteractive(true);
		$this->expectException(Exception::class);
		Form::processForm($form, $input, [], null, true);
	}

	public function testAnInvalidValueThrowsInsteadOfRenderingWhenNobodyIsWatching(): void
	{
		// The most likely failure for a scripted import: a value the field
		// validation rejects. This runs before any plausibility check.
		$form = $this->formWith(null);
		$form['groups']['testgroup']['fields']['somefield']['type'] = 'int';
		$input = ['somefield' => 'not-a-number'];

		Form::setNonInteractive(true);
		$this->expectException(Exception::class);
		Form::processForm($form, $input, [], null, true);
	}

	public function testAnUnverifiableOtpSettingIsReportedAsSkipped(): void
	{
		// Away from a browser froxlor cannot verify a one-time password, so the
		// change is left out - as it always was. What is new is that the caller
		// is told, instead of being handed a clean success.
		$form = $this->formWith(null);
		$form['groups']['testgroup']['fields']['somefield']['required_otp'] = true;
		$input = ['somefield' => 'newvalue'];

		Form::setNonInteractive(true);
		$this->assertNotFalse(Form::processForm($form, $input, [], null, true));
		$this->assertSame(['somefield'], Form::getSkippedFields());
	}

	public function testNothingIsReportedAsSkippedWhenEverythingApplies(): void
	{
		$form = $this->formWith(null);
		$input = ['somefield' => 'newvalue'];

		Form::setNonInteractive(true);
		$this->assertNotFalse(Form::processForm($form, $input, [], null, true));
		$this->assertSame([], Form::getSkippedFields());
	}

	public function testImportReportsWhichSettingsItCouldNotApply(): void
	{
		global $admin_userdata;

		$logger = $this->forceDatabaseLogging();
		Database::query('START TRANSACTION');
		try {
			$settings = $this->resign($this->exportedSettings());
			$result = json_decode(
				Froxlor::getLocal($admin_userdata, ['json_str' => json_encode($settings)])->importSettings(),
				true
			)['data'];
			$this->assertIsArray($result, 'the import must report what it did');
			$this->assertTrue($result['imported']);
			$this->assertIsArray($result['skipped']);
		} finally {
			Database::query('ROLLBACK');
			$this->restoreLogging($logger);
		}
	}

	public function testAnApiClientCannotAskForTheRenderingMode(): void
	{
		global $admin_userdata;

		// A non-internal call must report, whatever the caller puts in the
		// params. If "interactive" were still honoured this would render a page
		// and exit(), taking the test runner with it.
		$settings = $this->exportedSettings();
		$settings['session.sessiontimeout'] = 'not-a-number';
		$settings = $this->resign($settings);

		Database::query('START TRANSACTION');
		try {
			$this->expectException(Exception::class);
			Froxlor::getLocal($admin_userdata, [
				'json_str' => json_encode($settings),
				'interactive' => true
			])->importSettings();
		} finally {
			Database::query('ROLLBACK');
		}
	}

	public function testImportRejectsATamperedFile(): void
	{
		global $admin_userdata;

		// Changing a value without recomputing the checksum must be refused. This
		// also guards the other import tests from passing for the wrong reason.
		$settings = $this->exportedSettings();
		$settings['panel.standardlanguage'] = 'Klingon';

		$this->expectException(Exception::class);
		$this->expectExceptionMessage('SHA check');
		Froxlor::getLocal($admin_userdata, ['json_str' => json_encode($settings)])->importSettings();
	}

	public function testAValidImportSucceedsAndIsLoggedOnce(): void
	{
		global $admin_userdata;

		$logger = $this->forceDatabaseLogging();
		Database::query('START TRANSACTION');
		try {
			$before = $this->countImportLogEntries();
			$settings = $this->resign($this->exportedSettings());

			$result = Froxlor::getLocal($admin_userdata, ['json_str' => json_encode($settings)])->importSettings();
			$this->assertNotFalse($result);
			$this->assertSame($before + 1, $this->countImportLogEntries());
		} finally {
			Database::query('ROLLBACK');
			$this->restoreLogging($logger);
		}
	}

	public function testFailedImportIsNotLoggedAsSuccessful(): void
	{
		global $admin_userdata;

		$logger = $this->forceDatabaseLogging();
		Database::query('START TRANSACTION');
		try {
			$before = $this->countImportLogEntries();
			try {
				Froxlor::getLocal($admin_userdata, ['json_str' => 'this is not json'])->importSettings();
				$this->fail('an invalid import must throw');
			} catch (Exception $e) {
				// expected
			}
			$this->assertSame($before, $this->countImportLogEntries(), 'a failed import must not be logged as an import');
		} finally {
			Database::query('ROLLBACK');
			$this->restoreLogging($logger);
		}
	}

	public function testTheOtpFailureMessageExists(): void
	{
		// Form.php raises this on a rejected code; without the string the panel
		// shows the raw identifier "error.otpnotvalidated".
		foreach (['en', 'de'] as $language) {
			$strings = require __DIR__ . '/../../lng/' . $language . '.lng.php';
			$this->assertArrayHasKey('otpnotvalidated', $strings['error'], $language . ' is missing the message');
			$this->assertNotSame('', trim($strings['error']['otpnotvalidated']));
		}
	}

	/**
	 * A minimal settings form with one field and the given plausibility check.
	 */
	private function formWith(?array $check): array
	{
		return [
			'groups' => [
				'testgroup' => [
					'title' => 'test',
					'fields' => [
						'somefield' => [
							'label' => 'test',
							'settinggroup' => 'panel',
							'varname' => 'standardlanguage',
							'type' => 'text',
							// the current value; processForm only acts on a change
							'value' => 'oldvalue',
							'plausibility_check_method' => $check ?? '',
							'save_method' => 'storeSettingField'
						]
					]
				]
			]
		];
	}

	private function exportedSettings(): array
	{
		global $admin_userdata;
		$export = json_decode(Froxlor::getLocal($admin_userdata)->exportSettings(), true)['data'];
		$settings = json_decode($export, true);
		$this->assertIsArray($settings);
		return $settings;
	}

	/**
	 * Recompute the checksum the importer verifies.
	 */
	private function resign(array $settings): array
	{
		unset($settings['_sha']);
		$settings['_sha'] = sha1(var_export($settings, true));
		return $settings;
	}

	/**
	 * The suite shares one database, and other tests change the logger settings.
	 * Pin what these assertions depend on instead of inheriting it.
	 *
	 * @return array<string,string> the previous values
	 */
	private function forceDatabaseLogging(): array
	{
		$previous = [];
		foreach (['enabled' => '1', 'logtypes' => 'mysql', 'severity' => '2'] as $name => $value) {
			$previous[$name] = (string)Settings::Get('logger.' . $name);
			Settings::Set('logger.' . $name, $value, true);
		}
		// FroxlorLogger builds its writers once and caches them, so a setting
		// changed afterwards has no effect until that state is cleared.
		$this->resetLogger();
		return $previous;
	}

	private function resetLogger(): void
	{
		foreach (['ml' => null, 'logtypes' => null, 'is_initialized' => false] as $property => $value) {
			$reflected = new ReflectionProperty(FroxlorLogger::class, $property);
			$reflected->setAccessible(true);
			$reflected->setValue(null, $value);
		}
	}

	/**
	 * @param array<string,string> $previous
	 */
	private function restoreLogging(array $previous): void
	{
		foreach ($previous as $name => $value) {
			Settings::Set('logger.' . $name, $value, true);
		}
		$this->resetLogger();
	}

	private function countImportLogEntries(): int
	{
		$stmt = Database::query("SELECT COUNT(*) FROM `" . TABLE_PANEL_LOG . "` WHERE `text` LIKE '%imported settings%'");
		return (int)$stmt->fetchColumn();
	}
}
