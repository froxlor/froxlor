<?php
use PHPUnit\Framework\TestCase;

use Froxlor\FileDir;

/**
 * Regression tests for the symlink-escape validation in FileDir::makeCorrectDir()
 * and FileDir::makeCorrectFile(). These are pure filesystem/string checks and do
 * not require the database, so they run against real temp directories/symlinks.
 *
 * @covers \Froxlor\FileDir
 */
class FileDirTest extends TestCase
{
	private $workdir;

	// a directory *outside* $workdir, standing in for a target a malicious symlink
	// could escape to (e.g. another customer's webspace, or a system directory)
	private $outsidedir;

	protected function setUp(): void
	{
		$id = uniqid();
		$this->workdir = sys_get_temp_dir() . '/frx_filedirtest_' . $id . '/';
		$this->outsidedir = sys_get_temp_dir() . '/frx_filedirtest_outside_' . $id . '/';
		mkdir($this->workdir, 0777, true);
		mkdir($this->outsidedir, 0777, true);
	}

	protected function tearDown(): void
	{
		exec('rm -rf ' . escapeshellarg($this->workdir) . ' ' . escapeshellarg($this->outsidedir));
	}

	/**
	 * baseline: a genuine nested directory, no symlink involved, must be accepted
	 * regardless of whether $fixed_homedir carries a trailing slash or not.
	 */
	public function testLegitimateNestedPathIsAccepted()
	{
		mkdir($this->workdir . 'a/etc', 0777, true);

		$result = FileDir::makeCorrectDir($this->workdir . 'a/etc/', $this->workdir);
		$this->assertEquals($this->workdir . 'a/etc/', $result);

		// same check, homedir passed without its trailing slash
		$result = FileDir::makeCorrectDir($this->workdir . 'a/etc/', rtrim($this->workdir, '/'));
		$this->assertEquals($this->workdir . 'a/etc/', $result);
	}

	/**
	 * path == homedir itself must be accepted
	 */
	public function testHomedirItselfIsAccepted()
	{
		$result = FileDir::makeCorrectDir($this->workdir, $this->workdir);
		$this->assertEquals($this->workdir, $result);
	}

	/**
	 * regression test for the off-by-one that allowed a symlinked intermediate path
	 * component to slip through when the checked path is already a clean, normalized,
	 * single-slash path (e.g. re-validating a previously stored destination, as
	 * ExportCron does at cron-time). Before the fix this call did NOT throw and
	 * resolved straight through the symlink.
	 */
	public function testSymlinkedIntermediateComponentIsRejectedOnCleanPath()
	{
		mkdir($this->workdir . 'a/etc', 0777, true);
		mkdir($this->outsidedir . 'etc', 0777, true);

		exec('rm -rf ' . escapeshellarg($this->workdir . 'a'));
		symlink($this->outsidedir, $this->workdir . 'a');

		$this->expectExceptionMessage('Found symlink pointing outside of customer home directory: a');
		FileDir::makeCorrectDir($this->workdir . 'a/etc/', $this->workdir);
	}

	/**
	 * same attack, but built the way most API commands construct the path
	 * ($homedir . '/' . $path), which produces a double slash at the boundary.
	 * This must be rejected as well - this is the pattern already covered indirectly
	 * by FtpsTest::testCustomerFtpsAddSymlinkOutsideHomedir(), asserted here directly
	 * against FileDir so a future change to that concatenation pattern can't silently
	 * reopen the gap.
	 */
	public function testSymlinkedIntermediateComponentIsRejectedOnConcatenatedPath()
	{
		mkdir($this->workdir . 'a/etc', 0777, true);
		mkdir($this->outsidedir . 'etc', 0777, true);

		exec('rm -rf ' . escapeshellarg($this->workdir . 'a'));
		symlink($this->outsidedir, $this->workdir . 'a');

		$this->expectExceptionMessage('Found symlink pointing outside of customer home directory: a');
		FileDir::makeCorrectDir($this->workdir . '/' . 'a/etc', $this->workdir);
	}

	/**
	 * original GHSA-75h4 case: symlink as the final path component
	 */
	public function testSymlinkedFinalComponentIsRejected()
	{
		symlink($this->outsidedir, $this->workdir . 'a');

		$this->expectExceptionMessage('Found symlink pointing outside of customer home directory: a');
		FileDir::makeCorrectDir($this->workdir . 'a/', $this->workdir);
	}

	/**
	 * a symlink is fine as long as it still resolves within the customer homedir
	 */
	public function testSymlinkStayingWithinHomedirIsAccepted()
	{
		mkdir($this->workdir . 'real', 0777, true);
		symlink($this->workdir . 'real', $this->workdir . 'a');

		$result = FileDir::makeCorrectDir($this->workdir . 'a/', $this->workdir);
		$this->assertEquals($this->workdir . 'a/', $result);
	}

	/**
	 * relative symlink targets must be resolved relative to the link's own directory
	 * and are rejected the same way if they escape the homedir
	 */
	public function testRelativeSymlinkEscapingHomedirIsRejected()
	{
		mkdir($this->workdir . 'a', 0777, true);
		symlink('../../', $this->workdir . 'a/escape');

		$this->expectExceptionMessage('Found symlink pointing outside of customer home directory: a/escape');
		FileDir::makeCorrectDir($this->workdir . 'a/escape/etc/', $this->workdir);
	}

	/**
	 * regression test: a relative symlink target using '..' must be resolved lexically
	 * before the homedir-prefix check, otherwise it can lexically "start with" the
	 * homedir while actually escaping to a sibling directory - e.g. another customer's
	 * webspace one level up from the customer's own homedir.
	 */
	public function testRelativeSymlinkEscapingToSiblingIsRejected()
	{
		mkdir($this->workdir . 'a', 0777, true);
		mkdir($this->outsidedir . 'secret', 0777, true);
		file_put_contents($this->outsidedir . 'secret/data.txt', 'top secret');

		// relative target, resolves (lexically) to $this->outsidedir/secret:
		// one '..' to leave 'a', one more to leave $workdir itself, then into the sibling
		$relative_target = '../../' . basename(rtrim($this->outsidedir, '/')) . '/secret';
		symlink($relative_target, $this->workdir . 'a/escape');

		$this->expectExceptionMessage('Found symlink pointing outside of customer home directory: a/escape');
		FileDir::makeCorrectDir($this->workdir . 'a/escape/', $this->workdir);
	}

	/**
	 * a relative symlink that still resolves within the homedir must be accepted
	 */
	public function testRelativeSymlinkStayingWithinHomedirIsAccepted()
	{
		mkdir($this->workdir . 'a/real', 0777, true);
		mkdir($this->workdir . 'sub', 0777, true);
		// one '..' leaves 'sub', landing back in $workdir, then into 'a/real'
		symlink('../a/real', $this->workdir . 'sub/link');

		$result = FileDir::makeCorrectDir($this->workdir . 'sub/link/', $this->workdir);
		$this->assertEquals($this->workdir . 'sub/link/', $result);
	}

	/**
	 * a sibling directory whose name merely starts with the same characters as the
	 * homedir (e.g. "foo" vs "foobar") must not be treated as being inside it - this
	 * guards against a naive string-prefix comparison.
	 */
	public function testSiblingDirectoryWithSimilarNameIsRejected()
	{
		$homedir = rtrim($this->workdir, '/') . '_foo/';
		$sibling = rtrim($this->workdir, '/') . '_foobar/';
		mkdir($homedir, 0777, true);
		mkdir($sibling, 0777, true);

		$this->expectExceptionMessage('Target path not within the required customer home directory');
		FileDir::makeCorrectDir($sibling, $homedir);
	}

	/**
	 * without a $fixed_homedir, no symlink validation is performed at all - this is
	 * intentional/opt-in behaviour, asserted here so it stays a conscious choice
	 */
	public function testNoValidationWithoutFixedHomedir()
	{
		$target = $this->workdir . 'target';
		mkdir($target, 0777, true);
		symlink($target, $this->workdir . 'a');

		$result = FileDir::makeCorrectDir($this->workdir . 'a/');
		$this->assertEquals($this->workdir . 'a/', $result);
	}

	/**
	 * makeCorrectDir() always returns a path with leading and trailing slash
	 */
	public function testReturnValueHasLeadingAndTrailingSlash()
	{
		$result = FileDir::makeCorrectDir('some/relative/path');
		$this->assertStringStartsWith('/', $result);
		$this->assertStringEndsWith('/', $result);
	}

	/**
	 * makeCorrectFile() is the sibling of makeCorrectDir() and already normalizes
	 * $fixed_homedir correctly - kept under test so it can't regress independently
	 */
	public function testMakeCorrectFileRejectsSymlinkedIntermediateComponent()
	{
		mkdir($this->workdir . 'a', 0777, true);

		exec('rm -rf ' . escapeshellarg($this->workdir . 'a'));
		symlink($this->outsidedir, $this->workdir . 'a');

		$this->expectExceptionMessage('Found symlink pointing outside of customer home directory: a');
		FileDir::makeCorrectFile($this->workdir . 'a/export.tar.gz', $this->workdir);
	}

	public function testMakeCorrectFileAcceptsLegitimateNestedFile()
	{
		mkdir($this->workdir . 'a', 0777, true);

		$result = FileDir::makeCorrectFile($this->workdir . 'a/export.tar.gz', $this->workdir);
		$this->assertEquals($this->workdir . 'a/export.tar.gz', $result);
	}
}
