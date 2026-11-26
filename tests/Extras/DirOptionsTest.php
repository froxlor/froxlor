<?php
use PHPUnit\Framework\TestCase;

use Froxlor\Api\Commands\Admins;
use Froxlor\Api\Commands\Customers;
use Froxlor\Api\Commands\DirOptions;

/**
 *
 * @covers \Froxlor\Api\ApiCommand
 * @covers \Froxlor\Api\ApiParameter
 * @covers \Froxlor\Api\Commands\DirOptions
 */
class DirOptionsTest extends TestCase
{

	public function testCustomerDirOptionsAdd()
	{
		global $admin_userdata;

		// get customer
		$json_result = Customers::getLocal($admin_userdata, array(
			'loginname' => 'test1'
		))->get();
		$customer_userdata = json_decode($json_result, true)['data'];

		$data = [
			'path' => '/test',
			'options_indexes' => 1,
			'options_cgi' => 1,
			'error404path' => '/404.html',
			'error403path' => '/403.html',
			'error500path' => '/500.html'
		];
		$json_result = DirOptions::getLocal($customer_userdata, $data)->add();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals($customer_userdata['documentroot'] . 'test/', $result['path']);
		$this->assertEquals('1', $result['options_cgi']);
		$this->assertEquals('/403.html', $result['error403path']);
	}

	public function testCustomerDirOptionsAddDuplicatePath()
	{
		global $admin_userdata;

		// get customer
		$json_result = Customers::getLocal($admin_userdata, array(
			'loginname' => 'test1'
		))->get();
		$customer_userdata = json_decode($json_result, true)['data'];

		$data = [
			'path' => '/test',
			'options_indexes' => 0,
			'options_cgi' => 0,
			'error404path' => '/404a.html',
			'error403path' => '/403a.html',
			'error500path' => '/500a.html'
		];
		$this->expectExceptionMessage("Option for path /test/ already exists");
		DirOptions::getLocal($customer_userdata, $data)->add();
	}

	public function testAdminDirOptionsGet()
	{
		global $admin_userdata;

		// get customer
		$json_result = Customers::getLocal($admin_userdata, array(
			'loginname' => 'test1'
		))->get();
		$customer_userdata = json_decode($json_result, true)['data'];

		$data = [
			'id' => 1,
			'loginname' => 'test1'
		];
		$json_result = DirOptions::getLocal($admin_userdata, $data)->get();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals($customer_userdata['documentroot'] . 'test/', $result['path']);
	}

	public function testResellerDirOptionsGet()
	{
		global $admin_userdata;
		// get reseller
		$json_result = Admins::getLocal($admin_userdata, array(
			'loginname' => 'reseller'
		))->get();
		$reseller_userdata = json_decode($json_result, true)['data'];
		$reseller_userdata['adminsession'] = 1;
		// get customer
		$json_result = Customers::getLocal($admin_userdata, array(
			'loginname' => 'test1'
		))->get();
		$customer_userdata = json_decode($json_result, true)['data'];

		$data = [
			'id' => 1,
			'loginname' => 'test1'
		];
		$json_result = DirOptions::getLocal($reseller_userdata, $data)->get();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals($customer_userdata['documentroot'] . 'test/', $result['path']);
	}

	public function testCustomerDirOptionsGetNotFound()
	{
		global $admin_userdata;

		// get customer
		$json_result = Customers::getLocal($admin_userdata, array(
			'loginname' => 'test1'
		))->get();
		$customer_userdata = json_decode($json_result, true)['data'];

		$data = [
			'id' => 1337
		];
		$this->expectExceptionMessage("Directory option with id #1337 could not be found");
		DirOptions::getLocal($admin_userdata, $data)->get();
	}

	public function testCustomerDirOptionsUpdate()
	{
		global $admin_userdata;

		// get customer
		$json_result = Customers::getLocal($admin_userdata, array(
			'loginname' => 'test1'
		))->get();
		$customer_userdata = json_decode($json_result, true)['data'];

		$data = [
			'id' => 1,
			'options_indexes' => 0,
			'options_cgi' => 0,
			'error403path' => '/403-test.html'
		];
		$json_result = DirOptions::getLocal($customer_userdata, $data)->update();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals($customer_userdata['documentroot'] . 'test/', $result['path']);
		$this->assertEquals('0', $result['options_cgi']);
		$this->assertEquals('/403-test.html', $result['error403path']);
	}

	public function testAdminDirOptionsList()
	{
		global $admin_userdata;

		// get customer
		$json_result = Customers::getLocal($admin_userdata, array(
			'loginname' => 'test1'
		))->get();
		$customer_userdata = json_decode($json_result, true)['data'];

		$json_result = DirOptions::getLocal($admin_userdata)->listing();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals(1, $result['count']);
		$this->assertEquals($customer_userdata['documentroot'] . 'test/', $result['list'][0]['path']);

		$json_result = DirOptions::getLocal($admin_userdata)->listingCount();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals(1, $result);
	}

	/**
	 *
	 * @depends testAdminDirOptionsList
	 */
	public function testCustomerDirOptionsDelete()
	{
		global $admin_userdata;

		// get customer
		$json_result = Customers::getLocal($admin_userdata, array(
			'loginname' => 'test1'
		))->get();
		$customer_userdata = json_decode($json_result, true)['data'];

		$data = [
			'id' => 1
		];
		$json_result = DirOptions::getLocal($customer_userdata, $data)->delete();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals($customer_userdata['documentroot'] . 'test/', $result['path']);

		$data = [
			'id' => 1
		];
		$this->expectExceptionMessage("Directory option with id #1 could not be found");
		DirOptions::getLocal($admin_userdata, $data)->get();
	}

	public function testCustomerDirOptionsAddMalformed()
	{
		global $admin_userdata;

		// get customer
		$json_result = Customers::getLocal($admin_userdata, array(
			'loginname' => 'test1'
		))->get();
		$customer_userdata = json_decode($json_result, true)['data'];

		$data = [
			'path' => '/testmalformed',
			'error404path' => '/"'.PHP_EOL.'something/../../../../weird 404.html'.PHP_EOL.'#'
		];
		// quotes and comment-signs would end up in the webserver-configuration
		$this->expectExceptionMessage("The value given as ErrorDocument does not seem to be a valid file, URL or string.");
		DirOptions::getLocal($customer_userdata, $data)->add();
	}

	public function testCustomerDirOptionsAddFileWithSpace()
	{
		global $admin_userdata;

		// get customer
		$json_result = Customers::getLocal($admin_userdata, array(
			'loginname' => 'test1'
		))->get();
		$customer_userdata = json_decode($json_result, true)['data'];

		$data = [
			'path' => '/testspace',
			'error404path' => '/errors/../weird 404.html',
			'error403path' => 'https://www.froxlor.org/403.html',
			'error500path' => '"Something went wrong"'
		];
		$json_result = DirOptions::getLocal($customer_userdata, $data)->add();
		$result = json_decode($json_result, true)['data'];
		$this->assertEquals('/errors/./weird\ 404.html', $result['error404path']);
		$this->assertEquals('https://www.froxlor.org/403.html', $result['error403path']);
		$this->assertEquals('"Something went wrong"', $result['error500path']);
		DirOptions::getLocal($customer_userdata, ['id' => $result['id']])->delete();
	}

	/**
	 * @dataProvider configBreakingErrorDocuments
	 */
	public function testCustomerDirOptionsAddConfigBreakingValue(string $field, string $value)
	{
		global $admin_userdata;

		// get customer
		$json_result = Customers::getLocal($admin_userdata, array(
			'loginname' => 'test1'
		))->get();
		$customer_userdata = json_decode($json_result, true)['data'];

		$this->expectExceptionMessage("The value given as ErrorDocument does not seem to be a valid file, URL or string.");
		DirOptions::getLocal($customer_userdata, [
			'path' => '/testbreaking',
			$field => $value
		])->add();
	}

	public function configBreakingErrorDocuments(): array
	{
		return [
			['error404path', '/404.html}'],
			['error403path', '/403.html{'],
			['error500path', '/500.html#'],
			['error404path', "/404'.html"],
			['error403path', 'https://www.froxlor.org/$host'],
			['error403path', 'https://www.froxlor.org/a;b'],
			['error500path', '"costs $uri"'],
			['error500path', '"ends with backslash\\"']
		];
	}

	public function testCustomerDirOptionsAddMalformedInvalid()
	{
		global $admin_userdata;

		// get customer
		$json_result = Customers::getLocal($admin_userdata, array(
			'loginname' => 'test1'
		))->get();
		$customer_userdata = json_decode($json_result, true)['data'];

		$data = [
			'path' => '/testmalformed',
			'error404path' => '"'.PHP_EOL.'IncludeOptional /something/else/'.PHP_EOL.'#'
		];
		$this->expectExceptionMessage("The value given as ErrorDocument does not seem to be a valid file, URL or string.");
		DirOptions::getLocal($customer_userdata, $data)->add();

		$data = [
			'path' => '/testmalformed',
			'error404path' => '"something"oh no a quote within the string"'
		];
		$this->expectExceptionMessage("The value given as ErrorDocument does not seem to be a valid file, URL or string.");
		DirOptions::getLocal($customer_userdata, $data)->add();
	}
}
