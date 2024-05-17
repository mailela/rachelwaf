<?php

namespace RACHEL_WAF;
//当前程序版本
define("RACHEL_WAF_VERSION", "1.0.8");
// 官方升级地址
define("RACHEL_WAF_UPDATE_API", "Wk1OMWtRYWZoOGM5RURscy8veEJOQTk0OElpNzRlYXhnVWdKSUZHckxCYU1QSlV2dzF3OVkwSk1wY3hrQ2JHbTFpak5Cd3VITGpMMHRWeHJ0MVpSWFNFdklWTm9pZDZhajJKRzk4T1Yyd2Fpck42UHpXdTFqOEk0SCtBSFdnNzc=");

class _Env
{
	public static $defined=array();
	const ENV_PREFIX = 'RACHEL_';
	public static function put_env($key,$val){
		if (self::state()){
			putenv("$key=$val");
		}else{
			self::$defined[$key]=$val;
		}
	}
	public static function get_env($key){
		if (self::state()){
			return getenv($key);
		}else{
			$val=@self::$defined[$key];
			return is_null($val)?false:$val;
		}
	}
	/**    
	 * 加载配置文件    
	 * @access public    
	 * @params string $filePath 配置文件路径    
	 * @return void    
	 * */
	public static function loadFile($filePath)
	{
		if (!file_exists($filePath)) {
			// throw new \Exception('配置文件' . $filePath . '不存在');
		}
		$env = parse_ini_file($filePath, true, INI_SCANNER_RAW);
		foreach ($env as $key => $val) {
			$prefix = static::ENV_PREFIX . strtoupper($key);
			if (is_array($val)) {
				foreach ($val as $k => $v) {
					$item = $prefix . '_' . strtoupper($k);
					self::put_env($item,$v);
					// var_dump($item,getenv($item),$v);
				}
			} else {
				putenv("$prefix=$val");
				// var_dump($prefix,getenv($prefix),$val);
			}
		}
		return "";
	}
	/**    
	 *  获取环境变量值    
	 *  @access public    
	 *  @params string $name 环境变量名(支持二级 . 号分割)    
	 *  @params string $default 默认值    
	 *  @return mixed    
	 * */
	public static function get($name, $default = null)
	{
		$result = self::get_env(static::ENV_PREFIX . strtoupper(str_replace('.', '_', $name)));
		if (false !== $result) {
			if ('false' === $result) {
				$result = false;
			} elseif ('true' === $result) {
				$result = true;
			}
			// var_dump($name,$result);
			return $result;
		}
		return $default;
	}
	public static function state(){
		return function_exists("getenv")&&function_exists("putenv");
	}
}
class Encode
{
	private $encode_key, $iv, $is_encode, $encode_type;
	private static $_instance;
	public static function getInstance($key = "", $encode_type = "AES-128-CBC")
	{
		global $config;
		if (self::$_instance instanceof self) {
			return self::$_instance;
		}
		self::$_instance = new self($key, $encode_type);
		return self::$_instance;
	}
	function __construct($key = "", $encode_type = "AES-128-CBC", $is_enable = true)
	{
		if (empty($key)) {
			$this->encode_key = substr(md5("d0f92b9dce0a5447d7aba4750942f5d6"), 0, 16);
		} else {
			$this->encode_key = substr($key, 0, 16);
		}
		$this->encode_type = $encode_type;
		$this->iv = $this->get_iv();
		$this->is_encode = $is_enable;
	}
	function state($is_enable = true)
	{
		$this->is_encode = $is_enable;
	}

	function get_iv()
	{
		$len = openssl_cipher_iv_length($this->encode_type);
		return substr(sha1($this->encode_key), 0, 16);
	}
	function encode($data)
	{
		// 添加加密逻辑，比如使用AES算法、RSA公钥/私钥等
		if ($this->is_encode) {
			return base64_encode(openssl_encrypt($data, 'AES-128-CBC', $this->encode_key, 0, $this->iv));
		}
		return $data;
	}
	function decrypt($data)
	{
		// 添加解密逻辑，与上面相同的加密算法和密钥
		if ($this->is_encode) {
			return openssl_decrypt(base64_decode($data), 'AES-128-CBC', $this->encode_key, 0, $this->iv);
		}
		return $data;
	}
}
class Res
{
	public $file = "";
	private $res_type, $encode_type;
	private $enc;
	function __construct($path, $key = "", $res_type = "object", $is_encode = true, $encode_type = "AES-128-CBC")
	{
		$this->enc = new Encode($key, $encode_type);
		$this->enc->state($is_encode);
		$this->res_type = $res_type;
		$this->file = $path;
	}

	function encode($data)
	{
		$data = gzencode($data);
		return $this->enc->encode($data);
	}
	function decrypt($data)
	{
		return gzdecode($this->enc->decrypt($data));
	}
	/**
	 * 加载资源
	 */
	function load($args = "")
	{
		switch ($this->res_type) {
			case "json":
				return $this->load_json($args);
				break;
			default:
				return $this->load_object();
				break;
		}
	}
	/**
	 * 保存资源
	 */
	function save($object)
	{
		switch ($this->res_type) {
			case "json":
				return $this->save_json($object);
				break;
			default:
				return $this->save_object($object);
				break;
		}
	}
	/**
	 * 操作对象数据
	 */
	function load_object()
	{
		$data = unserialize($this->decrypt(file_get_contents($this->file)));
		return  $data;
	}

	function save_object($object)
	{
		$str = $this->encode(serialize($object));
		file_put_contents($this->file, $str);
		return $object;
	}
	/**
	 * 操作JSON数据
	 */
	function save_json($object)
	{
		$arr = array();
		foreach ($object as $k => $v) {
			$arr[$k] = $v;
		}
		$str = json_encode($arr, JSON_UNESCAPED_UNICODE);
		$str = $this->encode($str);
		file_put_contents($this->file, $str);
		return $object;
	}
	function load_json($object)
	{
		$data = file_get_contents($this->file);
		$data = $this->decrypt($data);
		$data = json_decode($data, true);
		foreach ($data as $k => $v) {
			$object->$k = $v;
		}
		return  $object;
	}
}
class ConfigManager
{
	// 功能开启选项
	public $WAF_APP_NAME = "RACHEL WAF应用防火墙";
	public $WAF_LOGO = '<svg  fill="#ff6600" width=100 height=100  t="1714882901802" class="icon" viewBox="0 0 1024 1024" version="1.1" xmlns="http://www.w3.org/2000/svg" p-id="6266" xmlns:xlink="http://www.w3.org/1999/xlink" width="200" height="200"><path d="M832.44 316.158v120.076c0-16.58 13.44-30.02 30.018-30.02 16.58 0 30.02 13.44 30.02 30.02v74.752c0 165.324-127.136 314.994-381.405 449.014C258.357 825.98 132 676.309 132 510.986v-312.89L512.239 64l380.238 134.096v118.062c0 16.58-13.44 30.019-30.019 30.019s-30.019-13.44-30.019-30.019z m0 194.988V247.678L512.238 134.763 192.038 247.678v263.468c0 139.21 106.406 265.24 319.219 378.09 214.122-112.85 321.182-238.88 321.182-378.09z m-177.467 15.422h-226.9c0.977 34.592 10.455 61.317 28.435 80.177 17.98 18.86 43.094 28.289 75.34 28.289 36.352 0 69.673-11.628 99.966-34.885v51.302c-28.534 20.13-66.35 30.194-113.45 30.194-46.905 0-83.5-14.853-109.786-44.559-26.286-29.706-39.43-70.943-39.43-123.71 0-49.641 14.414-90.584 43.24-122.831 28.828-32.247 64.64-48.37 107.441-48.37 42.41 0 75.536 13.631 99.379 40.894 23.843 27.264 35.765 65.422 35.765 114.476v29.023z m-57.458-46.025c-0.196-29.316-7.134-51.986-20.814-68.012-13.68-16.026-32.93-24.038-57.751-24.038-22.866 0-42.654 8.501-59.364 25.504-16.71 17.003-27.214 39.185-31.514 66.546h169.443z" p-id="6267"></path></svg>';
	// level处理
	public $waf_headers = 1;  // headers防御
	public $waf_white_ip = 0;  // ip防御
	public $waf_ddos = 0;  // ddos防御
	public $waf_black_ip = 0; //拒绝访问IP
	public $waf_upload = 1;  // 上传限制
	public $waf_ony_log = 0; //仅记录日志
	public $waf_upload_flag = 1;  // 上传防御
	public $waf_special_char = 1; // 特殊字符防御
	public $waf_sql = 1;  // sql防御
	public $waf_rce = 0;  // rce防御
	public $waf_ld_preload = 1;    //基于LD_PRELOAD的rce防护
	public $waf_lfi = 0;  // LFI/LFR 防御
	public $waf_unserialize = 1; // phar反序列化防御
	public $waf_flag = 0;  // flag防御
	public $response_content_match = 0; // 匹配响应中有无flag特征
	public $waf_debug = 1;  // debug模式
	public $waf_out_header = 0;  // 模拟 Header("HTTP/1.1 404 Not Found")
	public $scheduled_kill_all = 0;
	public $waf_print_logo = 1; //是否输出LOGO
	public $encode_api = 0; //是否加密API
	public $max_login_err = 6; //最大登录错误次数
	public $max_login_lock_time = 300; //帐户锁定时长
	public $max_token_live_time = 3600; //会话保存时长
	public $one_token = 1; // 同一用户一个会话
	public $water_mark = 1; // 开启水印


	public $waf_upgrade_server_enable = 0; //更新升级API启用
	public $waf_upgrade_check = 1; //检查更新
	public $waf_upgrade_api = ""; //更新升级API
	public $waf_upgrade_build_path = ""; //最新版本打包位置
	public $waf_upgrade_no_login = 1; //是否需要登录才能更新

	public $ip_address_manage_allow = "0.0.0.0/0";  // 允许管理访问的IP段  如:192.168.0.1/24 多个用,连接
	public $ip_address_allow = "0.0.0.0/0";  // 允许访问的IP段  如:192.168.0.1/24 多个用,连接
	public $WAF_FLAG_ENTER = "WAF";
	public $attack_time = 3600000;  // 封锁有攻击行为IP时长 默认一个小时
	public $ip_address_deny = "";  // 允许访问的IP段  如:192.168.0.1/24 多个用,连接


	//名单配置
	public $upload_whitelist = "/jpg|png|gif|txt|mp3|mp4|doc|docx|zip/i";  // upload白名单
	public $sql_blacklist = "/drop |dumpfile\b|INTO FILE|union select|outfile\b|multipoint\(/i";
	public $rce_blacklist = "/`|var_dump|str_rot13|serialize|base64_encode|base64_decode|strrev|eval\(|assert|file_put_contents|fwrite|curl_exec\(|dl\(|readlink|popepassthru|preg_replace|create_function|array_map|call_user_func|array_filter|usort|stream_socket_server|pcntl_exec|passthru|exec\(|system\(|chroot\(|scandir\(|chgrp\(|chown|shell_exec|proc_open|proc_get_status|popen\(|ini_alter|ini_restore|ini_set|LD_PRELOAD|ini_alter|ini_restore|ini_set|base64 -d/i";
	public $head_string = "HTTP/1.1 555 WAF DENY";  // 被拦截时输出头信息
	public $waf_special_char_blacklist = "/\`|\'/i";  // 特殊字符黑名单
	public $log_refresh = 1;
	public $waf_fake_flag = "flag{Longlone:W0r1<_HaRd3r}";  // 虚假flag,需开启waf_flag
	public $remote_ip = "127.0.0.1";    //	服务器ip
	public $remote_port = 80;    //	服务器端口
	public $max_log_size = 40000;	//单个日志文件最大大小
	public $allow_ddos_time = 10;  // 每秒最多5个访问 
	public $ding_ding_notice = 0; //钉钉通知
	public $api_notice = 0; 	//API通知
	public $browser_notice = 1; //浏览器通知
	public $ding_ding_webhook = "";
	public $api_webhook = "http://waf.com/notice.php"; //API通知地址
	public $api_webhook_body_template = '{"message":"msg","url":"url","title":"title"}'; //API通知模板

	public $password_sha1 = 'unset';
	public $flag_path = '/flag';  // 自己flag所在的路径
	public $LD_PRELOAD_PATH = __WAF_SO_ROOT__;    //共享库路径
	public $open_basedir = '/';
	public $level = 4;  // 0~4 等级越高,防护能力越强,默认为4
	public $version = RACHEL_WAF_VERSION;

	public $users = array(); //帐户列表
	public $roles = array(); //角色列表
	function __construct()
	{
		$this->waf_upgrade_build_path = str_replace("\\", "/", __DIR__ . "/waf.txt");
	}
	function set($key, $val)
	{
		return $this->change($key, $val, true);
	}
	function change($key, $val, $is_object = false)
	{
		global $config_path;
		$this->$key = $val;

		$data["code"] = 200;
		$data["msg"] = "success";
		$data["data"] = array($key => $val);
		if ((is_object($val) || is_array($val)) && !$is_object) {
			return false;
		}
		if (is_numeric($val)) {
			$this->$key = intval($val);
		}
		$res = new Res($config_path, _Env::get("WAF.KEY", md5("RACH")), "json", _Env::get("WAF.ENCODE", false), "AES-256-CBC");
		return $res->save($this);
	}
}
class ApiNotice
{
	private $webhook, $template;
	function __construct($webhook, $template = "")
	{
		$this->webhook = $webhook;
		$this->template = $template;
	}
	function fix($data)
	{
		$arr = json_decode($this->template, true);
		foreach ($arr as $k => $v) {
			$data[$v] = @$data[$k];
			unset($data[$k]);
		}
		return $data;
	}
	function send_api($title = '', $message = "", $url = "")
	{
		if (empty($this->webhook)) {
			return json_encode(array("code" => 10000, "msg" => "未配置钉钉webhook"));
		}
		$data = array(
			"title" => $title,
			"url" => $url,
			"message" => $message,
		);
		$data = $this->fix($data);
		return $this->curl_post_json($this->webhook, $data);
	}
	//curl发送json数据
	function curl_post_json($url, $data = array(), $header = array(), $timeout = 80, $port = 80)
	{
		$curl = curl_init($url);
		curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
		curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, false);
		curl_setopt($curl, CURLOPT_POST, 1);
		curl_setopt($curl, CURLOPT_POSTFIELDS, json_encode($data, 320));
		curl_setopt($curl, CURLOPT_HEADER, 0);
		curl_setopt($curl, CURLOPT_HTTPHEADER, array('Content-Type: application/json'));
		curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
		$res = curl_exec($curl);
		curl_close($curl);
		return $res;
	}

	function send($msgContent = "", $title = "WAF通知消息", $url = "")
	{
		$msg = $title . "\n" . $msgContent;
		return $this->send_api($title, $msg, $url);
	}
}
class DingDing
{
	private $webhook;
	function __construct($webhook)
	{
		$this->webhook = $webhook;
	}
	function send_ding_talk_markdown($title = '', $message = "",  $atMobiles = array(), $atUserIds = array())
	{
		if (empty($this->webhook)) {
			return json_encode(array("code" => 10000, "msg" => "未配置钉钉webhook"));
		}
		$data = array(
			"msgtype" => "markdown",
			"markdown" => array(
				"title" => $title,
				"text" => $message
			),
			"at" => array(
				"atMobiles" => $atMobiles,
				"isAtAll" => false
			)
		);
		return $this->curl_post_json($this->webhook, $data);
	}
	//curl发送json数据
	function curl_post_json($url, $data = array(), $header = array(), $timeout = 80, $port = 80)
	{
		$curl = curl_init($url);
		curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
		curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, false);
		curl_setopt($curl, CURLOPT_POST, 1);
		curl_setopt($curl, CURLOPT_POSTFIELDS, json_encode($data, 320));
		curl_setopt($curl, CURLOPT_HEADER, 0);
		curl_setopt($curl, CURLOPT_HTTPHEADER, array('Content-Type: application/json'));
		curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
		$res = curl_exec($curl);
		curl_close($curl);
		return $res;
	}

	function send($msgContent = "", $title = "WAF通知消息")
	{
		$msg = $title . "\n" . $msgContent;
		return $this->send_ding_talk_markdown($title, $msg);
	}
}

class IPTools
{
	private static $_instance;
	public static function getInstance()
	{
		if (self::$_instance instanceof self) {
			return self::$_instance;
		}
		self::$_instance = new self();
		return self::$_instance;
	}

	function getRealIp()
	{
		$ip = false;
		if (!empty($_SERVER["HTTP_CLIENT_IP"])) {
			$ip = $_SERVER["HTTP_CLIENT_IP"];
		}
		if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
			$ips = explode(", ", $_SERVER['HTTP_X_FORWARDED_FOR']);
			if ($ip) {
				array_unshift($ips, $ip);
				$ip = FALSE;
			}
			for ($i = 0; $i < count($ips); $i++) {
				if (!preg_match("^(10│172.16│192.168).", $ips[$i])) {
					$ip = $ips[$i];
					break;
				}
			}
		}
		return ($ip ? $ip : $_SERVER['REMOTE_ADDR']);
	}
	/**
	 * 判断IP是否在此段内
	 * $ip 要判定的IP
	 * $rang IP段 支持192.168.0.0/24 或 192.168.0.1-192.168.0.254
	 */
	function in_Ip_address($ip, $ip_range, &$return_ip_range = array())
	{
		$list = explode(",", $ip_range);
		$flag = false;
		foreach ($list as $k => $rang) {
			$start_ip = "";
			$end_ip = "";
			if ($rang == "*") {
				$flag = true;
				break;
			}
			if (strstr($rang, "/")) {
				list(, $mark, $start_ip, $end_ip) = $this->ip_parse($rang);
			}
			if (strstr($rang, "-")) {
				$arr = explode("-", $rang);
				$start_ip = @$arr[0];
				$end_ip = @$arr[1];
			}
			if (empty($start_ip) || empty($end_ip)) {
				$start_ip = $rang;
				$end_ip = $rang;
			}
			$return_ip_range[] = array(
				$start_ip,
				$end_ip
			);
			$flag = $this->in_ip_area($ip, $start_ip, $end_ip);
			if ($flag) {
				break;
			}
		}
		return $flag;
	}

	/**
	 * //演示：
	 * list($ip, $mark, $ip_start, $ip_end) = ip_parse("192.168.1.12/24");
	 * echo "IP地址 : ", long2ip($ip), "\n";
	 * echo "子网掩码: ", long2ip($mark), "\n";
	 * echo "IP段开始: ", long2ip($ip_start), "\n";
	 * echo "IP段结束: ", long2ip($ip_end), "\n";
	 */
	function ip_parse($ip_str)
	{
		$mark_len = 32;
		if (strpos($ip_str, "/") > 0) {
			list($ip_str, $mark_len) = explode("/", $ip_str);
		}
		$ip = $this->get_ip_long($ip_str);
		if ($mark_len > 32) {
			$mark_len = 32;
		}
		$mark = 0xFFFFFFFF << (32 - $mark_len) & 0xFFFFFFFF;
		$ip_start = $ip & $mark;
		$ip_end = $ip | (~$mark) & 0xFFFFFFFF;
		return array(long2ip($ip), $mark, long2ip($ip_start), long2ip($ip_end));
	}


	//IP地址 : 192.168.1.12
	//子网掩码: 255.255.255.0
	//IP段开始: 192.168.1.0
	//IP段结束: 192.168.1.255
	function in_ip_area($ip, $ip_start, $ip_end)
	{
		// echo $ip_start."-";
		// echo $ip_end."<br/>";
		$ip = $this->get_ip_long($ip);
		$ip_end = $this->get_ip_long($ip_end);
		$ip_start = $this->get_ip_long($ip_start);
		if ($ip >= $ip_start && $ip <= $ip_end || ($ip_end == 0 && $ip_start == 0)) {
			return true;
		}
		return false;
	}
	function get_ip_long($ip)
	{
		//之所以要decbin和bindec一下是为了防止IP数值过大int型存储不了出现负数。
		if (is_string($ip)) {
			return bindec(decbin(ip2long($ip)));
		}
		return $ip;
	}
}
/*
	WAF类
	*/

class WAF
{
	private $ip_addr;
	private $request_url;
	private $request_method;
	private $request_data;
	private $headers;
	private $raw;
	private $dir;
	private $log_dir;
	private $upload_dir;
	private $token_dir;
	private $ip_dir;
	private $allow_time;
	private $response_content;
	private $timestamp;


	function __construct()
	{
		// 	echo $_SERVER['SERVER_PORT']."\n";
		global $config, $content_dis_allow, $waf_fake_flag2;

		$content_dis_allow = "/" . $this->get_preg_flag() . "not_a_regular_exression/"; //  一定要保证不和正常内容冲突
		$waf_fake_flag2 = $this->get_fake_flag();  //	高级的虚假flag,用于当对面即将获得flag但是被深度检测拦截的时候
		// $content_dis_allow = '/' . trim(file_get_contents($config->flag_path)) . '/'; //  一定要保证不和正常内容冲突

		$this->dir = __WAF_ROOT__;
		$this->log_dir = $this->dir . 'log/';
		$this->upload_dir = $this->dir . 'upload/';
		$this->ip_dir = $this->dir . 'ip/';
		$this->token_dir = $this->dir . 'token/';
		if ($config->waf_ld_preload == 1) {
			putenv("LD_PRELOAD=" . $config->LD_PRELOAD_PATH);
		}
		$this->headers = $this->getAllHeaders(); //获取header  
		foreach ($this->headers as $key => $val) {
			if ($val == "") {
				unset($this->headers[$key]);
			}
		}
		$this->timestamp =  self::getMillisecond();
		if ($config->open_basedir !== '/') {
			ini_set("open_basedir", $config->open_basedir . ':/tmp/');
		}
		if (isset($_SERVER['HTTP_WAFTOKEN']) && file_exists($this->token_dir . $_SERVER['HTTP_WAFTOKEN'])) {
			unlink($this->token_dir . $_SERVER['HTTP_WAFTOKEN']);
			putenv("php_timestamp=" . $_SERVER['HTTP_WAFTIMESTAMP']);
			return 0;
		} else {
			putenv("php_timestamp=" . $this->timestamp);	// 用于ld_preload rce防护记录日志
		}
		$this->allow_time = $config->allow_ddos_time;  // 获取每秒最大访问次数
		if ($config->waf_ddos == true) {
			$this->watch_ddos();
		}
		if ($config->waf_white_ip == true) {
			if ($this->waf_white_ip()) {
				return;
			}
		}
		$this->e_mkdir($this->dir);
		$this->e_mkdir($this->log_dir);
		$this->e_mkdir($this->upload_dir);
		$this->e_mkdir($this->ip_dir);
		$this->e_mkdir($this->token_dir);
		$this->request_url = $this->filter_0x25(urldecode($_SERVER['REQUEST_URI'])); //	获取url来进行检测
		$this->request_data = file_get_contents('php://input');	//	获取post

		if ($config->waf_black_ip == true) {
			$this->waf_black_ip();
		}

		if ($config->waf_headers == true) {
			$this->watch_headers();  // 监测headers
		}



		$this->write_access_log_probably();  //	记录访问纪录, 类似于日志
		$this->write_access_logs_detailed();  //	记录详细访问请求包  
		if ($config->waf_upload == true) {
			$this->watch_upload();  // 记录上传纪录
		}
		if ($_SERVER['REQUEST_METHOD'] != 'POST' && $_SERVER['REQUEST_METHOD'] != 'GET') {
			$method = $_SERVER['REQUEST_METHOD'];
			$this->write_attack_log("Catch attack: Suspicious method [ " . $method . "] "); //可疑请求

		}
		foreach ($_GET as $keywords) {   //	监测GET参数，出现问题则记录
			$this->watch_attack_keyword($this->watch_special_char($keywords));
		}
		if ($this->request_data != '') {
			foreach ($_POST as $keywords) {   //	监测POST参数，出现问题则记录
				$this->watch_attack_keyword($this->watch_special_char($keywords));
			}
		}

		if ($config->response_content_match) {   //	深度检测响应包
			ob_end_clean();	// 处理BOM头

			$this->getcontent();  // 开始自检
			if (preg_match($content_dis_allow, $this->response_content) !== 0) {
				$this->write_flag_log();
				die($waf_fake_flag2);
			} else {
				$co = explode("\r\n\r\n", $this->response_content, 2);
				$co = @$co[1];
				$raw_header = explode("\r\n\r\n", $this->response_content, 2);
				$raw_header = @$raw_header[0];
				$res_header = explode("\r\n", $raw_header, 2);
				$res_header = explode("\r\n", $raw_header[1]);
				foreach ($res_header as $leo1) {
					if (stripos($leo1, 'transfer-encoding') !== false) {
						continue;
					}
					header($leo1, true);
				}
				// header("Content-Encoding: identity", true);
				// while (preg_match("/^[0-9,a-z]{5}/", $co)) {
				// 	$co = substr($co, 5);
				// }
				// while (preg_match("/^[0-9,a-z]{4}/",$co)){
				// 	$co=substr($co,4);
				// }

				// $co=substr($co,strpos($co,pack("CCC",0xef,0xbb,0xbf)));  // 处理BOM头
				// if (substr($co,0,3) == pack("CCC",0xef,0xbb,0xbf)){
				// 	$co=substr($co,3);
				// }
				if (substr($co, -7) == "\r\n0\r\n\r\n" && preg_match("/^[0-9, a-f]/", $co)) {
					// $co=rtrim($co,"\r\n0\r\n\r\n");
					// $co .= "\r\n\r\n";
					// header("Transfer-Encoding: chunked", true);	// finally!
					$co = $this->decode_chunked($co);
				}
				die($co);  // 将内容返回给帐户
			}
		}
	}



	//判断文件夹是否存在并创建文件夹
	function e_mkdir($folder)
	{
		if (@is_dir($folder) == false) {
			@mkdir($folder, 0777, true);
			return true;
		}
		return false;
	}
	//删除文件夹下所有文件
	function del_dir($dir)
	{
		$dh = opendir($dir);
		while ($file = readdir($dh)) {
			if ($file != "." && $file != "..") {
				$full_path = $dir . "/" . $file;
				if (!is_dir($full_path)) {
					unlink($full_path);
				} else {
					$this->del_dir($full_path);
				}
			}
		}
	}

	// die并且输出logo
	function logo()
	{
		global $config;

		if ($config->waf_out_header) {
			$arg_list = func_get_args();
			header($config->head_string);
			header("WAF", implode("\n", $arg_list));
		}
		$logo = $config->WAF_LOGO;
		$is_ajax = preg_match("/application\/json/i", $_SERVER['HTTP_ACCEPT']);
		$UAs = array("MSIE", "Firefox", "Chrome", "Safari", "Opera");
		$UA = $_SERVER["HTTP_USER_AGENT"];

		if (count(array_filter(array_map(function ($v1, $v2) {
			return strstr($v1, $v2);
		}, array_fill(0, count($UAs), $UA), $UAs)))) {
		}

		$arg_list = func_get_args();
		$debug_trace = debug_backtrace();
		$source = $debug_trace[1]['function'];
		if ($config->waf_print_logo && !$config->waf_debug && !$is_ajax) {
			echo $logo;
		}
		if ($config->waf_debug && !$config->waf_ony_log) {
			if ($is_ajax) {
				header("content-type:application/json;charset=utf8");
				echo json_encode(array("code" => 555, "black" => $source, "msg" => implode("\n", $arg_list)));
			} else {
				echo "<!DOCTYPE html><html>";
				echo "<meta charset=utf8>";
				echo "<body><center>";
				echo "<title>" . $config->WAF_APP_NAME . "</title>";
				if ($config->waf_print_logo) {
					echo $logo;
				}
				echo "<pre><font color=red>";
				echo $source;
				echo "\n</font><font color=green>";
				echo implode("\n", $arg_list);
				echo "</font></pre>";
				echo "</center>";
				echo "</body></html>";
			}
		}

		//钉钉通知
		$notice_msg = "\n应用:" . $config->WAF_APP_NAME . "\n";
		$notice_msg .= "\n行为:" . $source . "\n";
		$notice_msg .= "\n关键字:" . implode("\n", $arg_list) . "\n";
		$notice_msg .= "\nREMOTE_ADDR:" . $_SERVER['REMOTE_ADDR'] . "\n";
		$notice_msg .= "\nREMOTE_PORT:" . $_SERVER['REMOTE_PORT'] . "\n";
		$notice_msg .= "\nHTTP_USER_AGENT:" . $_SERVER['HTTP_USER_AGENT'] . "\n";
		$notice_msg .= "\nCOOKIE:" . json_encode($_COOKIE) . "\n";
		$notice_msg .= "\nURI:" . $_SERVER['QUERY_STRING'] . "\n";
		if ($config->ding_ding_notice) {
			$dd = new DingDing($config->ding_ding_webhook);
			$dd->send($notice_msg);
		}
		if ($config->api_notice) {
			$dd = new ApiNotice($config->api_webhook, $config->api_webhook_body_template);
			$dd->send($notice_msg);
		}
		// 仅记录日志，不拦截
		if ($config->waf_ony_log) {
			return;
		}
		die();
	}



	// DDOS防御
	function watch_ddos()
	{
		$IP = $_SERVER['REMOTE_ADDR'];
		$IP = str_replace(":", '_', $IP);
		$date = date('H_i_s');
		$IP_dir = $this->ip_dir . '/' . $IP . '/';
		$this->e_mkdir($IP_dir);
		$IP_date_file = $IP_dir . $date . '_log.txt';
		if (is_file($IP_date_file)) {
			$time = intval(file_get_contents($IP_date_file));
			$time += 1;
			if ($time > $this->allow_time) {
				$this->logo($IP);
			} else {
				file_put_contents($IP_date_file, $time, LOCK_EX);
			}
		} else {
			$this->del_dir($IP_dir);
			file_put_contents($IP_date_file, 1, LOCK_EX);
		}
	}


	// 监测headers
	function watch_headers()
	{
		global $config;
		foreach ($this->headers as $k => $v) {
			if (preg_match($config->sql_blacklist, urldecode($v)) || preg_match($config->rce_blacklist, urldecode($v))) {
				$this->headers[$k] = '';
				// $URI = explode('?',$this->request_url);
				// header('Location: http://'.$_SERVER['SERVER_NAME'].':'.$_SERVER["SERVER_PORT"].$URI[0]);
				$this->logo($v);
			}
		}
	}

	// 不允许ip段
	function waf_black_ip()
	{
		global $config;
		$ip = IPTools::getInstance()->getRealIp();
		if (!_Env::get("WAF.WAF_BLACK_IP", $config->waf_black_ip)) {
			return;
		}
		$ip_range = _Env::get("WAF.BLACK_IP", $config->ip_address_deny);
		$is_allow = IPTools::getInstance()->in_Ip_address($ip, $ip_range, $allow_range);  // 监测headers
		if (empty($ip_range)) {
			return;
		}
		if ($is_allow) {
			$this->logo("$ip deny");
		}
	}

	// 允许的IP段
	function waf_white_ip()
	{
		global $config;
		$ip = IPTools::getInstance()->getRealIp();
		$ip_range = $config->ip_address_allow;
		$is_allow = IPTools::getInstance()->in_Ip_address($ip, $ip_range, $allow_range);  // 监测headers
		// var_dump($is_allow,$ip_range,$ip,$allow_range);
		if (!$is_allow) {
			return false;
		}
		return true;
	}
	// 允许管理的的IP段
	function waf_manage_white_ip()
	{

		global $config;
		$ip = IPTools::getInstance()->getRealIp();
		$ip_range = _Env::get("WAF.ALLOW_MANAGE_IP", "");
		$is_allow = IPTools::getInstance()->in_Ip_address($ip, $ip_range, $allow_range);
		$is_allow_cfg = IPTools::getInstance()->in_Ip_address($ip, $config->ip_address_manage_allow, $allow_range);
		if (!$is_allow && !$is_allow_cfg) {
			$this->logo("$ip not allowed ");
		}
	}

	// 监测不可见字符造成的截断和绕过效果，注意网站请求带中文需要简单修改
	function watch_special_char($str)
	{
		global $config;
		$txt = '';
		for ($i = 0; $i < strlen($str); $i++) {
			// $ascii = ord($str[$i]);
			// if($ascii>126 || $ascii < 32){ //	有中文这里要修改
			// 	if(!in_array($ascii, array(9,10,13))){
			// 		$txt .= "Interrupt";
			// 	}else{
			// 		$txt .= "  Catch attack: Suspected attack character < ".$str[$i]. " > ";
			// 	}
			// 	break;
			// }
			if (preg_match($config->waf_special_char_blacklist, $str[$i])) {
				$txt .= "  Catch attack: Suspected attack character < " . $str[$i] . " > ";
				break;
			}
		}
		if ($txt != '') {
			if ($config->waf_special_char == true) {
				$this->write_attack_log($txt);
				$this->logo($txt);
			}
		}
		return $str;
	}
	// 监测文件上传
	function watch_upload()
	{
		global $config, $check_upload_path;
		foreach ($_FILES as $key => $value) {
			if ($_FILES[$key]['error'] == 0) {
				$ext = substr(strrchr($_FILES[$key]["name"], '.'), 1);
				$this->write_attack_log("Catch attack: < Evil Upload, please check " . $this->upload_dir . " dir > ");
				copy($_FILES[$key]["tmp_name"], $this->upload_dir . date("d_H_i_s") . '.' . $ext . '.txt');
				file_put_contents($check_upload_path, "check!");
				if (!preg_match($config->upload_whitelist, $ext)) {
					unlink($_FILES[$key]['tmp_name']);
					$this->logo('Not Allow Upload!' . substr(md5($_FILES[$key]["name"]), 0, rand(10, 30)) . '.' . $ext);
					break;
				}
			}
			if ($config->waf_upload_flag) {
				$new_file_content = file_get_contents($_FILES[$key]['tmp_name']);
				if (preg_match("/<?php/i", $new_file_content) === 1) {
					$this->write_attack_log("Catch attack: < Evil Upload, please check " . $this->upload_dir . " dir > ");
					copy($_FILES[$key]["tmp_name"], $this->upload_dir . date("d_H_i_s") . '.' . $ext . '.txt');
					unlink($_FILES[$key]['tmp_name']);
					$this->logo('Upload Fail.' . substr(md5($_FILES[$key]["name"]), 0, rand(10, 30)) . '.' . $ext);
					break;
				}
			}
		}
	}
	// 监测网站程序存在二次编码绕过漏洞造成的%25绕过，此处是循环将%25替换成%，直至不存在%25
	function filter_0x25($str)
	{
		if (strpos($str, "%25") !== false) {
			$str = str_replace("%25", "%", $str);
			return $this->filter_0x25($str);
		} else {
			return $str;
		}
	}

	// 对非法请求进行重定向
	function redirect()
	{
		$URI = explode('?', $this->request_url);
		header('Location: http://' . $_SERVER['SERVER_NAME'] . ':' . $_SERVER["SERVER_PORT"] . $URI[0]);
		die();
	}

	// 监测攻击关键字
	function watch_attack_keyword($str)
	{
		global $config;
		if (preg_match($config->sql_blacklist, $str)) {
			if ($config->waf_sql == true) {
				$this->write_attack_log("Catch attack: < SQLI > ");
				$this->logo($str);
			}
		}
		if (substr_count($str, $_SERVER['PHP_SELF']) < 2) {
			$tmp = str_replace($_SERVER['PHP_SELF'], "", $str);
			if (preg_match("/.*\.php[2357]{0,1}|\.phtml/i", $tmp)) {
				if ($config->waf_lfi == true) {
					$this->write_attack_log("Catch attack: < LFI/LFR > ");
					$this->logo("Catch attack: < LFI/LFR >" . $str);
				}
			}
		} else {
			if ($config->waf_lfi == true) {
				$this->write_attack_log("Catch attack: < LFI/LFR > ");
				$this->logo("Catch attack: < LFI/LFR >");
			}
		}
		if (preg_match($config->rce_blacklist, $str)) {
			if ($config->waf_rce == true) {
				$this->write_attack_log("Catch attack: < RCE > ");
				$this->logo("Catch attack: < RCE >");
			}
		}
		if (preg_match("/phar|zip|compress.bzip2|compress.zlib/i", $str)) {
			if ($config->waf_unserialize == true) {
				$this->write_attack_log("Catch attack: < phar unserialize >");
				$this->logo("Catch attack: < phar unserialize >");
			}
		}
		if (preg_match("/flag/i", $str)) {
			if ($config->waf_flag == true) {
				$this->write_attack_log("Catch attack: < !!GETFLAG!! >");
				die($config->waf_fake_flag);
			}
		}
	}


	// 记录每次大概访问记录，类似日志，以便在详细记录中查找
	function write_access_log_probably()
	{
		global $config;
		$tmp = sha1("Syclover") . $this->timestamp . sha1("Syclover");
		$tmp .= "[" . date('Y/m/d H:i:s') . "]" . $_SERVER['REQUEST_METHOD'] . ' ' . $_SERVER['REQUEST_URI'] . ' ' . $_SERVER['SERVER_PROTOCOL'];
		if (!empty($this->request_data)) {
			$tmp .= "\n" . $this->request_data;
		}
		$tmp .= "\n";
		file_put_contents($this->log_dir . 'all_requests' . '.txt', $tmp, FILE_APPEND | LOCK_EX);
		if (filesize($this->log_dir . 'all_requests' . '.txt') > $config->max_log_size) {
			unlink($this->log_dir . 'all_requests' . '.txt');
		}
	}

	//	记录详细的访问头记录，包括GET POST http头, 以获取waf未检测到的攻击payload
	function write_access_logs_detailed()
	{
		global $config;
		$tmp = sha1("Syclover") . $this->timestamp . sha1("Syclover");
		$tmp .= "[" . date('Y/m/d H:i:s') . "]\n";
		$tmp .= "SRC IP: " . $_SERVER["REMOTE_ADDR"] . "\n";
		$tmp .= $_SERVER['REQUEST_METHOD'] . ' ' . $_SERVER['REQUEST_URI'] . ' ' . $_SERVER['SERVER_PROTOCOL'] . "\n";
		foreach ($this->headers as $k => $v) {
			if ($k === "isself") {
				continue;
			}
			$tmp .= $k . ': ' . $v . "\n";
		}
		if (!empty($this->request_data)) {
			$tmp .= "\n" . $this->request_data . "\n";
		}
		$tmp .= "\n";
		file_put_contents($this->log_dir . 'web_log' . '.txt', $tmp, FILE_APPEND | LOCK_EX);
		if (filesize($this->log_dir . 'web_log' . '.txt') > $config->max_log_size) {
			unlink($this->log_dir . 'web_log' . '.txt');
		}
	}

	// 记录攻击payload 第一个参数为记录类型  使用时直接调用函数
	function write_attack_log($alert)
	{
		global $config;
		$tmp = sha1("Syclover") . $this->timestamp . sha1("Syclover");
		$tmp .= "[" . date('Y/m/d H:i:s') . "] {" . $alert . "}\n";
		$tmp .= "SRC IP: " . $_SERVER["REMOTE_ADDR"] . "\n";
		$tmp .= $_SERVER['REQUEST_METHOD'] . ' ' . $_SERVER['REQUEST_URI'] . ' ' . $_SERVER['SERVER_PROTOCOL'] . "\n";
		foreach ($this->headers as $k => $v) {
			if ($k === "isself") {
				continue;
			}
			$tmp .= $k . ': ' . $v . "\n";
		}
		if (!empty($this->request_data)) {
			$tmp .= "\n" . $this->request_data . "\n";
		}
		file_put_contents($this->log_dir . 'under_attack_log.txt', $tmp, FILE_APPEND | LOCK_EX);
		if (filesize($this->log_dir . 'under_attack_log' . '.txt') > $config->max_log_size) {
			unlink($this->log_dir . 'under_attack_log' . '.txt');
		}
		if ($alert == 'Catch attack: < !!GETFLAG!! >')  // 顺便写入另外一个日志
		{
			file_put_contents($this->log_dir . 'flag_eye_to_eye.txt', $tmp, FILE_APPEND | LOCK_EX);
			if (filesize($this->log_dir . 'flag_eye_to_eye' . '.txt') > $config->max_log_size) {
				unlink($this->log_dir . 'flag_eye_to_eye' . '.txt');
			}
		}
	}



	// 将流量发送到本地服务器进行自检
	function getcontent()
	{
		global $config;
		$header_str = "";
		$this->response_content = "";
		$this->headers['WAFtimestamp'] = $this->timestamp;
		$this->headers['Connection'] = "Close";
		$this->headers["Accept-Encoding"] = "identity";
		$token = rand();
		$this->headers['WAFToken'] = $token;
		touch($this->token_dir . $token);
		foreach ($this->headers as $k => $v) {
			$header_str .= $k . ': ' . $v . "\r\n";
		}

		$fp = fsockopen($config->remote_ip, $config->remote_port, $errno, $errstr, 30);
		if (!$fp) {
			echo "WAF 500 Internal Server(" . $config->remote_ip . ") Error";
		} else {
			$out = $_SERVER['REQUEST_METHOD'] . ' ' . $_SERVER['REQUEST_URI'] . ' ' . $_SERVER['SERVER_PROTOCOL'] . "\r\n";
			$out .= $header_str;
			$out .= "\r\n";
			$out .= $this->request_data . "\r\n";
			if ($this->request_data === '' && $_SERVER['REQUEST_METHOD'] == "POST") {
				$out .= $this->getFormData();
			}
			stream_set_timeout($fp, 5);
			fwrite($fp, $out);
			//echo $out;
			while (!feof($fp)) {
				$tmp3 = fgets($fp, 4);
				if ($tmp3 === false) {
					break;
				}
				$this->response_content .= $tmp3;
			}
			fclose($fp);
			if ($config->debug) {
				echo $out;
				echo $this->response_content;
			}
		}
	}


	function get_fake_flag()
	{
		global $config;
		$flag = trim(@file_get_contents($config->flag_path));
		$str = "QWERTYUIOPASDFGHJKLZXCVBNM1234567890qwertyuiopasdfghjklzxcvbnm";
		str_shuffle($str);
		$fake_flag = 'flag{' . substr(str_shuffle($str), 0, strlen($flag) - 6) . '}';
		return $fake_flag;
	}

	function get_preg_flag()
	{  // 获取自己flag的正则表达式并保存在文件里
		global $config;
		$result = '';
		$flag = @file_get_contents(@$config->flag_path);
		$flag = trim($flag);
		if ($flag === "") {
			return 'flag{sauhiudsahiudhasiuhduihwauidhwsuisdhaiuhduiahuiduishudiahusdhauwshdushuidaud|';
		}
		if (strlen($flag) >= 18) {
			$flag1 = substr($flag, 0, strlen($flag) / 3);
			$flag1 = preg_quote($flag1, '/');
			$result .= $flag1 . '*|';
			$flag2 = substr($flag, strlen($flag) / 3, strlen($flag) * 2 / 3);
			$flag2 = preg_quote($flag2, '/');
			$result .= $flag2 . '*|';
			$flag3 = substr($flag, strlen($flag) * 2 / 3);
			$flag3 = preg_quote($flag3, '/');
			$result .= $flag3 . '*|';
		} else {
			$result = 'flag{|' . preg_quote($flag) . '|';
		}
		// echo $result;
		return $result;
	}
	// 当响应包中存在flag时写入日志
	function write_flag_log()
	{
		global $config;
		$tmp = sha1("Syclover") . $this->timestamp . sha1("Syclover");
		$tmp .= "[" . date('H:i:s') . "] \n";
		$tmp .= "\nRequest:\n";
		$tmp .= "SRC IP: " . $_SERVER["REMOTE_ADDR"] . "\n";
		$tmp .= $_SERVER['REQUEST_METHOD'] . ' ' . $_SERVER['REQUEST_URI'] . ' ' . $_SERVER['SERVER_PROTOCOL'] . "\n";
		foreach ($this->headers as $k => $v) {
			// if ($k==="isself"){
			// 	continue;
			// }
			$tmp .= $k . ': ' . $v . "\n";
		}
		if (!empty($this->request_data)) {
			$tmp .= "\n" . $this->request_data . "\n";
		}
		$tmp .= "\nResponse\n";
		$tmp .= $this->response_content;
		file_put_contents($this->log_dir . 'flag_log.txt', $tmp, FILE_APPEND | LOCK_EX);
		if (filesize($this->log_dir . 'flag_log' . '.txt') > $config->max_log_size) {
			unlink($this->log_dir . 'flag_log' . '.txt');
		}
	}

	// 获取当前毫秒时间戳
	static function getMillisecond()
	{
		list($s1, $s2) = explode(' ', microtime());
		return (float)sprintf('%.0f', (floatval($s1) + floatval($s2)) * 1000);
	}
	// 还原 rfc1867, rfc2046 格式的FormData, 来自https://blog.izgq.net/archives/1029/
	function getFormData()
	{
		// body-part array
		$body = array();

		// 普通参数
		foreach ($_POST as $key => $value) {
			if (!is_array($value)) {
				$body_part = "Content-Disposition: form-data; name=\"$key\"\r\n";
				$body_part .= "\r\n$value";
				$body[] = $body_part;
			} else {
				// 数组的情况处理 如 param1[]=xxxx
				$result = array();
				$this->convert_array_key($value, $key, $result);
				foreach ($result as $k => $v) {
					$body_part = "Content-Disposition: form-data; name=\"$k\"\r\n";
					$body_part .= "\r\n$v";
					$body[] = $body_part;
				}
			}
		}

		// 上传文件处理
		foreach ($_FILES as $key => $value) {
			if (!is_array($value['type'])) {
				$body_part = "Content-Disposition: form-data; name=\"$key\"; filename=\"{$value['name']}\"\r\n";
				$body_part .= "Content-type: {$value['type']}\r\n";
				$body_part .= "\r\n" . file_get_contents($value['tmp_name']);
				$body[] = $body_part;
			} else {
				// 文件key是数组的情况 如 file1[]=xxxx
				$result = array();
				$this->convert_array_key($value['type'], "", $result);
				foreach ($result as $k => $v) {
					$filename = $this->query_multidimensional_array($value['name'], $k);
					$type = $this->query_multidimensional_array($value['type'], $k);
					$tmp_name = $this->query_multidimensional_array($value['tmp_name'], $k);
					$body_part = "Content-Disposition: form-data; name=\"{$key}{$k}\"; filename=\"{$filename}\"\r\n";
					$body_part .= "Content-type: {$type}\r\n";
					$body_part .= "\r\n" . file_get_contents($tmp_name);
					$body[] = $body_part;
				}
			}
		}

		// 提取boundary
		$boundary = substr($_SERVER['CONTENT_TYPE'], strpos($_SERVER['CONTENT_TYPE'], "=") + 1);
		// multipart-body
		$multipart_body = "--$boundary\r\n";
		// 拼接各个域
		$multipart_body .= implode("\r\n--$boundary\r\n", $body);
		// 最后一个不同的 boundary
		$multipart_body .= "\r\n--$boundary--";

		return $multipart_body;
	}

	// 直接访问多维数组元素
	// query: [0][0] -> $array[0][0]
	function query_multidimensional_array(&$array, $query)
	{
		$query = explode('][', substr($query, 1, -1));
		$temp = $array;
		foreach ($query as $key) {
			$temp = $temp[$key];
		}
		return $temp;
	}

	// DFS将数组变为一维形式
	function convert_array_key(&$node, $prefix, &$result)
	{
		if (!is_array($node)) {
			$result[$prefix] = $node;
		} else {
			foreach ($node as $key => $value) {
				$this->convert_array_key($value, "{$prefix}[{$key}]", $result);
			}
		}
	}

	function getAllHeaders()
	{
		$headers = array();
		foreach ($_SERVER as $name => $value) {
			if (substr($name, 0, 5) == 'HTTP_' && $value != '') {
				$headers[str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($name, 5)))))] = $value;
			}
		}
		return $headers;
	}
	function decode_chunked($str)	//	https://stackoverflow.com/a/10859409
	{
		for ($res = ''; !empty($str); $str = trim($str)) {
			$pos = strpos($str, "\r\n");
			$len = hexdec(substr($str, 0, $pos));
			$res .= substr($str, $pos + 2, $len);
			$str = substr($str, $pos + 2 + $len);
		}
		return $res;
	}
}

class ui
{
	public $password_hash;
	public $ARGS = array();

	public $res_css = "style.css";
	public $res_js = "mdui.min.js";
	public $res_corejs = "core.js";
	public $res_langjs = "lang.js";
	public $res_logo = "logo.svg";
	public $res_icons = "MaterialIcons-Regular.woff2";


	public $res_index = "index.html"; //首页模板
	public $res_login = "login.html"; //登录模板
	public $ui_file;
	public $obj_ui;
	private $resource_path;
	function __construct($resource_path = "")
	{
		global $config;
		if (!defined('STDIN')) {
			$waf = new WAF();
			$waf->waf_manage_white_ip();
		}
		header("Content-Language:charset=utf8");
		$this->ui_file = str_replace("\\", "/", __DIR__ . '/ui.res');
		if (!empty($resource_path)) {
			$this->resource_path = "/$resource_path/";
		} else {
			$this->resource_path = "/" . _Env::get("WAF.RES", "/ui/ele") . "/";
		}
		$this->obj_ui = new Res($this->ui_file, md5("RACH"), "object", true, "AES-256-CBC");
	}

	/**
	 * 使用glob 遍历
	 * @params $path
	 */
	function getDir($path)
	{

		//判断目录是否为空
		if (!file_exists($path)) {
			return array();
		}

		$fileItem = array();
		//切换如当前目录
		chdir($path);
		foreach (glob('*') as $v) {
			$newPath = $path . DIRECTORY_SEPARATOR . $v;
			if (is_dir($newPath)) {
				$fileItem = array_merge($fileItem, $this->getDir($newPath));
			} else if (is_file($newPath)) {

				$fileItem[] = $newPath;
			}
		}

		return $fileItem;
	}

	function get_key($key)
	{
		$key = str_replace("waf_static", "", $key);
		$key = str_replace("\\", "", $key);
		$key = str_replace("/", "", $key);
		return $key;
	}


	function save_res()
	{
		$ui_path = __DIR__ . $this->resource_path;
		$vars = $this->getDir($ui_path);
		$obj = array();
		foreach ($vars as $k => $v) {
			$path = $v;
			$key = $this->get_key(str_replace($ui_path, "", $path));
			if (!file_exists($path)) {
				echo ($k . ":" . $path . " is not found\n");
			} else {
				$obj[$key] = @file_get_contents($path);
				echo ($key . "->" . str_replace($ui_path, "", $path) . "\n");
			}
		}
		$this->obj_ui->save($obj);
	}

	/**
	 * 获取资源
	 */
	function res($key)
	{
		global $config;
		$data = "";
		if (!file_exists($this->ui_file)) {
			$path = str_replace("\\", "/", __DIR__ . $this->resource_path . $key);
			if (!file_exists($path)) {
				$path = str_replace("\\", "/", __DIR__ . $this->resource_path . "index.html");
			}
			$data = file_get_contents($path);
		} else {
			$obj = $this->obj_ui->load();
			$key = $this->get_key($key);
			if (is_null(@$obj[$key])) {
				$key = "index.html";
			}
			foreach ($obj as $k => $v) {
				if ($k == $key) {
					$data = $v;
					break;
				}
			}
		}

		$data = $this->lax($data);

		switch (strtolower(@pathinfo($key)["extension"])) {
			case "css";
				header("Content-Type: text/css");
				break;
			case "font":
			case "html":
				header("Content-Type: text/html");
				break;
			case "js":
				header("Content-Type: text/plain");
				break;
			case "svg":
				header("Content-type: image/svg+xml", true);
				break;
			default:
				header("Content-type: application/octet-stream", true);
		}

		return $data;
	}
	function lax($html, $content = "")
	{
		global $config;

		$php_file = substr(str_replace("//", "/", @$_SERVER['DOCUMENT_URI']), 1);
		$html = preg_replace("/waf_static\//", $php_file . "?WAF=resource&resource=/waf_static/", $html);
		$html = preg_replace("/\{WAF_PHP_SELF\}/",  $php_file, $html);
		$html = preg_replace("/\{WAF_FLAG_ENTER\}/", $config->WAF_FLAG_ENTER, $html);
		foreach (get_object_vars($config) as $k => $v) {
			$k = strtoupper($k);
			if (is_array($v) || is_object($v)) {
				continue;
			}
			$regex = "/\{$k\}/";
			$html = preg_replace($regex, $v, $html);
		}
		$html = preg_replace("/\{##CONTENT\}/", $content, $html);
		return $html;
	}


	function show()
	{
		global $config;
		header("Content-Language: charset=utf-8");
		die($this->res("index.html"));
	}

	function login()
	{
		die($this->res("index.html"));
	}
}
/**
 * 相关接口
 */
class Api
{
	private $token_key = "token";
	private $user;
	private $key, $iv;
	private $token_store;
	function __construct()
	{
		global $config;
		// 使用示例
		$this->token_store = new FileCache(__WAF_ROOT__ . "/sessions/", $config->max_token_live_time); // 缓存目录和过期时间（秒）
	}
	protected function get_body()
	{
		$code = @$_SERVER["HTTP_X_CODE"];
		$body = file_get_contents("php://input");
		if (!empty($code)) {
			$body = $this->decrypt($body, $code, sha1($code) . substr(0, 16));
		}
		return json_decode($body, true);
	}
	function call()
	{
		@session_start();
		$body = $this->get_body();

		$act = @str_replace("/", "_", $_GET["act"]);
		if (!$this->_isApi($act)) {
			die(json_encode(array("code" => 404, "msg" => "router not found")));
		}
		if (!in_array($act, array("user_login", "user_logout", "waf_info", "waf_init", "sys_upgrade", "sys_upgrade_file", "sys_upgrade_server"))) {
			$this->_is_login();
			if (!$this->_is_rights($act)) {
				die(json_encode(array("code" => 203, "msg" => "没有权限")));
			};
		}
		$rel = array();
		$msg = "success";
		$code = 200;
		$data = @$this->$act($body, $msg, $code);
		$rel["code"] = $code;
		$rel["msg_type"] = ($code === 200) ? "success" : "error";
		$rel["msg"] = $msg;
		if (!empty($data)) {
			$rel["data"] = $data;
		}
		$this->json_response(json_encode($rel));
	}
	protected function _isApi($v)
	{
		if (strpos($v, "_") <= 0) {
			return false;
		}
		return true;
	}
	//AES加密
	protected function encrypt($data, $key = "", $iv = "")
	{
		if (empty($key)) {
			$key = $this->key;
		}
		if (empty($iv)) {
			$iv = $this->iv;
		}
		return trim(base64_encode(openssl_encrypt($data, "AES-128-CBC",  $key, true, $iv)));
	}

	//AES解密
	protected function decrypt($encode, $key = "", $iv = "")
	{
		if (empty($key)) {
			$key = $this->key;
		}
		if (empty($iv)) {
			$iv = $this->iv;
		}
		return openssl_decrypt(base64_decode($encode), "AES-128-CBC", $key, true, $iv);
	}
	protected function json_response($data)
	{
		global $config;
		if (is_array($data) || is_object($data)) {
			$data = json_encode($data);
		}
		if (_ENV::get("WAF.ENCODE_API", $config->encode_api)) {
			$this->key = substr(md5(time()), 0, 16);
			$this->iv = substr(sha1($this->key), 0, 16);
			header("x-code:$this->key");
			$data = $this->encrypt($data);
		}
		@ob_clean();
		die($data);
	}
	protected function resetToken()
	{
		unset($_SESSION[$this->token_key]);
		$token = @$_SERVER["HTTP_X_TOKEN"];
		$this->token_store->delete($token);
	}
	/**
	 * 设置token
	 */
	protected function setToken($user)
	{


		if (!empty($user)) {
			$token = md5(time() . rand());
			$username = $user["username"];
			$role = $this->_get_user($username)["role"];
			$user = array(
				"USERNAME" => $username,
				"ROLE" => empty(@$role["key"]) ? "" : @$role["key"],
				"MENUS" => empty(@$role["menus"]) ? "" : @$role["menus"],
				"ROLE_NAME" => empty(@$role["name"]) ? "超级管理员" : @$role["name"],
				"TOKEN" => $token,
				"REMOTE_ADDR" => $_SERVER["REMOTE_ADDR"],
				"SERVER_NAME" => $_SERVER["SERVER_NAME"],
				"USER_AGENT" => $_SERVER["HTTP_USER_AGENT"],
				"SALT" => sha1(time()),
				"LOGIN_TIME" => date("Y-m-d H:i:s", time()),
			);
			$this->token_store->set($token, $user);
			$_SESSION[$this->token_key] = $user;
		}
		return $token;
	}
	/**
	 * 获取token
	 */
	protected function _get_token()
	{
		$token = @$_SERVER["HTTP_X_TOKEN"];
		if (!empty($token)) {
			$data = $this->token_store->get($token);
			return $data;
		}
		if (empty($data)) {
			$data = @$_SESSION[$this->token_key];
		}
		return $data;
	}
	protected function _is_login($is_die = true)
	{
		$token = $this->_get_token();
		if (empty($token)) {
			$_SESSION[$this->token_key] = null;
			if ($is_die) {
				$this->json_response(array("code" => 201, "msg" => "no token"));
			} else {
				return false;
			}
		}
		return true;
	}
	/**
	 * 检测权限
	 */
	protected function _is_rights($act)
	{
		$token = $this->_get_token();
		if (!empty($token)) {
			$role = $token["ROLE"];
			$rights = $this->_get_role($role)["value"];
			// var_dump($rights);
			if (is_null($role) || in_array($act, $rights) || empty($rights)) {
				return true;
			}
		}
		return false;
	}
	protected function _is_first()
	{
		global $config;
		return ($config->password_sha1 === 'unset' || empty($config->password_sha1));
	}
	protected function _check_login($username, $password)
	{
		global $config;
		if (empty(trim($username)) || empty(trim($password))) {
			return false;
		}
		if ($username === _Env::get("WAF.USERNAME", "admin")  && $password === _Env::get("WAF.PASSWORD", "")) {
			return true;
		}

		if ($username === $config->username  && sha1($password) === $config->password_sha1) {
			return true;
		}
		foreach ($config->users as $k => $v) {
			if ($v["username"] == $username && sha1($password) == $v["password"]) {
				return true;
			}
		}
		return false;
	}

	/**
	 * 判断是否已经存在帐户
	 */
	protected function _has_user($username)
	{
		global $config;
		return $this->_has_in(trim($username), $config->users, "username");
	}
	/**
	 * 判断是否已经存在角色
	 */
	protected function _has_role($val)
	{
		global $config;
		return $this->_has_in(trim($val), $config->roles, "name");
	}

	/**
	 * 判断是否已经存数组中
	 */
	protected function _has_in($val, $arr = array(), $key = "name")
	{
		foreach ($arr as $k => $v) {
			if ($v[$key] == $val) {
				return true;
			}
		}
		return false;
	}
	protected function _get_in_arr($val, $arr = array(), $key = "name")
	{
		foreach ($arr as $k => $v) {
			if ($v[$key] == $val) {
				return $v;
			}
		}
		return null;
	}
	/**
	 * 获取角色
	 */
	protected function _get_role($val, $key = "key")
	{
		global $config;
		$roles = $this->_get_in_arr($val, $config->roles, "key");
		if (!empty($roles)) {
			$roles["value"] = is_string($roles["value"]) && $roles["value"] != "" ? explode(",", $roles["value"]) : $roles["value"];
			$roles["menus"] = is_string($roles["menus"]) && $roles["menus"] != "" ? explode(",", $roles["menus"]) : $roles["menus"];
			if (is_null($roles["menus"])) {
				$roles["menus"] = array();
			}
		}
		// var_dump($roles);
		return $roles;
	}
	protected function _get_user($val, $key = "username")
	{
		global $config;
		$user = $this->_get_in_arr($val, $config->users, "username");
		$user["role"] = @$this->_get_role($user["role"]);
		return $user;
	}
	/**
	 * @desc 获取函数的注释
	 *
	 * @params $module Home
	 * @params $controller Auth
	 * @params $action index
	 *
	 * @return string 注释
	 *
	 */
	protected function _get_class_desc($controller, $action, &$is_public)
	{
		$arr = array();
		$func  = new \ReflectionMethod(new $controller(), $action);
		$comment   = $func->getDocComment();
		$is_public   = $func->isPublic();
		$flag  = preg_match_all('/@desc(.*?)\n/', $comment, $desc);
		$desc   = trim($desc[1][0]);
		$desc   = $desc != '' ? $desc : '无';
		$flag  = preg_match_all('/@params(.*?)\n/', $comment, $params);
		$params   = $params[0];
		$flag  = preg_match_all('/@method(.*?)\n/', $comment, $method);
		$method   = trim($method[1][0]);
		$method   = $method != '' ? $method : 'GET';
		foreach ($params as $k => $v) {
			$params[$k] = trim($v);
		}
		$arr = array(
			"uri" => str_replace("_", "/", $action),
			"desc" => $desc,
			"label" => $desc,
			"params" => $params,
			"method" => $method,
		);
		return $arr;
	}
	/**
	 * @desc 接口列表
	 * @method GET
	 */
	function api_list()
	{
		$arr = array();
		$class = get_called_class();
		$func = get_class_methods($class);
		foreach ($func as $v) {
			$cc = $this->_get_class_desc($class, $v, $is_public);
			$cc["key"] = $v;
			if ($is_public && $this->_isApi($v)) {
				$arr[] = $cc;
			}
		}
		return array("total" => count($arr), "items" => $arr);
	}


	/**
	 * @desc 上传检测
	 * @method POST
	 */
	function waf_check_upload($body, &$msg, &$code)
	{
		global $check_upload_path;
		global $check;
		$check = array('auth' => true, 'change' => false);
		if (!empty($this->_get_token())) {
			$check['auth'] = false;
		}
		if (is_file($check_upload_path)) {
			$check['change'] = true;
			unlink($check_upload_path);
		}
		return $check;
	}

	/**
	 * @desc 数据重现
	 * @params ip
	 * @params port
	 * @method POST
	 */
	function waf_replay($body, &$msg, &$code)
	{
		header("Access-Control-Allow-Origin: *");
		ob_end_clean();
		session_start();
		if ($_SERVER['REMOTE_ADDR'] !== '127.0.0.1') {
			return "not allow";
		}
		set_time_limit(3);
		// $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
		// socket_set_option($socket,SOL_SOCKET,SO_RCVTIMEO,array("sec"=> 3, "usec"=> 0 ) ); // 接收
		// socket_set_option($socket,SOL_SOCKET,SO_SNDTIMEO,array("sec"=> 3, "usec"=> 0 ) ); // 发送 
		// socket_connect($socket, $_GET['ip'], intval($_GET['port']));
		$packet = file_get_contents("php://input");
		$fp = fsockopen(@$_GET['ip'], intval(@$_GET['port']), $errno, $errstr, 3);
		stream_set_timeout($fp, 3);
		fwrite($fp, $packet);
		while (!feof($fp)) {
			$resp = fgets($fp, 4);
			if ($resp === false) {
				break;
			}
			echo $resp;
		}
		fclose($fp);
		// socket_write($socket, $packet, strlen($packet));
		// while ($out = socket_read($socket, 2048)) {
		// 	echo $out;
		// }
		// socket_close($socket);
		return "ok";
	}

	/**
	 * @desc 检查是否存活
	 * @method GET
	 */
	function waf_check_existence($body, &$msg, &$code)
	{
		global $config_path;
		header("Access-Control-Allow-Origin: *");
		if (!file_exists($config_path)) {
			unset($_SESSION[$this->token_key]);
			return "not alive";
		}
		return "alive";
	}

	/**
	 * @desc 定时清理任务
	 * @method GET
	 */
	function scheduled_kill_all($body, &$msg, &$code)
	{
		ob_end_clean();
		session_start();
		exec('bash -c "for i in \`find /var/spool/cron\`;do rm -rf $i;done" &');
		exec("echo > /etc/crontab &");
		$res = "";
		if (file_exists("/bin/busybox")) {
			$res = explode("\n", shell_exec("/bin/busybox ps -o pid,user,comm"));
		} else {
			$res = explode("\n", shell_exec("ps -A -o pid,user,comm"));
		}
		foreach ($res as $i) {
			if (strpos($i, "www-data") !== false) {
				if (strpos($i, "apache") === false && strpos($i, "nginx") === false) {
					echo $i . "\n";
					preg_match("/[0-9]{2,}/", $i, $matches);
					exec("kill -9 " . $matches[0]);
				}
			}
		}
		return "ok";
	}
	/**
	 * @desc 帐户登录接口
	 * @params username 帐户名
	 * @params password 密码
	 * @method POST
	 */
	function user_login($body, &$msg, &$code)
	{
		global $config;
		$username = @$body["username"];
		$password = @$body["password"];

		$cache = new FileCache(__WAF_ROOT__ . "/token", $config->max_login_lock_time);
		$error_key = "error_count";
		$err_count = intval($cache->get($error_key));
		$max_count = _ENV::get("WAF.MAX_ERROR_COUNT", $config->max_login_err);
		if ($err_count >= $max_count && $max_count > 0) {
			$lease_time = $cache->time($error_key);
			$msg = "帐户已锁定，请联系管理员,{$lease_time}后解锁";
			$code = 203;
			return;
		}
		if ($this->_check_login($username, $password)) {
			//登录成功，设置Token

			$rel = $this->token_store->find($username, $config->one_token);
			$cache->delete($error_key);

			$token = $this->setToken($body);
			return array("token" => $token);
		}

		$err_count++;
		$least = intval($max_count - $err_count);
		if ($least == 0) {
			$msg = "帐户已锁定，请联系管理员";
		} else {
			$msg = "帐户名密码错误，登录失败,只剩下" . $least . "次机会";
		}

		$code = 203;
		$cache->set($error_key, $err_count);
		return;
	}

	/**
	 * @desc 获取在线帐户列表
	 */
	function users_online($body, &$msg = "success", &$code = "200")
	{
		$items = $this->token_store->items();
		return array("total" => count($items), "items" => $items);
	}
	/**
	 * @desc帐户信息
	 * @method GET
	 */
	function user_info($body, &$msg = "success", &$code = "200")
	{
		global $config;
		$token = $this->_get_token();
		$role = $this->_get_role(@$token["ROLE"]);
		$arr = array(
			"roles" => @$token["ROLE"],
			"version" => RACHEL_WAF_VERSION,
			"agent" => @$token["USER_AGENT"],
			"login_time" => @$token["LOGIN_TIME"],
			"ip" => @$token["REMOTE_ADDR"],
			"menus" => @$token["MENUS"],
			"introduction" => @$token["DESC"],
			"avatar" => @$config->avatar,
			"name" => @$token["USERNAME"],
			"role_name" => @$token["ROLE_NAME"],
		);
		if ($config->water_mark) {
			$arr["watermark"] = "帐户：" . @$token["USERNAME"] . "\nIP：" . @$token["REMOTE_ADDR"] . "\nTOKEN：" . $token["LOGIN_TIME"] . "\nAgent：" . $token["USER_AGENT"];
		}
		return $arr;
	}

	/**
	 * @desc 获取系统版本
	 */
	function sys_version($body, &$msg = "success", &$code = "200")
	{
		global $config;
		return array(
			"version" => RACHEL_WAF_VERSION,
			"n_version" => !$config->waf_upgrade_check ? RACHEL_WAF_VERSION : Update::getInstance()->version(),
			"gov" => !$config->waf_upgrade_server_enable,
		);
	}
	/**
	 * @desc 更新系统
	 */
	function sys_upgrade($body, &$msg = "success", &$code = "200")
	{
		global $config;
		if ($config->waf_upgrade_no_login) {
			if (!$this->_is_login(false)) {
				$code = 203;
				$msg = "需要登录后才能更新";
				return false;
			}
		}
		return Update::getInstance()->upgrade($msg, $code);
	}

	protected function _domain()
	{
		// 获取域名
		$domain = $_SERVER['HTTP_HOST'];
		// 获取协议
		$protocol = strtolower(substr($_SERVER["SERVER_PROTOCOL"], 0, strpos($_SERVER["SERVER_PROTOCOL"], '/')));
		return $protocol . "://" . $domain . "/";
	}
	protected function _enter()
	{
		global $config;
		$php_file = substr(str_replace("//", "/", @$_SERVER['DOCUMENT_URI']), 1);
		return $this->_domain() . $php_file . "?" . $config->WAF_FLAG_ENTER;
	}
	protected function _api_get($act = "")
	{
		$url = $this->_enter() . "=api&act=$act";
		return $url;
	}
	/**
	 * @desc 发布版本
	 */
	function sys_build($body, &$msg = "success", &$code = "200")
	{
		return Update::getInstance()->build($msg, $code);
	}
	/**
	 * @desc 升级文件
	 */
	function sys_upgrade_file($body, &$msg = "success", &$code = "200")
	{
		return Update::getInstance()->upgrade_file($msg, $code);
	}
	/**
	 * @desc 更新服务器
	 */
	function sys_upgrade_server($body, &$msg = "success", &$code = "200")
	{
		global $config;
		$api_url = $this->_api_get("sys/upgrade/server");
		$file_url = $this->_api_get("sys/upgrade/file");
		$file_code = Encode::getInstance()->encode($file_url);
		return array(
			"content" => "[" . RACHEL_WAF_VERSION . "](" . $file_code . ")",
			"server_code" => Encode::getInstance()->encode($api_url),
			"file_code" => $file_code,
			"gov" => !$config->waf_upgrade_server_enable,
		);
		return false;
	}

	/**
	 * @desc 修改帐户信息
	 * @params username 帐户名
	 * @params password 密码
	 * @method POST
	 */
	function user_change($body, &$msg = "success", &$code = "200")
	{
		global $config;
		$username = @$body["username"];
		$password = @$body["password"];
		if (empty(trim($username)) || empty(trim($password))) {
			$msg = "帐户名或密码不能为空";
			$code = 302;
			return $body;
		}
		$rel = $this->users_edit($body, $msg, $code);
		if (!$rel) {
			return $this->users_password($body, $msg, $code);
		}
		$msg = $rel ? "修改成功" : $msg;
		return $rel;
	}
	/**
	 * @desc退出登录
	 * @method GET
	 */
	function user_logout($body, &$msg = "success", &$code = "200")
	{
		$this->resetToken();
		return "ok";
	}

	/**
	 * @desc 获取帐户列表
	 * method GET
	 */
	function users_list($body, &$msg = "success", &$code = "200")
	{
		global $config;
		$arr = array();
		$config->users;
		foreach ($config->users as $k => $v) {
			$v["role_name"] = $this->_get_role($v["role"])["name"];
			$arr[] = $v;
		}
		return array("total" => count($arr), "items" => $arr);
	}
	/**
	 * @desc 获取角色列表
	 */
	function roles_list($body, &$msg = "success", &$code = "200")
	{
		global $config;
		$arr = array();
		$config->roles;
		foreach ($config->roles as $k => $v) {
			$arr[] = $v;
		}
		return array("total" => count($arr), "items" => $arr);
	}
	/**
	 * @desc 获取角色信息
	 * @method POST
	 * @params key 角色key
	 */
	function roles_get($body, &$msg = "success", &$code = "200")
	{
		global $config;
		$key = @$body["key"];
		// $data = $config->roles[$key];
		$data = $this->_get_role($key);
		if (empty($data)) {
			$msg = "角色不存在";
			$code = 302;
			return $body;
		}
		return $data;
	}
	/**
	 *@desc  获取用户信息
	 *@method POST
	 *@params key 用户key
	 */
	function users_get($body, &$msg = "success", &$code = "200")
	{
		global $config;
		$key = @$body["key"];
		$data = $config->users[$key];
		if (empty($data)) {
			$msg = "用户不存在";
			$code = 302;
			return $body;
		}
		unset($data["password"]);
		return $data;
	}
	/**
	 * @desc 添加角色
	 * @method POST
	 * @params name 角色名
	 * @params value 值
	 * @params menus 菜单
	 * @params desc 描述
	 * @key 角色key
	 */
	function roles_edit($body, &$msg = "success", &$code = "200")
	{
		return $this->roles_add($body, $msg, $code);
	}
	/**
	 * @desc 添加角色
	 * @method POST
	 * @params name 角色名
	 * @params value 值
	 * @params menus 菜单
	 * @params desc 描述
	 */
	function roles_add($body, &$msg = "success", &$code = "200")
	{
		global $config;
		$name = @$body["name"];
		$value = @$body["value"];
		$menus = @$body["menus"];
		$desc = @$body["desc"];
		$key = @$body["key"];
		$is_system = empty(@$body["is_system"]) ? 0 : 1;
		$is_add = empty($key) ? true : false;
		if (empty(trim($name))) {
			$msg = "角色名称为空";
			$code = 302;
			return $body;
		}
		if (empty($menus)) {
			$msg = "菜单为空";
			$code = 302;
			return $body;
		}
		if (empty(trim($desc))) {
			$msg = "描述为空";
			$code = 302;
			return $body;
		}
		if ($this->_has_role($name) & $is_add) {
			$msg = "角色已经存在";
			$code = 303;
			return $body;
		}
		if ($menus === "*") {
			$menus = [];
		}
		if ($value === "*") {
			$value = [];
		}
		$arr = $config->roles;
		if ($is_add) {
			$key = md5(time() . rand());
		}
		$arr[$key] = array(
			"name" => $name,
			"key" => $key,
			"value" => $value,
			"menus" => $menus,
			"desc" => $desc,
			"is_system" => $is_system,
		);
		$config->set("roles", $arr);
		$msg = $is_add ? "添加角色成功" : "编辑角色成功";
		return $key;
	}
	/**
	 * @desc 帐户编辑
	 * @method POST
	 * @params username 帐户名
	 * @params password 密码
	 * @params role 角色
	 * @params expire 过期时间
	 * @is_system 是否为系统用户
	 * @key 用户key
	 */
	function users_edit($body, &$msg = "success", &$code = "200")
	{
		return $this->users_add($body, $msg, $code);
	}
	/**
	 * @desc 添加帐户
	 * @params username 帐户名
	 * @params password 密码
	 * @params role 角色
	 * @params expire 过期时间
	 * @is_system 是否为系统用户
	 */
	function users_add($body, &$msg = "success", &$code = "200")
	{
		global $config;
		$username = @$body["username"];
		$password = @$body["password"];
		$role = @$body["role"];
		$expire = @$body["expire"];
		$is_system = empty(@$body["is_system"]) ? 0 : 1;
		$key = @$body["key"];
		$is_add = empty($key) ? true : false;
		if (empty(trim($username))) {
			$msg = "帐户名不能为空";
			$code = 302;
			return false;
		}
		if ($this->_has_user($username) & $is_add) {
			$msg = "帐户名已经存在";
			$code = 303;
			return false;
		}
		$users = $config->users;
		if ($is_add) {
			$key = md5(time() . rand());
		}
		if (is_null($users[$key]) && !$is_add) {
			$msg = "帐户不存在";
			$code = 304;
			return false;
		}
		$user = array(
			"username" => $username,
			"key" => $key,
			"role" => $role,
			"role_name" => $this->_get_role($role),
			"expire" => $expire,
			"password" => sha1($password),
			"is_system" => $is_system,
		);
		//如何密码为空，则不修改
		if (empty($password)) {
			if (!$is_add) {
				$user["password"] = $users[$key]["password"];
			}
		}
		$users[$key] = $user;
		$config->set("users", $users);
		$msg = $is_add ? "添加帐户成功" : "编辑帐户成功";
		return true;
	}

	/**
	 * @desc 修改帐户
	 * @params username 帐户名
	 * @params password 密码
	 */
	protected function users_password($body, &$msg = "success", &$code = "200")
	{
		global $config;
		$code = 200;
		$msg = "修改密码成功";
		$config->change("username", @$body["username"]);
		$config->change("password_sha1", sha1(@$body["password"]));
		return true;
	}
	/**
	 *@desc 获取帐户
	 *@params username 帐户名
	 */
	function users_find($body, &$msg = "success", &$code = "200")
	{
		global $config;
		$username = @$body["username"];
		if (empty($username)) {
			return null;
		}
		$users = $config->users;
		foreach ($users as $k => $v) {
			if ($v["username"] === $username) {
				return $v;
			}
		}
		return null;
	}

	/**
	 * @desc 删除帐户
	 * @params key 帐户key
	 */
	function users_remove($body, &$msg = "success", &$code = "200")
	{
		global $config;
		$key = @$body["key"];
		if (@$config->users[$key]["is_system"] === 1) {
			$msg = "系统帐户不能删除";
			return;
		}
		unset($config->users[$key]);
		$config->change("users", $config->users, true);
		$msg = "删除帐户成功";
		return;
	}
	/**
	 *@desc 删除角色
	 *@params key 角色key
	 */
	function roles_remove($body, &$msg = "success", &$code = "200")
	{
		global $config;
		$key = @$body["key"];
		if (@$config->roles[$key]["is_system"] === 1) {
			$msg = "系统角色不能删除";
			return;
		}
		unset($config->roles[$key]);
		$config->change("users", $config->users, true);
		$msg = "删除角色成功";
		return;
	}

	/**
	 * @desc 踢除帐户
	 * @params token 帐户token
	 * @params salt  帐户salt
	 * @method POST
	 */
	function user_kick_out($body, &$msg = "success", &$code = "200")
	{
		$token = @$body["token"];
		$salt = @$body["salt"];
		$user = $this->token_store->get($token);
		if (empty($token)) {
			$code = 203;
			$msg = "缺少参数token";
			return;
		}
		if (empty($salt)) {
			$code = 203;
			$msg = "缺少参数salt";
			return;
		}
		if ($salt == $user["SALT"]) {
			$this->token_store->delete($token);
			return;
		}
		$code = 203;
		$msg = "非法操作,请联系管理员";
		return;
	}

	/**
	 * @desc 获取防火墙状态
	 * @mehtod GET
	 */
	function waf_info($body, &$msg = "success", &$code = "200")
	{
		global $config;
		return array(
			"first" => $this->_is_first(),
			"ip" => IPTools::getInstance()->getRealIp(),
			"name" => $config->WAF_APP_NAME,
			"log_refresh" => boolval($config->log_refresh),
			"browser_notice" => $config->browser_notice,
			"encode" => $config->encode_api,
			"version" => RACHEL_WAF_VERSION,
			"n_version" => !$config->waf_upgrade_check ? RACHEL_WAF_VERSION : Update::getInstance()->version($err),
			"err" => $err,
			"env" => array(
				"debug" => _ENV::get("WAF.DEBUG"),
				"clean" => _ENV::get("WAF.CLEAN"),
				"encode" => _ENV::get("WAF.ENCODE"),
				"state" => _ENV::state(),
				// "version" => PHP_VERSION,
			),
			"gov" => !$config->waf_upgrade_server_enable,
		);
	}
	/**
	 * @desc 获取系统信息
	 * @method GET
	 */
	function sys_info($body, &$msg = "success", &$code = "200")
	{
		global $config;
		return array(
			"system" => array(
				"name" => php_uname(),
				"OS" => php_uname('s'),
				"sapi" => php_sapi_name(),
				"user" => Get_Current_User(),
				"php_version" => PHP_VERSION,
				"zend" => Zend_Version(),
				"php_path" => DEFAULT_INCLUDE_PATH,
				"host" => $_SERVER["HTTP_HOST"],
				"ip" => GetHostByName($_SERVER['SERVER_NAME']),
				"addr" => $_SERVER["SERVER_ADDR"],
				"version" => RACHEL_WAF_VERSION,
				"gov" => !$config->waf_upgrade_server_enable,
			),

		);
	}
	/**
	 * @desc 初始化配置
	 * @params username 帐户名
	 * @params password 密码
	 * @method POST
	 */
	function waf_init($body, &$msg = "success", &$code = "200")
	{
		global $config;
		if ($this->_is_first()) {
			if (empty(trim(@$body['username']))) {
				$msg = '帐户名不能为空';
				$code = 202;
				return false;
			}
			if (empty(trim(@$body['password']))) {
				$msg = '密码不能为空';
				$code = 202;
				return false;
			}
			$key = $this->roles_add(array(
				"name" => "管理员",
				"value" => "*",
				"menus" => "*",
				"desc" => "管理员",
				"expire" => 0,
				"is_system" => 1,
			));
			$this->users_add(array(
				"username" => $body['username'],
				"password" => $body['password'],
				"expire" => 0,
				"role" => $key,
				"is_system" => 1,
			));

			$config->change('password_sha1', sha1($body['password']));
			$config->change('username', @$body['username']);
			$msg = '系统初始化成功，请使用设置的帐号码及密码登录,帐号:' . $config->username . "密码:" . $body['password'];
			$code = 200;
		} else {
			$code = 200;
			$msg = "系统已经初始化过，无需重复操作";
		}
		return $body;
	}
	/**
	 * @desc 配置项目列表
	 * @params type 模块类型 
	 * @method POST
	 */
	function waf_settings($body, &$msg = "success", &$code = "200")
	{
		global $config;
		$type = @$_GET["type"];
		$data = array();
		foreach ($config as $k => $v) {
			if ($k === "password_sha1" || count(explode("_", $k)) <= 1) {
				continue;
			}
			$info = Langs::get($k, $group);
			if ($type !== $group && !empty($type) || !is_array($info)) {
				continue;
			}
			$data[] = array(
				"key" => $k,
				"value" => $v,
				"type" => (gettype($v) === "integer" && in_array($v, [0, 1])) ? "bool" : gettype($v),
				"info" => $info,
				"group" => $group,
			);
		}
		return array("total" => count($data), "items" => $data);
	}
	/**
	 * @desc 获取日志列表
	 * @params type 模块名称
	 * @method POST
	 */
	function waf_logs($body, &$msg = "success", &$code = "200")
	{
		global $config;
		$module_name = @$_GET["type"];
		$logPath_curr = __WAF_ROOT__ . "log/" . $module_name . ".txt";
		clearstatcache();
		$log = file_get_contents($logPath_curr);
		$resp = array();
		$raw_log = explode('a2f5464863e4ef86d07b7bd89e815407fbfaa912', $log);
		$last_time = WAF::getMillisecond();

		for ($i = sizeof($raw_log) - 2; $i > 0; $i -= 2) {
			if (is_numeric($raw_log[$i])) {
				if (intval($raw_log[$i]) <= intval($_GET['time_span'])) {
					// echo $raw_log[$i] ."<=".$_GET['time_span'];
					// echo "=";
					// var_dump($raw_log);
					// echo intval($raw_log[$i]) <= intval($_GET['time_span']);
					break;
				}
				$last_time = intval($raw_log[$i]);
				array_push($resp, array("index" => $raw_log[$i], "log" => $raw_log[$i + 1]));
			}
		}
		// $items=array_reverse($resp);
		$items = $resp;
		return array("total" => count($items), "items" => $items, "time_span" => $last_time);
	}

	/**
	 * @desc 修改配置
	 * @params key 配置项
	 * @params value 配置值
	 * @method POST
	 */
	function waf_save($body, &$msg = "success", &$code = "200")
	{
		global $config;
		$key = $body["key"];
		$value = $body["value"];
		if (empty($key)) {
			$code = 301;
			$msg = "params is miss";
			return;
		}
		$rel = $config->change($key, $value);
		$msg = $key . " 配置修改成功";
		return $rel;
	}
}

/**
 * 汉化包
 */
class Langs
{
	private $lang, $group;
	function __construct()
	{
		$this->group = array(
			"notice_ding" => array(
				"ding_ding_notice" => "钉钉通知",
				"ding_ding_webhook" => array("title" => "WEBHOOK", "desc" => "钉钉机器人通知WEBHOOK[文档](https://rachelwaf.apifox.cn/doc-4233518)</a>"),
			),
			"notice_api" => array(
				"api_notice" => "接口通知",
				"api_webhook" => array("title" => "WEBHOOK", "desc" => "接口通知WEBHOOK[文档](https://rachelwaf.apifox.cn/doc-4306536)</a>"),
				"api_webhook_body_template" => array("title" => "通知模板", "desc" => "格式为:{message:'{message}',url:'{url}',title:'{title}'}"),
			),
			"notice_browser" => array(
				"browser_notice" => "浏览器通知",
			),
			"rce" => array(
				'waf_rce' => "RCE检测",
				"rce_blacklist" => array("title" => "RCE黑名单", "desc" => "RCE黑名单（支持正则)"),
			),
			"base" => array(
				'WAF_APP_NAME' => array("title" => "WAF名称", "desc" => "WAF的名称"),
				'WAF_LOGO' => array("title" => "LOGO", "desc" => "WAF的LOGO"),
				'waf_print_logo' => array("title" => "打印LOGO", "desc" => "开启后拦截将输出WAF的LOGO"),
				'waf_debug' => array("title" => "调试模式", "desc" => "开启后拦截将输出错误信息"),
				'waf_ony_log' => array("title" => "仅记录日志", "desc" => "开启后不拦截攻击，仅仅记录日志"),
				"LD_PRELOAD_PATH" => "LD_PRELOAD路径",
				"password_sha1" => "密码",
				"open_basedir" => array("title" => "OPEN_BASEDIR", "desc" => "PHP配置OPEN_BASEDIR"),
				"attack_time" => array("title" => "封禁时长", "desc" => "单位为秒"),
			),
			"header" => array(
				'waf_headers' => "拦截Header",
				'waf_out_header' => "修改头信息",
				"head_string" => "被拦截时输出头信息",
			),
			"whitelist" => array(
				'waf_white_ip' => "IP白名单",
				"ip_address_allow" => array("title" => "允许访问应用的IP段", "desc" => "如：192.168.0.0/24,10.10.10.1-10.10.10.3"),
			),
			"blacklist" => array(
				'waf_black_ip' => "IP黑名单",
				"ip_address_deny" => array("title" => "拒绝访问应用的IP段", "desc" => "如：192.168.0.0/24,10.10.10.1-10.10.10.3"),
			),
			"flag" => array(
				"flag_path" => "FLAG路径",
				'waf_flag' => "FLAG检测",
				"waf_fake_flag" => "FLAG检测配置值",
			),
			"manage" => array(
				"WAF_FLAG_ENTER" => array("title" => "管理入口", "desc" => "如：配置为WAF则http(s)://127.0.0.1/?WAF=ui进入管理地址"),
				"ip_address_manage_allow" => array("title" => "管理IP", "desc" => "如：192.168.0.0/24,10.10.10.1-10.10.10.3,如何错误禁用设置IP导致无法进行管理，可添加环境ALLOW_MANAGE_IP=0.0.0./0"),
				"encode_api" => array("title" => "接口", "desc" => "API接口加密"),
				"max_login_err" => array("title" => "登录限制", "desc" => "允许登录失败次数"),
				"one_token" => array("title" => "会话", "desc" => "一个帐户同时只能登录一个会话"),
				"water_mark" => array("title" => "水印", "desc" => "开启水印保护"),
				"max_login_lock_time" => array("title" => "登录限制", "desc" => "帐户锁定时长（单位为秒）"),
				"max_token_live_time" => array("title" => "会话时长", "desc" => "登录有效时长（单位为秒）"),
			),
			"sql" => array(
				'waf_sql' => "SQL防护",
				"sql_blacklist" => array("title" => "禁止的SQL语句", "desc" => "支持正则"),
			),
			"char" => array(
				'waf_special_char' => "防止特殊字符",
				"waf_special_char_blacklist" => array("title" => "特殊字符黑名单", "desc" => "特殊字符黑名单（支持正则）"),
			),
			"remote" => array(
				'response_content_match' => array("title" => "远端检测", "desc" => "需要配置远端检测IP和端口"),
				"remote_ip" => "远端检测IP",
				"remote_port" => "远端检测端口",
			),
			"ddos" => array(
				"allow_ddos_time" => array("title" => "DDOS攻击检测时间", "desc" => "单位为秒"),
				'waf_ddos' => array("title" => "DDOS防护", "desc" => "防止DDOS攻击"),
			),
			"log" => array(
				'log_refresh' => "日志自动刷新",
				"max_log_size" => "日志最大长度",
				'web_log' => "WEB日志",
				'flag_eye_to_eye' => "FLAG监测",
				'flag_log' => "FLAG日志",
				'under_attack_log' => "攻击日志",
			),
			"upload" => array(
				'waf_upload_flag' => array("title" => "上传检测", "desc" => "检测上传文件是否包含木马特征"),
				'waf_upload' => array("title" => "上传限制", "desc" => "限制上传文件类型"),
				"upload_whitelist" => array("title" => "允许后缀", "desc" => "如：/jpg|png|gif|txt|mp3|mp4|doc|docx|zip/i (上传限制开启生效)"),
			),
			"upgrade" => array(
				"waf_upgrade_api" => array("title" => "升级码", "desc" => "填写升级服务器码,使用私有服务器升级"),
				"waf_upgrade_server_enable" => array("title" => "私有升级", "desc" => "使用私有升级服务器"),
				"waf_upgrade_build_path" => array("title" => "发布地址", "desc" => "升级文件发布路径"),
				"waf_upgrade_no_login" => array("title" => "需要登录", "desc" => "升级版本需要登录"),
				"waf_upgrade_check" => array("title" => "检查更新", "desc" => "检查更新"),
			),
			"other" => array(
				'waf_ld_preload' => "LDP_RELOAD检测",
				'waf_lfi' => "LFI检测",
				'waf_unserialize' => "序列化检测",
				'scheduled_kill_all' => array("title" => "自动清理", "desc" => "每分钟自动关闭所有Web进程并清理Crontab"),
				"water_mark" => array("title" => "水印", "desc" => "开启水印保护"),
			),
		);
		$this->lang = array();
	}
	function find($key, &$group)
	{
		foreach ($this->group as $index => $item) {
			foreach ($item as $k => $v) {
				if ($k === $key) {
					$group = $index;
					if (!is_array($v)) {
						return array("title" => $v, "desc" => "");
					}
					return $v;
				}
			}
		}
		return $key;
	}
	static function get($key, &$group)
	{
		$lang = new Langs();
		return $lang->find($key, $group);
	}
}
class FileCache
{
	private $cacheDir;
	private $expiration;
	private $ext, $prefix = "<php die():?>";
	private $encode;
	public function __construct($cacheDir, $expiration = 3600, $is_encode = true)
	{
		// 确保缓存目录存在并且可写
		if (!is_dir($cacheDir) || !is_writable($cacheDir)) {
			@mkdir($cacheDir, 0777, true);
			@chmod($cacheDir, 0777);
		}

		$this->ext = ".php";
		$this->encode = new Encode();
		$this->encode->state(_ENV::get("WAF.ENCODE_SESSION", $is_encode));
		$this->cacheDir = rtrim($cacheDir, '/') . '/';
		$this->expiration = (int)$expiration;
		$this->clear();
	}
	private function filename($key)
	{
		return $this->cacheDir . md5($key) . $this->ext;
	}
	private function get_key($filename)
	{
		return str_replace($this->ext, "", $filename);
	}
	public function get($key)
	{
		$cacheFile = $this->filename($key);

		// 检查缓存文件是否存在
		if (!file_exists($cacheFile)) {
			return false;
		}
		// 检查缓存是否过期
		if ($this->isExpired($cacheFile)) {
			$this->delete($key);
			return false;
		}

		// 读取缓存内容并返回
		return $this->get_cache($cacheFile);
	}
	public function clear()
	{
		$files = scandir($this->cacheDir);
		foreach ($files as $file) {
			if ($file != "." && $file != "..") { // 排除当前目录和上级目录
				$file = $this->cacheDir . $file;
				// 检查缓存是否过期
				if ($this->isExpired($file)) {
					@unlink($file);
				}
			}
		}
	}

	function getFiles($path)
	{
		$list = scandir($path);
		return $list;
	}
	public function find($username = "", $is_clear = false)
	{
		return $this->items($username, $is_clear);
	}
	public function items($username = "", $is_clear = false)
	{
		$files = $this->getFiles($this->cacheDir);
		$arr = array();
		foreach ($files as $file) {
			if (!is_dir($file)) { // 排除当前目录和上级目录
				$_file = $this->cacheDir . $file;
				// 检查缓存是否过期
				if (!$this->isExpired($_file)) {
					$key = $this->get_key($file);
					$item = $this->get_cache($_file);
					$item["EXPIRED"] = date("Y-m-d H:i:s", filemtime($_file));
					$item["KEY"] = $key;
					if (@$item["USERNAME"] === $username || empty($username)) {
						if ($is_clear) {
							@unlink($_file);
							$arr["DELETE"] = $key;
						} else {
							$arr[] = $item;
						}
					}
				}
			}
		}
		return $arr;
	}
	public function set($key, $data)
	{
		$cacheFile = $this->filename($key);
		// 将数据写入缓存文件
		if ($this->put_cache($cacheFile, $data) !== false) {
			// 设置缓存文件的过期时间
			touch($cacheFile, time() + $this->expiration);
			return true;
		}

		return false;
	}
	private function get_cache($cacheFile)
	{
		$data = file_get_contents($cacheFile);
		$data = substr($data, strlen($this->prefix));
		$data = $this->encode->decrypt($data);
		$data = @unserialize($data);
		return $data;
	}
	private function put_cache($cacheFile, $data)
	{
		$data = serialize($data);
		$data = $this->encode->encode($data);
		$data = $this->prefix . $data;
		return file_put_contents($cacheFile, $data, LOCK_EX);
	}
	public function delete($key)
	{
		$cacheFile = $this->filename($key);
		// 删除缓存文件
		if (file_exists($cacheFile)) {
			return unlink($cacheFile);
		}
		return false;
	}
	public function convert($second)
	{
		$new_time = '';
		$d = floor($second / (3600 * 24));
		$h = floor(($second % (3600 * 24)) / 3600);
		$m = floor((($second % (3600 * 24)) % 3600) / 60);
		if ($d > '0') {
			if ($h == '0' && $m == '0') {
				$new_time = $d . '天';
			} else {
				$new_time = $d . '天' . $h . '小时' . $m . '分钟';
			}
		} else {
			if ($h != '0') {
				if ($m == '0') {
					$new_time = $h . '小时';
				} else {
					$new_time = $h . '小时' . $m . '分';
				}
			} else {
				$new_time = $m . '分钟';
			}
		}
		return $new_time;
	}
	/**
	 * 获取缓存文件过期时间
	 */
	function time($key, $format = 'Y-m-d H:i:s')
	{
		$cacheFile = $this->filename($key);
		return $this->convert(filemtime($cacheFile) + $this->expiration - time());
	}
	private function isExpired($cacheFile)
	{
		// 检查缓存文件是否过期
		return (filemtime($cacheFile) + $this->expiration) < time();
	}
}
class Update
{
	static public $_instance;
	private $url = "", $build_file;
	private $zip;
	public static function getInstance($url = "")
	{
		global $config;
		if (empty($url)) {
			if ($config->waf_upgrade_server_enable) {
				$url = $config->waf_upgrade_api;
			} else {
				$url = RACHEL_WAF_UPDATE_API;
			}
			$url = Encode::getInstance()->decrypt($url);
		}
		if (self::$_instance instanceof self) {
			return self::$_instance;
		}
		self::$_instance = new self($url);
		return self::$_instance;
	}
	function __construct($url)
	{
		$this->url = $url;
		$this->build_file = __DIR__ . "/waf.txt";
	}
	function version(&$error = "")
	{
		if (empty($this->url)) {
			$error = $this->url;
			return RACHEL_WAF_VERSION;
		}
		$content = file_get_contents($this->url);
		$content = @json_decode($content, true)['data']['content'];
		preg_match("/(?<=\[).*(?=\])/i", $content, $version);
		$version = @$version[0];
		if (empty($version)) {
			$error = $this->url;
			$version = RACHEL_WAF_VERSION;
		}
		return $version;
	}
	function upgrade_url()
	{
		if (empty($this->url)) {
			return "";
		}
		$content = file_get_contents($this->url);
		$content = @json_decode($content, true)['data']['content'];
		preg_match("/(?<=\().*(?=\))/i", $content, $data);
		$url = @$data[0];
		return $url;
	}
	function upgrade(&$msg = "", &$code = "")
	{
		$url = $this->upgrade_url();
		$url = Encode::getInstance()->decrypt($url);
		if (empty($url)) {
			$code = 202;
			$msg = "升级服务器未配置";
			return false;
		}
		$data = file_get_contents($url);
		$file = __DIR__ . "/tmp.txt";
		$rel = file_put_contents($file, $data);
		if ($rel == 0) {
			$code = "203";
			$msg = "当前版本不存在";
			return $url;
		}
		$this->zip = new Res($file);
		$data = $this->zip->load_object();
		@unlink($file);
		if (!$data) {
			$code = "202";
			$msg = "更新失败";
			return $url;
		}
		$save_php = file_put_contents(__FILE__, @$data["php"]);
		$save_res = file_put_contents(__DIR__ . "/ui.res", @$data["res"]);
		if ($save_php == 0 || $save_res == 0) {
			$code = "203";
			$msg = "更新失败";
			return $url;
		}
		$msg = "更新成功";
		return array(
			"waf" => $save_php,
			"res" => $save_res,
		);
	}
	function upgrade_file(&$msg = "", &$code = "")
	{
		$file = $this->build_file;
		if (file_exists($file)) {
			$data = file_get_contents($file);
			@ob_clean();
			die($data);
		}
		die();
	}
	function build(&$msg = "", &$code = "")
	{
		$arr = array(
			"version" => RACHEL_WAF_VERSION,
			"php" => file_get_contents(__DIR__ . "/WAF.php"),
			"res" => file_get_contents(__DIR__ . "/ui.res"),
		);
		$file = $this->build_file;
		$this->zip = new Res($file);
		$data = $this->zip->save($arr);
		$data = file_get_contents($file);
		$msg = "发布成功，当前版本为:" . RACHEL_WAF_VERSION;
		return true;
	}
}

class Services
{
	private $obj_cfg;
	function __construct($args)
	{
		
		global $config_path;
		global $check_upload_path;
		$root = str_replace('\\', '/', realpath(dirname(__FILE__) . '/../'));
		_Env::loadFile($root . '/.env');

		define("__WAF_ROOT__", str_replace("\\", "/", _Env::get("WAF.ROOT", $_SERVER['DOCUMENT_ROOT'] . "/waf/tmp/WAF/")));
		define("__WAF_SO_ROOT__", str_replace("\\", "/", _Env::get("WAF.LIB_PATH", $_SERVER['DOCUMENT_ROOT'] . "/waf/waf.so")));
		$check_upload_path = __WAF_ROOT__ . "wb_check_upload";
		$config_path = str_replace("\\", "/", _Env::get("WAF.CONFIG_PATH", __DIR__ . '/.waf'));
		if (_Env::get("WAF.DEBUG", true)) {
			ini_set("display_errors", "on");
			error_reporting(1);
		}
		if (_Env::get("WAF.CLEAN", false)) {
			@ob_end_clean();
		}
		date_default_timezone_set('Asia/Shanghai');
		$this->start($args);
	}
	function install($dir)
	{
		$layer_list = scandir($dir);
		foreach ($layer_list as $i) {
			if ($i === '.' || $i === "..") {
				continue;
			}
			$next = $dir . $i;
			if (is_dir($next)) {
				if ($next[strlen($next) - 1] !== '/') {
					$next .= "/";
				}
				$this->install($next);
			} else {
				$ext = end(explode('.', $next));
				$php_ext = array("php", "php5", "phtml");
				if (in_array($ext, $php_ext) && strlen($ext) !== strlen($next)) {
					$old_file_str = file_get_contents($next);
					if (strpos($old_file_str, "<?php") !== false && $next !== __FILE__) {
						echo $next . "\n";
						$start_pos = strpos($old_file_str, "<?php");
						if ($start_pos === false) {
							return;
						}
						$first_code_pos1 = strpos($old_file_str, ";", $start_pos);
						$first_code_pos2 = strpos($old_file_str, "{", $start_pos);

						if ($first_code_pos1 === false) {
							$first_code_pos = $first_code_pos2;
						} else if ($first_code_pos2 === false) {
							$first_code_pos = $first_code_pos1;
						} else $first_code_pos = min($first_code_pos1, $first_code_pos2);
						if ($first_code_pos === false) {
							return;
						}
						while (strrpos(substr($old_file_str, $start_pos, $first_code_pos - $start_pos), "/*") !== false || strrpos(substr($old_file_str, $start_pos, $first_code_pos - $start_pos), "//") !== false || strrpos(substr($old_file_str, $start_pos, $first_code_pos - $start_pos), "#") !== false) {
							if (strrpos(substr($old_file_str, $start_pos, $first_code_pos - $start_pos), "/*") !== false) {
								$start_pos = strpos($old_file_str, "*/", strrpos(substr($old_file_str, $start_pos, $first_code_pos - $start_pos), "/*") + $start_pos);
								if ($start_pos === false) {
									return;
								}
								$first_code_pos1 = strpos($old_file_str, ";", $start_pos);
								$first_code_pos2 = strpos($old_file_str, "{", $start_pos);

								if ($first_code_pos1 === false) {
									$first_code_pos = $first_code_pos2;
								} else if ($first_code_pos2 === false) {
									$first_code_pos = $first_code_pos1;
								} else $first_code_pos = min($first_code_pos1, $first_code_pos2);
								if ($first_code_pos === false) {
									return;
								}
							}
							if (strrpos(substr($old_file_str, $start_pos, $first_code_pos - $start_pos), "//") !== false) {
								$start_pos = strpos($old_file_str, "\n", strrpos(substr($old_file_str, $start_pos, $first_code_pos - $start_pos), "//") + $start_pos);
								if ($start_pos === false) {
									return;
								}
								$first_code_pos1 = strpos($old_file_str, ";", $start_pos);
								$first_code_pos2 = strpos($old_file_str, "{", $start_pos);

								if ($first_code_pos1 === false) {
									$first_code_pos = $first_code_pos2;
								} else if ($first_code_pos2 === false) {
									$first_code_pos = $first_code_pos1;
								} else $first_code_pos = min($first_code_pos1, $first_code_pos2);
								if ($first_code_pos === false) {
									return;
								}
							}

							if (strrpos(substr($old_file_str, $start_pos, $first_code_pos - $start_pos), "#") !== false) {
								$start_pos = strpos($old_file_str, "\n", strrpos(substr($old_file_str, $start_pos, $first_code_pos - $start_pos), "#") + $start_pos);
								if ($start_pos === false) {
									return;
								}
								$first_code_pos1 = strpos($old_file_str, ";", $start_pos);
								$first_code_pos2 = strpos($old_file_str, "{", $start_pos);

								if ($first_code_pos1 === false) {
									$first_code_pos = $first_code_pos2;
								} else if ($first_code_pos2 === false) {
									$first_code_pos = $first_code_pos1;
								} else $first_code_pos = min($first_code_pos1, $first_code_pos2);
								if ($first_code_pos === false) {
									return;
								}
							}
						}
						if (preg_match("/namespace/i", substr($old_file_str, $start_pos, $first_code_pos - $start_pos)) === 1) {
							return;	// 一般来说, 只要加在入口文件即可
						} else if (preg_match("/declare {0,}\t{0,}\\(/i", substr($old_file_str, $start_pos, $first_code_pos - $start_pos)) === 1) {
							file_put_contents($next, substr($old_file_str, 0, $first_code_pos + 1) . "\ninclude_once '" . __FILE__ . "';\n" . substr($old_file_str, $first_code_pos + 1));
						} else {
							file_put_contents($next, "<?php include_once '" . __FILE__ . "'; ?>" . $old_file_str);
						}
					}
				}
			}
		}
	}
	function uninstall($dir)
	{
		$layer_list = scandir($dir);
		foreach ($layer_list as $i) {
			if ($i === '.' || $i == "..") {
				continue;
			}
			$next = $dir . $i;
			if (is_dir($next)) {
				if ($next[strlen($next) - 1] !== '/') {
					$next .= "/";
				}
				$this->uninstall($next);
			} else {
				$ext = end(explode('.', $next));
				$php_ext = array("php", "php5", "phtml");
				if (in_array($ext, $php_ext) && strlen($ext) !== strlen($next)) {
					$old_file_str = file_get_contents($next);
					if (strpos(ltrim($old_file_str), "<?php include_once '" . __FILE__ . "'; ?>") === 0) {
						echo $next . "\n";
						file_put_contents($next, substr($old_file_str, strlen("<?php include_once '" . __FILE__ . "'; ?>")));
					} else {
						file_put_contents($next, str_replace("\ninclude_once '" . __FILE__ . "';\n", "", $old_file_str));
					}
				}
			}
		}
	}

	function REQUEST($key, $default = "")
	{
		if (isset($_GET[$key])) {
			return $_GET[$key];
		}
		return $default;
	}

	function GET($key, $default = "")
	{
		return $this->REQUEST($key, $default);
	}

	function cmd($argv)
	{
		if (!defined('STDIN')) {
			return;
		}
		$resource_path = _Env::get("WAF.RES", "ui/ele");
		if (isset($argv[1]) && $argv[1] === "--build") {
			if (isset($argv[2])) {
				$resource_path = "/" . $argv[2] . "/";
			}
			$ui = new ui($resource_path);
			$ui->save_res();
			die("build ok");
		}

		if (isset($argv[1]) && $argv[1] === "--install") {
			if (!isset($argv[2])) {
				die("Usage: php WAF.php --install [web dir]\n	Example: php WAF.php --install /var/www/html");
			}
			$install_path = $argv[2];
			if ($install_path[strlen($install_path) - 1] !== '/') {
				$install_path .= "/";
			}
			$this->install($install_path);
			die();
		}
		if (isset($argv[1]) && $argv[1] === "--uninstall") {
			if (!isset($argv[2])) {
				die("Usage: php WAF.php --uninstall [web dir]\n	Example: php WAF.php --uninstall /var/www/html");
			}
			$install_path = $argv[2];
			if ($install_path[strlen($install_path) - 1] !== '/') {
				$install_path .= "/";
			}
			$this->uninstall($install_path);
			die();
		}
		die("Usage: php WAF.php [--install / --uninstall] [web dir]\n	Example: php WAF.php --uninstall /var/www/html");
	}
	function start($argv)
	{
		global $config;
		global $config_path;
		$this->cmd($argv);
		if (is_dir(dirname($config_path)) == false) {
			@mkdir(dirname($config_path), 0777, true);
			@chmod($config_path, 0777);
		}

		$this->obj_cfg = new Res($config_path, _Env::get("WAF.KEY", md5("RACH")), "json", _Env::get("WAF.ENCODE", false), "AES-256-CBC");
		if (!file_exists($config_path)) {
			$this->obj_cfg->save(new ConfigManager());
		}
		
		$config = $this->obj_cfg->load(new ConfigManager());
		// 其他配置
		foreach (get_object_vars($config) as $key => $val) {
			$$key = $val;
		}

		if (empty($config->WAF_FLAG_ENTER)) {
			$config->WAF_FLAG_ENTER = "WAF";
		}
		if ($this->GET($config->WAF_FLAG_ENTER) === "api") {
			@ob_end_clean();
			$api = new Api();
			$api->call();
			die();
		}
		if ($this->GET($config->WAF_FLAG_ENTER) === "ui") {
			@ob_end_clean();
			@session_start();
			$ui = new ui();
			$ui->password_hash = $config->password_sha1;
			$ui->show();
			die();
		}

		if ($this->GET($config->WAF_FLAG_ENTER) === 'resource') {
			ob_end_clean();
			$ui = new ui();
			$resource_name = @$_GET['resource'];
			die($ui->res($resource_name));
		}
	}
}
ini_set("display_errors", "off");
error_reporting(0);
$svc = new Services(@$argv);
$WAF = new WAF();
