<?php

namespace RainLoop;

class Utils
{
	/**
	 * @var string
	 */
	static $CookieDefaultPath = '';

	/**
	 * @var bool|null
	 */
	static $CookieDefaultSecure = null;

	const
		/**
		 * 30 days cookie
		 * Used by: ServiceProxyExternal, compileLogParams, GetCsrfToken
		 */
		CONNECTION_TOKEN = 'smtoken',

		/**
		 * Session cookie
		 * Used by: EncodeKeyValuesQ, DecodeKeyValuesQ
		 */
		SESSION_TOKEN = 'smsession',

		/**
		 *  Max secure cookie chunk length
		 * 	Used by: GetSecureCookie, SetSecureCookie
		 */
		SECURE_COOKIE_CHUNK_LENGTH = 2500,

		/**
		 *  Total combined secure cookie length
		 * 	Used by: GetSecureCookie, SetSecureCookie
		 */
		SECURE_COOKIE_MAX_LENGTH = (self::SECURE_COOKIE_CHUNK_LENGTH * 5);

	public static function EncodeKeyValuesQ(array $aValues, string $sCustomKey = '') : string
	{
		return \SnappyMail\Crypt::EncryptUrlSafe(
			$aValues,
			\sha1(APP_SALT.$sCustomKey.'Q'.static::GetSessionToken())
		);
	}

	public static function DecodeKeyValuesQ(string $sEncodedValues, string $sCustomKey = '') : array
	{
		return \SnappyMail\Crypt::DecryptUrlSafe(
			$sEncodedValues,
			\sha1(APP_SALT.$sCustomKey.'Q'.static::GetSessionToken(false))
		) ?: array();
	}

	public static function GetSessionToken(bool $generate = true) : ?string
	{
		$sToken = static::GetCookie(self::SESSION_TOKEN, null);
		if (!$sToken) {
			if (!$generate) {
				return null;
			}
			\SnappyMail\Log::debug('TOKENS', 'New SESSION_TOKEN');
			$sToken = \MailSo\Base\Utils::Sha1Rand(APP_SALT);
			static::SetCookie(self::SESSION_TOKEN, $sToken);
		}
		return \sha1('Session'.APP_SALT.$sToken.'Token'.APP_SALT);
	}

	public static function GetConnectionToken() : string
	{
		$sToken = static::GetCookie(self::CONNECTION_TOKEN);
		if (!$sToken)
		{
			$sToken = \MailSo\Base\Utils::Sha1Rand(APP_SALT);
			static::SetCookie(self::CONNECTION_TOKEN, $sToken, \time() + 3600 * 24 * 30);
		}

		return \sha1('Connection'.APP_SALT.$sToken.'Token'.APP_SALT);
	}

	public static function GetCsrfToken() : string
	{
		return \sha1('Csrf'.APP_SALT.self::GetConnectionToken().'Token'.APP_SALT);
	}

	public static function UpdateConnectionToken() : void
	{
		$sToken = static::GetCookie(self::CONNECTION_TOKEN);
		if ($sToken)
		{
			static::SetCookie(self::CONNECTION_TOKEN, $sToken, \time() + 3600 * 24 * 30);
		}
	}

	public static function ClearHtmlOutput(string $sHtml) : string
	{
//		return $sHtml;
		return \preg_replace(
			['@\\s*/>@', '/\\s*&nbsp;/i', '/&nbsp;\\s*/i', '/[\\r\\n\\t]+/', '/>\\s+</'],
			['>', "\xC2\xA0", "\xC2\xA0", ' ', '><'],
			\trim($sHtml)
		);
	}

	/**
	 * @param mixed $mDefault = null
	 * @return mixed
	 */
	public static function GetCookie(string $sName, $mDefault = null)
	{
		return isset($_COOKIE[$sName]) ? $_COOKIE[$sName] : $mDefault;
	}

	public static function GetSecureCookie(string $sName)
	{
		if (!isset($_COOKIE[$sName]) || 1024 > strlen($_COOKIE[$sName])) {
			return;
		}

		// any cookies that have been split will have their first character as caret - anything that isn't
		// a caret and bigger than 1kb will be safe to presume is a standard secure cookie
		if (substr($_COOKIE[$sName], 0, 1) !== '^') {
			return \SnappyMail\Crypt::DecryptFromJSON(\MailSo\Base\Utils::UrlSafeBase64Decode($_COOKIE[$sName]));
		}

		// anything that proceeds down this step will be presumed to be a secure cookie
		// there is no checksums involved here as it's essentially double encoded - if properly unpacked it will
		// be JSON and if not it'll be a garbage byte stream that will either fail to be decrypted or fail to
		// be parsed via the JSON library
		$iMaxChunks = (int) ceil(static::SECURE_COOKIE_MAX_LENGTH / static::SECURE_COOKIE_CHUNK_LENGTH);
		$sBuffer = '';

		for ($i = 0; $i < $iMaxChunks; ++$i) {
			$sSplitName = ($i > 0)
				? $sName . '$' . $i
				: $sName;

			if (!isset($_COOKIE[$sSplitName])) {
				return;
			}

			$sStartChar = substr($_COOKIE[$sSplitName], 0, 1);
			$sEndChar = substr($_COOKIE[$sSplitName], -1, 1);

			if ($i === 0 && $sStartChar !== '^' || $i > 0 && $sStartChar !== '~') {
				return;
			}
			if ($sEndChar !== '$' && $sEndChar !== '~') {
				return;
			}

			$sBuffer .= substr($_COOKIE[$sSplitName], 1, -1);

			if ($sEndChar === '$') {
				break;
			}
		}

		return \SnappyMail\Crypt::DecryptFromJSON(\MailSo\Base\Utils::UrlSafeBase64Decode($sBuffer));
	}

	public static function SetCookie(string $sName, string $sValue = '', int $iExpire = 0, bool $bHttpOnly = true)
	{
		$sPath = static::$CookieDefaultPath;
		$_COOKIE[$sName] = $sValue;
		\setcookie($sName, $sValue, array(
			'expires' => $iExpire,
			'path' => $sPath && \strlen($sPath) ? $sPath : '/',
//			'domain' => $sDomain,
			'secure' => isset($_SERVER['HTTPS']) || static::$CookieDefaultSecure,
			'httponly' => $bHttpOnly,
			'samesite' => 'Strict'
		));
	}

	public static function SetSecureCookie(string $sName, mixed $sValue = '', int $iExpire = 0, bool $bHttpOnly = true)
	{
        $sValue = \MailSo\Base\Utils::UrlSafeBase64Encode(\SnappyMail\Crypt::EncryptToJSON($sValue));

        $iCookieLength = strlen($sValue);

		if ($iCookieLength > static::SECURE_COOKIE_MAX_LENGTH) {
			return null;
		}
		if ($iCookieLength <= static::SECURE_COOKIE_CHUNK_LENGTH) {
			return static::SetCookie($sName, $sValue, $iExpire, $bHttpOnly);
		}

		// cookie splitting!
		//
		// logic for this is interesting - we're going to split the cookie up into chunks of say, a large amount
		// of characters and then add some suffixes and prefixes to determine whether or not the string is contiguous
		// there is no need for checksums because it's encrypted and JSON encoded, any failure will be unrecoverable
		//
		// note: first split will be kept with its original name as there appear to be places in code that check
		// for $_COOKIE and then end up calling GetSecureCookie - changing that would be very dangerous
		$iCookieChunkLength = static::SECURE_COOKIE_CHUNK_LENGTH;
		$iRequiredChunks = (int) ceil($iCookieLength / $iCookieChunkLength);

		for ($i = 0; $i < $iRequiredChunks; ++$i) {
			$sSplitName = ($i > 0)
				? $sName . '$' . $i
				: $sName;

			$sChunkedValue = ($i === 0) ? '^' : '~';
			$sChunkedValue .= substr($sValue, $iCookieChunkLength * $i, $iCookieChunkLength);
			$sChunkedValue .= (($i + 1) < $iRequiredChunks) ? '~' : '$';

			static::SetCookie($sSplitName, $sChunkedValue, $iExpire, $bHttpOnly);
		}

		return;
	}

	public static function ClearCookie(string $sName)
	{
		$aCookieNames = [];
		$sPath = static::$CookieDefaultPath;

		foreach (array_keys($_COOKIE) as $sCookieName) {
			if (strtok($sCookieName, '$') === $sName) {
				$aCookieNames[] = $sCookieName;
			}
		}

		foreach ($aCookieNames as $sCookieName) {
			unset($_COOKIE[$sCookieName]);

			setcookie($sCookieName, '', array(
				'expires' => \time() - 3600 * 24 * 30,
				'path' => $sPath && \strlen($sPath) ? $sPath : '/',
				'secure' => isset($_SERVER['HTTPS']) || static::$CookieDefaultSecure,
				'httponly' => true,
				'samesite' => 'Strict'
			));
		}
	}

	public static function UrlEncode(string $sV, bool $bEncode = false) : string
	{
		return $bEncode ? \urlencode($sV) : $sV;
	}

	public static function WebPath() : string
	{
		static $sAppPath;
		if (!$sAppPath) {
			$sAppPath = \rtrim(Api::Config()->Get('webmail', 'app_path', '')
				?: \preg_replace('#index\\.php.*$#D', '', $_SERVER['SCRIPT_NAME']),
			'/') . '/';
		}
		return $sAppPath;
	}

	public static function WebVersionPath() : string
	{
		return self::WebPath().'snappymail/v/'.APP_VERSION.'/';
	}

	public static function WebStaticPath(string $path = '') : string
	{
		return self::WebVersionPath() . 'static/' . $path;
	}

	public static function RemoveSuggestionDuplicates(array $aSuggestions) : array
	{
		$aResult = array();

		foreach ($aSuggestions as $aItem)
		{
			$sLine = \implode('~~', $aItem);
			if (!isset($aResult[$sLine]))
			{
				$aResult[$sLine] = $aItem;
			}
		}

		return array_values($aResult);
	}

	public static function inOpenBasedir(string $name) : string
	{
		static $open_basedir;
		if (null === $open_basedir) {
			$open_basedir = \array_filter(\explode(PATH_SEPARATOR, \ini_get('open_basedir')));
		}
		if ($open_basedir) {
			foreach ($open_basedir as $dir) {
				if (\str_starts_with($name, $dir)) {
					return true;
				}
			}
			\SnappyMail\Log::warning('OpenBasedir', "open_basedir restriction in effect. {$name} is not within the allowed path(s): " . \ini_get('open_basedir'));
			return false;
		}
		return true;
	}

	/**
	 * Replace control characters, ampersand, spaces and reserved characters (based on Win95 VFAT)
	 * en.wikipedia.org/wiki/Filename#Reserved_characters_and_words
	 */
	public static function fixName(string $filename) : string
	{
		return \preg_replace('#[|\\\\?*<":>+\\[\\]/&\\s\\pC]#su', '-', $filename);
	}

	public static function saveFile(string $filename, string $data) : void
	{
		$dir = \dirname($filename);
		if (!\is_dir($dir) && !\mkdir($dir, 0700, true)) {
			throw new Exceptions\Exception('Failed to create directory "'.$dir.'"');
		}
		if (false === \file_put_contents($filename, $data)) {
			throw new Exceptions\Exception('Failed to save file "'.$filename.'"');
		}
		\clearstatcache();
		\chmod($filename, 0600);
/*
		try {
		} catch (\Throwable $oException) {
			throw new Exceptions\Exception($oException->getMessage() . ': ' . \error_get_last()['message']);
		}
*/
	}
}
