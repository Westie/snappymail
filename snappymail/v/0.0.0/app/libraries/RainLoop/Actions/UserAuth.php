<?php

namespace RainLoop\Actions;

use RainLoop\Notifications;
use RainLoop\Utils;
use RainLoop\Model\Account;
use RainLoop\Model\MainAccount;
use RainLoop\Model\AdditionalAccount;
use RainLoop\Providers\Storage\Enumerations\StorageType;
use RainLoop\Exceptions\ClientException;

trait UserAuth
{
	/**
	 * @var string
	 */
	private $oAdditionalAuthAccount = false;
	private $oMainAuthAccount = false;

	/**
	 * @throws \RainLoop\Exceptions\ClientException
	 */
	public function LoginProcess(string &$sEmail, string &$sPassword, bool $bSignMe = false, bool $bMainAccount = true): Account
	{
		$sInputEmail = $sEmail;

		$this->Plugins()->RunHook('login.credentials.step-1', array(&$sEmail));

		$sEmail = \MailSo\Base\Utils::Trim($sEmail);
		if ($this->Config()->Get('login', 'login_lowercase', true)) {
			$sEmail = \mb_strtolower($sEmail);
		}

		if (false === \strpos($sEmail, '@')) {
			$this->Logger()->Write('The email address "' . $sEmail . '" is not complete', \MailSo\Log\Enumerations\Type::INFO, 'LOGIN');

			if (false === \strpos($sEmail, '@') && $this->Config()->Get('login', 'determine_user_domain', false)) {
				$sUserHost = \trim($this->Http()->GetHost(false, true, true));
				$this->Logger()->Write('Determined user domain: ' . $sUserHost, \MailSo\Log\Enumerations\Type::INFO, 'LOGIN');

				$bAdded = false;

				$iLimit = 14;
				$aDomainParts = \explode('.', $sUserHost);

				$oDomainProvider = $this->DomainProvider();
				while (\count($aDomainParts) && 0 < $iLimit) {
					$sLine = \trim(\implode('.', $aDomainParts), '. ');

					$oDomain = $oDomainProvider->Load($sLine, false);
					if ($oDomain) {
						$bAdded = true;
						$this->Logger()->Write('Check "' . $sLine . '": OK (' . $sEmail . ' > ' . $sEmail . '@' . $sLine . ')',
							\MailSo\Log\Enumerations\Type::INFO, 'LOGIN');

						$sEmail = $sEmail . '@' . $sLine;
						break;
					} else {
						$this->Logger()->Write('Check "' . $sLine . '": NO', \MailSo\Log\Enumerations\Type::INFO, 'LOGIN');
					}

					\array_shift($aDomainParts);
					$iLimit--;
				}

				if (!$bAdded) {
					$sLine = $sUserHost;
					$oDomain = $oDomainProvider->Load($sLine, true);
					if ($oDomain && $oDomain) {
						$bAdded = true;
						$this->Logger()->Write('Check "' . $sLine . '" with wildcard: OK (' . $sEmail . ' > ' . $sEmail . '@' . $sLine . ')',
							\MailSo\Log\Enumerations\Type::INFO, 'LOGIN');

						$sEmail = $sEmail . '@' . $sLine;
					} else {
						$this->Logger()->Write('Check "' . $sLine . '" with wildcard: NO', \MailSo\Log\Enumerations\Type::INFO, 'LOGIN');
					}
				}

				if (!$bAdded) {
					$this->Logger()->Write('Domain was not found!', \MailSo\Log\Enumerations\Type::INFO, 'LOGIN');
				}
			}

			$sDefDomain = \trim($this->Config()->Get('login', 'default_domain', ''));
			if (false === \strpos($sEmail, '@') && \strlen($sDefDomain)) {
				$this->Logger()->Write('Default domain "' . $sDefDomain . '" was used. (' . $sEmail . ' > ' . $sEmail . '@' . $sDefDomain . ')',
					\MailSo\Log\Enumerations\Type::INFO, 'LOGIN');

				$sEmail = $sEmail . '@' . $sDefDomain;
			}
		}

		$this->Plugins()->RunHook('login.credentials.step-2', array(&$sEmail, &$sPassword));

		if (false === \strpos($sEmail, '@') || !\strlen($sPassword)) {
			$this->loginErrorDelay();

			throw new ClientException(Notifications::InvalidInputArgument);
		}

		$this->Logger()->AddSecret($sPassword);

		$sLogin = $sEmail;
		if ($this->Config()->Get('login', 'login_lowercase', true)) {
			$sLogin = \mb_strtolower($sLogin);
		}

		$this->Plugins()->RunHook('login.credentials', array(&$sEmail, &$sLogin, &$sPassword));

		$this->Logger()->AddSecret($sPassword);

		$oAccount = null;
		try {
			$oAccount = $bMainAccount
				? MainAccount::NewInstanceFromCredentials($this, $sEmail, $sLogin, $sPassword, true)
				: AdditionalAccount::NewInstanceFromCredentials($this, $sEmail, $sLogin, $sPassword, true);
			if (!$oAccount) {
				throw new ClientException(Notifications::AuthError);
			}
		} catch (\Throwable $oException) {
			$this->LoggerAuthHelper($oAccount, $this->getAdditionalLogParamsByUserLogin($sInputEmail));
			$this->loginErrorDelay();
			throw $oException;
		}

		try {
			$this->CheckMailConnection($oAccount, true);
			if ($bMainAccount) {
				$bSignMe && $this->SetSignMeToken($oAccount);
				$this->StorageProvider()->Put($oAccount, StorageType::SESSION, Utils::GetSessionToken(), 'true');
			}
		} catch (\Throwable $oException) {
			$this->loginErrorDelay();

			throw $oException;
		}

		return $oAccount;
	}

	private static function SetAccountCookie(string $sName, ?Account $oAccount)
	{
		if ($oAccount) {
			Utils::SetCookie(
				$sName,
				\MailSo\Base\Utils::UrlSafeBase64Encode(\SnappyMail\Crypt::EncryptToJSON($oAccount))
			);
		} else {
			Utils::ClearCookie($sName);
		}
	}

	public function switchAccount(string $sEmail) : bool
	{
		$this->Http()->ServerNoCache();
		$oMainAccount = $this->getMainAccountFromToken(false);
		if ($sEmail && $oMainAccount && $this->GetCapa(\RainLoop\Enumerations\Capa::ADDITIONAL_ACCOUNTS)) {
			$oAccount = null;
			if ($oMainAccount->Email() === $sEmail) {
				$this->SetAdditionalAuthToken($oAccount);
				return true;
			}
			$sEmail = \MailSo\Base\Utils::IdnToAscii($sEmail);
			$aAccounts = $this->GetAccounts($oMainAccount);
			if (!isset($aAccounts[$sEmail])) {
				throw new ClientException(Notifications::AccountDoesNotExist);
			}
			$oAccount = AdditionalAccount::NewInstanceFromTokenArray(
				$this, $aAccounts[$sEmail]
			);
			if (!$oAccount) {
				throw new ClientException(Notifications::AccountSwitchFailed);
			}

			// Test the login
			$this->CheckMailConnection($oAccount);

			$this->SetAdditionalAuthToken($oAccount);
			return true;
		}
		return false;
	}

	/**
	 * Returns RainLoop\Model\AdditionalAccount when it exists,
	 * else returns RainLoop\Model\Account when it exists,
	 * else null
	 *
	 * @throws \RainLoop\Exceptions\ClientException
	 */
	public function getAccountFromToken(bool $bThrowExceptionOnFalse = true): ?Account
	{
		$this->getMainAccountFromToken($bThrowExceptionOnFalse);

		if (false === $this->oAdditionalAuthAccount && isset($_COOKIE[self::AUTH_ADDITIONAL_TOKEN_KEY])) {
			$aData = Utils::GetSecureCookie(self::AUTH_ADDITIONAL_TOKEN_KEY);
			if ($aData) {
				$this->oAdditionalAuthAccount = AdditionalAccount::NewInstanceFromTokenArray(
					$this,
					$aData,
					$bThrowExceptionOnFalse
				);
			}
			if (!$this->oAdditionalAuthAccount) {
				$this->oAdditionalAuthAccount = null;
				Utils::ClearCookie(self::AUTH_ADDITIONAL_TOKEN_KEY);
			}
		}

		return $this->oAdditionalAuthAccount ?: $this->oMainAuthAccount;
	}

	/**
	 * @throws \RainLoop\Exceptions\ClientException
	 */
	public function getMainAccountFromToken(bool $bThrowExceptionOnFalse = true): ?MainAccount
	{
		if (false === $this->oMainAuthAccount) try {
			$this->oMainAuthAccount = null;
			if (isset($_COOKIE[self::AUTH_SPEC_LOGOUT_TOKEN_KEY])) {
				Utils::ClearCookie(self::AUTH_SPEC_LOGOUT_TOKEN_KEY);
				Utils::ClearCookie(self::AUTH_SIGN_ME_TOKEN_KEY);
//				Utils::ClearCookie(self::AUTH_SPEC_TOKEN_KEY);
//				Utils::ClearCookie(self::AUTH_ADDITIONAL_TOKEN_KEY);
				Utils::ClearCookie(Utils::SESSION_TOKEN);
			}

			$aData = Utils::GetSecureCookie(self::AUTH_SPEC_TOKEN_KEY);
			if ($aData) {
				/**
				 * Server side control/kickout of logged in sessions
				 * https://github.com/the-djmaze/snappymail/issues/151
				 */
				if (empty($_COOKIE[Utils::SESSION_TOKEN])) {
//					\MailSo\Base\Http::StatusHeader(401);
					$this->Logout(true);
//					$sAdditionalMessage = $this->StaticI18N('SESSION_UNDEFINED');
					\SnappyMail\Log::notice('TOKENS', 'SESSION_TOKEN empty');
					throw new ClientException(Notifications::InvalidToken, null, 'Session undefined');
				}
				$oMainAuthAccount = MainAccount::NewInstanceFromTokenArray(
					$this,
					$aData,
					$bThrowExceptionOnFalse
				);
				$oMainAuthAccount || \SnappyMail\Log::notice('TOKENS', 'AUTH_SPEC_TOKEN_KEY invalid');
				$sToken = $oMainAuthAccount ? Utils::GetSessionToken(false) : null;
				$sTokenValue = $sToken ? $this->StorageProvider()->Get($oMainAuthAccount, StorageType::SESSION, $sToken) : null;
				if ($oMainAuthAccount && $sTokenValue) {
					$this->oMainAuthAccount = $oMainAuthAccount;
				} else {
					if ($oMainAuthAccount) {
						$sToken || \SnappyMail\Log::notice('TOKENS', 'SESSION_TOKEN not found');
						if ($sToken) {
							$oMainAuthAccount && $this->StorageProvider()->Clear($oMainAuthAccount, StorageType::SESSION, $sToken);
							$sTokenValue || \SnappyMail\Log::notice('TOKENS', 'SESSION_TOKEN value invalid: ' . \gettype($sTokenValue));
						}
					}
					Utils::ClearCookie(Utils::SESSION_TOKEN);
//					\MailSo\Base\Http::StatusHeader(401);
					$this->Logout(true);
//					$sAdditionalMessage = $this->StaticI18N('SESSION_GONE');
					throw new ClientException(Notifications::InvalidToken, null, 'Session gone');
				}
			} else {
				$oAccount = $this->GetAccountFromSignMeToken();
				if ($oAccount) {
					$this->StorageProvider()->Put(
						$oAccount,
						StorageType::SESSION,
						Utils::GetSessionToken(),
						'true'
					);
					$this->SetAuthToken($oAccount);
				}
			}

			if (!$this->oMainAuthAccount) {
				throw new ClientException(Notifications::InvalidToken, null, 'Account undefined');
			}
		} catch (\Throwable $e) {
			if ($bThrowExceptionOnFalse) {
				throw $e;
			}
		}

		return $this->oMainAuthAccount;
	}

	public function SetAuthToken(MainAccount $oAccount): void
	{
		$this->oAdditionalAuthAccount = false;
		$this->oMainAuthAccount = $oAccount;
		static::SetAccountCookie(self::AUTH_SPEC_TOKEN_KEY, $oAccount);
	}

	public function SetAdditionalAuthToken(?AdditionalAccount $oAccount): void
	{
		$this->oAdditionalAuthAccount = $oAccount ?: false;
		static::SetAccountCookie(self::AUTH_ADDITIONAL_TOKEN_KEY, $oAccount);
	}

	/**
	 * SignMe methods used for the "remember me" cookie
	 */

	private static function GetSignMeToken(): ?array
	{
		$sSignMeToken = Utils::GetCookie(self::AUTH_SIGN_ME_TOKEN_KEY);
		if ($sSignMeToken) {
			$aResult = \SnappyMail\Crypt::DecryptUrlSafe($sSignMeToken);
			if (isset($aResult['e'], $aResult['u']) && \SnappyMail\UUID::isValid($aResult['u'])) {
				return $aResult;
			}
			\SnappyMail\Log::notice(self::AUTH_SIGN_ME_TOKEN_KEY, 'invalid');
		}
		return null;
	}

	private function SetSignMeToken(MainAccount $oAccount): void
	{
		$this->ClearSignMeData();

		$uuid = \SnappyMail\UUID::generate();
		$data = \SnappyMail\Crypt::Encrypt($oAccount);

		Utils::SetCookie(
			self::AUTH_SIGN_ME_TOKEN_KEY,
			\SnappyMail\Crypt::EncryptUrlSafe([
				'e' => $oAccount->Email(),
				'u' => $uuid,
				$data[0] => \base64_encode($data[1])
			]),
			\time() + 3600 * 24 * 30 // 30 days
		);

		$this->StorageProvider()->Put(
			$oAccount,
			StorageType::SIGN_ME,
			$uuid,
			$data[2]
		);
	}

	public function GetAccountFromSignMeToken(): ?MainAccount
	{
		$aTokenData = static::GetSignMeToken();
		if ($aTokenData) {
			try
			{
				$sAuthToken = $this->StorageProvider()->Get(
					$aTokenData['e'],
					StorageType::SIGN_ME,
					$aTokenData['u']
				);
				if ($sAuthToken) {
					$aAccountHash = \SnappyMail\Crypt::Decrypt([
						\array_key_last($aTokenData),
						\base64_decode(\end($aTokenData)),
						$sAuthToken
					]);
					if (\is_array($aAccountHash)) {
						$oAccount = MainAccount::NewInstanceFromTokenArray($this, $aAccountHash);
						if ($oAccount) {
							$this->CheckMailConnection($oAccount);
							// Update lifetime
							$this->SetSignMeToken($oAccount);
							return $oAccount;
						}
						\SnappyMail\Log::notice(self::AUTH_SIGN_ME_TOKEN_KEY, 'has no account');
					} else {
						\SnappyMail\Log::notice(self::AUTH_SIGN_ME_TOKEN_KEY, 'decrypt failed');
					}
				} else {
					\SnappyMail\Log::notice(self::AUTH_SIGN_ME_TOKEN_KEY, "server token not found for {$aTokenData['e']}/.sign_me/{$aTokenData['u']}");
				}
			}
			catch (\Throwable $oException)
			{
				\SnappyMail\Log::notice(self::AUTH_SIGN_ME_TOKEN_KEY, $oException->getMessage());
			}
		}

		$this->ClearSignMeData();

		return null;
	}

	protected function ClearSignMeData() : void
	{
		$aTokenData = static::GetSignMeToken();
		if ($aTokenData) {
			$this->StorageProvider()->Clear($aTokenData['e'], StorageType::SIGN_ME, $aTokenData['u']);
		}
		Utils::ClearCookie(self::AUTH_SIGN_ME_TOKEN_KEY);
	}

	/**
	 * Logout methods
	 */

	public function SetAuthLogoutToken(): void
	{
		\header('X-RainLoop-Action: Logout');
		Utils::SetCookie(self::AUTH_SPEC_LOGOUT_TOKEN_KEY, \md5($_SERVER['REQUEST_TIME_FLOAT']));
	}

	public function GetSpecLogoutCustomMgsWithDeletion(): string
	{
		$sResult = Utils::GetCookie(self::AUTH_SPEC_LOGOUT_CUSTOM_MSG_KEY, '');
		if (\strlen($sResult)) {
			Utils::ClearCookie(self::AUTH_SPEC_LOGOUT_CUSTOM_MSG_KEY);
		}

		return $sResult;
	}

	public function SetSpecLogoutCustomMgsWithDeletion(string $sMessage): void
	{
		Utils::SetCookie(self::AUTH_SPEC_LOGOUT_CUSTOM_MSG_KEY, $sMessage);
	}

	protected function Logout(bool $bMain) : void
	{
		Utils::ClearCookie(self::AUTH_ADDITIONAL_TOKEN_KEY);
		$bMain && Utils::ClearCookie(self::AUTH_SPEC_TOKEN_KEY);
	}

	/**
	 * @throws \RainLoop\Exceptions\ClientException
	 */
	protected function CheckMailConnection(Account $oAccount, bool $bAuthLog = false): void
	{
		try {
			$oAccount->IncConnectAndLoginHelper($this->Plugins(), $this->MailClient(), $this->Config());
		} catch (ClientException $oException) {
			throw $oException;
		} catch (\MailSo\Net\Exceptions\ConnectionException $oException) {
			throw new ClientException(Notifications::ConnectionError, $oException);
		} catch (\MailSo\Imap\Exceptions\LoginBadCredentialsException $oException) {
			if ($bAuthLog) {
				$this->LoggerAuthHelper($oAccount);
			}

			if ($this->Config()->Get('labs', 'imap_show_login_alert', true)) {
				throw new ClientException(Notifications::AuthError, $oException, $oException->getAlertFromStatus());
			} else {
				throw new ClientException(Notifications::AuthError, $oException);
			}
		} catch (\Throwable $oException) {
			throw new ClientException(Notifications::AuthError, $oException);
		}
	}

}
