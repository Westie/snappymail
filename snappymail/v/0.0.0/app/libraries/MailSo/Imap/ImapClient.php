<?php

/*
 * This file is part of MailSo.
 *
 * (c) 2014 Usenko Timur
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace MailSo\Imap;

/**
 * @category MailSo
 * @package Imap
 */
class ImapClient extends \MailSo\Net\NetClient implements \SnappyMail\AuthInterface
{
	use Traits\ResponseParser;
//	use Commands\ACL;
	use Commands\Folders;
	use Commands\Messages;
	use Commands\Metadata;
	use Commands\Quota;

	const
		TAG_PREFIX = 'TAG';

	/**
	 * @var int
	 */
	private $iTagCount = 0;

	/**
	 * @var array
	 */
	private $aCapabilityItems = null;

	/**
	 * @var FolderInformation
	 */
	private $oCurrentFolderInfo = null;

	/**
	 * Used by \MailSo\Mail\MailClient::MessageMimeStream
	 * @var array
	 */
	private $aFetchCallbacks;

	/**
	 * @var array
	 */
	private $aTagTimeouts = array();

	/**
	 * @var bool
	 */
	private $bIsLoggined = false;

	/**
	 * @var string
	 */
	private $sLogginedUser = '';

	/**
	 * @var bool
	 */
	public $__FORCE_SELECT_ON_EXAMINE__ = false;
	public $__DISABLE_METADATA = false;

	/**
	 * @var bool
	 */
	private $UTF8 = false;

	public function GetLogginedUser() : string
	{
		return $this->sLogginedUser;
	}

	/**
	 * @throws \MailSo\Base\Exceptions\InvalidArgumentException
	 * @throws \MailSo\Net\Exceptions\Exception
	 * @throws \MailSo\Imap\Exceptions\Exception
	 */
	public function Connect(\MailSo\Net\ConnectSettings $oSettings) : void
	{
		$this->aTagTimeouts['*'] = \microtime(true);

		parent::Connect($oSettings);

		$this->setCapabilities($this->getResponse('*'));

		if ($this->IsSupported('STARTTLS') && \MailSo\Net\Enumerations\ConnectionSecurityType::UseStartTLS($this->iSecurityType))
		{
			$this->SendRequestGetResponse('STARTTLS');
			$this->EnableCrypto();

			$this->aCapabilityItems = null;
		}
		else if (\MailSo\Net\Enumerations\ConnectionSecurityType::STARTTLS === $this->iSecurityType)
		{
			$this->writeLogException(
				new \MailSo\Net\Exceptions\SocketUnsuppoterdSecureConnectionException('STARTTLS is not supported'),
				\MailSo\Log\Enumerations\Type::ERROR, true);
		}
	}

	/**
	 * @throws \MailSo\Base\Exceptions\InvalidArgumentException
	 * @throws \MailSo\Net\Exceptions\Exception
	 * @throws \MailSo\Imap\Exceptions\Exception
	 */
	public function Login(array $aCredentials) : self
	{
		if (!empty($aCredentials['ProxyAuthUser']) && !empty($aCredentials['ProxyAuthPassword'])) {
			$sLogin = \MailSo\Base\Utils::IdnToAscii(\MailSo\Base\Utils::Trim($aCredentials['ProxyAuthUser']));
			$sPassword = $aCredentials['ProxyAuthPassword'];
			$sProxyAuthUser = $aCredentials['Login'];
		} else {
			$sLogin = \MailSo\Base\Utils::IdnToAscii(\MailSo\Base\Utils::Trim($aCredentials['Login']));
			$sPassword = $aCredentials['Password'];
			$sProxyAuthUser = '';
		}

		if (!\strlen($sLogin) || !\strlen($sPassword))
		{
			$this->writeLogException(
				new \MailSo\Base\Exceptions\InvalidArgumentException,
				\MailSo\Log\Enumerations\Type::ERROR, true);
		}

		$this->sLogginedUser = $sLogin;

		$type = \SnappyMail\SASL::detectType($this, $aCredentials);

		$SASL = \SnappyMail\SASL::factory($type);
		$SASL->base64 = true;

		try
		{
			if (0 === \strpos($type, 'SCRAM-'))
			{
				$sAuthzid = $this->getResponseValue($this->SendRequestGetResponse('AUTHENTICATE', array($type)), Enumerations\ResponseType::CONTINUATION);
				$this->sendRaw($SASL->authenticate($sLogin, $sPassword/*, $sAuthzid*/), true);
				$sChallenge = $SASL->challenge($this->getResponseValue($this->getResponse(), Enumerations\ResponseType::CONTINUATION));
				if ($this->oLogger) {
					$this->oLogger->AddSecret($sChallenge);
				}
				$this->sendRaw($sChallenge, true, '*******');
				$oResponse = $this->getResponse();
				$SASL->verify($this->getResponseValue($oResponse));
			}
			else if ('CRAM-MD5' === $type)
			{
				$sChallenge = $this->getResponseValue($this->SendRequestGetResponse('AUTHENTICATE', array($type)), Enumerations\ResponseType::CONTINUATION);
				$this->oLogger->Write('challenge: '.\base64_decode($sChallenge));
				$sAuth = $SASL->authenticate($sLogin, $sPassword, $sChallenge);
				if ($this->oLogger) {
					$this->oLogger->AddSecret($sAuth);
				}
				$this->sendRaw($sAuth, true, '*******');
				$oResponse = $this->getResponse();
			}
			else if ('PLAIN' === $type)
			{
				$sAuth = $SASL->authenticate($sLogin, $sPassword);
				if ($this->oLogger) {
					$this->oLogger->AddSecret($sAuth);
				}
				if ($this->IsSupported('SASL-IR')) {
					$oResponse = $this->SendRequestGetResponse('AUTHENTICATE', array($type, $sAuth));
				} else {
					$this->SendRequestGetResponse('AUTHENTICATE', array($type));
					$this->sendRaw($sAuth, true, '*******');
					$oResponse = $this->getResponse();
				}
			}
			else if ('OAUTHBEARER' === $type)
			{
				$sAuth = $SASL->authenticate($sLogin, $sPassword, 'n');
				if ($this->oLogger) {
					$this->oLogger->AddSecret($sAuth);
				}
				if ($this->IsSupported('SASL-IR')) {
					$oResponse = $this->SendRequestGetResponse('AUTHENTICATE', array($type, $sAuth));
				} else {
					$this->SendRequestGetResponse('AUTHENTICATE', array($type));
					$this->sendRaw($sAuth, true, '*******');
					$oResponse = $this->getResponse();
				}
			}
			else if ('XOAUTH2' === $type)
			{
				$sAuth = $SASL->authenticate($sLogin, $sPassword);
				$this->SendRequest('AUTHENTICATE', array($type, $sAuth));
				$oResponse = $this->getResponse();
				$oR = $oResponse->getLast();
				if ($oR && Enumerations\ResponseType::CONTINUATION === $oR->ResponseType) {
					if (!empty($oR->ResponseList[1]) && preg_match('/^[a-zA-Z0-9=+\/]+$/', $oR->ResponseList[1])) {
						$this->Logger()->Write(\base64_decode($oR->ResponseList[1]),
							\MailSo\Log\Enumerations\Type::WARNING);
					}
					$this->sendRaw('');
					$oResponse = $this->getResponse();
				}
			}
			else if ($this->IsSupported('LOGINDISABLED'))
			{
				$sB64 = $this->getResponseValue($this->SendRequestGetResponse('AUTHENTICATE', array($type)), Enumerations\ResponseType::CONTINUATION);
				$this->sendRaw($SASL->authenticate($sLogin, $sPassword, $sB64), true);
				$this->getResponse();
				$sPass = $SASL->challenge(''/*UGFzc3dvcmQ6*/);
				if ($this->oLogger) {
					$this->oLogger->AddSecret($sPass);
				}
				$this->sendRaw($sPass, true, '*******');
				$oResponse = $this->getResponse();
			}
			else
			{
				$sPassword = $this->EscapeString(\utf8_decode($sPassword));
				if ($this->oLogger)
				{
					$this->oLogger->AddSecret($sPassword);
				}
				$oResponse = $this->SendRequestGetResponse('LOGIN',
					array(
						$this->EscapeString($sLogin),
						$sPassword
					));
			}

			$this->setCapabilities($oResponse);

			if (\strlen($sProxyAuthUser))
			{
				$this->SendRequestGetResponse('PROXYAUTH', array($this->EscapeString($sProxyAuthUser)));
			}
/*
			// TODO: RFC 9051
			if ($this->IsSupported('IMAP4rev2')) {
				$this->Enable('IMAP4rev1');
			}
*/
			// RFC 6855 || RFC 5738
			$this->UTF8 = $this->IsSupported('UTF8=ONLY') || $this->IsSupported('UTF8=ACCEPT');
			if ($this->UTF8) {
				$this->Enable('UTF8=ACCEPT');
			}
		}
		catch (Exceptions\NegativeResponseException $oException)
		{
			$this->writeLogException(
				new Exceptions\LoginBadCredentialsException(
					$oException->GetResponses(), '', 0, $oException),
				\MailSo\Log\Enumerations\Type::NOTICE, true);
		}

		$this->bIsLoggined = true;

		return $this;
	}

	/**
	 * @throws \MailSo\Net\Exceptions\Exception
	 */
	public function Logout() : void
	{
		if ($this->bIsLoggined)
		{
			$this->bIsLoggined = false;
			$this->SendRequestGetResponse('LOGOUT');
		}
	}

	public function IsLoggined() : bool
	{
		return $this->IsConnected() && $this->bIsLoggined;
	}

	public function IsSelected() : bool
	{
		return $this->IsLoggined() && $this->oCurrentFolderInfo;
	}

	/**
	 * @throws \MailSo\Net\Exceptions\Exception
	 * @throws \MailSo\Imap\Exceptions\Exception
	 */
	public function Capability() : ?array
	{
		if (!$this->aCapabilityItems) {
			$this->setCapabilities($this->SendRequestGetResponse('CAPABILITY'));
		}
/*
		$this->aCapabilityItems[] = 'X-DOVECOT';
*/
		return $this->aCapabilityItems;
	}

	private function setCapabilities(ResponseCollection $oResponseCollection) : void
	{
		$aList = $oResponseCollection->getCapabilityResult();
		if ($aList && $this->__DISABLE_METADATA) {
			// Issue #365: Many folders on Cyrus IMAP breaks login
			$aList = \array_diff($aList, ['METADATA']);
		}
		$this->aCapabilityItems = $aList;
	}

	/**
	 * Test support for things like:
	 *     IMAP4rev1 IMAP4rev2 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE SORT SORT=DISPLAY
	 *     THREAD=REFERENCES THREAD=REFS THREAD=ORDEREDSUBJECT MULTIAPPEND
	 *     URL-PARTIAL CATENATE UNSELECT CHILDREN NAMESPACE UIDPLUS LIST-EXTENDED
	 *     I18NLEVEL=1 CONDSTORE QRESYNC ESEARCH ESORT SEARCHRES WITHIN CONTEXT=SEARCH
	 *     LIST-STATUS BINARY MOVE SNIPPET=FUZZY PREVIEW=FUZZY STATUS=SIZE LITERAL+ NOTIFY SPECIAL-USE
	 *     STARTTLS AUTH= LOGIN LOGINDISABLED QUOTA
	 *     METADATA METADATA-SERVER
	 *
	 * @throws \MailSo\Net\Exceptions\Exception
	 * @throws \MailSo\Imap\Exceptions\Exception
	 */
	public function IsSupported(string $sExtentionName) : bool
	{
		$sExtentionName = \trim($sExtentionName);
		return $sExtentionName && \in_array(\strtoupper($sExtentionName), $this->Capability() ?: []);
	}

	/**
	 *  IsAuthSupported
	 */
	public function IsAuthSupported(string $sAuth) : bool
	{
		return $this->IsSupported('AUTH=' . $sAuth);
	}

	/**
	 * RFC 5161
	 */
	public function Enable(/*string|array*/ $mCapabilityNames) : void
	{
		if (\is_string($mCapabilityNames)) {
			$mCapabilityNames = [$mCapabilityNames];
		}
		if (\is_array($mCapabilityNames)) {
			$this->SendRequestGetResponse('ENABLE', $mCapabilityNames);
		}
	}

	/**
	 * @throws \MailSo\Net\Exceptions\Exception
	 * @throws \MailSo\Imap\Exceptions\Exception
	 */
	public function GetNamespace() : ?NamespaceResult
	{
		if (!$this->IsSupported('NAMESPACE')) {
			return null;
		}

		try {
			$oResponseCollection = $this->SendRequestGetResponse('NAMESPACE');
			foreach ($oResponseCollection as $oResponse) {
				if (Enumerations\ResponseType::UNTAGGED === $oResponse->ResponseType
				 && 'NAMESPACE' === $oResponse->StatusOrIndex)
				{
					$oReturn = new NamespaceResult;
					$oReturn->InitByImapResponse($oResponse);
					return $oReturn;
				}
			}
			throw new Exceptions\ResponseException;
		} catch (\Throwable $e) {
			$this->writeLogException($e, \MailSo\Log\Enumerations\Type::ERROR);
			throw $e;
		}
	}

	/**
	 * RFC 7889
	 * APPENDLIMIT=<number> indicates that the IMAP server has the same upload limit for all mailboxes.
	 * APPENDLIMIT without any value indicates that the IMAP server supports this extension,
	 * and that the client will need to discover upload limits for each mailbox,
	 * as they might differ from mailbox to mailbox.
	 */
	public function AppendLimit() : ?int
	{
		if ($this->Capability()) {
			foreach ($this->aCapabilityItems as $string) {
				if ('APPENDLIMIT=' === \substr($string, 0, 12)) {
					return (int) \substr($string, 12);
				}
			}
		}
		return null;
	}

	/**
	 * @throws \MailSo\Net\Exceptions\Exception
	 * @throws \MailSo\Imap\Exceptions\Exception
	 */
	public function Noop() : self
	{
		$this->SendRequestGetResponse('NOOP');
		return $this;
	}

	/**
	 * @throws \MailSo\Base\Exceptions\InvalidArgumentException
	 * @throws \MailSo\Net\Exceptions\Exception
	 */
	public function SendRequest(string $sCommand, array $aParams = array(), bool $bBreakOnLiteral = false) : string
	{
		$sCommand = \trim($sCommand);
		if (!\strlen($sCommand))
		{
			$this->writeLogException(
				new \MailSo\Base\Exceptions\InvalidArgumentException,
				\MailSo\Log\Enumerations\Type::ERROR, true);
		}

		$this->IsConnected(true);

		$sTag = $this->getNewTag();

		$sRealCommand = $sTag.' '.$sCommand.$this->prepareParamLine($aParams);

		$sFakeCommand = '';
		if ($aFakeParams = $this->secureRequestParams($sCommand, $aParams)) {
			$sFakeCommand = $sTag.' '.$sCommand.$this->prepareParamLine($aFakeParams);
		}

//		$this->lastCommand = $sFakeCommand ?: $sRealCommand;

		$this->aTagTimeouts[$sTag] = \microtime(true);

		if ($bBreakOnLiteral && !\preg_match('/\d\+\}\r\n/', $sRealCommand))
		{
			$iPos = \strpos($sRealCommand, "}\r\n");
			if (false !== $iPos)
			{
				$iFakePos = \strpos($sFakeCommand, "}\r\n");

				$this->sendRaw(\substr($sRealCommand, 0, $iPos + 1), true,
					false !== $iFakePos ? \substr($sFakeCommand, 0, $iFakePos + 3) : '');

				return \substr($sRealCommand, $iPos + 3);
			}
		}

		$this->sendRaw($sRealCommand, true, $sFakeCommand);
		return '';
	}

	protected function secureRequestParams(string $sCommand, array $aParams) : ?array
	{
		if ('LOGIN' === $sCommand && isset($aParams[1])) {
			$aParams[1] = '"********"';
			return $aParams;
		}
		return null;
	}

	/**
	 * @throws \MailSo\Base\Exceptions\InvalidArgumentException
	 * @throws \MailSo\Net\Exceptions\Exception
	 * @throws \MailSo\Imap\Exceptions\Exception
	 */
	public function SendRequestGetResponse(string $sCommand, array $aParams = array()) : ResponseCollection
	{
		$this->SendRequest($sCommand, $aParams);
		return $this->getResponse();
	}

	protected function getResponseValue(ResponseCollection $oResponseCollection, int $type = 0) : string
	{
		$oResponse = $oResponseCollection->getLast();
		if ($oResponse && (!$type || $type === $oResponse->ResponseType)) {
			$sResult = $oResponse->ResponseList[1] ?? null;
			if ($sResult) {
				return $sResult;
			}
			$this->writeLogException(
				new Exceptions\LoginException,
				\MailSo\Log\Enumerations\Type::NOTICE, true);
		}
		$this->writeLogException(
			new Exceptions\LoginException,
			\MailSo\Log\Enumerations\Type::NOTICE, true);
	}

	/**
	 * TODO: passthru to parse response in JavaScript
	 * This will reduce CPU time on server and moves it to the client
	 * And can be used with the new JavaScript AbstractFetchRemote.streamPerLine(fCallback, sGetAdd)
	 *
	 * @throws \MailSo\Imap\Exceptions\ResponseNotFoundException
	 * @throws \MailSo\Imap\Exceptions\InvalidResponseException
	 * @throws \MailSo\Imap\Exceptions\NegativeResponseException
	 */
	protected function streamResponse(string $sEndTag = null) : void
	{
		try {
			if (\is_resource($this->ConnectionResource())) {
				\SnappyMail\HTTP\Stream::start();
				$sEndTag = ($sEndTag ?: $this->getCurrentTag()) . ' ';
				$sLine = \fgets($this->ConnectionResource());
				do {
					if (\str_starts_with($sLine, $sEndTag)) {
						echo 'T '.\substr($sLine, \strlen($sEndTag));
						break;
					}
					echo $sLine;
					$sLine = \fgets($this->ConnectionResource());
				} while (\strlen($sLine));
				exit;
			}
		} catch (\Throwable $e) {
			$this->writeLogException($e, \MailSo\Log\Enumerations\Type::WARNING);
			throw $e;
		}
	}

	protected function getResponse(string $sEndTag = null) : ResponseCollection
	{
		try {
			$oResult = new ResponseCollection;

			if (\is_resource($this->ConnectionResource())) {
				$sEndTag = $sEndTag ?: $this->getCurrentTag();

				while (true) {
					$oResponse = $this->partialParseResponse();
					$oResult->append($oResponse);

					// RFC 5530
					if ($sEndTag === $oResponse->Tag && \is_array($oResponse->OptionalResponse) && 'CLIENTBUG' === $oResponse->OptionalResponse[0]) {
						// The server has detected a client bug.
//						\SnappyMail\Log::warning('IMAP', "{$oResponse->OptionalResponse[0]}: {$this->lastCommand}");
					}

					if ($sEndTag === $oResponse->Tag || Enumerations\ResponseType::CONTINUATION === $oResponse->ResponseType) {
						if (isset($this->aTagTimeouts[$sEndTag])) {
							$this->writeLog((\microtime(true) - $this->aTagTimeouts[$sEndTag]).' ('.$sEndTag.')',
								\MailSo\Log\Enumerations\Type::TIME);

							unset($this->aTagTimeouts[$sEndTag]);
						}

						break;
					}
				}
			}

			$oResult->validate();

		} catch (\Throwable $e) {
			$this->writeLogException($e, \MailSo\Log\Enumerations\Type::WARNING);
			throw $e;
		}

		return $oResult;
	}

//	public function yieldUntaggedResponses(string $sEndTag = null) : \Generator
	public function yieldUntaggedResponses(string $sEndTag = null) : iterable
	{
		try {
			$oResult = new ResponseCollection;

			if (\is_resource($this->ConnectionResource())) {
				$sEndTag = $sEndTag ?: $this->getCurrentTag();

				while (true) {
					$oResponse = $this->partialParseResponse();
					if (Enumerations\ResponseType::UNTAGGED === $oResponse->ResponseType) {
						yield $oResponse;
					} else {
						$oResult->append($oResponse);
					}

					// RFC 5530
					if ($sEndTag === $oResponse->Tag && \is_array($oResponse->OptionalResponse) && 'CLIENTBUG' === $oResponse->OptionalResponse[0]) {
						// The server has detected a client bug.
//						\SnappyMail\Log::warning('IMAP', "{$oResponse->OptionalResponse[0]}: {$this->lastCommand}");
					}

					if ($sEndTag === $oResponse->Tag || Enumerations\ResponseType::CONTINUATION === $oResponse->ResponseType) {
						if (isset($this->aTagTimeouts[$sEndTag])) {
							$this->writeLog((\microtime(true) - $this->aTagTimeouts[$sEndTag]).' ('.$sEndTag.')',
								\MailSo\Log\Enumerations\Type::TIME);

							unset($this->aTagTimeouts[$sEndTag]);
						}

						break;
					}
				}
			}

			$oResult->validate();

		} catch (\Throwable $e) {
			$this->writeLogException($e, \MailSo\Log\Enumerations\Type::WARNING);
			throw $e;
		}
	}

	protected function prepareParamLine(array $aParams = array()) : string
	{
		$sReturn = '';
		foreach ($aParams as $mParamItem)
		{
			if (\is_array($mParamItem) && \count($mParamItem))
			{
				$sReturn .= ' ('.\trim($this->prepareParamLine($mParamItem)).')';
			}
			else if (\is_string($mParamItem))
			{
				$sReturn .= ' '.$mParamItem;
			}
		}
		return $sReturn;
	}

	protected function getNewTag() : string
	{
		++$this->iTagCount;
		return $this->getCurrentTag();
	}

	protected function getCurrentTag() : string
	{
		return self::TAG_PREFIX.$this->iTagCount;
	}

	public function EscapeString(?string $sStringForEscape) : string
	{
		if (null === $sStringForEscape) {
			return 'NIL';
		}
/*
		// literal-string
		if (\preg_match('/[\r\n\x00\x80-\xFF]/', $sStringForEscape)) {
			return \sprintf("{%d}\r\n%s", \strlen($sStringForEscape), $sStringForEscape);
		}
*/
		// quoted-string
		return '"' . \addcslashes($sStringForEscape, '\\"') . '"';
	}

	public function getLogName() : string
	{
		return 'IMAP';
	}

	/**
	 * RFC 2971
	 * Don't have to be logged in to call this command
	 */
	public function ServerID() : string
	{
		if ($this->IsSupported('ID')) {
			foreach ($this->SendRequestGetResponse('ID', [null]) as $oResponse) {
				if ('ID' === $oResponse->ResponseList[1] && \is_array($oResponse->ResponseList[2])) {
					$c = \count($oResponse->ResponseList[2]);
					$aResult = [];
					for ($i = 0; $i < $c; $i += 2) {
						$aResult[] = $oResponse->ResponseList[2][$i] . '=' . $oResponse->ResponseList[2][$i+1];
					}
					return \implode(' ', $aResult);
				}
			}
		}
		return 'UNKNOWN';
	}

	/**
	 * RFC 4978
	 * It is RECOMMENDED that the client uses TLS compression.
	 *//*
	public function Compress() : bool
	{
		try {
			if ($this->IsSupported('COMPRESS=DEFLATE')) {
				$this->SendRequestGetResponse('COMPRESS', ['DEFLATE']);
				\stream_filter_append($this->ConnectionResource(), 'zlib.inflate');
				\stream_filter_append($this->ConnectionResource(), 'zlib.deflate', STREAM_FILTER_WRITE, array(
					'level' => 6, 'window' => 15, 'memory' => 9
				));
				return true;
			}
		} catch (\Throwable $e) {
		}
		return false;
	}*/

	public function EscapeFolderName(string $sFolderName) : string
	{
		return $this->EscapeString($this->UTF8 ? $sFolderName : \MailSo\Base\Utils::Utf8ToUtf7Modified($sFolderName));
	}

	public function toUTF8(string $sText) : string
	{
		return $this->UTF8 ? $sText : \MailSo\Base\Utils::Utf7ModifiedToUtf8($sText);
	}

}
