<?php

namespace SnappyMail;

abstract class SASL
{
	public
		$base64 = false;

	abstract public function authenticate(string $authcid, string $passphrase, ?string $authzid = null) : string;

	public function challenge(string $challenge) : ?string
	{
		return null;
	}

	public function verify(string $data) : bool
	{
		return false;
	}

	final public static function detectType(AuthInterface $client, array $aCredentials): string
	{
		// with the order from https://github.com/the-djmaze/snappymail/pull/423
		if (empty($aCredentials['SASLMechanisms'])) {
			$aCredentials['SASLMechanisms'] = [
				'LOGIN',
				'PLAIN',
			];
		}

		foreach ($aCredentials['SASLMechanisms'] as $mechanism) {
			if ($client->IsAuthSupported($mechanism) && static::isSupported($mechanism)) {
				return $mechanism;
			}
		}

		throw new Exception('No supported SASL mechanism found');
	}

	final public static function factory(string $type)
	{
		if (\preg_match('/^([A-Z2]+)(?:-(.+))?$/Di', $type, $m)) {
			$class = __CLASS__ . "\\{$m[1]}";
			if (\class_exists($class)) {
				return new $class($m[2] ?? '');
			}
		}
		throw new \Exception("Unsupported SASL mechanism type: {$type}");
	}

	public static function isSupported(string $type) : bool
	{
		if (\preg_match('/^([A-Z2]+)(?:-(.+))?$/Di', $type, $m)) {
			$class = __CLASS__ . "\\{$m[1]}";
			return \class_exists($class) && $class::isSupported($m[2] ?? '');
		}
		return false;
	}

	final protected function decode(string $data) : string
	{
		return $this->base64 ? \base64_decode($data) : $data;
	}

	final protected function encode(string $data) : string
	{
		return $this->base64 ? \base64_encode($data) : $data;
	}

}
