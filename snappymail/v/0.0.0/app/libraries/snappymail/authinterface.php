<?php

namespace SnappyMail;

interface AuthInterface
{
	/**
	 *  Check if auth mechanism is supported
	 */
	public function IsAuthSupported(string $sAuth) : bool;
}
