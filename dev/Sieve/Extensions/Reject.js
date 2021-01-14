/**
 * https://tools.ietf.org/html/rfc5429
 */

(Sieve => {

const Grammar = Sieve.Grammar;

/**
 * https://tools.ietf.org/html/rfc5429#section-2.1
 */
class Ereject extends Grammar.Command
{
	constructor()
	{
		super('ereject');
		this._reason = new Grammar.QuotedString;
	}

	toString()
	{
		return 'ereject ' + this._reason + ';';
	}

	get reason()
	{
		return this._reason.value;
	}

	set reason(value)
	{
		this._reason.value = value;
	}

	pushArguments(args)
	{
		if (args[0] instanceof Grammar.StringType) {
			this._reason = args[0];
		}
	}
}

/**
 * https://tools.ietf.org/html/rfc5429#section-2.2
 */
class Reject extends Grammar.Command
{
	constructor()
	{
		super('reject');
		this._reason = new Grammar.QuotedString;
	}

	toString()
	{
		return 'reject ' + this._reason + ';';
	}

	get reason()
	{
		return this._reason.value;
	}

	set reason(value)
	{
		this._reason.value = value;
	}

	pushArguments(args)
	{
		if (args[0] instanceof Grammar.StringType) {
			this._reason = args[0];
		}
	}
}

Sieve.Extensions.Ereject = Ereject;
Sieve.Extensions.Reject = Reject;

})(this.Sieve);