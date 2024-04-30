
/*
 * This will match any file containing unicode "hello" anywhere.
 */
rule UnicodeExample {
strings:
	// The 'wide' keyword indicates the string is unicode
	$unicode_string = "hello" wide

condition:
	$unicode_string
}

