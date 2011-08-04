/*
** Many Thanks to O'Reilly Hacks
** http://oreilly.com/hacks/
** http://oreilly.com/pub/h/2127
*/

// XML writer with attributes and smart attribute quote escaping 
function element(name,content,attributes){
	var att_str = '';
	if (attributes) { // tests false if this arg is missing!
		att_str = formatAttributes(attributes)
	}
	var xml;
	if (!content) {
		xml='<' + name + att_str + '/>'
	}
	else {
		xml='<' + name + att_str + '>' + content + '</'+name+'>'
	}
	return xml
}

var	APOS = "\'"
	, QUOTE = '\"'
	, ESCAPED_QUOTE = {};
	ESCAPED_QUOTE[2] = '&quot;';
	ESCAPED_QUOTE[APOS] = '&apos;';
   
/*
   Format a dictionary of attributes into a string suitable
   for inserting into the start tag of an element.  Be smart
   about escaping embedded quotes in the attribute values.
*/
function formatAttributes(attributes) {
	var att_value
	, apos_pos, quot_pos
	, use_quote, escape, quote_to_escape
	, att_str
	, re
	, result = '';
   
	for (var att in attributes) {
		att_value = attributes[att]
        
		// Find first quote marks if any
		apos_pos = att_value.indexOf(APOS)
		quot_pos = att_value.indexOf(QUOTE)
       
		// Determine which quote type to use around 
		// the attribute value
		if (apos_pos == -1 && quot_pos == -1) {
			att_str = ' ' + att + "='" + att_value +  "'";
			result += att_str;
			continue
		}
        
		// Prefer the single quote unless forced to use double
		if (quot_pos != -1 && quot_pos < apos_pos) {
			use_quote = APOS;
		} else {
			use_quote = QUOTE;
		}
   
		// Figure out which kind of quote to escape
		// Use nice dictionary instead of yucky if-else nests
		escape = ESCAPED_QUOTE[use_quote];
        
		// Escape only the right kind of quote
		re = new RegExp(use_quote,'g');
		att_str = ' ' + att + '=' + use_quote + 
			att_value.replace(re, escape) + use_quote;
		result += att_str;
	}
	return result
}