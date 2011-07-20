function XMLtoString(elem){
// Convert a DOM element to XML string
	var serialized;
	try {
		// XMLSerializer exists in current Mozilla browsers
		serializer = new XMLSerializer();
		serialized = serializer.serializeToString(elem);
	} catch (e) {
		// Internet Explorer has a different approach to serializing XML
		serialized = elem.xml;
	}
	return serialized;
}

function mkXML(text) {
	//turns xml string into XMLDOM
	if (typeof DOMParser != "undefined") {
		return (new DOMParser()).parseFromString(text, "text/xml");
	}
}
/*
** SAML Format
** root XML
** samlp:RESPONSE
** saml:Issuer
** samlp:Status -- samlp:StatusCode
** saml:Assertion
** saml:Issuer
** saml:Subject -- saml:NameID -- saml:SubjectConfirmation -- saml:SubjectConfirmationData
** saml:Conditions
*/
function appendNode() {}

// Append Node -- append a node at the bottom
// Insert Node -- Insert a node at the pointer
// Set node value -- i.e. <node>Parameter</node>
// Set node parameter -- i.e. <node parameter = "this is a test"/>

function submit_form() {
	if(document.SAMLForm.url[0].checked == true) {
		//Set Action URL, set TCID number and Assertion number
		document.SAMLForm.action="https://fedwb01i.hughestelematics.com/local/pnr.cgi";
		var xmlDoc = mkXML(samlTemplate);
		//var x = xmlDoc.getElementsByTagName("NameID")[0].childNodes[0];
		//x.nodeValue=document.myform.anbr.value;
		//var y = xmlDoc.getElementsByTagName("Assertion")[0].childNodes[0];
		//y.nodeValue=document.SAMLForm.assert.value;
		// extract STRING to XML for POST
		document.SAMLForm.SAMLResponse.value = base64Encode(XMLtoString(xmlDoc));
		document.SAMLForm.SAMLResponse.value = XMLtoString(xmlDoc);
	} else if(document.SAMLForm.url[1].checked == true) {
		//Set Action URL, set TCID number and Assertion number
		document.SAMLForm.action="https://fedwb01i.hughestelematics.com/local/cwv.cgi";
		var xmlDoc = mkXML(samlTemplate);
		//var x = xmlDoc.getElementsByTagName("NameID")[0].childNodes[0];
		//x.nodeValue=document.SAMLForm.anbr.value;
		//var y = xmlDoc.getElementsByTagName("Assertion")[0].childNodes[0];
		//y.nodeValue=document.SAMLForm.assert.value;
		// extract STRING to XML for POST
		document.SAMLForm.SAMLResponse.value = base64Encode(XMLtoString(xmlDoc));
	}
	document.SAMLForm.submit();
	//var createData = { "url":"http://www.novell.com"};
	//chrome.tabs.create({"url":"http://www.novell.com"});
	//window.close();
}