function XMLtoString(elem){
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
	//turns xml string into XMLDOM -- Chrome only?
	if (typeof DOMParser != "undefined") {
		return (new DOMParser()).parseFromString(text, "text/xml");
	}
	}

// Append Node -- append a node at the bottom
// Insert Node -- Insert a node at the pointer
// Set node value -- i.e. <node>Parameter</node>
// Set node parameter -- i.e. <node parameter = "this is a test"/>



function submit_form() {
	if(document.myform.url[0].checked == true) {
		//Set Action URL, set TCID number and Assertion number
		document.myform.action="https://fedwb01i.hughestelematics.com/engine/Assertion";
		var xmlDoc = mkXML(samlTemplate);
		var x = xmlDoc.getElementsByTagName("NameID")[0].childNodes[0];
		x.nodeValue=document.myform.anbr.value;
		var y = xmlDoc.getElementsByTagName("Assertion")[0].childNodes[0];
		y.nodeValue=document.myform.assert.value;
		// extract STRING to XML for POST
		//document.myform.SAMLResponse.value = base64Encode(XMLtoString(xmlDoc));
		document.myform.SAMLResponse.value = XMLtoString(xmlDoc);
	} else if(document.myform.url[1].checked == true) {
		//Set Action URL, set TCID number and Assertion number
		document.myform.action="https://fedwb01i.hughestelematics.com/fed/sp/authnResponse20?providerid=dss.sso.test.statefarm.com&returnurl=https://fedwb01i.hughestelematics.com/engine";
		var xmlDoc = mkXML(samlTemplate);
		var x = xmlDoc.getElementsByTagName("NameID")[0].childNodes[0];
		x.nodeValue=document.myform.anbr.value;
		var y = xmlDoc.getElementsByTagName("Assertion")[0].childNodes[0];
		y.nodeValue=document.myform.assert.value;
		// extract STRING to XML for POST
		document.myform.SAMLResponse.value = base64Encode(XMLtoString(xmlDoc));
	}
	document.myform.submit();
}