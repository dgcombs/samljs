function base64Encode(text){
	if (/([^\u0000-\u00ff])/.test(text)){
		throw new Error("Can't base64 encode non-ASCII characters.");
	} 
	var digits = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	, i = 0
	, cur
	, prev
	, byteNum
	, result=[];
	while(i < text.length){
		cur = text.charCodeAt(i);
		byteNum = i % 3;
		switch(byteNum){
		case 0: //first byte
			result.push(digits.charAt(cur >> 2));
			break;
		case 1: //second byte
			result.push(digits.charAt((prev & 3) << 4 | (cur >> 4)));
			break;
		case 2: //third byte
			result.push(digits.charAt((prev & 0x0f) << 2 | (cur >> 6)));
			result.push(digits.charAt(cur & 0x3f));
			break;
		}
	prev = cur;
	i++;
	}
	if (byteNum == 0){
		result.push(digits.charAt((prev & 3) << 4));
		result.push("==");
	} else if (byteNum == 1){
		result.push(digits.charAt((prev & 0x0f) << 2));
		result.push("=");
	}
	return result.join("");
}