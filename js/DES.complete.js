// DES.complete.js
// ------------------------------------------------------------------
//
// complete set of modules for doing DES encryption in the browser.
//
// Author     : Dino
// Created    : Tue May 10 11:31:44 2011
// on Machine : DINO-PC
// Last-saved : <2011-May-10 11:32:06>
//
// ------------------------------------------------------------------



// sha1.js
// ------------------------------------------------------------------
//
// Javascript implementation of SHA1.  usable in any browser, any OS.
//
// Author     : Dino
// Created    : Thu Apr 21 20:16:47 2011
// on Machine : DINO-PC
// Last-saved : <2011-April-22 17:31:43>
//
// ------------------------------------------------------------------

/* ======================================================= */
// Credit:

/*
 * A JavaScript implementation of the Secure Hash Algorithm, SHA-1, as defined
 * in FIPS 180-1
 * Version 2.2 Copyright Paul Johnston 2000 - 2009.
 * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
 * Distributed under the BSD License
 * See http://pajhome.org.uk/crypt/md5/sha1.html
 */


// Re-packaged as a Javascript OO library by Dino Chiesa
// Thu, 21 Apr 2011  20:36
// dpchiesa@hotmail.com

//
// usage examples:
//
//  Produce a hex-encoded string containing the SHA1 hash of a message:
//    SHA1.hash_asHex("abc")
//
//  Produce a Base64-encoded string containing the SHA1 hash of a message:
//    SHA1.hash_asB64("This is the message to hash")
//
//  Produce a Base64-encoded string containing the SHA1HMAC of a message.
//    SHA1.hmac_asB64("This is the message to hash")
//

(function() {

    if (typeof Exception == "undefined") {

        Exception = function(type, description, optionalNumber) {
            var instance         = {};
            instance.type        = type || "Exception";
            instance.description = description || "unknown exception";
            instance.number      = optionalNumber || 0;
            return instance;
        };
    }
})();



(function() {

    if (typeof SHA1 !== "undefined") {
        throw new Exception("TypeDefinitionException", "SHA1 is already defined");
    }

    /*
     * Configurable variables. You may need to tweak these to be compatible with
     * the server-side, but the defaults work in most cases.
     */
    var hexcase = 0;  /* hex output format. 0 - lowercase; 1 - uppercase        */
    var b64pad  = ""; /* base-64 pad character. "=" for strict RFC compliance   */

    /*
     * Convert an array of big-endian words to a string
     */
    function binb2rstr(input){
        var output = "";
        for(var i = 0; i < input.length * 32; i += 8) {
            output += String.fromCharCode((input[i>>5] >>> (24 - i % 32)) & 0xFF);
        }
        return output;
    }



    /*
     * Calculate the SHA1 of a raw string
     */
    function rstr_sha1(s) {
        return binb2rstr(binb_sha1(rstr2binb(s), s.length * 8));
    }

    function binb2hex(binarray) {
        var hex_tab = hexcase ? "0123456789ABCDEF" : "0123456789abcdef";
        var str = "";
        for(var i = 0; i < binarray.length * 4; i++) {
            str += hex_tab.charAt((binarray[i>>2] >> ((3 - i%4)*8+4)) & 0xF) +
                hex_tab.charAt((binarray[i>>2] >> ((3 - i%4)*8  )) & 0xF);
        }
        return str;
    }


    /*
     * Calculate the HMAC-SHA1 of a key and some data (raw strings)
     */
    function rstr_hmac_sha1(key, data)
    {
        var bkey = rstr2binb(key);
        if(bkey.length > 16) {bkey = binb_sha1(bkey, key.length * 8); }

        var ipad = Array(16), opad = Array(16);
        for(var i = 0; i < 16; i++)
        {
            ipad[i] = bkey[i] ^ 0x36363636;
            opad[i] = bkey[i] ^ 0x5C5C5C5C;
        }

        var hash = binb_sha1(ipad.concat(rstr2binb(data)), 512 + data.length * 8);
        return binb2rstr(binb_sha1(opad.concat(hash), 512 + 160));
    }

    /*
     * Convert a raw string to a hex string
     */
    function rstr2hex(input) {
        hexcase = hexcase || 0;
        var hex_tab = hexcase ? "0123456789ABCDEF" : "0123456789abcdef";
        var output = "";
        var x;
        for(var i = 0; i < input.length; i++) {
            x = input.charCodeAt(i);
            output += hex_tab.charAt((x >>> 4) & 0x0F) +
                hex_tab.charAt( x & 0x0F);
        }
        return output;
    }

    /*
     * Convert a raw string to a base-64 string
     */
    function rstr2b64(input) {
        b64pad = b64pad || '';
        var tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        var output = "";
        var len = input.length;
        for(var i = 0; i < len; i += 3) {
            var triplet = (input.charCodeAt(i) << 16)
                | (i + 1 < len ? input.charCodeAt(i+1) << 8 : 0)
                | (i + 2 < len ? input.charCodeAt(i+2)      : 0);
            for(var j = 0; j < 4; j++) {
                if(i * 8 + j * 6 > input.length * 8) {output += b64pad; }
                else {output += tab.charAt((triplet >>> 6*(3-j)) & 0x3F);}
            }
        }
        return output;
    }

    /*
     * Convert a raw string to an arbitrary string encoding
     */
    function rstr2any(input, encoding) {
        var divisor = encoding.length;
        var remainders = Array();
        var i, q, x, quotient;

        /* Convert to an array of 16-bit big-endian values, forming the dividend */
        var dividend = Array(Math.ceil(input.length / 2));
        for(i = 0; i < dividend.length; i++) {
            dividend[i] = (input.charCodeAt(i * 2) << 8) | input.charCodeAt(i * 2 + 1);
        }

        /*
         * Repeatedly perform a long division. The binary array forms the dividend,
         * the length of the encoding is the divisor. Once computed, the quotient
         * forms the dividend for the next step. We stop when the dividend is zero.
         * All remainders are stored for later use.
         */
        while(dividend.length > 0) {
            quotient = Array();
            x = 0;
            for(i = 0; i < dividend.length; i++) {
                x = (x << 16) + dividend[i];
                q = Math.floor(x / divisor);
                x -= q * divisor;
                if(quotient.length > 0 || q > 0) {
                    quotient[quotient.length] = q;
                }
            }
            remainders[remainders.length] = x;
            dividend = quotient;
        }

        /* Convert the remainders to the output string */
        var output = "";
        for(i = remainders.length - 1; i >= 0; i--) {
            output += encoding.charAt(remainders[i]);
        }

        /* Append leading zero equivalents */
        var full_length = Math.ceil(input.length * 8 /
                                    (Math.log(encoding.length) / Math.log(2)));
        for(i = output.length; i < full_length; i++) {
            output = encoding[0] + output;
        }

        return output;
    }

    /*
     * Encode a string as utf-8.
     * For efficiency, this assumes the input is valid utf-16.
     */
    function str2rstr_utf8(input) {
        var output = "";
        var i = -1;
        var x, y;

        while(++i < input.length) {
            /* Decode utf-16 surrogate pairs */
            x = input.charCodeAt(i);
            y = i + 1 < input.length ? input.charCodeAt(i + 1) : 0;
            if(0xD800 <= x && x <= 0xDBFF && 0xDC00 <= y && y <= 0xDFFF) {
                x = 0x10000 + ((x & 0x03FF) << 10) + (y & 0x03FF);
                i++;
            }

            /* Encode output as utf-8 */
            if(x <= 0x7F) {
                output += String.fromCharCode(x);
            }
            else if(x <= 0x7FF) {
                output += String.fromCharCode(0xC0 | ((x >>> 6 ) & 0x1F),
                                              0x80 | ( x         & 0x3F));
            }
            else if(x <= 0xFFFF) {
                output += String.fromCharCode(0xE0 | ((x >>> 12) & 0x0F),
                                              0x80 | ((x >>> 6 ) & 0x3F),
                                              0x80 | ( x         & 0x3F));
            }
            else if(x <= 0x1FFFFF) {
                output += String.fromCharCode(0xF0 | ((x >>> 18) & 0x07),
                                              0x80 | ((x >>> 12) & 0x3F),
                                              0x80 | ((x >>> 6 ) & 0x3F),
                                              0x80 | ( x         & 0x3F));
            }
        }
        return output;
    }

    /*
     * Encode a string as utf-16
     */
    function str2rstr_utf16le(input) {
        var output = "";
        for(var i = 0; i < input.length; i++) {
            output += String.fromCharCode( input.charCodeAt(i)        & 0xFF,
                                           (input.charCodeAt(i) >>> 8) & 0xFF);
        }
        return output;
    }

    function str2rstr_utf16be(input) {
        var output = "";
        for(var i = 0; i < input.length; i++) {
            output += String.fromCharCode((input.charCodeAt(i) >>> 8) & 0xFF,
                                          input.charCodeAt(i)        & 0xFF);
        }
        return output;
    }

    /*
     * Convert a raw string to an array of big-endian words
     * Characters >255 have their high-byte silently ignored.
     */
    function rstr2binb(input) {
        var output = Array(input.length >> 2);
        var i;
        for(i = 0; i < output.length; i++) {
            output[i] = 0;
        }
        for(i = 0; i < input.length * 8; i += 8) {
            output[i>>5] |= (input.charCodeAt(i / 8) & 0xFF) << (24 - i % 32);
        }
        return output;
    }


    /*
     * Calculate the SHA-1 of an array of big-endian words, and a bit length
     */
    function binb_sha1(x, len) {
        /* append padding */
        x[len >> 5] |= 0x80 << (24 - len % 32);
        x[((len + 64 >> 9) << 4) + 15] = len;

        var w = Array(80);
        var a =  1732584193;
        var b = -271733879;
        var c = -1732584194;
        var d =  271733878;
        var e = -1009589776;

        for(var i = 0; i < x.length; i += 16) {
            var olda = a;
            var oldb = b;
            var oldc = c;
            var oldd = d;
            var olde = e;

            for(var j = 0; j < 80; j++) {
                if(j < 16) {w[j] = x[i + j]; }
                else {w[j] = bit_rol(w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16], 1);}
                var t = safe_add(safe_add(bit_rol(a, 5), sha1_ft(j, b, c, d)),
                                 safe_add(safe_add(e, w[j]), sha1_kt(j)));
                e = d;
                d = c;
                c = bit_rol(b, 30);
                b = a;
                a = t;
            }

            a = safe_add(a, olda);
            b = safe_add(b, oldb);
            c = safe_add(c, oldc);
            d = safe_add(d, oldd);
            e = safe_add(e, olde);
        }
        return [a, b, c, d, e];
    }


    /*
     * Perform the appropriate triplet combination function for the current
     * iteration
     */
    function sha1_ft(t, b, c, d) {
        if(t < 20) {return (b & c) | ((~b) & d); }
        if(t < 40) {return b ^ c ^ d; }
        if(t < 60) {return (b & c) | (b & d) | (c & d); }
        return b ^ c ^ d;
    }

    /*
     * Determine the appropriate additive constant for the current iteration
     */
    function sha1_kt(t) {
        return (t < 20) ?  1518500249 : (t < 40) ?  1859775393 :
            (t < 60) ? -1894007588 : -899497514;
    }

    /*
     * Add integers, wrapping at 2^32. This uses 16-bit operations internally
     * to work around bugs in some JS interpreters.
     */
    function safe_add(x, y) {
        var lsw = (x & 0xFFFF) + (y & 0xFFFF);
        var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
        return (msw << 16) | (lsw & 0xFFFF);
    }

    /*
     * Bitwise rotate a 32-bit number to the left.
     */
    function bit_rol(num, cnt) {
        return (num << cnt) | (num >>> (32 - cnt));
    }


    SHA1 = {

        __version : "1.0",

        /*
         * These are the functions you'll usually want to call
         * They take string arguments and return either hex or base-64 encoded strings
         */
        binb : function(x, len) {
            return binb_sha1(x, len);
        },

        // convert a string to an array of words?
        strToBin : function (s) {
            return rstr2binb(s) ;
        },
        // convert a string to a string-rep of an array of hex bytes
        strToHex : function (s) {
            return rstr2hex(s) ;
        },

        binToHex : function (a) {
            return binb2hex(a) ;
        },

        hash_asHex : function (s) {
            return rstr2hex(rstr_sha1(str2rstr_utf8(s)));
        },
        hash_asB64 : function (s) {
            return rstr2b64(rstr_sha1(str2rstr_utf8(s)));
        },
        hash_Encoded : function (s,encoding) {
            return rstr2any(rstr_sha1(str2rstr_utf8(s)), encoding);
        },
        hmac_asHex : function (k,d) {
            return rstr2hex(rstr_hmac_sha1(str2rstr_utf8(k), str2rstr_utf8(d)));
        },
        hmac_asB64 : function (k,d) {
            return rstr2b64(rstr_hmac_sha1(str2rstr_utf8(k), str2rstr_utf8(d)));
        },
        hmac_Encoded : function (k,d,encoding) {
            return rstr2any(rstr_hmac_sha1(str2rstr_utf8(k), str2rstr_utf8(d)),
                            encoding);
        }
    };


    // simple self-test
    (function() {
        if (SHA1.hash_asHex("abc").toLowerCase() !==
            "a9993e364706816aba3e25717850c26c9cd0d89d") {
            throw new Exception("Sha1Exception", "SHA1 is not working properly");
        }
    })();


})();

// pbkdf2.js
// ------------------------------------------------------------------
//
// RFC 2898 - compliant key derivation function, implemente din Javascript.
//
//
// Author     : Dino Chiesa
//            : dpchiesa@hotmail.com
// Created    : Thu Apr 21 20:16:47 2011
// on Machine : DINO-PC
// Last-saved : <2011-April-22 15:24:12>
//
// ------------------------------------------------------------------


// Credit:
/*
 * JavaScript implementation of Password-Based Key Derivation Function 2
 * (PBKDF2) as defined in RFC 2898.
 * Version 1.1
 * Copyright (c) 2007, Parvez Anandam
 * parvez.anandam@cern.ch
 * http://anandam.name/pbkdf2
 *
 * Distributed under the BSD license
 *
 * (Uses Paul Johnston's excellent SHA-1 JavaScript library sha1.js)
 * Thanks to Felix Gartsman for pointing out a bug in version 1.0
 */


// Re-packaged as a Javascript OO library by Dino Chiesa
// Thu, 21 Apr 2011  20:36
// dpchiesa@hotmail.com

//
// usage examples:
//
// Produce a 16-byte key from a string, following RFC2898, for 1000 iterations:
//
//   var password = "This is a secret!";
//   var pbkdf2 = new PBKDF2(password, "salt", 1000);
//   pbkdf2.deriveBytes(16);

(function() {

    if (typeof Exception == "undefined") {

        Exception = function(type, description, optionalNumber) {
            var instance         = {};
            instance.type        = type || "Exception";
            instance.description = description || "unknown exception";
            instance.number      = optionalNumber || 0;
            return instance;
        };
    }
})();


    // function includeFile (filename) {
    //     var fileData;
    //     var fso = new ActiveXObject ("Scripting.FileSystemObject");
    //     var fileStream = fso.openTextFile (filename);
    //     fso = null;
    //     var fileData = fileStream.readAll();
    //     fileStream.Close();
    //     fileStream = null;
    //     eval(fileData);
    // }
    //
    // includeFile("sha1.js");

(function() {

    if (typeof PBKDF2 !== "undefined") {
        throw new Exception("TypeDefinitionException", "PBKDF2 is already defined");
    }

    var m_bpassword;
    var m_salt;
    var m_totalBlocks = 0;
    var m_total_iterations = 0;

    var leftoverBytes = "";

    // Run iterations in chunks instead of all at once, so as to not block.
    // Define size of chunk here; adjust for slower or faster machines if necessary.
    var m_iterations_in_chunk = 100;

    // Key length, as number of bytes
    var m_key_length;

    // The length (number of bytes) of the output of the pseudo-random function.
    // Since HMAC-SHA1 is the standard, and what is used here, it's 20 bytes.
    var m_hash_length = 20;

    // Used in the HMAC-SHA1 computations
    var m_ipad = new Array(16);
    var m_opad = new Array(16);

    var m_hash= "";

    // The workhorse
    var PBKDF2_do_iterations = function (nBytes, cbStatus, cbDone) {
        cbStatus("do iterations");
        // see if we have enough from a previous call.
        if (nBytes * 2 <= leftoverBytes.length ) {
            var r1 = leftoverBytes.substr(0, nBytes * 2);
            cbStatus("using leftover bytes");
            leftoverBytes = leftoverBytes.substr(nBytes * 2);
            cbDone(r1);
            return;
        }

        var nBlocks = Math.ceil(nBytes/m_hash_length);
        var bytes = "";
        var n = 0;
        var m = 0;
        var buffer = [0,0,0,0,0];

        var doOneChunk = function(chunkIterations) {
            for(var i=0; i<chunkIterations; ++i) {
                //var hash = "";
                // compute HMAC-SHA1
                //if (m_firstRun == 0 && m==0)
                if (m === 0) {
                    var x = n + m_totalBlocks;
                    var salt_block = m_salt +
                        String.fromCharCode(x >> 24 & 0xF) +
                        String.fromCharCode(x >> 16 & 0xF) +
                        String.fromCharCode(x >>  8 & 0xF) +
                        String.fromCharCode(x       & 0xF);

                    m_hash = SHA1.binb(m_ipad.concat(SHA1.strToBin(salt_block)),
                                       512 + salt_block.length * 8);
                    m_hash = SHA1.binb(m_opad.concat(m_hash), 512 + 160);
                }
                else {
                    m_hash = SHA1.binb(m_ipad.concat(m_hash),
                                       512 + m_hash.length * 32);
                    m_hash = SHA1.binb(m_opad.concat(m_hash), 512 + 160);
                }

                for(var j=0; j<m_hash.length; ++j) {
                    buffer[j] ^= m_hash[j];
                }

                m++;
            }
        };


        var doIterationsByChunks = function (cb) {
            // do N iterations, one chunk at a time
            cbStatus("doIterationsByChunks (n,m)=(" + n + "," + m +")");

            if (m >= m_total_iterations) {
                // done with all chunks
                bytes += SHA1.binToHex(buffer);
                if (cb) { cb(bytes); }
                return;
            }

            var chunkIterations = m_iterations_in_chunk;
            if (m_total_iterations - m < m_iterations_in_chunk) {
                chunkIterations = m_total_iterations - m;
            }

            doOneChunk(chunkIterations);  // synchronous

            setTimeout(function() {doIterationsByChunks(cb);}, 1);
        };



        // This fn does one block (hash-sized blocks in the derived key
        // (called 'l' in RFC2898))

        var doBlocks = function(cb) {
            n++;
            buffer = [0,0,0,0,0];
            m = 0;

            var oneBlockDone = function(interim) {
                // done with one block
                if (n >= nBlocks) {
                    if (cb) { cb(bytes); }
                    return;
                }
                // call self again
                setTimeout(function(){doBlocks(cb);}, 1);
            };

            setTimeout(function() {doIterationsByChunks(oneBlockDone);}, 1);
        };


        var doneIterations = function() {
            m_totalBlocks += nBlocks;
            var aggregate = leftoverBytes + bytes;
            var result = aggregate.substr(0, nBytes * 2);
            leftoverBytes = aggregate.substr(nBytes * 2);
            cbDone(result);
            return;
        };

        cbStatus("kickoff");
        // Start computation with the first block
        setTimeout(function() { doBlocks(doneIterations); }, 1);
    };

    var reinit = function() {
        m_totalBlocks = 0;
        m_total_iterations = 0;

        leftoverBytes = "";

        // Run iterations in chunks instead of all at once, so as to not block.
        // Define size of chunk here; adjust for slower or faster machines if necessary.
        m_iterations_in_chunk = 100;

        // Key length, as number of bytes

        // Used in the HMAC-SHA1 computations
        m_ipad = new Array(16);
        m_opad = new Array(16);

        m_hash= "";
    };

    // initialize the PBKDF2 "class"
    PBKDF2 = function(password, salt, iterations) {
        this.__version = "1.0";
        reinit();
        m_bpassword = SHA1.strToBin(password);
        m_salt = salt;
        m_total_iterations = iterations;

        // Set up the HMAC-SHA1 computations
        if (m_bpassword.length > 16) {
            m_bpassword = SHA1.binb(m_bpassword, password.length * 8);
        }
        for(var i = 0; i < 16; ++i) {
            m_ipad[i] = m_bpassword[i] ^ 0x36363636;
            m_opad[i] = m_bpassword[i] ^ 0x5C5C5C5C;
        }
    };

    PBKDF2.prototype = {
        deriveBytes : function (length, cbStatus, cbDone){
            PBKDF2_do_iterations(length, cbStatus, function(stringRep) {
                var bytes= [];
                for(var i = 0; i < stringRep.length; i+=2) {
                    val = parseInt(stringRep.substr(i,2),16) ;
                    bytes.push(val);
                }
                cbDone(bytes);
            });
        }
    };

})();


// des.js
// ------------------------------------------------------------------
//
// A pure Javascript implementation of DES and Triple-DES, implemented as
// a Javascript "class".  Usable from any browser, any OS.
//
// Depends on sha1.js and pbkdf2.js
//
// Author     : Dino
// Created    : Thu Apr 21 18:59:51 2011
// on Machine : DINO-PC
// Last-saved : <2011-April-22 16:44:38>
//
// ------------------------------------------------------------------


// Credit for original DES logic to Paul Tero, http://www.tero.co.uk/des/
//
// Optimised for performance with large blocks by Michael Hayworth, November 2001
// http://www.netdealing.com
//
// This notice was on the original DES code:
// ----
// THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED
// WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
// IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
// GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
// IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
// OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
// IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


// Re-packaged as a Javascript OO library by Dino Chiesa
// Thu, 21 Apr 2011  20:36
// dpchiesa@hotmail.com

//
// usage examples:
//
// Produce a DES-encrypted form of a message:
//   var password = "Albatros1";
//   var salt = "saltines";
//   var iterations = 1000;
//   say("password  : " + password);
//   say("salt      : " + salt + " ("+ SHA1.strToHex(salt) +")");
//   say("iterations: " + iterations);
//   var pbkdf2 = new PBKDF2(password, salt, iterations);
//   var key = pbkdf2.deriveBytes(8); // use 24 for 3DES
//   say("key       : " + key);
//   var iv = pbkdf2.deriveBytes(8);
//   say("iv        : " + iv);
//
//   var des = new DES(key,iv);
//
//   var plaintext = "This is the plaintext!! Heyo heyo heyo";
//   var ciphertext = des.encrypt(plaintext);
//
//   say("original  : "+ plaintext);
//   say("Ciphertext: " + stringToHex (ciphertext));
//
//   var decrypted = des.decrypt(ciphertext);
//   say("decrypted : "+ decrypted);
//

(function() {

    if (typeof Exception == "undefined") {

        Exception = function(type, description, optionalNumber) {
            var instance         = {};
            instance.type        = type || "Exception";
            instance.description = description || "unknown exception";
            instance.number      = optionalNumber || 0;
            return instance;
        };
    }
})();



(function() {

    if (typeof DES !== "undefined") {
        throw new Exception("TypeDefinitionException", "DES is already defined");
    }

    var DesCryptoDirection = {
        None : 0,
        Encryption : 1,
        Decryption : 2
    };

    DesCryptoMode = {
        ECB : 0,
        CBC : 1
    };

    DesPadding = {
        Zeros : 0,
        PKCS7 : 1,
        Spaces : 2
    };


    // initialize the DES "class"
    DES = function(key, iv) {
        this.__version = "1.0";
        this.key = key;
        this.iv = iv || "\0\0\0\0\0\0\0\0"; // used only for CBC mode?
        this.padding = DesPadding.PKCS7;
        this.mode = DesCryptoMode.CBC;
        if (this.key === null) {
            throw new Exception("ArgumentException", "key must not be null");
        }
    };

    // these arrays are used internally by createSubkeys
    var pc2bytes0  = [0,0x4,0x20000000,0x20000004,0x10000,0x10004,0x20010000,0x20010004,0x200,0x204,0x20000200,0x20000204,0x10200,0x10204,0x20010200,0x20010204];
    var pc2bytes1  = [0,0x1,0x100000,0x100001,0x4000000,0x4000001,0x4100000,0x4100001,0x100,0x101,0x100100,0x100101,0x4000100,0x4000101,0x4100100,0x4100101];
    var pc2bytes2  = [0,0x8,0x800,0x808,0x1000000,0x1000008,0x1000800,0x1000808,0,0x8,0x800,0x808,0x1000000,0x1000008,0x1000800,0x1000808];
    var pc2bytes3  = [0,0x200000,0x8000000,0x8200000,0x2000,0x202000,0x8002000,0x8202000,0x20000,0x220000,0x8020000,0x8220000,0x22000,0x222000,0x8022000,0x8222000];
    var pc2bytes4  = [0,0x40000,0x10,0x40010,0,0x40000,0x10,0x40010,0x1000,0x41000,0x1010,0x41010,0x1000,0x41000,0x1010,0x41010];
    var pc2bytes5  = [0,0x400,0x20,0x420,0,0x400,0x20,0x420,0x2000000,0x2000400,0x2000020,0x2000420,0x2000000,0x2000400,0x2000020,0x2000420];
    var pc2bytes6  = [0,0x10000000,0x80000,0x10080000,0x2,0x10000002,0x80002,0x10080002,0,0x10000000,0x80000,0x10080000,0x2,0x10000002,0x80002,0x10080002];
    var pc2bytes7  = [0,0x10000,0x800,0x10800,0x20000000,0x20010000,0x20000800,0x20010800,0x20000,0x30000,0x20800,0x30800,0x20020000,0x20030000,0x20020800,0x20030800];
    var pc2bytes8  = [0,0x40000,0,0x40000,0x2,0x40002,0x2,0x40002,0x2000000,0x2040000,0x2000000,0x2040000,0x2000002,0x2040002,0x2000002,0x2040002];
    var pc2bytes9  = [0,0x10000000,0x8,0x10000008,0,0x10000000,0x8,0x10000008,0x400,0x10000400,0x408,0x10000408,0x400,0x10000400,0x408,0x10000408];
    var pc2bytes10 = [0,0x20,0,0x20,0x100000,0x100020,0x100000,0x100020,0x2000,0x2020,0x2000,0x2020,0x102000,0x102020,0x102000,0x102020];
    var pc2bytes11 = [0,0x1000000,0x200,0x1000200,0x200000,0x1200000,0x200200,0x1200200,0x4000000,0x5000000,0x4000200,0x5000200,0x4200000,0x5200000,0x4200200,0x5200200];
    var pc2bytes12 = [0,0x1000,0x8000000,0x8001000,0x80000,0x81000,0x8080000,0x8081000,0x10,0x1010,0x8000010,0x8001010,0x80010,0x81010,0x8080010,0x8081010];
    var pc2bytes13 = [0,0x4,0x100,0x104,0,0x4,0x100,0x104,0x1,0x5,0x101,0x105,0x1,0x5,0x101,0x105];

    //this takes as input a 64 bit key (even though only 56 bits are used)
    //as an array of 2 integers, and returns 16 48 bit keys
    // the key must be an array of bytes. For des, 8 bytes in length.
    var createSubkeys = function (key) {
        //how many iterations (1 for des, 3 for triple des)
        var iterations = key.length > 8 ? 3 : 1; //changed by Paul 16/6/2007 to use Triple DES for 9+ byte keys
        //stores the return keys
        var keys = []; // new Array (32 * iterations);
        //now define the left shifts which need to be done
        var shifts = [0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0];
        //other variables
        var lefttemp, righttemp, m=0, n=0, temp;

        for (var j=0; j<iterations; j++) { //either 1 or 3 iterations
            left = (key[m++] << 24) | (key[m++] << 16) | (key[m++] << 8) | key[m++];
            right = (key[m++] << 24) | (key[m++] << 16) | (key[m++] << 8) | key[m++];

            temp = ((left >>> 4) ^ right) & 0x0f0f0f0f; right ^= temp; left ^= (temp << 4);
            temp = ((right >>> -16) ^ left) & 0x0000ffff; left ^= temp; right ^= (temp << -16);
            temp = ((left >>> 2) ^ right) & 0x33333333; right ^= temp; left ^= (temp << 2);
            temp = ((right >>> -16) ^ left) & 0x0000ffff; left ^= temp; right ^= (temp << -16);
            temp = ((left >>> 1) ^ right) & 0x55555555; right ^= temp; left ^= (temp << 1);
            temp = ((right >>> 8) ^ left) & 0x00ff00ff; left ^= temp; right ^= (temp << 8);
            temp = ((left >>> 1) ^ right) & 0x55555555; right ^= temp; left ^= (temp << 1);

            //the right side needs to be shifted and to get the last four bits of the left side
            temp = (left << 8) | ((right >>> 20) & 0x000000f0);
            //left needs to be put upside down
            left = (right << 24) | ((right << 8) & 0xff0000) | ((right >>> 8) & 0xff00) | ((right >>> 24) & 0xf0);
            right = temp;

            //now go through and perform these shifts on the left and right keys
            for (var i=0; i < shifts.length; i++) {
                //shift the keys either one or two bits to the left
                if (shifts[i]) {left = (left << 2) | (left >>> 26); right = (right << 2) | (right >>> 26);}
                else {left = (left << 1) | (left >>> 27); right = (right << 1) | (right >>> 27);}
                left &= -0xf; right &= -0xf;

                //now apply PC-2, in such a way that E is easier when encrypting or decrypting
                //this conversion will look like PC-2 except only the last 6 bits of each byte are used
                //rather than 48 consecutive bits and the order of lines will be according to
                //how the S selection functions will be applied: S2, S4, S6, S8, S1, S3, S5, S7
                lefttemp = pc2bytes0[left >>> 28] | pc2bytes1[(left >>> 24) & 0xf]
                    | pc2bytes2[(left >>> 20) & 0xf] | pc2bytes3[(left >>> 16) & 0xf]
                    | pc2bytes4[(left >>> 12) & 0xf] | pc2bytes5[(left >>> 8) & 0xf]
                    | pc2bytes6[(left >>> 4) & 0xf];
                righttemp = pc2bytes7[right >>> 28] | pc2bytes8[(right >>> 24) & 0xf]
                    | pc2bytes9[(right >>> 20) & 0xf] | pc2bytes10[(right >>> 16) & 0xf]
                    | pc2bytes11[(right >>> 12) & 0xf] | pc2bytes12[(right >>> 8) & 0xf]
                    | pc2bytes13[(right >>> 4) & 0xf];
                temp = ((righttemp >>> 16) ^ lefttemp) & 0x0000ffff;
                keys[n++] = lefttemp ^ temp;
                keys[n++] = righttemp ^ (temp << 16);
            }
        } //for each iterations
        //return the keys we've created
        return keys;
    };


    var spfunction1 = [0x1010400,0,0x10000,0x1010404,0x1010004,0x10404,0x4,0x10000,0x400,0x1010400,0x1010404,0x400,0x1000404,0x1010004,0x1000000,0x4,0x404,0x1000400,0x1000400,0x10400,0x10400,0x1010000,0x1010000,0x1000404,0x10004,0x1000004,0x1000004,0x10004,0,0x404,0x10404,0x1000000,0x10000,0x1010404,0x4,0x1010000,0x1010400,0x1000000,0x1000000,0x400,0x1010004,0x10000,0x10400,0x1000004,0x400,0x4,0x1000404,0x10404,0x1010404,0x10004,0x1010000,0x1000404,0x1000004,0x404,0x10404,0x1010400,0x404,0x1000400,0x1000400,0,0x10004,0x10400,0,0x1010004];
    var spfunction2 = [-0x7fef7fe0,-0x7fff8000,0x8000,0x108020,0x100000,0x20,-0x7fefffe0,-0x7fff7fe0,-0x7fffffe0,-0x7fef7fe0,-0x7fef8000,-0x80000000,-0x7fff8000,0x100000,0x20,-0x7fefffe0,0x108000,0x100020,-0x7fff7fe0,0,-0x80000000,0x8000,0x108020,-0x7ff00000,0x100020,-0x7fffffe0,0,0x108000,0x8020,-0x7fef8000,-0x7ff00000,0x8020,0,0x108020,-0x7fefffe0,0x100000,-0x7fff7fe0,-0x7ff00000,-0x7fef8000,0x8000,-0x7ff00000,-0x7fff8000,0x20,-0x7fef7fe0,0x108020,0x20,0x8000,-0x80000000,0x8020,-0x7fef8000,0x100000,-0x7fffffe0,0x100020,-0x7fff7fe0,-0x7fffffe0,0x100020,0x108000,0,-0x7fff8000,0x8020,-0x80000000,-0x7fefffe0,-0x7fef7fe0,0x108000];
    var spfunction3 = [0x208,0x8020200,0,0x8020008,0x8000200,0,0x20208,0x8000200,0x20008,0x8000008,0x8000008,0x20000,0x8020208,0x20008,0x8020000,0x208,0x8000000,0x8,0x8020200,0x200,0x20200,0x8020000,0x8020008,0x20208,0x8000208,0x20200,0x20000,0x8000208,0x8,0x8020208,0x200,0x8000000,0x8020200,0x8000000,0x20008,0x208,0x20000,0x8020200,0x8000200,0,0x200,0x20008,0x8020208,0x8000200,0x8000008,0x200,0,0x8020008,0x8000208,0x20000,0x8000000,0x8020208,0x8,0x20208,0x20200,0x8000008,0x8020000,0x8000208,0x208,0x8020000,0x20208,0x8,0x8020008,0x20200];
    var spfunction4 = [0x802001,0x2081,0x2081,0x80,0x802080,0x800081,0x800001,0x2001,0,0x802000,0x802000,0x802081,0x81,0,0x800080,0x800001,0x1,0x2000,0x800000,0x802001,0x80,0x800000,0x2001,0x2080,0x800081,0x1,0x2080,0x800080,0x2000,0x802080,0x802081,0x81,0x800080,0x800001,0x802000,0x802081,0x81,0,0,0x802000,0x2080,0x800080,0x800081,0x1,0x802001,0x2081,0x2081,0x80,0x802081,0x81,0x1,0x2000,0x800001,0x2001,0x802080,0x800081,0x2001,0x2080,0x800000,0x802001,0x80,0x800000,0x2000,0x802080];
    var spfunction5 = [0x100,0x2080100,0x2080000,0x42000100,0x80000,0x100,0x40000000,0x2080000,0x40080100,0x80000,0x2000100,0x40080100,0x42000100,0x42080000,0x80100,0x40000000,0x2000000,0x40080000,0x40080000,0,0x40000100,0x42080100,0x42080100,0x2000100,0x42080000,0x40000100,0,0x42000000,0x2080100,0x2000000,0x42000000,0x80100,0x80000,0x42000100,0x100,0x2000000,0x40000000,0x2080000,0x42000100,0x40080100,0x2000100,0x40000000,0x42080000,0x2080100,0x40080100,0x100,0x2000000,0x42080000,0x42080100,0x80100,0x42000000,0x42080100,0x2080000,0,0x40080000,0x42000000,0x80100,0x2000100,0x40000100,0x80000,0,0x40080000,0x2080100,0x40000100];
    var spfunction6 = [0x20000010,0x20400000,0x4000,0x20404010,0x20400000,0x10,0x20404010,0x400000,0x20004000,0x404010,0x400000,0x20000010,0x400010,0x20004000,0x20000000,0x4010,0,0x400010,0x20004010,0x4000,0x404000,0x20004010,0x10,0x20400010,0x20400010,0,0x404010,0x20404000,0x4010,0x404000,0x20404000,0x20000000,0x20004000,0x10,0x20400010,0x404000,0x20404010,0x400000,0x4010,0x20000010,0x400000,0x20004000,0x20000000,0x4010,0x20000010,0x20404010,0x404000,0x20400000,0x404010,0x20404000,0,0x20400010,0x10,0x4000,0x20400000,0x404010,0x4000,0x400010,0x20004010,0,0x20404000,0x20000000,0x400010,0x20004010];
    var spfunction7 = [0x200000,0x4200002,0x4000802,0,0x800,0x4000802,0x200802,0x4200800,0x4200802,0x200000,0,0x4000002,0x2,0x4000000,0x4200002,0x802,0x4000800,0x200802,0x200002,0x4000800,0x4000002,0x4200000,0x4200800,0x200002,0x4200000,0x800,0x802,0x4200802,0x200800,0x2,0x4000000,0x200800,0x4000000,0x200800,0x200000,0x4000802,0x4000802,0x4200002,0x4200002,0x2,0x200002,0x4000000,0x4000800,0x200000,0x4200800,0x802,0x200802,0x4200800,0x802,0x4000002,0x4200802,0x4200000,0x200800,0,0x2,0x4200802,0,0x200802,0x4200000,0x800,0x4000002,0x4000800,0x800,0x200002];
    var spfunction8 = [0x10001040,0x1000,0x40000,0x10041040,0x10000000,0x10001040,0x40,0x10000000,0x40040,0x10040000,0x10041040,0x41000,0x10041000,0x41040,0x1000,0x40,0x10040000,0x10000040,0x10001000,0x1040,0x41000,0x40040,0x10040040,0x10041000,0x1040,0,0,0x10040040,0x10000040,0x10001000,0x41040,0x40000,0x41040,0x40000,0x10041000,0x1000,0x40,0x10040040,0x1000,0x41040,0x10001000,0x40,0x10000040,0x10040000,0x10040040,0x10000000,0x40000,0x10001040,0,0x10041040,0x40040,0x10000040,0x10040000,0x10001000,0x10001040,0,0x10041040,0x41000,0x41000,0x1040,0x1040,0x40040,0x10000000,0x10041000];


    var doDes =  function (key, message, direction, mode, iv, padding) {

        //create the 16 (DES) or 48 (3DES) subkeys we will need
        var encrypt = (direction == DesCryptoDirection.Encryption);
        var wantCBC = (mode == DesCryptoMode.CBC);
        var keys = createSubkeys(key);
        var m=0, i, j, temp, temp2, right1, right2, left, right, looping;
        var cbcleft, cbcleft2, cbcright, cbcright2;
        var endloop, loopinc;
        var len = message.length;
        var chunk = 0;
        //set up the loops for single and triple des
        var iterations = keys.length == 32 ? 3 : 9; //single or triple des
        if (iterations == 3) {
            looping = encrypt ? [0, 32, 2] : [30, -2, -2];
        }
        else {
            looping = encrypt ?
                [0, 32, 2, 62, 30, -2, 64, 96, 2] :
                [94, 62, -2, 32, 64, 2, 30, -2, -2];
        }

        // when encrypting, apply padding
        if (encrypt){
            if (padding == DesPadding.Spaces) {
                message += "        ";
            }
            else if (padding == DesPadding.PKCS7) {
                temp = 8-(len%8);
                message += String.fromCharCode (temp,temp,temp,temp,temp,temp,temp,temp);
                if (temp==8) {len+=8;}
            }
            else if (padding == DesPadding.Zeros) {
                message += "\0\0\0\0\0\0\0\0"; //pad the message out with null bytes
            }
            else {
                throw new Exception("CryptoException", "Invalid padding");
            }
        }

        // store the result here
        result = "";
        tempresult = "";

        if (wantCBC) {
            var cbcleft =
                (iv[m++] << 24) |
                (iv[m++] << 16) |
                (iv[m++] << 8) |
                iv[m++];
            cbcright =
                (iv[m++] << 24) |
                (iv[m++] << 16) |
                (iv[m++] << 8) |
                iv[m++];
            m=0; // reset
        }

        // loop through each 64 bit chunk of the message
        while (m < len) {
            left = (message.charCodeAt(m++) << 24) | (message.charCodeAt(m++) << 16) | (message.charCodeAt(m++) << 8) | message.charCodeAt(m++);
            right = (message.charCodeAt(m++) << 24) | (message.charCodeAt(m++) << 16) | (message.charCodeAt(m++) << 8) | message.charCodeAt(m++);

            //for Cipher Block Chaining, xor the message with the previous result
            if (wantCBC) {
                if (encrypt) {
                    left ^= cbcleft;
                    right ^= cbcright;
                } else {
                    cbcleft2 = cbcleft;
                    cbcright2 = cbcright;
                    cbcleft = left;
                    cbcright = right;
                }
            }

            //first each 64 but chunk of the message must be permuted according to IP
            temp = ((left >>> 4) ^ right) & 0x0f0f0f0f; right ^= temp; left ^= (temp << 4);
            temp = ((left >>> 16) ^ right) & 0x0000ffff; right ^= temp; left ^= (temp << 16);
            temp = ((right >>> 2) ^ left) & 0x33333333; left ^= temp; right ^= (temp << 2);
            temp = ((right >>> 8) ^ left) & 0x00ff00ff; left ^= temp; right ^= (temp << 8);
            temp = ((left >>> 1) ^ right) & 0x55555555; right ^= temp; left ^= (temp << 1);

            left = ((left << 1) | (left >>> 31));
            right = ((right << 1) | (right >>> 31));

            //do this either 1 or 3 times for each chunk of the message
            for (j=0; j<iterations; j+=3) {
                endloop = looping[j+1];
                loopinc = looping[j+2];
                //now go through and perform the encryption or decryption
                for (i=looping[j]; i!=endloop; i+=loopinc) { //for efficiency
                    right1 = right ^ keys[i];
                    right2 = ((right >>> 4) | (right << 28)) ^ keys[i+1];
                    //the result is attained by passing these bytes through the S selection functions
                    temp = left;
                    left = right;
                    right = temp ^ (spfunction2[(right1 >>> 24) & 0x3f] |
                                    spfunction4[(right1 >>> 16) & 0x3f] |
                                    spfunction6[(right1 >>>  8) & 0x3f] |
                                    spfunction8[right1 & 0x3f] |
                                    spfunction1[(right2 >>> 24) & 0x3f] |
                                    spfunction3[(right2 >>> 16) & 0x3f] |
                                    spfunction5[(right2 >>>  8) & 0x3f] |
                                    spfunction7[right2 & 0x3f]);
                }
                temp = left;
                left = right;
                right = temp; //unreverse left and right
            } //for either 1 or 3 iterations

            //move then each one bit to the right
            left = ((left >>> 1) | (left << 31));
            right = ((right >>> 1) | (right << 31));

            //now perform IP-1, which is IP in the opposite direction
            temp = ((left >>> 1) ^ right) & 0x55555555; right ^= temp; left ^= (temp << 1);
            temp = ((right >>> 8) ^ left) & 0x00ff00ff; left ^= temp; right ^= (temp << 8);
            temp = ((right >>> 2) ^ left) & 0x33333333; left ^= temp; right ^= (temp << 2);
            temp = ((left >>> 16) ^ right) & 0x0000ffff; right ^= temp; left ^= (temp << 16);
            temp = ((left >>> 4) ^ right) & 0x0f0f0f0f; right ^= temp; left ^= (temp << 4);

            //for Cipher Block Chaining, xor the message with the previous result
            if (wantCBC) {if (encrypt) {cbcleft = left; cbcright = right;} else {left ^= cbcleft2; right ^= cbcright2;}}
            tempresult += String.fromCharCode ((left>>>24), ((left>>>16) & 0xff), ((left>>>8) & 0xff), (left & 0xff), (right>>>24), ((right>>>16) & 0xff), ((right>>>8) & 0xff), (right & 0xff));

            chunk += 8;
            if (chunk == 512) {
                result += tempresult;
                tempresult = "";
                chunk = 0;
            }
        } //for every 8 characters, or 64 bits in the message

        //return the result as an array (??)
        result = result + tempresult;

        if (!encrypt) {
            if (padding == DesPadding.Spaces) {
                var rtrim = function(s){
                    var r=s.length -1;
                    while(r > 0 && s[r] == ' ') { r-=1; }
                    return s.substring(0, r+1);
                }
                result = rtrim(result);
            }
            else if (padding == DesPadding.PKCS7) {
                var padBytes = result.charCodeAt(len-1);
                result = result.substring(0, len-padBytes);
            }
            else if (padding == DesPadding.Zeros) {
                var rtrim = function(s){
                    var r=s.length -1;
                    while(r > 0 && s[r] == '\0') { r-=1; }
                    return s.substring(0, r+1);
                }
                result = rtrim(result);
            }
            else {
                throw new Exception("CryptoException", "Invalid padding");
            }
        }

        return result ;
    };


    DES.prototype = {
        encrypt : function(plaintext) {
            return doDes(this.key,
                         plaintext,
                         DesCryptoDirection.Encryption,
                         this.mode,
                         this.iv,
                         this.padding);
        },

        decrypt : function(cryptotext) {
            return doDes(this.key,
                         cryptotext,
                         DesCryptoDirection.Decryption,
                         this.mode,
                         this.iv,
                         this.padding);
        }
    };

})();




var msgDiv;

function hexStringToByteArray(s) {
    var r= Array(s.length/2);
    for (var i = 0; i < s.length; i+=2)
    {
        r[i/2] = parseInt(s.substr(i,2),16);
    }
    return r;
}

function byteArrayToHexString(a, upcase) {
    upcase = upcase || true;
    var hex_tab = upcase ? "0123456789ABCDEF" : "0123456789abcdef";
    var r= "";
    for (var i = 0; i < a.length; i++) {
        var b  = hex_tab.charAt((a[i] >> 4) & 0x0F) +
            hex_tab.charAt(a[i] & 0x0F);
        r+= b;
    }
    return r;
}

function binStringToHexString(s, upcase) {
  upcase = upcase || true;
  var hex_tab = upcase ? "0123456789ABCDEF" : "0123456789abcdef";
  var r ='';
  for (var i=0; i<s.length; i++) {
    r += hex_tab.charAt(s.charCodeAt(i) >> 4) +
         hex_tab.charAt(s.charCodeAt(i) & 0xf);
  }
  return r;
}

function hexStringToBinString(s) {
  var r ='';
  for (var i=0; i<s.length; i+=2) {
      r += String.fromCharCode(parseInt(s.substr(i,2), 16));
  }
  return r;
}


function getRadioValue(id) {
  var elts = document.getElementsByName(id);
  var radioValue = '';
  for (var i = 0; i < elts.length && radioValue==''; i++) {
    if (elts[i].type == 'radio') {
      if(elts[i].checked) {
        radioValue = elts[i].value; //innerHTML;
      }
    }
  }
  return radioValue;
}


function getKeyAndIv(password, salt, iterations, callback) {
  var e;
  e = document.getElementById("key");
  e.value = 'calculating...';
  e.disabled = true;
  e = document.getElementById("iv");
  e.value = '';
  showMsg("password: '" + password + "'");
  showMsg("salt: '" + salt + "'");
  showMsg("iterations: '" + iterations + "'");

  var pbkdf2 = new PBKDF2(password, salt, iterations);


  var alg = getRadioValue('alg');
  showMsg('alg: ' + alg);
  var keysize = (alg == "DES") ? 8 : 24;
  var blocksize = 8; // always

  pbkdf2.deriveBytes(keysize, showMsg, function(key) {
    var e1 = document.getElementById("key");
    e1.value = byteArrayToHexString(key);
    e1.disabled = false;

    pbkdf2.deriveBytes(blocksize, showMsg, function(iv) {
      var e2 = document.getElementById("iv");
      e2.value = byteArrayToHexString(iv);
      if (callback) { callback(key,iv);}
    });
  });
}



function doButtons(status){
  var e;
  e = document.getElementById("btnEncrypt");
  e.disabled = status;
  e = document.getElementById("btnDecrypt");
  e.disabled = status;
  e = document.getElementById("btnReset");
  e.disabled = status;
}

function disableButtons(){
  doButtons(true);
}

function enableButtons(){
  doButtons(false);
}


function resetKeyAndIv() {
  var e;
  e = document.getElementById("iv");
  e.value = '';
  e = document.getElementById("key");
  e.value = '';
}

function password_change() {
  resetKeyAndIv();
}

function crypto_change() {
  resetKeyAndIv();
}


function decrypt_click() {
  disableButtons();
  showMsg("Decrypt.", true);
  var e, key, iv;
  e = document.getElementById("plaintext");
  e.value = '';
  e = document.getElementById("iv");
  iv = e.value;
  e = document.getElementById("key");
  key = e.value;

  var doTheWork = function(key,iv) {
    showMsg("key: " + byteArrayToHexString(key));
    showMsg("iv: " + byteArrayToHexString(iv));
    var e1;
    var des = new DES(key,iv);
    var mode = getRadioValue('mode');
    des.mode = (mode == "CBC") ? DesCryptoMode.CBC : DesCryptoMode.ECB;
    var padding = getRadioValue('padding');
    des.padding = (padding == "PKCS7") ? DesPadding.PKCS7 :
        (padding == "Zeroes") ? DesPadding.Zeroes : DesPadding.Spaces ;

    e1 = document.getElementById("ciphertext");
    var ciphertext = hexStringToBinString(e1.value);
    var plaintext = des.decrypt(ciphertext);
    e1 = document.getElementById("plaintext");
    e1.value = plaintext;
    enableButtons();
    e1 = document.getElementById("ciphertext");
    e1.value = '';
    e1 = document.getElementById("btnDecrypt");
    e1.disabled = true;
  };

  if (key == '' || iv == '') {
    var password, salt, iterations;
    e = document.getElementById("password");
    password = e.value;
    e = document.getElementById("salt");
    salt = e.value;
    e = document.getElementById("iterations");
    iterations = parseInt(e.value);
    getKeyAndIv(password, salt, iterations, doTheWork);
  } else {
    // convert hex string back to byte array
    doTheWork(hexStringToByteArray(key),hexStringToByteArray(iv));
  }
}


function encrypt_click() {
  disableButtons();
  showMsg("Encrypt.");
  var e, key, iv;
  e = document.getElementById("ciphertext");
  e.value = '';
  e = document.getElementById("iv");
  iv = e.value; // hex string
  e = document.getElementById("key");
  key = e.value; // hex string

  var doTheWork = function(key,iv) {
    var e1;
    showMsg("key: " + byteArrayToHexString(key));
    showMsg("iv: " + byteArrayToHexString(iv));
    var des = new DES(key,iv);
    var mode = getRadioValue('mode');
    des.mode = (mode == "CBC") ? DesCryptoMode.CBC : DesCryptoMode.ECB;
    var padding = getRadioValue('padding');
    des.padding = (padding == "PKCS7") ? DesPadding.PKCS7 :
        (padding == "Zeroes") ? DesPadding.Zeroes : DesPadding.Spaces ;

    e1 = document.getElementById("plaintext");
    var plaintext = e1.value;
    var ciphertext = des.encrypt(plaintext);
    e1 = document.getElementById("ciphertext");
    e1.value = binStringToHexString(ciphertext);
    enableButtons();
    e1 = document.getElementById("plaintext");
    e1.value = '';
    e1 = document.getElementById("btnEncrypt");
    e1.disabled = true;
  };

  if (key == '' || iv == '') {
    var password, salt, iterations;
    e = document.getElementById("password");
    password = e.value;
    e = document.getElementById("salt");
    salt = e.value;
    e = document.getElementById("iterations");
    iterations = parseInt(e.value);
    getKeyAndIv(password, salt, iterations, doTheWork);
  } else {
    // convert hex string back to byte array
    doTheWork(hexStringToByteArray(key),hexStringToByteArray(iv));
  }
}



function setDefaults() {
  msgDiv = document.getElementById('msgs');
  var e = document.getElementById('plaintext');
  e.value = "Hello. This is a test. of the emergency broadcasting system.";
  e = document.getElementById('password');
  e.value = "Albatros1";
  e = document.getElementById('salt');
  e.value = "saltines";
  e = document.getElementById('ciphertext');
  e.value = "";
  e = document.getElementById('iterations');
  e.value = 1000;
  e = document.getElementById('iv');
  e.value = '';
  e = document.getElementById('key');
  e.value = '';
  enableButtons();
  e = document.getElementById('btnDecrypt');
  e.disabled = true;
}


function reset_click() {
  setDefaults();
  showMsg("reset.", true);
}

function onload() {
  setDefaults();
}


function showMsg(msg, clear) {
  if (clear === null) { clear = false; }
  if (clear) { msgDiv.innerHTML = ''; }
  var h = msgDiv.innerHTML;
  h += msg + "<br/>";
  msgDiv.innerHTML = h;
}



