// pbkdf2.js
// ------------------------------------------------------------------
//
// RFC 2898 -compliant key derivation function, implemente din Javascript.
//
//
// Author     : Dino Chiesa
//            : dpchiesa@hotmail.com
// Created    : Thu Apr 21 20:16:47 2011
// on Machine : DINO-PC
// Last-saved : <2011-April-22 11:38:09>
//
// ------------------------------------------------------------------


function say(x){ WScript.Echo(x); }


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
    var m_iterations_in_chunk = 10;

    // Key length, as number of bytes
    var m_key_length;

    // The length (number of bytes) of the output of the pseudo-random function.
    // Since HMAC-SHA1 is the standard, and what is used here, it's 20 bytes.
    var m_hash_length = 20;

    // Used in the HMAC-SHA1 computations
    var m_ipad = new Array(16);
    var m_opad = new Array(16);

    // The function to call with the result
    var m_result_func;

    // The function to call with status after computing every chunk
    var m_status_func;

    var m_hash= "";

    // The workhorse
    var PBKDF2_do_iterations = function (nBytes) {

        // see if we have enough from a previous call.
        if (nBytes * 2 <= leftoverBytes.length ) {
            var r1 = leftoverBytes.substr(0, nBytes * 2);
            leftoverBytes = leftoverBytes.substr(nBytes * 2);
            return r1;
        }

        // Number of hash-sized blocks in the derived key (called 'l' in RFC2898)
        // Start computation with the first block
        var nBlocks = Math.ceil(nBytes/m_hash_length);
        var bytes = "";

        for(var n= 0; n < nBlocks; ) {
            n++;
            var buffer = [0,0,0,0,0];

            for(var m=0; m < m_total_iterations; ) {
                var chunkIterations = m_iterations_in_chunk;
                if (m_total_iterations - m < m_iterations_in_chunk) {
                    chunkIterations = m_total_iterations - m;
                }

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

                // Call the status callback function
                //m_status_func( (m_current_block - 1 + j/m_total_iterations)
                // / m_total_blocks * 100);
            }
            bytes += SHA1.binToHex(buffer);
        }

        m_totalBlocks+= nBlocks;

        // We've computed the final block T_l; we're done.

        //var tmp = binb2hex(buffer);
        //bytes += tmp.substr(0, (length - (total_blocks - 1) * m_hash_length) * 2 );

        var aggregate = leftoverBytes + bytes;
        var result = aggregate.substr(0, nBytes * 2);
        leftoverBytes = aggregate.substr(nBytes * 2);

        // Call the result callback function
        //m_result_func(m_key);

        return result;
    };


    // initialize the PBKDF2 "class"
    PBKDF2 = function(password, salt, iterations) {
        this.__version = "1.0";
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
        deriveBytes : function (length){
            var stringRep = PBKDF2_do_iterations(length);
            //return SHA1.strToBin(stringRep);
            var bytes= [];
            for(var i = 0; i < stringRep.length; i+=2) {
                val = parseInt(stringRep.substr(i,2),16) ;
                bytes.push(val);
            }
            return bytes;
        }
    };

})();



