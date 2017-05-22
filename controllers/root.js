//import SecureWorker from 'secureworker';
var config = require('./../config.js'),
    proxy = require('./../lib/HTTPClient.js'),
    IDM = require('./../lib/idm.js').IDM,
    AZF = require('./../lib/azf.js').AZF,
    zmq = require('zeromq');
//const https = require('https');
//const request = require('request');
var log = require('./../lib/logger').logger.getLogger("Root"); 

var attestSocket = zmq.socket('req');
var sharedKey;

const libcurl = require('node-libcurl').Curl;
var curl;
const fs = require('fs');
const crypto = require('crypto');
const aesCmac = require('node-aes-cmac').aesCmac;
const format = require('sprintf');
var EC = require("elliptic").ec;
var ec = new EC("p256");

const X_LENGTH = 32;
const Y_LENGTH = 64;
const MSG0 = 0;
const MSG1 = 1;
const MSG2 = 2;
const MSG3 = 3;
const MSG4 = 4;
const MSG_SUCCESS = 5;

//TODO CHECK IF ATTESTATION PROCESS WILL BE DONE...

var Root = (function() {

    //{token: {user_info: {}, date: Date, verb1: [res1, res2, ..], verb2: [res3, res4, ...]}}
    var tokens_cache = {};

    var pep = function(req, res) {
    	
    	var auth_token = req.headers['x-auth-token'];
        
        log.info('Token --> ', auth_token);

        if (auth_token === undefined && req.headers['authorization'] !== undefined) {
            var header_auth = req.headers['authorization'].split(' ')[1];
            auth_token = new Buffer(header_auth, 'base64').toString();
        }

    	if (auth_token === undefined) {
            log.error('Auth-token not found in request header');
            var auth_header = 'IDM uri = ' + config.account_host;
            res.set('WWW-Authenticate', auth_header);
            res.status(401).send('Auth-token not found in request header');
    	} else {

            if (config.magic_key && config.magic_key === auth_token) {
                var options = {
                    host: config.app_host,
                    port: config.app_port,
                    path: req.url,
                    method: req.method,
                    headers: proxy.getClientIp(req, req.headers)
               };
                log.info(options);
 		log.info(req.body);
		log.info(res);
                proxy.sendData('http', options, req.body, res);
                return;

            }
            IDM.check_token(auth_token, function (user_info) {

                if (config.azf.enabled) {
                    
                    AZF.check_permissions(auth_token, user_info, req, function () {
                      log.info('User roles --> ', user_info.roles);

                      if (config.sgx_attest.enabled) {
                         var role = '';
                         var attested = false;
                         for(var i = 0; i < user_info.roles.length; ++i){
                            //log.info('\n---- ROLE: ', user_info.roles[i].name);
                            role = user_info.roles[i].name;
                            if (role.toUpperCase() === 'ATTESTED') {
                               attested = true;
                            }
                         }

                         if (attested) {
                            log.info('Attestation Process starting...');
                            var pepECDH = crypto.createECDH('prime256v1');
                            pepECDH.generateKeys();
                          
                            attestSocket.connect('tcp://10.30.0.21:8888'); //TODO
                            startAttestation(pepECDH);

                            attestSocket.on('message', function(msg){
                               var msgJSON = JSON.parse(msg);                                 
                               if (msgJSON.message_type == MSG1) {
                                  console.log('\n*********** Processing MSG1 ************\n');
                                  processMsg1(Buffer.from(msgJSON.payload, 'base64'), pepECDH);
                               } else if (msgJSON.message_type == MSG3) {
                                         buff = Buffer.from(msgJSON.payload, 'base64');
                                         console.log('\n*********** Processing MSG3 ************\n');
                                         processMsg3(Buffer.from(msgJSON.payload, 'base64'), pepECDH);
                               } else if (msgJSON.message_type == MSG_SUCCESS) {
                                         console.log('Remote attestation process completed!');
                                         redir_request(req, res, user_info); 
                               } else {
                                         console.log('Attestation process failed!');
                               }
                            });                         
                           
                         } else {
                             redir_request(req, res, user_info);  
                         }
                      } else {
                          redir_request(req, res, user_info);
                      }
                   }, function (status, e) {

                        if (status === 401) {
                            log.error('User access-token not authorized: ', e);
                            res.status(401).send('User token not authorized');
                        } else if (status === 404) {
                            log.error('Domain not found: ', e);
                            res.status(404).send(e);
                        } else {
                            log.error('Error in AZF communication ', e);
                            res.status(503).send('Error in AZF communication');
                        }

                    }, tokens_cache);
                } else {	    
                    log.info(user_info);
                    redir_request(req, res, user_info);
                }

    	    }, function (status, e) {
        	if (status === 404) {
                    log.error('User access-token not authorized');
                    res.status(401).send('User token not authorized');
                } else {
                    log.error('Error in IDM communication ', e);
                    res.status(503).send('Error in IDM communication');
                }
    	    }, tokens_cache);
    	};	
    };

    var swap = function(l_index, h_index, array) {
        var aux;
        while (l_index < h_index) {
              aux = array[l_index];
              array[l_index] = array[h_index];
              array[h_index] = aux;
              l_index++;
              h_index--;
        }
    }

    var changeKeyEndianess = function(key) {
        swap(0, X_LENGTH-1, key);
        swap(X_LENGTH, Y_LENGTH-1, key);   
    }

    var reqToAS = function(asEndpoint, reqMethod, headers, data) {
        curl = new libcurl();
        var options = {
            url: config.sgx_attest.as_url,
            port: config.sgx_attest.as_port,
            endpoint: asEndpoint,
            method: reqMethod,           
            key: config.sgx_attest.client_key,
            cert: config.sgx_attest.client_cert,
            headers: headers,
            data: data
        };

        curl.setOpt('URL', options.url+ ':'+options.port+options.endpoint);

        if (options.headers.length > 0) curl.setOpt('HTTPHEADER', options.headers);
        curl.setOpt('SSLCERT', options.cert);
        curl.setOpt('SSLKEY', options.key);
        if (options.data.length > 0) curl.setOpt('POSTFIELDS', options.data);     
 
/*        request.post(options, function (error, response, body) {
           console.log('error:', error); // Print the error if one occurred 
           console.log('statusCode:', response && response.statusCode); // Print the response status code if a response was received 
           console.log('body:', body); // Print the HTML for the Google homepage. 
        });*/
/*        var asReq = https.request(options, function(asRes) {
            console.log('-------------------reeeeessssssssss: ');//.statusCode);
            asRes.on('data', function(d) {
	        console.log("AAAAAAAAAAAAAAIAIAIAIAIAIAIAI");
                console.log(d);
          });
        });
        asReq.on('error', (e) => {
            console.error(e);
        });
        asReq.end();*/
    }

    var generateCMAC = function(key, data) {
        var options = {returnAsBuffer: true};
        return aesCmac(key, data, options);
    }

    var deriveKey = function(sharedKey, label) {
        swap(0, sharedKey.length-1, sharedKey);
        var key0s = Buffer.from('00000000000000000000000000000000', 'hex');

        var cmacKey0s = generateCMAC(key0s, Buffer.from(sharedKey));
        
        var auxInfo = Buffer.concat([Buffer.from('01', 'hex'), Buffer.from(label), Buffer.from('008000', 'hex')]);
        var derivedKey = generateCMAC(cmacKey0s, auxInfo);
        return derivedKey;
    }

    var startAttestation = function(pepECDH) {
        var pepPublicKey = pepECDH.getPublicKey().slice(1); //removing the unecessary first position of the public key (04 value)      
        changeKeyEndianess(pepPublicKey);
        msg0JSON = JSON.stringify({"message_type": MSG0, "payload": pepPublicKey.toString('base64')});            
        attestSocket.send(msg0JSON);        
    };

    var processMsg1 = function(msg1, pepECDH) {       
        var pepPublicKeyLE = pepECDH.getPublicKey().slice(1); 
        changeKeyEndianess(pepPublicKeyLE);
        //Gets context, gid and consumer's public key
        var context = msg1.slice(68, 72);
        var gid = msg1.slice(64, 68);
        swap(0, gid.length-1, gid);
        var consumerPublicKeyLE = msg1.slice(0, 64);      
        var consumerKey = Buffer.from(consumerPublicKeyLE);

        //Changes the endianess of the consumer's public key
        changeKeyEndianess(consumerKey);             
        consumerKey = [0x04, ...consumerKey];//key_begin.concat(consumerKey);

        //Gets the shared key from consumer's public key
        sharedKey = pepECDH.computeSecret(new Buffer(consumerKey));

        //Derives the SMK and SK keys
        var derivedKeySMK = deriveKey(sharedKey, 'SMK');
        var symmetricKey = deriveKey(sharedKey, 'SK');

        //SPID, quote type and kdfID
        var spid = Buffer.from('cb831ce194a3733369575ae6e6e9dbee', 'hex');
        var quoteType = Buffer.from('0000', 'hex');     
        var kdfID = Buffer.from('0100', 'hex');      

        //Concatenates the server and consumer keys
        concatenatedPublicKeys = Buffer.concat([pepPublicKeyLE, consumerPublicKeyLE]);

        //Signs the concatenated keys
        var privateKey = pepECDH.getPrivateKey();
        var shaMsg = crypto.createHash("sha256").update(concatenatedPublicKeys).digest();
	var publicKeysSign = ec.sign(shaMsg, privateKey, {canonical: true});

        var r = publicKeysSign.r.toBuffer('le', 32);
        var s = publicKeysSign.s.toBuffer('le', 32); 
        var publicKeysSignLE = Buffer.concat([r, s]);

        var bundle = Buffer.concat([pepPublicKeyLE, spid, quoteType, kdfID, publicKeysSignLE]); 
  
        //Generates CMAC for bundle
        var bundleCMAC = generateCMAC(derivedKeySMK, bundle);

        //Gets the revoked list from IAS
        var asEndpoint = '/attestation/sgx/v1/sigrl/';
        var sig = {};
        reqToAS(asEndpoint+gid.toString('hex'), 'POST', '', ''); //{'content-length': '0', 'Transfer-encoding': 'chunked'});

       	curl.on( 'end', function( statuscode, body, headers) {
            var sigReLSize = new Buffer(format.sprintf("%08x", body.length), 'hex');
            var msg2 = Buffer.concat([bundle, Buffer.from(bundleCMAC), sigReLSize, Buffer.from(body), context]);
            this.close();
            var msg2JSON = JSON.stringify({"message_type": MSG2, "payload": msg2.toString('base64')});
            attestSocket.send(msg2JSON);    
        });

        curl.on( 'error', curl.close.bind( curl ) );
        curl.perform();
       
//        c = cmac.CMAC(algorithms.AES(derived_key_smk), backend=default_backend())	
        //publicKeysSign = sign.sign(pepPrivateKeyPEM);
        //signedPublicKeys = ecdsa.sign(sign, pepPrivateKey);
    }

    var processMsg3 = function(msg3, pepECDH) {
        var mac = Buffer.from(msg3.slice(0, 16)); 
        var consumerPublicKeyLE = Buffer.from(msg3.slice(16, 80));
        var psSecProp = Buffer.from(msg3.slice(80, 336)); 
        var quote = Buffer.from(msg3.slice(336, msg3.length - 4));
        var context = Buffer.from(msg3.slice(msg3.length - 4, msg3.length));

        var aepDict = {"isvEnclaveQuote": quote.toString('base64')};
        var headers = {'Content-Type': 'application/json'};

        var asEndpoint = '/attestation/sgx/v1/report';
        reqToAS(asEndpoint, 'POST', headers, JSON.stringify(aepDict));

        curl.on( 'end', function(statuscode, body, headers) {
            var res = JSON.parse(body); console.log('------------ RES: ', res);
            console.log('\n Status code -- ', statuscode, '\nTOTAL TIME ', this.getInfo( 'total_time' ));
            if (res.isvEnclaveQuoteStatus.valueOf() == 'OK') {
                console.log('\n*** Successfully verified QUOTE with IAS. ***');
                var msg4 = Buffer.concat([Buffer.from('01', 'hex'), context]);
                this.close();            
                var msg4JSON = JSON.stringify({'message_type': MSG4, 'payload': msg4.toString('base64')});
                attestSocket.send(msg4JSON);
            } else {
                   console.log('There was something wrong while processing the MSG3.');
            }
        });

        curl.on( 'error', curl.close.bind( curl ) );
        curl.perform();

    }

    var public = function(req, res) {
        redir_request(req, res);
    };

    var redir_request = function (req, res, user_info) {

        if (user_info) {

            log.info('Access-token OK. Redirecting to app...');

            if (config.tokens_engine === 'keystone') {
                req.headers['X-Nick-Name'] = user_info.token.user.id;
                req.headers['X-Display-Name'] = user_info.token.user.id;
                req.headers['X-Roles'] = user_info.token.roles;
                req.headers['X-Organizations'] = user_info.token.project;
            } else {
                req.headers['X-Nick-Name'] = user_info.id;
                req.headers['X-Display-Name'] = user_info.displayName;
                req.headers['X-Roles'] = JSON.stringify(user_info.roles);
                req.headers['X-Organizations'] = JSON.stringify(user_info.organizations);
                if (sharedKey) req.headers['Shared-Key'] = sharedKey.toString('base64');
            }
        } else {
            log.info('Public path. Redirecting to app...');
        }

        var protocol = config.app_ssl ? 'https' : 'http';
        
	var options = {
            host: config.app_host,
            port: config.app_port,
            path: req.url,
            method: req.method,
            headers: proxy.getClientIp(req, req.headers)//,
//            body: sharedKey ? sharedKey : ''
        };
	log.info('\n================== BODY: \n==========', req.body, '\n');
	//log.info(req.body.toString());
        proxy.sendData(protocol, options, req.body, res);
        //, function(status_code, data, headers) {log.info("Status: " + status_code.toString()); log.info("headers: " + headers.toString()); log.info("Data: " + data.toString()); }, function(status_code, data) {log.info("Status: " + status_code.toString()); log.info("Data: " + data.toString());});
    };

    return {
        pep: pep,
        public: public
    }
})();

exports.Root = Root;
