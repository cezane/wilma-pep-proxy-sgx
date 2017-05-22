const https = require('https');
var request = https.request({host: 'encrypted.google.com', port: 443, method: 'GET'}, function(response) {response.on('data', function(data) {console.log(data.toString());});});
request.end();
