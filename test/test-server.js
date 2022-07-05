const crypto = require('node:crypto');
const https = require('node:https');
const fs = require('node:fs');
const portfinder = require('portfinder');



let server;
let serverPort;
const pem = fs.readFileSync('test/data/certs/cert.pem');
let requestBody;
let requestDetails;



function startServer() {
    const options = {
      key: pem,
      cert: pem
    };

    server = https.createServer(options, function (req, res) {
      console.log('createServer', options);
      requestBody = Buffer.alloc(0);

      req.on('data', function (chunk) {
        console.log('server data', chunk);
        requestBody = Buffer.concat([requestBody, chunk]);
      });

      req.on('end', function () {
        requestDetails = req;

        if (req.url.indexOf('statusCode=404') !== -1) {
          res.writeHead(404);
          res.end();
        } else {
          res.writeHead(201);
          res.end('ok');
        }
      });
    });

    portfinder.getPort(function (err, port) {
      console.log('portfinder', port);
      if (err) {
        serverPort = 50005;
      } else {
        serverPort = port;
      }

      server.listen(serverPort);
    });

    // return new Promise(function (resolve) {
    //   server.on('listening', resolve);
    // });
  }

  function closeServer() {
    serverPort = null;
    return new Promise(function (resolve) {
      if (!server) {
        resolve();
        return;
      }

      server.on('close', function () {
        server = null;
        resolve();
      });
      server.close();
    });
  }

  startServer()
