var express = require('express');
var app = express();

var config = require('./config');
var flipdotLdap = require('./flipdotLdap');

app.post('/verify', function (req, res) {
  var user = req.query.user || '';
  var password = req.query.password || '';

  if(!user || !password) {
    return res.status(400).send({msg:'must include user and password via query string'}).end();
  }

  flipdotLdap.findByName(user, function(err, entry) {
    if(err) {
      console.err(err);
      return res.status(500).end();
    }

    if(!entry) {
      return res.status(401).end();
    }

    flipdotLdap.validatePassword(entry, password, function(err, passwordCorrect){
      if(err) {
        console.err(err);
        return res.status(500).end();
      }

      if(!passwordCorrect) {
        return res.status(401).end();
      }

      delete entry[config.propertyNames.password];
      res.send(entry).end();
    })
  })
});

var server = app.listen(3000, function () {
  var host = server.address().address;
  var port = server.address().port;

  console.log('REST-LDAP server listening at http://%s:%s', host, port);
});
