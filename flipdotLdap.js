var ldap = require('ldapjs');
var ssha = require('ssha');
var config = require('./config');

function doSearch(callback) {

  var client = ldap.createClient({
    url: config.ldapUrl
  });

  // authentication
  client.bind(config.login.user, config.login.password, function bindDone(err){
    if(err){
      return callback(err);
    }

    var options = {
      //filter: '()',
      scope: 'sub'
    };

    client.search(config.queryPath, options, function searchDone(err, res){
      if(err){
        return callback(err);
      }

      var entries = [];

      res.on('searchEntry', function(entry) {
        entries.push(entry.object);
      });

      res.on('error', function(err) {
        return callback(err);
      });

      res.on('end', function(result) {
        callback(null, entries)

        client.unbind(function(err) {
          if(err){
            return callback(err);
          }
        })
      });
    })
  })
}

function findByName(name, callback) {
  doSearch(function(err, entries){
    if(err) {
      return callback(err);
    }

    for(var i in entries) {
      var entry = entries[i];
      if(entry[config.propertyNames.name] === name) {
        return callback(null, entry);
      }
    }

    return callback(null, null);
  })
}

function validatePassword(entry, password, callback) {
  var passwordValue = entry[config.propertyNames.password];

  var regex = /\{(.*)\}.*/;
  var match = passwordValue.match(regex);
  if(!match) {
    return callback({err:'invalid password value :' + passwordValue});
  }

  if(match[1] != 'SSHA') {
    return callback({err:'unsupported hash method: '+match[1]});
  }

  var doesMatch = ssha.verify(password, passwordValue);
  callback(null, doesMatch);
}

module.exports = {
  doSearch: doSearch,
  findByName: findByName,
  validatePassword: validatePassword
}
