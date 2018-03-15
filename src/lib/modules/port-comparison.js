'use strict';
const _ = require('lodash');
const debug = require('debug')('snitch/modules/port-comparison');
const inRange = require('in-range');

let port = function (config, instance, allow){
  let ports = null;
  let port = null;
  let check = null;
  let group = {}
  let re = new RegExp(/^([0-9]*)?[\-]?([0-9]+)?/)
  if ( _.isString(config.port)) {
    ports = _.compact(config.port.match(re));
  } else {
    port = config.port
  }
  // debug('Ports: %j', ports)
  if (instance.to_port == 0 && instance.from_port == 0 ){
    group['ports'] = instance.from_port + '-' + instance.to_port;
  } else if ( ports && ports.length > 2)  {
    let config_from_port = parseInt(ports[1]);
    let config_to_port = parseInt(ports[2]);
    if ( allow ) {
      check = inRange(config_from_port, instance.to_port, instance.from_port) && inRange(config_to_port, instance.to_port, instance.from_port);
    } else {
      check = inRange(instance.to_port, config_from_port, config_to_port) || inRange(instance.from_port, config_from_port, config_to_port) || inRange(config_from_port, instance.to_port, instance.from_port) || inRange(config_to_port, instance.to_port, instance.from_port);
    }
    if ( check ) {
      group['ports'] = instance.from_port + '-' + instance.to_port;
    }
  } else {
    let config_port = port ? port : parseInt(ports[1]);
    if ( inRange(config_port, instance.to_port, instance.from_port)) {
      group['ports'] = instance.from_port + '-' + instance.to_port
    }
  }
  debug('Return Group: %j', group)
  // console.log('Return Group: ' + group)
  return group
}

module.exports = port