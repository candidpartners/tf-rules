'use strict';

const ip = require('ip');
const _ = require('lodash');
const debug = require('debug')('tfrules/modules/cidr-comparison');
const portComparison = require('./port-comparison');

// const cidr = {}

let cidr = function (config, instance, allow) {
  let check = null;
  let groups = [];
  let currCidr = ip.cidrSubnet(config.cidr);
  _.map(instance.cidr_blocks, block => {
    let group = {};
    // debug('Block: %j', block)
    let newCidr = ip.cidrSubnet(block);
    if ( allow === false ){
      check = currCidr.contains(newCidr.firstAddress) || currCidr.contains(newCidr.lastAddress) || newCidr.contains(currCidr.firstAddress) || newCidr.contains(currCidr.lastAddress);
    } else if ( allow ) {
      check = newCidr.contains(currCidr.firstAddress) && newCidr.contains(currCidr.lastAddress);
    }
    if ( check ){
      if (config.port) {
        group.ports = portComparison(config, instance, allow);
        if ( ! _.isEmpty(group.ports)){
          group.cidr = block;
          groups.push(group);
        }
      } else {
        group.cidr = block;
        groups.push(group);
      }
    }
  });
  return groups;
};

module.exports = cidr;