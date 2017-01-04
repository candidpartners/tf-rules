'use strict';
const co = require('co')
const debug = require('debug')('tfrules/aws-security-group-allow-inbound');
const _ = require('lodash');
var ip = require('ip')
const inRange = require('in-range');
const util = require('util')

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const AWSSecurityGroupAllowInbound = {};
let matchingGroups = {};

AWSSecurityGroupAllowInbound.docs = {
  description: 'Security Group allows inbound traffic through specified ports',
  recommended: true
};

AWSSecurityGroupAllowInbound.schema = {
  type : 'object',
  properties : {
    cidr : {
      type : 'string', 
      pattern : "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/([0-9]|[1-2][0-9]|3[0-2]))$"
    },
    port : {
      anyOf : [
        { 
          type : 'string',
          pattern : '^([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$'
        },
        { 
          type : 'string',
          pattern : '^([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])[\-]?([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])?$'
        }
      ]
    }
  }
};

AWSSecurityGroupAllowInbound.paths = {
  awsSecurityGroup : 'aws_security_group'
};

let cidrComparison = function (config, instance, name) {
  let currCidr = ip.cidrSubnet(config.cidr)
  _.map(instance.cidr_blocks, block => {
    let matchingGroup = {}
    // debug('Block: %j', block)
    let newCidr = ip.cidrSubnet(block)
    if ( newCidr.contains(currCidr.firstAddress) && newCidr.contains(currCidr.lastAddress) ) {
      matchingGroup['cidr'] = block
      if( config.port ){
        portComparison(config, instance, name, matchingGroup)
      } else {
        matchingGroups[name].push(matchingGroup)
      }
    }
  })
}

let portComparison = function (config, instance, name, matchingGroup){
  if ( !matchingGroup ){
    matchingGroup = {}
  }
  let re = new RegExp(/^([0-9]*)?[\-]?([0-9]+)?/)
  let ports = _.compact(config.port.match(re));
  // debug('Ports: %j', ports)
  if (instance.to_port == 0 && instance.from_port == 0 ){
    matchingGroups[name].push(matchingGroup)
  } else if (_.compact(ports).length > 2) {
    let config_from_port = parseInt(ports[1]);
    let config_to_port = parseInt(ports[2]);
    if ( inRange(config_from_port, instance.to_port, instance.from_port) && inRange(config_to_port, instance.to_port, instance.from_port)) {
      matchingGroup['ports'] = instance.from_port + '-' + instance.to_port;
      matchingGroups[name].push(matchingGroup)
    }
  } else {
    let config_port = parseInt(ports[1])
    if ( inRange(config_port, instance.to_port, instance.from_port)) {
      matchingGroup['ports'] = instance.from_port + '-' + instance.to_port
      matchingGroups[name].push(matchingGroup)
    }
  }
}

AWSSecurityGroupAllowInbound.validate = function *( context ) {
  // debug( '%O', context );
  debug('Config: %j', context.config)
  // debug('Instance: %j', context.instance.ingress)
  let result = null;
  let message = [];
  matchingGroups = {}
  matchingGroups[context.instance.name]= []
  if( context.config ) {
    context.config['port'] = context.config.port ? context.config.port : '0-65535';
    context.config['cidr'] = context.config.cidr ? context.config.cidr : '0.0.0.0/0'
    let currCidr = ip.cidrSubnet(context.config.cidr)
    // debug('Port: %j', context.config.port)
    // debug('CIDR: %j', context.config.cidr)
    _.map(context.instance.ingress, ingress => cidrComparison(context.config, ingress, context.instance.name))

    if ( ! _.isEmpty(matchingGroups[context.instance.name]) ){
      debug('Matching Groups: %j', matchingGroups)
      result = {
        valid : 'success'
      };
    } else {
      message.push('Security group "' + context.instance.name + '" should have inbound traffic allowed from CIDR Block "' + context.config.cidr + '" on ports "' + context.config.port + '"')

      result = {
        valid : 'fail',
        message
      }
    }
  };
  return result;
};

module.exports = AWSSecurityGroupAllowInbound;

