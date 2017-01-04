'use strict';
const co = require('co')
const debug = require('debug')('tfrules/aws-security-group-does-not-allow-inbound');
const _ = require('lodash');
var ip = require('ip')
const inRange = require('in-range');
const util = require('util')

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const AWSSecurityGroupDoesNotAllowInbound = {};
let insecureGroups = {};

AWSSecurityGroupDoesNotAllowInbound.docs = {
  description: 'Security Group does not allow specified inbound traffic',
  recommended: true
};

AWSSecurityGroupDoesNotAllowInbound.schema = {
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

AWSSecurityGroupDoesNotAllowInbound.paths = {
  awsSecurityGroup : 'aws_security_group'
};

let cidrComparison = function (config, instance, name) {
  let currCidr = ip.cidrSubnet(config.cidr)
  _.map(instance.cidr_blocks, block => {
    let insecureGroup = {}
    // debug('Block: %j', block)
    let newCidr = ip.cidrSubnet(block)
    if ( currCidr.contains(newCidr.firstAddress) || currCidr.contains(newCidr.lastAddress) || newCidr.contains(currCidr.firstAddress) || newCidr.contains(currCidr.lastAddress) ){
      insecureGroup['cidr'] = block
      if( config.port ){
        portComparison(config, instance, name, insecureGroup)
      } else {
        insecureGroups[name].push(insecureGroup)
      }
    }
  })
}

let portComparison = function (config, instance, name, insecureGroup){
  if ( !insecureGroup ){
    insecureGroup = {}
  }
  let re = new RegExp(/^([0-9]*)?[\-]?([0-9]+)?/)
  let ports = _.compact(config.port.match(re));
  // debug('Ports: %j', ports)
  if (instance.to_port == 0 && instance.from_port == 0 ){
    insecureGroup['ports'] = instance.from_port + '-' + instance.to_port;
    insecureGroups[name].push(insecureGroup);
  } else if (_.compact(ports).length > 2) {
    let config_from_port = parseInt(ports[1]);
    let config_to_port = parseInt(ports[2]);
    if ( inRange(instance.to_port, config_from_port, config_to_port) || inRange(instance.from_port, config_from_port, config_to_port) || inRange(config_from_port, instance.to_port, instance.from_port) || inRange(config_to_port, instance.to_port, instance.from_port)) {
      insecureGroup['ports'] = instance.from_port + '-' + instance.to_port;
      insecureGroups[name].push(insecureGroup)
    }
  } else {
    let config_port = parseInt(ports[1])
    if ( inRange(config_port, instance.to_port, instance.from_port)) {
      insecureGroup['ports'] = instance.from_port + '-' + instance.to_port
      insecureGroups[name].push(insecureGroup)
    }
  }
}

AWSSecurityGroupDoesNotAllowInbound.validate = function *( context ) {
  // debug( '%O', context );
  let result = null;
  let message = [];
  insecureGroups = {}
  insecureGroups[context.instance.name]= []
  if( context.config ) {
    // debug('Config: %j', context.config)
    // debug('Instance: %j', context.instance)
    for (let ingress of context.instance.ingress) {
      // debug('Ingress: %j', ingress)
      if (context.config.cidr) {
        cidrComparison(context.config, ingress, context.instance.name)
      } else if (context.config.port) {
        portComparison(context.config, ingress, context.instance.name)
      }
    }

    if ( ! _.isEmpty(insecureGroups[context.instance.name]) ){
      // debug('Insecure Groups: %j', insecureGroups)
      _.map(insecureGroups[context.instance.name], group => {
        if ( group.cidr && ! group.ports ) {
          message.push('CIDR Block ' + group.cidr + ' in security group ' + context.instance.name + ' should not be open to inbound traffic from ips: ' + context.config.cidr)
        } else if ( group.ports && ! group.cidr ) {
          message.push('Security group ' + context.instance.name + ' should not be taking traffic on ports: ' + context.config.port)
        } else if ( group.cidr && group.ports ) {
          message.push('CIDR Block ' + group.cidr + ' in security group ' + context.instance.name + ' should not be taking inbound traffic on ports: ' + context.config.port + ' from ips: ' + context.config.cidr)
        }
      })
      result = {
        valid : 'fail',
        message
      }
    } else {
      result = {
        valid : 'success'
      };
    }
  };
  return result;
};

module.exports = AWSSecurityGroupDoesNotAllowInbound;

