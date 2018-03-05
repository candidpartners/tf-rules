'use strict';
const co = require('co')
const debug = require('debug')('tfrules/aws-security-group-does-not-allow-inbound');
const _ = require('lodash');
const cidrComparison = require('../modules/cidr-comparison');
const portComparison = require('../modules/port-comparison');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const AWSSecurityGroupDoesNotAllowInbound = {};

AWSSecurityGroupDoesNotAllowInbound.uuid = "67477475-5d35-4444-bcb4-0c9053aa357e";
AWSSecurityGroupDoesNotAllowInbound.groupName = "Security Group";

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
          type: 'integer',
        },
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

AWSSecurityGroupDoesNotAllowInbound.validate = function *( context ) {
  // debug( '%O', context );
  let result = null;
  let message = [];
  let groups = {}
  if( context.config ) {
    // debug('Config: %j', context.config)
    // debug('Instance: %j', context.instance)
    for (let ingress of context.instance.ingress) {
      // debug('Ingress: %j', ingress)
      // debug('Send Groups: %j', groups)
      if (context.config.cidr) {
        groups[context.instance.name] = yield cidrComparison(context.config, ingress, false)
      } else if (context.config.port) {
        groups[context.instance.name] = yield portComparison(context.config, ingress, false)
      }
    }

    debug('Insecure Groups: %j', groups)
    if ( ! _.isEmpty(groups[context.instance.name]) ){
      debug('Insecure Groups: %j', groups)
      _.map(groups[context.instance.name], group => {
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
  debug('Result: %j', result)
  return result;
};

module.exports = AWSSecurityGroupDoesNotAllowInbound;

