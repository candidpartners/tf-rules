'use strict';
const co = require('co');
const debug = require('debug')('tfrules/aws-security-group-allow-inbound');
const _ = require('lodash');
const cidrComparison = require('./modules/cidr-comparison');
const portComparison = require('./modules/port-comparison');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const AWSSecurityGroupAllowInbound = {};

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

AWSSecurityGroupAllowInbound.validate = function *( context ) {
  // debug( '%O', context );
  debug('Config: %j', context.config);
  // debug('Instance: %j', context.instance.ingress)
  let result = null;
  let message = [];
  let groups = {};
  // groups[context.instance.name]= []
  if( context.config ) {
    context.config.port = context.config.port ? context.config.port : '0-65535';
    context.config.cidr = context.config.cidr ? context.config.cidr : '0.0.0.0/0';
    // let currCidr = ip.cidrSubnet(context.config.cidr)
    // debug('Port: %j', context.config.port)
    // debug('CIDR: %j', context.config.cidr)
    _.map(context.instance.ingress, ingress => {
      groups[context.instance.name] = cidrComparison(context.config, ingress, true);
    });

    if ( ! _.isEmpty(groups[context.instance.name]) ){
      debug('Matching Groups: %j', groups);
      result = {
        valid : 'success'
      };
    } else {
      message.push('Security group "' + context.instance.name + '" should have inbound traffic allowed from CIDR Block "' + context.config.cidr + '" on ports "' + context.config.port + '"');

      result = {
        valid : 'fail',
        message
      };
    }
  }
  return yield result;
};

module.exports = AWSSecurityGroupAllowInbound;

