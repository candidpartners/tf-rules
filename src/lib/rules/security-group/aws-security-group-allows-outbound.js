'use strict';
const co = require('co')
const debug = require('debug')('snitch/aws-security-group-allow-outbound');
const _ = require('lodash');
const cidrComparison = require('../../modules/cidr-comparison');
const portComparison = require('../../modules/port-comparison');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const AWSSecurityGroupAllowOutbound = {};

AWSSecurityGroupAllowOutbound.uuid = "1c995e85-d35f-4410-8cc6-b7dd2c390802";
AWSSecurityGroupAllowOutbound.groupName = "Security Group";

AWSSecurityGroupAllowOutbound.docs = {
  description: 'Security Group allows outbound traffic through specified ports',
  recommended: true
};

AWSSecurityGroupAllowOutbound.schema = {
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

AWSSecurityGroupAllowOutbound.paths = {
  awsSecurityGroup : 'aws_security_group'
};

AWSSecurityGroupAllowOutbound.validate = function *( context ) {
  // debug( '%O', context );
  debug('Config: %j', context.config)
  // debug('Instance: %j', context.instance.egress)
  let result = null;
  let message = [];
  let groups = {}
  if( context.config ) {
    context.config['port'] = context.config.port ? context.config.port : '0-65535';
    context.config['cidr'] = context.config.cidr ? context.config.cidr : '0.0.0.0/0'
    // debug('Port: %j', context.config.port)
    // debug('CIDR: %j', context.config.cidr)
    _.map(context.instance.egress, egress => {
      groups[context.instance.name] = cidrComparison(context.config, egress, true)
    })

    if ( ! _.isEmpty(groups[context.instance.name]) ){
      debug('Matching Groups: %j', groups)
      result = {
        valid : 'success'
      };
    } else {
      message.push('Security group "' + context.instance.name + '" should have outbound traffic allowed from CIDR Block "' + context.config.cidr + '" on ports "' + context.config.port + '"')

      result = {
        valid : 'fail',
        message
      }
    }
  };
  return result;
};

module.exports = AWSSecurityGroupAllowOutbound;

