'use strict';
const _  = require('lodash');
const debug = require('debug')('snitch/tag-format');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const EC2TagFormat = {};

EC2TagFormat.uuid = "d2065bd9-4ece-4cb7-a4dc-3ad161415e15";
EC2TagFormat.groupName = "EC2";
EC2TagFormat.tags = [];
EC2TagFormat.config_triggers = ["AWS::EC2::Instance"];
EC2TagFormat.paths = {EC2TagFormat : 'aws_instance'};
EC2TagFormat.docs = {
  description: "EC2 instance tag values match provided format.",
  recommended: false
};
EC2TagFormat.schema = {
  type : 'array',
  items : {
    type : 'object',
    properties : {
      name : {
        type : 'string'
      },
      format : {
        type : 'string'
      }
    }        
  }
};


EC2TagFormat.validate = function( context ) {
  let result = null;
  let tagSpec = null;
  let reqTags = [];
  let matchErrors = [];
  let message = ''

  debug('Config: %j', context.config)

  for ( let tagSpec of context.config){
    if (tagSpec.format) {
      try {
        let re = new RegExp(tagSpec.format);
        debug('Match: %j', re.test(context.instance.tags[tagSpec.name]))
        if ( ! re.test(context.instance.tags[tagSpec.name])) {
          matchErrors.push(tagSpec.name + ' tag does not match provided format of: ' + tagSpec.format)
        }
      } catch(e) {
        matchErrors.push(e)
      }
    }
    debug('Tag: %j', tagSpec)
  }

  if (matchErrors.length == 0) {
    result = {
      'valid' : 'success'
    }
  } else {
    result = {
      valid : 'fail',
      message : matchErrors
    }
  }

  return result;
};

module.exports = EC2TagFormat;

