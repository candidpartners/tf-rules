'use strict';
const _  = require('lodash');
const debug = require('debug')('tfrules/tag-compliance');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const EC2TagCompliance = {};

EC2TagCompliance.docs = {
  description: "Required tagging must exist",
  recommended: false
};

EC2TagCompliance.schema = {
  type : 'array',
  items : {
    anyOf : [
      { type : 'string' },
      { type : 'object',
        properties : {
          name : {
            type : 'string'
          },
          value : {
            type : 'string'
          }
        }        
      }
    ]
  }
};

EC2TagCompliance.paths = {
  awsInstance : 'aws_instance'
};

EC2TagCompliance.validate = function( context ) {
  let result = null;
  let tagSpec = null;
  let reqTags = [];
  let matchErrors = [];
  let message = ''
  debug('Config: %j', context.config)
  for ( let tagSpec of context.config){
    if ( _.isString(tagSpec)){
      reqTags.push(tagSpec)
    } else if ( _.isObject(tagSpec) && ! _.isArray(tagSpec)) {
      if (tagSpec.value) {
        let re = new RegExp(tagSpec.value);
        debug('Match: %j', context.instance.tags[tagSpec.name].match(re))
        if (context.instance.tags[tagSpec.name].match(re)) {
          reqTags.push(tagSpec.name)
        } else {
          matchErrors.push(tagSpec.name)
        }
      } else {
        reqTags.push(tagSpec.name)
      }
    }
    debug('Tag: %j', tagSpec)
  }
  if (matchErrors.length > 0) {
    message = 'Tag format mismatch for: ' + matchErrors.join() + '\n'
  }
  debug('Tag List: %j', reqTags)
  let missingTags = []
  missingTags = _.difference(reqTags, _.keys(context.instance.tags));
  if ( missingTags.length == 0 ) {
    result = { 
      valid : 'success',
    };
  } else {
    message += 'Missing the following tags: ' + missingTags
    result = {
      valid : 'fail',
      message
    };
  }
  return result;
};

module.exports = EC2TagCompliance;

