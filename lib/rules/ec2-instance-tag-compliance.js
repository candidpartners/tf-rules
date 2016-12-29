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
          format : {
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
  let reqTags = [];
  debug('Config: %j', context.config)
  for ( let tag in context.config){
    if (typeof context.config[tag] === 'string'){
      reqTags.push(context.config[tag])
    } else if (typeof context.config[tag] === 'object' && Array.isArray(context.config[tag]) == false) {
      reqTags.push(context.config[tag].name)
    }
    debug('Tag: %j', context.config[tag])
  }
  debug('Tag List: %j', reqTags)
  let missingTags = []
  missingTags = _.difference(reqTags, _.keys(context.instance.tags));
  if ( missingTags.length == 0 ) {
    result = { 
      valid : 'success',
    };
  } else {
    let message = 'Missing the following tags: ' + missingTags
    result = {
      valid : 'fail',
      message
    };
  }
  return result;
};

module.exports = EC2TagCompliance;

