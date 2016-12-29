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
  let tag = null;
  let reqTags = [];
  let matchErrors = [];
  debug('Config: %j', context.config)
  for ( let tagId in context.config){
    tag = context.config[tagId]
    if (typeof tag === 'string'){
      reqTags.push(tag)
    } else if (typeof tag === 'object' && Array.isArray(tag) == false) {
      if (tag.value) {
        let re = new RegExp(tag.value);
        debug('Match: %j', context.instance.tags[tag.name].match(re))
        if (context.instance.tags[tag.name].match(re)) {
          reqTags.push(tag.name)
        } else {
          matchErrors.push(tag.name)
        }
      } else {
        reqTags.push(tag.name)
      }
    }
    debug('Tag: %j', tag)
  }
  if (matchErrors.length > 0) {
    result = {
      valid : 'fail',
      message : 'Tag format mismatch for: ' + matchErrors.join()
    };
    return result
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

