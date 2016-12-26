'use strict';

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const EBSVolumeEncryption = {};

EBSVolumeEncryption.docs = {
  description: "require EBS volumes have encryption",
  recommended: false
};

EBSVolumeEncryption.liveCheck = true;

EBSVolumeEncryption.schema = {
  anyOf: [
    { type : 'boolean' },
    {
      type: 'object',
      properties : {
        exclude : {
          type : 'array',
          items : {
            type : 'string'
          }
        },
        include : {
          type : 'array',
          items : {
            type : 'string'
          }
        }
      }
    }
  ]
};

EBSVolumeEncryption.paths = {
  ebsVolume : 'aws_ebs_volume'
};

EBSVolumeEncryption.validate = function( context ) {
  let result = null;
  if( context.config == true && context.instance.encrypted == false ) {
    result = {
      valid : 'fail',
      message : 'EBS Volumes must be configured as true',
    };
  } else {
    result = {
      valid : 'success'
    };
  }
  return result;
};

module.exports = EBSVolumeEncryption;

