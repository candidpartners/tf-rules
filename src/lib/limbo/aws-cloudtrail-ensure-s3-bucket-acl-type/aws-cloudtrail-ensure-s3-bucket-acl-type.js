'use strict';
const _ = require('lodash');
const debug = require('debug')('tfrules/tag-format');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const CloudtrailEnsureS3BucketACLType = {};

CloudtrailEnsureS3BucketACLType.uuid = "58b2045a-3313-42db-abea-939af2330d11";
CloudtrailEnsureS3BucketACLType.groupName = "Cloudtrail";

CloudtrailEnsureS3BucketACLType.docs = {
    description: "Ensures the s3 bucket used for Cloudtrail logs has a configured ACL type. Only works for s3 buckets included in the plan.",
    recommended: false
};

CloudtrailEnsureS3BucketACLType.schema = {
    type: 'array',
    items: {
        type: 'string'
    }
};

CloudtrailEnsureS3BucketACLType.paths = {
    CloudtrailLogFileValidation: 'aws_cloudtrail'
};

CloudtrailEnsureS3BucketACLType.validate = function (context) {
    let {config, instance, plan} = context;

    let allowed_ACL_types = config || [];
    let cloudtrail_s3_bucket = instance.s3_bucket_name;
    let plan_s3_buckets = _.get(plan, "aws_s3_bucket", {});
    let cloudtrail_bucket_instance = _.find(plan_s3_buckets, (s3instance, tf_resource_name) => {
        return s3instance.bucket == cloudtrail_s3_bucket
    });

    //No cloudtrail_bucket_instance in the plan file, let tf check succeed. Other rule for live check might fail.
    if (!cloudtrail_bucket_instance)
        return {valid: 'success'};
    else{
        if(allowed_ACL_types.includes(cloudtrail_bucket_instance.acl))
            return {valid:'success'};
        else
            return {
                valid: 'fail',
                message: `The cloudtrail log bucket does not have a acl type of one of the following : ${JSON.stringify(allowed_ACL_types)}`
            }
    }
};

module.exports = CloudtrailEnsureS3BucketACLType;

