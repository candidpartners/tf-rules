// @flow
const {Resource, RuleResult, Context} = require('../../../rule-result');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const S3CloudTrailBucketIsNotPubliclyAccessible = {};

S3CloudTrailBucketIsNotPubliclyAccessible.uuid = "75760d07-6998-4c75-880f-290dc4947e62";
S3CloudTrailBucketIsNotPubliclyAccessible.groupName = "S3";
S3CloudTrailBucketIsNotPubliclyAccessible.tags = [["CIS", "1.1.0", "2.3"]];
S3CloudTrailBucketIsNotPubliclyAccessible.config_triggers = ["AWS::CloudTrail::Trail"];
S3CloudTrailBucketIsNotPubliclyAccessible.paths = {S3CloudTrailBucketIsNotPubliclyAccessible: "aws_s3_bucket"};
S3CloudTrailBucketIsNotPubliclyAccessible.docs = {
    description: 'The CloudTrail Logging S3 bucket is not publicly accessible.',
    recommended: true
};
S3CloudTrailBucketIsNotPubliclyAccessible.schema = {
    type: 'object',
    properties: {
        enabled: {
            type: 'boolean',
            title: "Enabled",
            default: true
        }
    }
};


S3CloudTrailBucketIsNotPubliclyAccessible.livecheck = async function(context /*: Context */) /*: Promise<RuleResult> */ {
    let {config, provider} = context;
    let cloud = new provider.CloudTrail();
    let s3 = new provider.S3();

    let trails = await cloud.describeTrails().promise();
    let buckets = trails.trailList.map(x => x.S3BucketName);

    try {
        let trailBuckets = await Promise.all(buckets.map(x => s3.getBucketPolicy({Bucket: x}).promise()));
        let bucketStatements = trailBuckets.map(x => x.Policy.Statement);
        let isBucketNonCompliant = x => x.Effect === "Allow" && x.Principal === "*";
        let nonCompliantBuckets = bucketStatements.filter(isBucketNonCompliant);

        return new RuleResult({
            valid: (nonCompliantBuckets.length > 0) ? "fail" : "success",
            message: "S3 Cloudtrail bucket should not be publicly accessible",
            resources: bucketStatements.map(x => {
                let isPublic = isBucketNonCompliant(x);

                return new Resource({
                    is_compliant: isPublic ? false : true,
                    resource_id: x.Resource,
                    resource_type: "AWS::S3::Bucket",
                    message: isPublic ? "is publicly accessible." : "is not publicly accessible"
                })
            })
        });

    // Thrown if the CloudTrail S3 bucket is in a different account than Snitch is being run in.
    } catch (err) {
        // if (err.code === 'AccessDenied') {
            return new RuleResult({
                valid: "fail",
                message: "Snitch encountered an error",
                resources: [
                    new Resource({
                        is_compliant: false,
                        resource_id: "AWS Error",
                        resource_type: "AWS::::Account",
                        message: err.message
                    })
                ]
            })
        // }
    }
};

module.exports = S3CloudTrailBucketIsNotPubliclyAccessible;