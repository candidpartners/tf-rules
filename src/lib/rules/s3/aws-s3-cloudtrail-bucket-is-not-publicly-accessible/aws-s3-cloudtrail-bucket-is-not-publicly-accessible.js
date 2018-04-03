const co = require('co');
const Papa = require('papaparse');
const {NonCompliantResource, RuleResult} = require('../../../rule-result');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const S3CloudTrailBucketIsNotPubliclyAccessible = {};

S3CloudTrailBucketIsNotPubliclyAccessible.uuid = "75760d07-6998-4c75-880f-290dc4947e62";
S3CloudTrailBucketIsNotPubliclyAccessible.groupName = "S3";
S3CloudTrailBucketIsNotPubliclyAccessible.tags = ["CIS | 1.1.0 | 2.3"];
S3CloudTrailBucketIsNotPubliclyAccessible.config_triggers = ["AWS::CloudTrail::Trail"];
S3CloudTrailBucketIsNotPubliclyAccessible.paths = {S3CloudTrailBucketIsNotPubliclyAccessible: "aws_s3_bucket"};
S3CloudTrailBucketIsNotPubliclyAccessible.docs = {
    description: 'The CloudTrail Logging S3 bucket is not publicly accessible.',
    recommended: true
};
S3CloudTrailBucketIsNotPubliclyAccessible.schema = {type: 'boolean'};


S3CloudTrailBucketIsNotPubliclyAccessible.livecheck = co.wrap(function* (context) {
    let {config, provider} = context;
    let cloud = new provider.CloudTrail();
    let s3 = new provider.S3();

    let trails = yield cloud.describeTrails().promise();
    let buckets = trails.trailList.map(x => x.S3BucketName);

    try {
        let trailBuckets = yield buckets.map(x => s3.getBucketPolicy({Bucket: x}).promise());
        let bucketStatements = trailBuckets.map(x => x.Policy.Statement);
        let nonCompliantBuckets = bucketStatements.filter(x => x.Effect === "Allow" && x.Principal === "*");

        if (nonCompliantBuckets.length > 0) {
            return new RuleResult({
                valid: "fail",
                message: "One or more CloudTrail S3 buckets is publicly accessible.",
                noncompliant_resources: nonCompliantBuckets.map(x => new NonCompliantResource({
                    resource_id: x.Resource,
                    resource_type: "AWS::S3::Bucket",
                    message: "is publicly accessible."
                }))
            })
        }
        else return new RuleResult({
            valid: "success"
        })

    // Thrown if the CloudTrail S3 bucket is in a different account than Snitch is being run in.
    } catch (err) {
        if (err.code === 'AccessDenied') {
            return new RuleResult({
                valid: "fail",
                message: "Snitch does not have access to the CloudTrail S3 bucket from this account.",
                noncompliant_resources: [
                    new NonCompliantResource({
                        resource_id: "Permission Error",
                        resource_type: "AWS::::Account",
                        message: "Snitch does not have access to the CloudTail S3 bucket from this account."
                    })
                ]
            })
        }
    }
});

module.exports = S3CloudTrailBucketIsNotPubliclyAccessible;