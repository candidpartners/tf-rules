const co = require('co');
const Papa = require('papaparse');
const _ = require('lodash');
const {NonCompliantResource, RuleResult} = require('../../../rule-result');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const RuleName = {};

RuleName.uuid = "6151e4fa-3814-462c-a017-1dc89a60ea0b";
RuleName.groupName = "S3";
RuleName.tags = [["Snitch", "1.0", "10"]];
RuleName.config_triggers = ["AWS::S3::Bucket"];
RuleName.paths = {};
RuleName.docs = {
    description: 'All S3 bucket policies only allows uploads if encryption is specified.',
    recommended: false
};

RuleName.schema = {
    type: 'object',
    properties: {
        AllowAES256: {type: "boolean"},
        AllowKMS: {type: "boolean"},
        ExcludeBuckets: {
            type: "array",
            items: {type: "string"}
        }
    }
};


RuleName.livecheck = co.wrap(function* (context) {
    let {config, provider} = context;

    let {AllowAES256} = config;
    let {AllowKMS} = config;
    let ExcludeBuckets = config.ExcludeBuckets || [];

    let s3 = new provider.S3();
    let buckets = yield s3.listBuckets().promise();
    let bucketNames = buckets.Buckets.map(x => x.Name);
    bucketNames = bucketNames.filter(name => ExcludeBuckets.includes(name) === false);

    let IsBucketValid = co.wrap(function* (Bucket) {
        // Get Bucket policy, or error if there isn't one.
        let policyResult = yield s3.getBucketPolicy({Bucket}).promise()
            .then(result => ({Bucket, result}))
            .catch(error => ({Bucket, error: error.code}))

        // If there was an error, fail the bucket
        if (policyResult.error)
            return {
                Bucket,
                valid: false,
                message: policyResult.error
            };

        let policy = JSON.parse(policyResult.result.Policy);
        let StatementArray = policy.Statement;

        function IsValidStatement(Statement){
            if(Statement.Effect !== 'Deny')
                return false;
            if(Statement.Principal !== "*")
                return false;
            if(Statement.Action !== "s3:PutObject")
                return false;
            if(Statement.Resource !== `arn:aws:s3:::${Bucket}/*`)
                return false;

            let encryptionType = _.get(Statement,"Condition.StringNotEquals.s3:x-amz-server-side-encryption","");
            if(AllowAES256 && encryptionType.toLowerCase() === "AES256".toLowerCase())
                return true;
            if(AllowKMS && encryptionType.toLowerCase() === "aws:kms".toLowerCase())
                return true;

            return false;
        }

        let EncryptionStatement = StatementArray.find(IsValidStatement);
        return {
            Bucket,
            valid: (EncryptionStatement) ? true : false,
            message: (EncryptionStatement) ? "Bucket is encrypted" : "Bucket is not encrypted"
        }
    });

    let result = yield Promise.all(bucketNames.map(IsBucketValid));

    let noncompliant_resources = result
        .filter(x => x.valid == false)
        .map(x => ({
        resource_id: x.Bucket,
        resource_type: "AWS::S3::Bucket",
        message: "allows unencrypted uploads."
        }));


    if (noncompliant_resources.length > 0) {
        return new RuleResult({
            valid: "fail",
            message: "Some S3 buckets allow unencrypted uploads",
            noncompliant_resources
        })
    }
    else return new RuleResult({
        valid: "success"
    })
});

module.exports = RuleName;