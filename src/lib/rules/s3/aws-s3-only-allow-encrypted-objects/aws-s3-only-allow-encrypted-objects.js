// @flow
const _ = require('lodash');
const {Resource, RuleResult, Context} = require('../../../rule-result');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const RuleName = {};

RuleName.uuid = "6151e4fa-3814-462c-a017-1dc89a60ea0b";
RuleName.groupName = "S3";
RuleName.tags = [["Candid", "1.0", "10"]];
RuleName.config_triggers = ["AWS::S3::Bucket"];
RuleName.paths = {};
RuleName.docs = {
    description: 'All S3 bucket policies only allow uploads if encryption is specified.',
    recommended: false
};

RuleName.schema = {
    type: 'object',
    properties: {
        AllowAES256: {type: "boolean", default: true},
        AllowKMS: {type: "boolean", default: true},
        ExcludeBuckets: {
            type: "array",
            items: {type: "string"}
        }
    }
};


RuleName.livecheck = async function (context /*: Context */) /*: Promise<RuleResult> */ {
    let {config, provider} = context;

    let {AllowAES256} = config;
    let {AllowKMS} = config;
    let ExcludeBuckets = config.ExcludeBuckets || [];

    let s3 = new provider.S3();
    let buckets = await s3.listBuckets().promise();
    let bucketNames = buckets.Buckets.map(x => x.Name);
    bucketNames = bucketNames.filter(name => ExcludeBuckets.includes(name) === false);

    let IsBucketValid = async function (Bucket) {
        // Get Bucket policy, or error if there isn't one.
        let policyResult = await s3.getBucketPolicy({Bucket}).promise()
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

        function IsValidStatement(Statement) {
            if (Statement.Effect !== 'Deny')
                return false;
            if (Statement.Principal !== "*")
                return false;
            if (Statement.Action !== "s3:PutObject")
                return false;
            if (Statement.Resource !== `arn:aws:s3:::${Bucket}/*`)
                return false;

            let encryptionType = _.get(Statement, "Condition.StringNotEquals.s3:x-amz-server-side-encryption", "");
            if (AllowAES256 && encryptionType.toLowerCase() === "AES256".toLowerCase())
                return true;
            if (AllowKMS && encryptionType.toLowerCase() === "aws:kms".toLowerCase())
                return true;

            return false;
        }

        let EncryptionStatement = StatementArray.find(IsValidStatement);
        return {
            Bucket,
            valid: (EncryptionStatement) ? true : false,
            message: (EncryptionStatement) ? "Bucket is encrypted" : "Bucket is not encrypted"
        }
    };

    let result = await Promise.all(bucketNames.map(IsBucketValid));

    let resources = result
        .map(x => ({
            is_compliant: x.valid,
            resource_id: x.Bucket,
            resource_type: "AWS::S3::Bucket",
            message: x.valid ? "requires encryption": "allows unencrypted uploads."
        }));

    return new RuleResult({
        valid: resources.find(x => x.is_compliant == false) ? "fail" : "success",
        message: "S3 should not allow encrypted objects",
        resources
    });

};

module.exports = RuleName;