// @flow
const Papa = require('papaparse');
const {Resource,RuleResult, Context} = require('../../../rule-result');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const IAMNoRootAccountAccessKeyExists = {};

IAMNoRootAccountAccessKeyExists.uuid = "3fea4347-2101-4e89-a83a-143d9a523bfd";
IAMNoRootAccountAccessKeyExists.groupName = "IAM";
IAMNoRootAccountAccessKeyExists.tags = [["CIS", "1.1.0", "1.12"]];
IAMNoRootAccountAccessKeyExists.config_triggers = ["AWS::IAM::User"];
IAMNoRootAccountAccessKeyExists.paths = {IAMAvoidUseOfRootAccount: "aws_iam_user"};
IAMNoRootAccountAccessKeyExists.docs = {
    description: 'No root account access key exists.',
    recommended: false
};
IAMNoRootAccountAccessKeyExists.schema = {type: 'boolean', default: true};


IAMNoRootAccountAccessKeyExists.livecheck = async function(context /*: Context */) /*: Promise<RuleResult> */{
    const IAM = new context.provider.IAM();
    // let {config, provider} = context;

    // Get credential report
    await IAM.generateCredentialReport().promise();
    let report = await IAM.getCredentialReport().promise();

    let content = report.Content.toString();
    let csv = Papa.parse(content, {header: true});
    let {data} = csv;

    // Get root user
    let rootUser = data.find(x => x.user === `<root_account>`);
    let key1 = rootUser.access_key_1_active == "true" ? true : false;
    let key2 = rootUser.access_key_2_active == "true" ? true : false;

    let isRootKey = (key1 || key2);
    return new RuleResult({
        valid: isRootKey ? "fail" : "success",
        message: "Root account should not have access keys",
        resources: [{
            is_compliant: isRootKey ? false : true,
            resource_id: rootUser.arn,
            resource_type: "AWS::IAM::User",
            message: isRootKey ? "Root account still has access keys enabled." : "The root account does not have access keys"
        }]
    });
};

module.exports = IAMNoRootAccountAccessKeyExists;