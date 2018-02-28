const Plan      = require('tf-parse').Plan;
const path = require('path');
const fs = require('fs');

let terraformOutput = fs.readFileSync(__dirname + '/aws-iam-user-policy-does-not-exist-terraform-output.txt').toString();
let goodOutput = fs.readFileSync(__dirname + "/../aws-iam-account-password-policy/aws-iam-account-password-policy-sample.txt").toString();

let plan = new Plan();

describe("tf-parse recognizes resources", () => {
    test("tf-parse can recognize iam_user_policy", () => {
        let user_policy_parse = plan.parse(terraformOutput);
        expect(terraformOutput.includes("aws_iam_user_policy_attachment")).toBeTruthy();
        expect(user_policy_parse.add).not.toEqual({})
    });

    test("tf-parse can recognize aws_iam_account_password_policy", () => {
        let iam_account_password_policy_parse = plan.parse(goodOutput);
        expect(iam_account_password_policy_parse.add).toHaveProperty("aws_iam_account_password_policy");
    });
});




