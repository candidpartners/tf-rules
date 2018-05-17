'use strict';
const AWS = require('aws-stub');
const AWSPromiseMock = require('../../../../aws-promise-mock');
const RealAWS = require('aws-sdk');

const rule = require('./aws-dynamodb-point-in-time-recovery-status');


describe('dynamodb-point-in-time-recovery-status', function () {
    it("should return as enabled", async function () {
        const instance = {TableName: 'MyDynamoDB', PointintimeRecovery: {status: "ENABLED"}};
        const provider = AWS('DynamoDB', 'MyDynamoDB');
        const context = {config: true, instance, provider};
        const result = await rule.validate(context);
        expect(result.valid).toBe('success');
    });
    it("should return a valid = 'fail'", async function() {
        const instance = {TableName: 'MyOtherDynamoDB'};
        const provider = AWS('DynamoDB', 'MyOtherDynamoDB');
        const context = {config: true, instance, provider};
        const result = await rule.validate(context);
        expect(result.valid).toBe('fail');
    });
    it("Recognizes a livecheck", async () => {
        let goodTables = {
            TableNames: [
                "GoodTable1",
                "GoodTable2"
            ]
        };
        let goodTable = {
            ContinuousBackupsDescription: {
                ContinuousBackupsStatus: "ENABLED",
                PointInTimeRecoveryDescription: {
                    PointInTimeRecoveryStatus: "ENABLED"
                }
            }
        };

        let badTables = {
            TableNames: [
                "BadTable1",
                "BadTable2"
            ]
        };
        let badTable = {
            ContinuousBackupsDescription: {
                ContinuousBackupsStatus: "ENABLED",
                PointInTimeRecoveryDescription: {
                    PointInTimeRecoveryStatus: "DISABLED"
                }
            }
        };

        let GoodAWSMock = new AWSPromiseMock();
        GoodAWSMock.Service('DynamoDB', 'listTables', goodTables);
        GoodAWSMock.Service('DynamoDB', 'describeContinuousBackups', goodTable);

        let BadAWSMock = new AWSPromiseMock();
        BadAWSMock.Service('DynamoDB', 'listTables', badTables);
        BadAWSMock.Service('DynamoDB', 'describeContinuousBackups', badTable);

        let result = await rule.livecheck({config: {}, provider: GoodAWSMock});
        expect(result.valid).toBe("success");

        let failResult = await rule.livecheck({config: {}, provider: BadAWSMock});
        expect(failResult.valid).toBe('fail');
        expect(failResult.message).toBeTruthy();
    });

});


