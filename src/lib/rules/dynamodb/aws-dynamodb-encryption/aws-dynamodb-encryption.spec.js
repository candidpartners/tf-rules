'use strict';
const AWS = require('aws-stub');
const AWSPromiseMock = require('../../../../aws-promise-mock');
const _ = require('lodash');
const RealAWS = require('aws-sdk');
const rule = require('./aws-dynamodb-encryption');
const co = require('co');

describe('dynamodb-encryption', function () {
    it("should return a valid = 'success'", co.wrap(function* () {
        const instance = {TableName: 'MyDynamoDB', SSEDescription: {status: "ENABLED"}};
        const provider = AWS('DynamoDB', 'MyDynamoDB');
        const context = {config: true, instance, provider};
        const result = yield rule.validate(context);
        expect(result.valid).toBe('success');
    }));
    it("should return a valid = 'fail'", co.wrap(function* () {
        const instance = {TableName: 'MyOtherDynamoDB'};
        const provider = AWS('DynamoDB', 'MyOtherDynamoDB');
        const context = {config: true, instance, provider};
        const result = yield rule.validate(context);
        expect(result.valid).toBe('fail');
    }));

    it("Recognizes a livecheck", async () => {
        let goodTables = {
            TableNames: [
                "GoodTable1",
                "GoodTable2"
            ]
        };
        let goodTable = {
            Table: {
                TableName: "GoodTable3",
                SSEDescription: {
                    Status: "ENABLED"
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
            Table: {
                TableName: "BadTable3"
            }
        };

        let GoodAWSMock = new AWSPromiseMock();
        GoodAWSMock.Service('DynamoDB', 'listTables', goodTables);
        GoodAWSMock.Service('DynamoDB', 'describeTable', goodTable);

        let BadAWSMock = new AWSPromiseMock();
        BadAWSMock.Service('DynamoDB', 'listTables', badTables);
        BadAWSMock.Service('DynamoDB', 'describeTable', badTable);

        let result = await rule.livecheck({config: {}, provider: GoodAWSMock});
        expect(result.valid).toBe("success");

        let failResult = await rule.livecheck({config: {}, provider: BadAWSMock});
        expect(failResult.valid).toBe('fail');
        expect(failResult.message).toBeTruthy();
    });

    it("It can exclude instances", async () => {
        let goodTables = {
            TableNames: [
                "GoodTable1",
                "GoodTable2",
                "BadTable"
            ]
        };
        let goodTable = {
            Table: {
                TableName: "GoodTable3",
                SSEDescription: {
                    Status: "ENABLED"
                }
            }
        };

        let GoodAWSMock = new AWSPromiseMock();
        GoodAWSMock.Service('DynamoDB', 'listTables', goodTables);
        GoodAWSMock.Service('DynamoDB', 'describeTable', goodTable);

        let result = await rule.livecheck({config: {exclude: "BadTable"}, provider: GoodAWSMock});
        expect(result.valid).toBe("success");
    })
});