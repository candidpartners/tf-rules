const AWSPromiseMock = require('./aws-promise-mock');

describe('AWSPromiseMock', () => {
    it('Recognizes a service', async () => {
        let AWSMock = new AWSPromiseMock();
        AWSMock.Service('EC2','describeInstances', "Hello World");
        let ec2 = new AWSMock.EC2();

        let result = await ec2.describeInstances().promise();
        expect(result).toBe('Hello World');
    });

    it("Can recognize multiple services", async () => {
        let AWSMock = new AWSPromiseMock();
        AWSMock.Service('EC2','describeInstances', "Hello World");
        AWSMock.Service('EC2','listInstances','My Instances');
        let ec2 = new AWSMock.EC2();

        let result = await ec2.describeInstances().promise();
        expect(result).toBe('Hello World');

        let result2 = await ec2.listInstances().promise();
        expect(result2).toBe("My Instances");
    })
});