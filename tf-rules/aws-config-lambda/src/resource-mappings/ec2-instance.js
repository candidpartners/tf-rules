require('dotenv').config();
const AWS = require('aws-sdk');
const co = require('co');
const _ = require('lodash');
const ec2 = new AWS.EC2();

let EC2 = {};

EC2.AWSConfigResourceType = "AWS::EC2::Instance";
EC2.terraformResourceType = "aws_instance";

EC2.getInstanceAsync = co.wrap(function * ({configurationItem}){
    let id = configurationItem.resourceId;

    // Get EC2 Instance
    let params = {
        InstanceIds: [id],
    };
    let result = yield ec2.describeInstances(params).promise();
    let instance = _.get(result,"Reservations[0].Instances[0]", []);
    if(!instance)
        throw `EC2 ${id} not found!`;

    return instance;
});

EC2.mapToTerraformResource = function(AWS_API_Instance){
    return {
        ami: AWS_API_Instance.ImageId,
        availability_zone: AWS_API_Instance.Placement.AvailabilityZone,
        placement_group: AWS_API_Instance.Placement.GroupName,
        tenancy: AWS_API_Instance.Placement.Tenancy,
        ebs_optimized: AWS_API_Instance.EbsOptimized,
        disable_api_termination: "",
        instance_initiated_shutdown_behavior: "",
        instance_type: AWS_API_Instance.InstanceType,
        key_name: AWS_API_Instance.KeyName,
        monitoring: "",
        security_groups: "",
        vpc_security_group_ids: "",
        subnet_id: "",
        associate_public_ip_address: "",
        private_ip: "",
        source_dest_check: "",
        user_data: "",
        user_data_base64: "",
        iam_instance_profile: "",
        ipv6_address_count: "",
        ipv6_addresses: "",
        tags: "",
        volume_tags: "",
        root_block_device: "",
        ebs_block_device: "",
        ephemeral_block_device: "",
        network_interface: ""
    }
};

EC2.getInstanceAsync({configurationItem: {resourceId: "i-0daad1455453c247e"}})
    .then(console.log)
    .catch(console.error);