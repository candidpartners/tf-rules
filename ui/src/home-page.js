import React from 'react';
import {Header, Button} from 'semantic-ui-react';

let downloadTxtFile = () => {
    var element = document.createElement('a');
    element.setAttribute('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent(
`provider :
  region                    : us-west-2
rules :
- aws-rds-encryption-key-exists : true`
    ));
    element.setAttribute('download', "terraform.tfrules");

    element.style.display = 'none';
    document.body.appendChild(element);

    element.click();

    document.body.removeChild(element);
}

const HomePage = ({}) => (
    <div style={{padding: '20px', height: "100vh", right:"0px", overflowY: "auto"}}>
        <h1>TF Rules</h1>
        TF-Rules is a library to ensure your organization's infrastructure conforms to your standards.

        <Header as='h2' dividing>
            Features
        </Header>
        <h4>Terraform Standards in CI/CD Pipelines</h4>
        <ul>
            <li>TF-Rules can read in a Terraform Plan output, making sure resources are only provisioned if they conform
                to your standards.
            </li>
        </ul>

        <h4>Livecheck Standards Anywhere</h4>
        <ul>
            <li>TF-Rules can perform livechecks to make sure provisioned infrastructure is up to date.</li>
        </ul>

        <h4>One Config File</h4>
        <ul>
            <li>Terraform and Livechecks are driven from the same config file, so you can be sure all your resources are
                held to the same standards.
            </li>
        </ul>
        <Header as='h2' dividing>
            Installation and Usage
        </Header>

        <h4>Dependencies</h4>
        <ul>
            <li>NodeJS 6.10+</li>
        </ul>

        <h4>Installation</h4>
        <pre>npm i -g @candidpartners/tf-rules</pre>

        <h4>Create a terraform.tfrules file in your directory</h4>

        <Button primary onClick={() => downloadTxtFile()}>Download</Button>

        <h4>Usage</h4>
        Pipe Terraform Output
        <pre>terraform plan | tfrules</pre>

        Use the Terraform -no-color option for better formatted terraform output
        <pre>terraform plan -no-color | tfrules</pre>

        Or pipe the terraform output to a file, and use the file as input.
        <pre>
            terraform plan -no-color > plan.txt
            <br/>
            tfrules --plan plan.txt
        </pre>

        To use the livechecks
        <pre>
            tfrules --livecheck
        </pre>
    </div>
);

export default HomePage;