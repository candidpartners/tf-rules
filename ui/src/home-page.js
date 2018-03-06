import React from 'react';
import {Header} from 'semantic-ui-react';

const HomePage = ({}) => (
    <div style={{padding:'20px'}}>

        <h1>TF Rules {`<Insert Awesome Logo Here>`}</h1>
        <Header as='h2' dividing>
            Introduction
        </Header>
        <Header as='h2' dividing>
            Installation
        </Header>
        <Header as='h2' dividing>
            Usage
        </Header>
    </div>
);

export default HomePage;