import React, {Component} from 'react';
import {Menu} from 'semantic-ui-react';
import {
    BrowserRouter as Router,
    Route,
    Link,
    Switch
} from 'react-router-dom';

import SideMenu from './side-menu';

import HomePage from './home-page';
import RulePage from './rule-page';

import './Main.css';
class App extends Component {

    render() {
        return (
            <div style={{display:"flex"}}>
                <SideMenu style={{width: '25vw'}}/>
                <div style={{width:'75vw'}}>
                    <Switch>
                        <Route exact path={"/"} component={HomePage}/>
                        <Route exact path={"/rules/:ruleName"} component={RulePage}/>
                    </Switch>
                </div>
            </div>
        );
    }
}

export default App;
