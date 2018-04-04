import React from 'react';
import ReactDOM from 'react-dom';
import './index.css';
import App from './Main';
import registerServiceWorker from './registerServiceWorker';
import {BrowserRouter} from 'react-router-dom';

const AppWrapper = (props) => (
    <BrowserRouter basename={"/snitch"}>
        <App/>
    </BrowserRouter>
);

ReactDOM.render(<AppWrapper />, document.getElementById('root'));
registerServiceWorker();
