const express = require('express');
const http = require('http');
const bodyParser = require('body-parser');
const morgan  = require('morgan');
const app = express();
const router = require('./router');
const config = require("./config");
const mongoose = require('mongoose');

app.use(morgan('combined'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true}));
mongoose.connect(config.getDbConnectionString(console.log('connected to database')));

router(app);



const port  = process.env.PORT || 3000;
const server  = http.createServer(app);
server.listen(port);
console.log('server listening on ', port);
