
var http=require('http');
var fs = require('fs');
var url = require('url');
var cors = require('cors')
var jsonFile = require('./response.json')

let express = require('express');
let app = express();

var corsOptions = {
    origin: '*',
    methods: "GET,HEAD,PUT,PATCH,POST,DELETE",
    preflightContinue: false,
    optionsSuccessStatus: 200 
}

app.use(cors(corsOptions))
app.get('/', (req, res)=>{
    res.json(jsonFile);
});
app.listen(4001, (err)=>{
    if(err)
        throw err;
    console.log('listening on port 4001');
});