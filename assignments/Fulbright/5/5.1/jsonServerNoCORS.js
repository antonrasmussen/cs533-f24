
var http=require('http');
var fs = require('fs');
var url = require('url');
var jsonFile = require('./response.json')

let express = require('express');
let app = express();

app.get('/', (req, res)=>{
    res.json(jsonFile);
});
app.listen(4001, (err)=>{
    if(err)
        throw err;
    console.log('listening on port 4001');
});