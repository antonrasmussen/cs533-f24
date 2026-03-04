
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
    optionsSuccessStatus: 200,
    'Access-Control-Expose-Headers': '*'
}

app.use(cors(corsOptions))
app.get('/', (req, res)=>{
    res.set("X-CS533f24-All-Good-Things", 'Good')
    res.set("X-CS533f24-Aviators", 'Better')
    res.set("X-CS533f24-Williams", 'Great')
    res.set("X-CS533f24-Loki", 'Best')
    res.json(jsonFile);
});
app.listen(4001, (err)=>{
    if(err)
        throw err;
    console.log('listening on port 4001');
});