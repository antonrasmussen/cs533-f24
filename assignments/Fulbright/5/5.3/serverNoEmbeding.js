
var http=require('http');
var fs = require('fs');
var url = require('url');
let express = require('express');
let app = express();

app.get('/', (req, res)=>{
    res.setHeader('Content-Security-Policy', "object-src 'none'");
    index = fs.readFileSync(('index.html'), 'utf8');
    res.send(index);
});
app.listen(4000, (err)=>{
    if(err)
        throw err;
    console.log('listening on port 4000');
});