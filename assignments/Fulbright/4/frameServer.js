const { response } = require('express');
const fs = require('fs');
var http = require('http');
let express = require('express');
let app=express()
async function everything(){
    fs.readFile('SFULB001@ODU.EDU.txt', 'utf8', (err, data)=>{
        everytingElse(data.split('\r\n'))
    });
    
}
async function everytingElse(website){
    for(var i=0;i<website.length;i++){
        let site = await website[i]
        //response = await fetch('')
        app.get("/".concat(i), (req, res)=>{
            index = fs.readFileSync(('./framable/'.concat(site,".html")), 'utf8');
            res.send(index);
        });
    }
    
    var server = app.listen(4000, (err)=>{
            if(err)
                throw err;
        });
}

everything();
