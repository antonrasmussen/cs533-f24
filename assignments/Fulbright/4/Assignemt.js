const fs = require('fs');
var request = require('request');
const { EventEmitter } = require('stream');
EventEmitter.setMaxListeners(100);

async function everything(){
    fs.readFile('SFULB001@ODU.EDU.txt', 'utf8', (err, data)=>{
        everytingElse(data.split('\r\n'))
    });
    
}
fs.writeFile('Results.md', "| Root Domain | Framable | X-Frame-Option |\n", (err)=>{
    if(err) throw err;
});
fs.appendFile('Results.md', "| :--- | :---: | :---: |\n", (err)=>{
    if(err) throw err;
});
async function everytingElse(website){
    var framable = 0;
    var nonframable=0;
    for(var i=0;i<website.length;i++){
        var site = await 'https://'.concat(website[i])
        request(site, async function(err, response){
            if(!err&&response.statusCode==200){
                var headers = response.headers;
                var xFrameOptions = headers['x-frame-options']||'';
                xFrameOptions=xFrameOptions.toLowerCase();
                if(xFrameOptions==='sameorigin'||xFrameOptions==='deny'){
                    nonframable+=1
                    await fs.appendFile('Results.md', " | False | ".concat(xFrameOptions, " |\n"), (err)=>{
                        if(err) throw err;
                    });
                }
                else{
                    await fs.appendFile('Results.md', " | True | ".concat(xFrameOptions, " |\n"), (err)=>{
                        if(err) throw err;
                    });
                    framable+=1
                }
            }
            else{
                await fs.appendFile('Results.md', " | Failed to aquire | Failed to aquire |\n", (err)=>{
                    if(err) throw err;
                });
                nonframable+=1
            }
        })
            
    }
    setTimeout(function(){

        fs.appendFile('Results.md','\n\n Number Framable: '.concat(framable), (err)=>{
            if(err) throw err;
        });
        
        fs.appendFile('Results.md','\n\n Number Not Framable: '.concat(nonframable), (err)=>{
            if(err) throw err;
        });
    }, 30000)
}
everything();
