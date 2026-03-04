const fs = require('fs');

async function everything(){
    fs.readFile('SFULB001@ODU.EDU.txt', 'utf8', (err, data)=>{
        everytingElse(data.split('\r\n'))
    });
    
}
fs.writeFile('Results.md', "| Root Domain | Number of HttpOnly | Number of Secure | Number of SameSite | Number of Lax | Number of Strict | Number of None | Termination Code |\n", (err)=>{
    if(err) throw err;
});
fs.appendFile('Results.md', "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |\n", (err)=>{
    if(err) throw err;
});
async function everytingElse(website){
    var total_cookies=[];
    for(var i=0;i<website.length;i++){
        try{
        const response = await fetch('https://'.concat(website[i]))
        cookies=response.headers.getSetCookie();
            var HttpOnly=0;
            var Secure=0;
            var sameSite=[0,0,0,0];
            total_cookies.push(cookies.length);
            for(var j=0;j<cookies.length;j++){
                cookie=cookies[j].toLowerCase();
                if(cookie.includes('httponly')){
                    HttpOnly++;
                }
                if(cookie.includes('secure')){
                    Secure++;
                }
                if(cookie.includes('samesite')){
                    sameSite[0]++;
                    if(cookie.includes('samesite=lax')){
                        sameSite[1]++;
                    }
                    else if(cookie.includes('samesite=strict')){
                        sameSite[2]++;
                    }
                    else if(cookie.includes('samesite=none')){
                        sameSite[3]++;
                    }
                }
            }
            results = "| ".concat(website[i]," | ",HttpOnly," | ",Secure," | ",sameSite[0]," | ",sameSite[1]," | ",sameSite[2]," | ",sameSite[3]," | ",response.status," |\n")
            fs.appendFile('results.md', results, (err)=>{
                if (err) throw err;
            })
            }
            catch(e){
                console.log(e)
                results = "| ".concat(website[i]," | 0 | 0 | 0 | 0 | 0 | 0 | ",e," |\n")
                fs.appendFile('results.md', results, (err)=>{
                    if (err) throw err;
                })
            }
            
    }
    var mean, min, max, median;
    var total=0;
    min =total_cookies[0];
    max= total_cookies[0];
    var len = total_cookies.length
    for(var j=0;j<len;j++){
        total+=total_cookies[j];
        if(max<total_cookies[j])
            max=total_cookies[j];
        if(min>total_cookies[j])
            min=total_cookies[j]
    }
    mean=total/len;
    if(total_cookies.len%2==0){
        sorted = total_cookies.sort()
        median=(sorted[len/2]+sorted[len/2+1])/2
    }
    else{
        median=total_cookies.sort()[((len/2) | 0)+1]
    }

    var output = "\n\nMin: ".concat(min)
    output=output.concat("\n\nMax: ", max)
    output=output.concat("\n\nMean: ", mean)
    output=output.concat("\n\nMedian: ", median)
    fs.appendFile('Results.md', output, (err)=>{
        if(err) throw err;
    });
}
everything();
