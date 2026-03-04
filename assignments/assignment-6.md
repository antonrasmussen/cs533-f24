## Assignment 6, CS CS 433/533 Web Security, Fall 2024

Due: 2024-12-02

Points available: 15

For this assignment, you will fingerprint various browsers on your local network.  

Relevant resources:

* [md5](https://www.npmjs.com/package/md5)
* [req.get](http://expressjs.com/en/api.html#req.get)
* [echo service](http://scooterlabs.com/echo) 
* [httpbing.org](https://httpbin.org/headers)

### Fingerprint at least six different clients 

Write server side code for your Express server that fingerprints browsers (as per week 7's lecture).  The server should write these fingerprints out to a server-side log and recognize the client when it visits again.  For different clients, use different browsers (Firefox, Chrome, Opera, curl, Safari, etc.) as well as different devices on your local network (phones, tablets, etc.).  

Use at least four different HTTP request headers to form your browser fingerprint.


### Extra credit (5 points)

For each fingerprint, serve a different HTML file based on some combination of your four favorite things from Assignment 2.  This way each client has a unique experience, different from other clients.  See also: [cloaking](https://en.wikipedia.org/wiki/Cloaking).

### Setting up directory "6"

All of the code, files, images, etc. necessary to complete this assignment will be in directory ```6```.  The README.md for this assignment will have links to the code, a short description of the fingerprinting algorithm, a screenshot of the 6+ fingerprints, as well as a link to the Youtube video demonstrating the clients connecting and being recognized by the server.

