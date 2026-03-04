#include<fstream>
#include<iostream>
#include<string>
#include<vector>
main(){
    std::vector<std::string> websiteNames;
    std::string line;
    std::ifstream htmlFile;
    std::ifstream results;
    std::string htmlFilePath = "template.html";
    htmlFile.open(htmlFilePath);
    results.open("Results.md");
    std::ifstream webistes;
    webistes.open("SFULB001@ODU.EDU.txt");
    std::string firstHalf="";
    std::string secondHalf="";
    std::ofstream FinalResults;
    FinalResults.open("FinalResults.md");
    bool second=0;
    while(std::getline(htmlFile, line)){
        if(line=="        <h1>The iframe element</h1>"){
            second=1;
        }
        else{
            if(!second){
                firstHalf+=(line+"\n");
            }
            else{
                secondHalf+=(line+"\n");
            }
        }
    }
    while(std::getline(webistes, line)){
        std::ofstream outHTML;
        websiteNames.push_back(line);
        outHTML.open("framable/"+line+".html");
        outHTML<<firstHalf<<"<iframe src=\"https://"<<line<<"\">"<<secondHalf;
        outHTML.close();
    }
    int index=0;
    while(std::getline(results, line)){
        if(line[0]==' '){
            FinalResults<<websiteNames[index]<<line<<std::endl;
            index++;
        }
        else{
            FinalResults<<line<<std::endl;
        }
    }
}