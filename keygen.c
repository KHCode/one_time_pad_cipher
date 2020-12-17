//////////////////////////////////////////////////////
////////////////----- keygen.c -----//////////////////
////                                              ////
////          Submitted by: Kris Hill             ////
////        CS344, sec. 400, Spring 2020          ////
////     Submitted Revised Version on: 6/8/20     ////
////                                              ////
////     Simple program for generating random     ////
////     sequences of capital letters and         ////
////     spaces of user-specified length.         ////
////                                              ////
//////////////////////////////////////////////////////
//////////////////////////////////////////////////////

#include <stdlib.h>
#include <stdio.h>
#include <time.h>

//generates pseudo-random capital letters or space and returns char
char GenChar(){
    int randNum = rand()%27;
    char a;
    if(randNum < 26){
        a = randNum + 65;
    }else{
        a = 32;
    }
    return a;
}

//generates the string of random capital letters and spaces
void KeyGen(int numChars){
    int i;//incrementor
    char* key;
    key = malloc(numChars+1); 
    for(i = 0; i < numChars; i++){//check for max number
        key[i] = GenChar();//genChar() generate random character
    }
    printf("%s\n", key);    //print character into file
    free(key);
}


int main(int argc, char** argv){

    srand(time(NULL));
    int numChars;
    numChars = atoi(argv[1]);   //turn user command into int
    KeyGen(numChars);           //generate and print string

    return 0;
}
