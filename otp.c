////////////////////////////////////////////////////////
///////////////////----- otp.c -----////////////////////
////                                                ////
////           Written by: Kris Hill                ////
////         Revised Version on: 6/8/20             ////
////                                                ////
////    Client program for running a one-time       ////
////    pad cipher. Operates get and post           ////
////    requests to a server (otp_d.c). Also        ////
////    runs the decryption and encryption logic.   ////
////                                                ////
////////////////////////////////////////////////////////
////////////////////////////////////////////////////////


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 

#define MAXCHARS 80000
#define MAXSEND 100000

void error(const char *msg) { perror(msg); exit(0); } // Error function used for reporting issues

char* PostPackager(char* mode, char* user, char* cipher);
char* GetPackager(char* mode, char* user);
char* Reader(char* fileName);
char* Encryptor(char* plaintext, char* key);
char* Decryptor(char* ciphertext, char* key);
int SendAll(int socketFD, char* package, int* len);
int RecAll(int socketFD, char* package, int* len);

//otp command line args syntax:
//| argv[0] | argv[1] | argv[2] |        argv[3]        |     argv[4]     | argv[5] |
//|   otp   |   get   |  <user> |    <key file name>    |     <port>      |---------|
//|   otp   |   post  |  <user> | <plaintext file name> | <key file name> |  <port> |
int main(int argc, char *argv[])
{
	int socketFD, portNumber, charsWritten, charsRead, packLen, charsIncoming;
	struct sockaddr_in serverAddress;
	struct hostent* serverHostInfo;
    char *plaintext, *key, *ciphertext;
    char *package;
    char *argMode, *argUser, *argPlainFile, *argKeyFile;
    argMode = malloc(256);
    argUser = malloc(256);
    argPlainFile = malloc(256);
    argKeyFile = malloc(256);

	// Set up the server address struct
	memset((char*)&serverAddress, '\0', sizeof(serverAddress)); // Clear out the address struct
	if(strcmp(argv[1], "get") == 0){
        portNumber = atoi(argv[4]);                             // Get the port number, convert to an integer from a string
    }else{
        portNumber = atoi(argv[5]);
    }
    serverAddress.sin_family = AF_INET;                         // Create a network-capable socket
	serverAddress.sin_port = htons(portNumber);                 // Store the port number
	serverHostInfo = gethostbyname("localhost");                    // Convert the machine name into a special form of address
	if (serverHostInfo == NULL) { fprintf(stderr, "CLIENT: ERROR, no such host\n"); fflush(stdout); exit(0); }
	memcpy((char*)&serverAddress.sin_addr.s_addr, (char*)serverHostInfo->h_addr, serverHostInfo->h_length); // Copy in the address

	// Set up the socket
	socketFD = socket(AF_INET, SOCK_STREAM, 0); // Create the socket
	if (socketFD < 0) error("CLIENT: ERROR opening socket");
	
	// Connect to server
	if (connect(socketFD, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) // Connect socket to address
		error("CLIENT: ERROR connecting");

    if(strcmp(argv[1], "post") == 0){//-------------------------------This section for POST processing---------------------------
        strcpy(argMode, argv[1]);         ////
        strcpy(argUser, argv[2]);           //
        strcpy(argPlainFile, argv[3]);      //----------------Put main args into easily readable names
        strcpy(argKeyFile, argv[4]);      ////
        plaintext = Reader(argPlainFile);   //converts file contents into string
        int m;
        for(m = 0; m < strlen(plaintext); m++){                           ////---checking plaintext for bad characters
            if(plaintext[m] < 65 || plaintext[m] > 90){                     //---if it's not a capital letter
                if(plaintext[m] == 32 || plaintext[m] == '\n'){             //---but is a space or a newline
                    continue;                                               //---then ignore and move on to the next char.
                }else{                                                      //---Else if it's anything but a capital letter or space,
                    printf("Bad characters in file: %s\n", argPlainFile);   //---print an error message
                    fflush(stdout);                                         //
                    exit(1);                                              ////---and exit the program
                }
            }
        }
        key = Reader(argKeyFile);               //open key file, read key file and save contents of file to variable
        if(strlen(key) < strlen(plaintext)){    //the key has to be the same size or bigger than the plaintext
            error("Not enough characters in the key");
        }
        ciphertext = Encryptor(plaintext, key);                 //encrypt plaintext and save to variable
        package = PostPackager(argMode, argUser, ciphertext);   //create package to send        
        packLen = strlen(package);                              //find length of the package
        send(socketFD, &packLen, sizeof(packLen), 0);           //send the length of the package to the server
        if(SendAll(socketFD, package, &packLen) == -1){         //SendAll sends the package in a loop to ensure all bytes are sent
            error("SendAll error");
            printf("only %d bytes were sent\n", packLen);
            fflush(stdout);
        }
    }else if(strcmp(argv[1], "get") == 0){//----------------------This section for GET processing----------------------------------
        strcpy(argMode, argv[1]);     ////
        strcpy(argUser, argv[2]);       //---------Put main args into easily readable names
        strcpy(argKeyFile, argv[3]);  ////
        package = GetPackager(argMode, argUser);        //create package to send
        packLen = strlen(package);                      //find the length of the package
        send(socketFD, &packLen, sizeof(packLen), 0);   //send the length of the package to the server
        if(SendAll(socketFD, package, &packLen) == -1){ //SendAll sends the package in a loop to ensure all bytes are sent
            error("SendAll error");
            printf("only %d bytes were sent\n", packLen);
            fflush(stdout);
        }
        ciphertext = malloc(MAXCHARS);
        memset(ciphertext, '\0', MAXCHARS);
        recv(socketFD, &charsIncoming, sizeof(charsIncoming), 0);   //receive length of message
        if(RecAll(socketFD, ciphertext, &charsIncoming) == -1){     //use length of message to receive whole message in a loop in RecAll
            error("RecAll error");
            printf("only %d bytes were received\n", charsIncoming);
            fflush(stdout);
        }
        if(strcmp(ciphertext, "Error: no such file") == 0){ //Check if error on server end
            error(ciphertext);                              //print error message and exit program 
        }else{                                              //otherwise,
            key = Reader(argKeyFile);                       //open and read file, and save to a string
            plaintext = Decryptor(ciphertext, key);         //decrypt ciphertexxt and save to variable
            printf("%s\n", plaintext);                      //print plaintext
            fflush(stdout);
        }
    }
    //-----------------Clean up...
    free(ciphertext);
    free(key);
    free(plaintext);
    free(package);

	close(socketFD); //Close the socket
	return 0;
}

//runs a loop to make sure all of the data that is supposed to be received is received
//source used for this function taken from Beej's Guide to Network Programming, https://beej.us/guide/bgnet/html/#sendall
int RecAll(int socketFD, char* package, int* len){
    int total = 0;
    int bytesLeft = *len;
    int n;

    while(total < *len){    //run until all bytes have been received
        n = recv(socketFD, package+total, bytesLeft, 0);    //save bytes received
        if(n == -1){break;}
        total += n;                                         //then add them to total
        bytesLeft -= n;                                     //and subtract them from bytesLeft
    }

    *len = total;       //save the total actual bytes received in the original len var
                        //most time, these will be the same, but if error, we want to know how many bytes were received before error
    if(n != -1){        //if last recv call was successful
        n = 0;          //save return value as 0
    }

    return n;           //used as flag in main to check success of RecAll
}

//runs a loop to make sure all of the data that is supposed to be sent is sent
//source used for this function taken from Beej's Guide to Network Programming, https://beej.us/guide/bgnet/html/#sendall
int SendAll(int socketFD, char* package, int* len){
    int total = 0;
    int bytesLeft = *len;
    int n;

    while(total < *len){    //run until all bytes have been sent
        n = send(socketFD, package+total, bytesLeft, 0);    //save bytes sent
        if(n == -1){break;}
        total += n;                                         //then add them to total
        bytesLeft -= n;                                     //and subtract them from bytesLeft
    }

    *len = total;       //save the total actual bytes sent in the original len var
                        //most time, these will be the same, but if error, we want to know how many bytes were sent before error
    if(n != -1){        //if last send call was successful
        n = 0;          //save return value as 0
    }

    return n;           //used as flag in main to check success of SendAll
}

//takes mode and user and concatinates them into one string, delimeted by "@@"
char* GetPackager(char* mode, char* user){
    char* getPackage;
    getPackage = malloc(MAXSEND);
    memset(getPackage, '\0', MAXSEND);
    strcpy(getPackage, mode);
    strcat(getPackage, "@@");
    strcat(getPackage, user);
    return getPackage;      //returns "mode@@username" (null-terminated)
}

//takes mode, user, and ciphertext and concatinates them into one string, delimited by "@@"
char* PostPackager(char *mode, char *user, char *cipher){
    char* postPackage;
    postPackage = malloc(MAXSEND);
    memset(postPackage, '\0', MAXSEND);
    strcpy(postPackage, mode);
    strcat(postPackage, "@@");
    strcat(postPackage, user);
    strcat(postPackage, "@@");
    strcat(postPackage, cipher);
    return postPackage;     //returns "mode@@username@@ciphertext" (null-terminated)
}

//takes filename found in Reader, opens file, and saves contents of file to string
char* Reader(char* filename){
    int len = 0;
    char* fileContents = malloc(MAXCHARS);
    memset(fileContents, '\0', MAXCHARS);
    size_t n = MAXCHARS;
    FILE* thisFile;
    thisFile = fopen(filename, "r");                            //open file to read
    if(thisFile == NULL){ error("CLIENT: could not open file");}
    int getCheck = getline(&fileContents, &n, thisFile);        //get the line from the file and save to a string
    if(getCheck == -1){ error("CLIENT: getline didnt work!");}
    fclose(thisFile);
    len = strlen(fileContents);
    if(fileContents[len-1] == '\n'){
        fileContents[len-1] = '\0';
    }
    return fileContents;    //return the string
}

//takes plaintext and key, encrypts plaintext and returns cipher
char* Encryptor(char* plaintext, char* key){
    char* ciphertext;
    ciphertext = malloc(MAXCHARS);
    memset(ciphertext, '\0', MAXCHARS);
    char tempChar1, tempChar2, tempChar3;
    int i, plainLen;
    plainLen = strlen(plaintext);
    if(plaintext[plainLen-1] == '\n'){      //just in case a string makes it this far with '\n' at the end, strip it off
        plaintext[plainLen-1] = '\0';
        plainLen--;
    }
    for(i = 0; i < plainLen; i++){
        if(plaintext[i] == 32){             //space character is 27th allowable character
            tempChar1 = 26;
        }else{
            tempChar1 = plaintext[i]-65;    //e.g., A=0, B=1, C=2, etc.
        }
        if(key[i] == 32){                   //space and capital chars in key handled same way as in ciphertext
            tempChar2 = 26;
        }else{
            tempChar2 = key[i]-65;
        }
        tempChar3 = tempChar1 + tempChar2;  //add key to cipher
        if(tempChar3 > 26){                 //make sure values are within 0-26 range
            tempChar3 -= 27;
        }
        if(tempChar3 == 26){                //reconvert chars to correct ascii codes for space and capital letters
            tempChar3 = 32;
        }else{
            tempChar3 += 65;
        }
        ciphertext[i] = tempChar3;          //encryption process done one letter at a time
    }
    return ciphertext;
}

//takes ciphertext and key, decrypts cipher and returns plaintext
char* Decryptor(char* ciphertext, char* key){
    char* plaintext;
    plaintext = malloc(MAXCHARS);
    memset(plaintext, '\0', MAXCHARS);
    char tempChar1, tempChar2, tempChar3;
    int i, cipherLen;
    cipherLen = strlen(ciphertext);
    if(ciphertext[cipherLen-1] == '\n'){    //just in case a string makes it this far with '\n' at the end, strip it off
        ciphertext[cipherLen-1] = '\0';
        cipherLen--;
    }
    for(i = 0; i < cipherLen; i++){
        if(ciphertext[i] == 32){            //space character is 27th allowable character
            tempChar1 = 26;
        }else{
            tempChar1 = ciphertext[i]-65;   //e.g., A=0, B=1, C=2, etc.
        }
        if(key[i] == 32){                   //space and capital chars in key handled same way as in ciphertext
            tempChar2 = 26;
        }else{
            tempChar2 = key[i]-65;
        }
        tempChar3 = tempChar1 - tempChar2;  //subtract key from cipher
        if(tempChar3 < 0){                  //make sure values are within 0-26 range
            tempChar3 += 27;
        }
        if(tempChar3 == 26){                //reconvert chars to correct ascii codes for space and capital letters
            tempChar3 = 32;
        }else{
            tempChar3 += 65;
        }
        plaintext[i] = tempChar3;           //decryption process done one letter at a time
    }
    return plaintext;
}
