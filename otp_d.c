///////////////////////////////////////////////////////
//////////////////----- otp.c ------///////////////////
////                                               ////
////          Written by: Kris Hill                ////
////        Revised Version on: 6/8/20             ////
////                                               ////
////    Server program for running a one-time      ////
////    pad cipher. Operates get and post          ////
////    requests with a client (otp.c). Only       ////
////    operates storage and retrieval of          ////
////    ciphertext.                                ////
////                                               ////
///////////////////////////////////////////////////////
///////////////////////////////////////////////////////

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>

#define MAXCHARS 80000
#define MAXSEND 100000

void error(const char *msg) { perror(msg); exit(1); } // Error function used for reporting issues
char* Finder(char* username);
char* Reader(char* filepath);
char* Recorder(char* username, char* ciphertext);
void CheckChildren(pid_t* pids, int* procStatus, int* numChildren);
char** Parser(char* package);
int SendAll(int socketFD, char* package, int* len);
int RecAll(int socketFD, char* package, int* len);

int main(int argc, char *argv[])
{
	int listenSocketFD;                 //will hold file descriptor of open, ready socket
    int establishedConnectionFD;        //will hold file descriptor of accepted, connected socket
    int portNumber;                     //will hold port number provided by user
    int charsRead, cipherLen, charsIncoming;       //will hold the amount of chars sent or received by server
	pid_t childpid;
    pid_t childpidCheck;
    pid_t pids[5];
    int i, j, k;
    for(i = 0; i < 5; i++){
        pids[i] = -999;
    }
    int currentpids = 0;
    int procStatus= 0;
    socklen_t sizeOfClientInfo;         //
	//char buffer[256];
	struct sockaddr_in serverAddress, clientAddress;
    char *ciphertext, *user, *mode, *filepath, *package;
    char **argsList;

	// Set up the address struct for this process (the server)
	memset((char *)&serverAddress, '\0', sizeof(serverAddress));    // Clear out the address struct
	portNumber = atoi(argv[1]);                                     // Get the port number, convert to an integer from a string
	serverAddress.sin_family = AF_INET;                             // Create a network-capable socket
	serverAddress.sin_port = htons(portNumber);                     // Store the port number
	serverAddress.sin_addr.s_addr = INADDR_ANY;                     // Any address is allowed for connection to this process

	// Set up the socket
	listenSocketFD = socket(AF_INET, SOCK_STREAM, 0);               // Create the socket
	if (listenSocketFD < 0) error("ERROR opening socket");

	// Enable the socket to begin listening
	if (bind(listenSocketFD, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0) // Connect socket to port
		error("ERROR on binding");
	listen(listenSocketFD, 5);                                      // Flip the socket on - it can now receive up to 5 connections
	while(1){
        sizeOfClientInfo = sizeof(clientAddress);                       // Get the size of the address for the client that will connect
        establishedConnectionFD = accept(listenSocketFD, (struct sockaddr *)&clientAddress, &sizeOfClientInfo);
        if (establishedConnectionFD < 0) error("ERROR on accept");
        childpid = fork();  //fork and save child process id
        switch(childpid){
            case -1:
                error("Could not fork!");
                break;
            case 0: //---------------------------------------------------Child Process---------------------------------------------------
                sleep(2);
                package = malloc(MAXSEND);
                memset(package, '\0', MAXSEND);
                recv(establishedConnectionFD, &charsIncoming, sizeof(charsIncoming), 0);//receive the amount of bytes that are going to be sent
                if(RecAll(establishedConnectionFD, package, &charsIncoming) == -1){     //RecAll runs loop to make sure all bytes are received
                    error("SERVER: RecAll error");          
                    printf("only %d bytes were received\n", charsIncoming);
                    fflush(stdout);
                }
                argsList = Parser(package); //break the package up into constituent parts and save in array
                mode = malloc(256);
                strcpy(mode, argsList[0]);  //save package parts into easily recognizable vars, more like this later
                if(strcmp(mode, "get") == 0){   //-------------------------------This section for GET processing--------------------------------------
                    user = malloc(256);
                    strcpy(user, argsList[1]);
                    filepath = Finder(user);    //find and save the filepath for user
                    if(strlen(filepath) == 0 || filepath == NULL){  //send error message to client if can't find file
                        ciphertext = malloc(MAXCHARS);
                        memset(ciphertext, '\0', MAXCHARS);
                        strcpy(ciphertext, "Error: no such file");
                    }else{                                          //otherwise...
                        ciphertext = Reader(filepath);              //save file contents to ciphertext string
                        remove(filepath);                           //and remove the file
                    }
                    cipherLen = strlen(ciphertext);
                    send(establishedConnectionFD, &cipherLen, sizeof(cipherLen), 0);    //send the amount of bytes to be sent in ciphertext
                    if(SendAll(establishedConnectionFD, ciphertext, &cipherLen) == -1){ //SendAll runs loop to make sure all bytes are received
                        error("SERVER: SendAll error");
                        printf("only %d bytes were sent\n", cipherLen);
                        fflush(stdout);
                    }
                    free(user);
                    free(filepath);
                    free(ciphertext);
                }else if(strcmp(mode, "post") == 0){    //------------------------This section for POST processing---------------------------------------
                    user = malloc(256);
                    strcpy(user, argsList[1]);
                    ciphertext = malloc(MAXCHARS);
                    strcpy(ciphertext, argsList[2]);
                    filepath = Recorder(user, ciphertext);  //save ciphertext to a file and save the filename
                    printf("%s\n", filepath);               //then print the file name
                    fflush(stdout);
                    free(user);
                    free(ciphertext);
                    free(filepath);
                }
                close(establishedConnectionFD);             //Close the existing socket which is connected to the client
                free(mode);
                
                for(j = 0; j < 3; j++){
                    free(argsList[j]);
                }
                free(argsList);
                exit(EXIT_SUCCESS);
                break;
            default:            //-------------------------------Parent process----------------------------------------
                childpidCheck = waitpid(childpid, &procStatus, WNOHANG);//check the just forked child process
                if(childpidCheck == 0){         //if still running
                    for(k = 0; k < 5; k++){     //iterate through entire pids array
                        if(pids[k] == -999){    //until it finds an element of pids that does not have another actual pid in it
                            pids[k] = childpid; //save pid there    
                            currentpids++;      //increment amount of child processes
                            break;
                        }
                    }
                }
                close(establishedConnectionFD);
        }
        CheckChildren(pids, &procStatus, &currentpids);//Check bg processes

    }
    close(listenSocketFD);                                          // Close the listening socket
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
        total += n;                                         //then add to total
        bytesLeft -= n;                                     //and subtract from bytesLeft
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

//takes package sent by client, parses it into its constituent parts, and saves them in an array
char** Parser(char* package){
    int i, j, k;
    char** argsList;
    char *startAdd, *endAdd;
    argsList = malloc(3*sizeof(*argsList));
    for(i = 0; i < 3; i++){
        if(i == 2){     //if the package is a post request, the last element will be ciphertext and those can be very large
            argsList[i] = malloc(MAXCHARS);
            memset(argsList[i], '\0', MAXCHARS);
        }else{          //otherwise, the elements of a package are a lot smaller
            argsList[i] = malloc(512);  
            memset(argsList[i], '\0', 512);
        }
    }
    startAdd = package;                 //save starting address of package string
    i = 0;
    while(*startAdd != '\0'){           //in while loop until the starting address == NULL
        endAdd = strstr(startAdd, "@@");//run strstr() and save return value - will be address of first char in delimiter
        if(endAdd == NULL){             //if strstr return value == NULL, we are at last element
            j = 0;
            while(startAdd[j] != '\0'){ //in while loop from start address until current char == '\0' 
                argsList[i][j] = startAdd[j];//start at beginning of package string, saving each char into a new string in array or args 
                j++;
            }
        }else{                          //else, we are in the middle of the package
            j = 0;
            while(&startAdd[j] != endAdd){//in while loop until the address of current char in package string == strstr return value
                argsList[i][j] = startAdd[j];//start at beginning of package string, saving each char into a new string in array or args 
                j++;
            }
        }
        startAdd = &startAdd[j] + 2;//add two to the starting address and resave to start address variable (skip over "@@")
        i++; 
    }
    
    return argsList;
}

//takes username and uses that to find the oldest file with user name and returns the name/filepath
char* Finder(char* username){
    int oldestFileTime, i = 0;
    char* oldestFileName;
    oldestFileName = malloc(256);
    memset(oldestFileName, '\0', 256);

    DIR* dirToCheck;
    struct dirent *fileInDir;
    struct stat fileAttributes;

    dirToCheck = opendir(".");  //open up current working directory
    if(dirToCheck > 0){
        while((fileInDir = readdir(dirToCheck)) !=NULL){//look through current working directory
            if(strstr(fileInDir->d_name, username) != NULL){
                stat(fileInDir->d_name, &fileAttributes);//check time last modified of current file
                if(i == 0){
                    oldestFileTime = (int)fileAttributes.st_mtime;      //base case: save the time and name of first file with user name
                    strcpy(oldestFileName, fileInDir->d_name);
                }else{
                    if((int)fileAttributes.st_mtime < oldestFileTime){  //all other iterations: check if current file is older
                        oldestFileTime = (int)fileAttributes.st_mtime;  //if it is, save time and name of file
                        memset(oldestFileName, '\0', 256);
                        strcpy(oldestFileName, fileInDir->d_name);
                    }
                }
                i++;
            }
        }
    }
    closedir(dirToCheck);
    return oldestFileName;
}

//takes filename found in Reader, opens file, and saves contents of file to string
char* Reader(char* filepath){
    FILE* cipherFile;
    char* ciphertext = malloc(MAXCHARS);
    memset(ciphertext, '\0', MAXCHARS);
    size_t n = MAXCHARS;
    cipherFile = fopen(filepath, "r");                      //open file to read
    if(cipherFile == NULL){ error("SERVER: fopen error");}
    int getCheck = getline(&ciphertext, &n, cipherFile);    //get the line from the file and save to a string
    if(getCheck == -1){error("SERVER: getline error");}
    fclose(cipherFile);
    return ciphertext;  //return the string
}

//takes user name and ciphertext string and save cipher to file with user's name on it
char* Recorder(char* username, char* ciphertext){
    FILE* newCipherFile;
    char* filepath = malloc(256);
    memset(filepath, '\0', 256);
    int currentPID = getpid();          //getpid
    char PIDString[20];
    sprintf(PIDString, "%d", currentPID);//turn pid to string
    strcpy(filepath, username);          //concat: username + ".cipher." + pidString and save to filepath var
    strcat(filepath, ".cipher.");
    strcat(filepath, PIDString);
    newCipherFile = fopen(filepath, "w");//open file with filepath var to write
    fprintf(newCipherFile, "%s\n", ciphertext);//write ciphertext to open file
    fflush(stdout);
    fclose(newCipherFile);
    return filepath;                    //return file name
}

//takes array of pids, number of those pids, and the var for holding status of a wait/waitpid call
void CheckChildren(pid_t* pids, int* procStatus, int* numChildren){
    int i;
    for(i = 0; i < 5; i++){//iterate through entire pids array
        if(pids[i] != -999){//if current pids element has actual pid
            int pidCheck = waitpid(pids[i], procStatus, WNOHANG);   //then check if it's done
            if(pidCheck > 0){                                       //and if it is done
                pids[i] = -999;                                     //replace the actual pid with holder value
                *numChildren--;                                     //then decrement the number of pids
            }else if(pidCheck == -1){
                error("waitpid error");
            }
        }
    }
}
