
#define GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/wait.h>

#include "userlist.h"
#include "user.h"
#include "sock.h"
#include "func.h"

#define MODE_SERVER 1
#define MODE_CONSOLE 2

void
init()
{
     init_userlist();
     logout();
}

void print_usage()
{
     printf("> register\t\tcreate a temporary user\n");
     printf("> login\t\tauthenticate a user\n");
     printf("> logout\t\tdestroy the current session\n");
     printf("\n");
     printf("functions as authenticated user\n");
     printf("> whoami\t\tshow user id\n");
     printf("> changepw\t\tchange the password\n");
     printf("> changename\t\tchange the username\n");
     printf("> shell\t\tstart the shell in the user profile\n");
     printf("\n");
     printf("system functions:\n");
     printf("> list\t\tshow all registered users\n");
     printf("> delete\t\tdelete a user\n");
     printf("> read\t\tparse the 'userlist' file\n");
     printf("> write\t\twrite out the 'userlist' file\n");
     printf("> purge\t\tempty the userlist\n");
     printf("> debug\t\tshow the userlist data structure\n");
     printf("> exit\t\tclose the program/connection\n");
}

void handle_client()
{
    char command[255];

    printf("handle_client");
    while(1) {
        fprintf(stdout, "\ncmd> ");
        if(fgets(command, sizeof(command), stdin) == NULL)
	{
	    break;
	}
        command[strcspn(command, "\n")] = 0x00; // null terminator

        if(strncmp(command, "list", 4) == 0)
        { // list
            if(! is_authenticated()) continue;
            walk_list(print_list_element);

	}
       	else if(strncmp(command, "register", 8) == 0)
        { 
	    // new user (free for all)
            create_user();
        }
        else if(strncmp(command, "delete", 6) == 0)
        { // delete
            if(! is_authenticated() || ! is_privileged()) continue;
            delete_user();
        }
        else if(strncmp(command, "read", 4) == 0)
        {
            if(! is_authenticated()) continue;
            if(! is_privileged()) continue;
            //purge_list();
            read_list("userlist");
        }
        else if(strncmp(command, "write", 5) == 0)
        {
            if(! is_authenticated()) continue;
            if(! is_privileged()) continue;
            write_list("userlist");
        } 
        else if(strncmp(command, "purge", 5) == 0)
        {
            if(! is_authenticated()) continue;
            if(! is_privileged()) continue;
            purge_list();
        }
        else if(strncmp(command, "debug", 5) == 0)
        {
            if(! is_authenticated()) continue;
            walk_list(print_debug);
        }
        else if(strncmp(command, "login", 5) == 0)
        {
            login();
        }
        else if(strncmp(command, "logout", 6) == 0)
        {
            if(! is_authenticated()) continue;
            logout();
        }
        // else if(strncmp(command, "shell", 5) == 0)
        // {
        //     if(! is_authenticated()) continue;
        //     shell();
        // }
        else if(strncmp(command, "changepw", 8) == 0)
        {
            if(! is_authenticated()) continue;
            change_password();
        }
        else if(strncmp(command, "changename", 10) == 0)
        {
            if(! is_authenticated()) continue;
            change_name();
        }
        else if(strncmp(command, "whoami", 6) == 0)
        {
            if(! is_authenticated()) continue;
            whoami();
        }
        else if(strncmp(command, "exit", 4) == 0)
        {
            //if net close client socket
            //close_client();
            //else is console
            return;
        }
        else if(strncmp(command, "help", 4) == 0)
        {
            print_usage();
	}
        else
        {
	    fprintf(stderr, "Type 'help' to print the usage.");
        }
    } // while
}

#ifndef LIBFUZZER
int
main(int argc, char** argv)
{
    int mode = -1;

    if(argc == 2 && strncmp("server", argv[1], 6) == 0)
    {
        mode = MODE_SERVER;
    }
    else if(argc == 2 && strncmp("console", argv[1], 7) == 0)
    {
        mode = MODE_CONSOLE;
    }
    else
    {
	printf("%s console\n", argv[0]);
	printf("%s server\n", argv[0]);
	exit(1);
    }

    assert(mode != -1);
    printf("starting up (pid %d)\n", getpid());
    setbuf(stdout, NULL); // unbuffered stdout
    init();
    read_list("userlist");
    switch(mode)
    {
       case MODE_SERVER:
          start_server(&handle_client);
          stop_server();
          break;
       case MODE_CONSOLE:
          handle_client();
          break;
       default:
	  printf("error\n");
	  exit(2);
	  break;
    }

    return 0;
}
#else
#include <stdint.h>

// static void cleanup()
// {
//     t_user_list_element *el = user_list.head;
//     while (el != null)
//     {
//         t_user_list_element *toFree = el;
//         el = el->next;
//         free(toFree->user);
//         free(toFree);
//     }
// }

static void doFuzz()
{
    init();
    // for now, fuzz with an empty list
    //read_list("userlist");
    handle_client();
    // do a manual cleanup
    purge_list();    
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) 
{
    static uint32_t counter = 0;

    // variant1, use freopen() and a temp file
    // FILE *fp = fopen("./corpus.bin", "w");
    // if (fp != NULL)
    // {
    //     fwrite(Data, Size, 1, fp);
    //     fflush(fp);
    //     fclose(fp);
    //     fclose(stdin);
    //     freopen("./corpus.bin", "r", stdin );

    //     doFuzz();
    //     counter++;
    // }
    // else
    // {
    //     printf("Failed to open a file handle after %d loops.", counter);
    //     assert(0);
    // }

    // alternative: use fmemopen()
    FILE *fp = fmemopen((void*)Data, Size, "r");
    if (fp != NULL) 
    {
        stdin = fp;  // Redirect stdin
        doFuzz();  // Call the function that reads from stdin
        fclose(fp);
        counter++;
    }
    else
    {
        printf("Failed to open a file handle after %d loops.", counter);
        assert(0);        
    }

    return 0;  // Values other than 0 and -1 are reserved for future use.
}
#endif