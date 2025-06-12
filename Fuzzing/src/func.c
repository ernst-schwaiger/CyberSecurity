

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/wait.h>

#include "userlist.h"
#include "runr.h"


struct _session
{
     t_user* logged_in_user;
     time_t start_time;
} typedef t_session;

// globals
t_session session;

int
is_authenticated()
{
    if(session.logged_in_user == NULL)
    {
        fprintf(stderr, "not logged in.\n");
        return 0;
    }
    else
    {
        return 1;
    }
}

int
is_privileged()
{
    t_user* user = session.logged_in_user;
     if(user->id < 1 || user->gid < 1) // is a root user
     {
          return 1;
     }
     else
     {
          fprintf(stderr, "privileged users only!");
          return 0;
     }
}


void 
delete_user()
{
    int id;

    walk_list(print_list_element);
    fprintf(stdout, "Which one? > ");
    scanf("%d", &id);
    if(!delete_user_by_id(id)) {
         fprintf(stderr, "not found.\n");
    }
}

void
create_user()
{
    char input_username[USERNAME_LENGTH];
    char input_password[PASSWORD_LENGTH];
    t_user* user;
    t_user_list_element* element;
    int free_id = -1;
    
    fprintf(stdout, "What is the name > ");
    fgets(input_username, sizeof(input_username), stdin);
    input_username[strcspn(input_username, "\n")] = 0x00; // terminator instead of a newline
   
    if(get_user_by_name(input_username) != NULL)
    {
         fprintf(stdout, "username already taken\n");
         return;
    }

    //input_password = getpass("Password: "); fflush(stdout);
    fprintf(stdout, "Password: ");
    fgets(input_password, sizeof(input_password), stdin);
    input_password[strcspn(input_password, "\n")] = 0x00; // terminator instead of a newline

    user = new_user(input_username, input_password);
    free_id = next_free_id();
    user->id = free_id;
    user->gid = free_id;
    /*
    element = get_last_element();
    if(element != NULL) // avoid NULL pointer exception
    {
         user->id = element->user->id + 1; // last known id+1
         user->gid = element->user->id + 1; // last known id+1
         //user->gid = element->user->id + 1; // same as id
    }
    */
    add_user_to_list(user);
    fprintf(stdout, "User added.");
}

void
shell()
{
    t_runr_args arg;
    char child_stack[STACK_SIZE];
    t_user* user = session.logged_in_user;
    pid_t pid = -1;

    fprintf(stdout, "starting shell '%s'. Name '%s' User ID %d, home '%s' ...\n", 
       	     user->shell, 
       	     user->name,
       	     user->id, 
       	     user->home); 
    fflush(stdout);

    arg.home = user->home;
    arg.id = user->id;
    arg.gid = 22222;
    strncpy(arg.proc, user->shell, strlen(user->shell));

    printf("cloning a new child\n");
    pid = runr_start(&arg); // this runs the shell in a container
    printf("child pid is %d\n", pid);
    waitpid(pid, NULL, 0);
    printf("child died\n");
}

void
login()
{
    char input_username[USERNAME_LENGTH];
    //char* input_password;
    char input_password[PASSWORD_LENGTH];
    t_user* user;

    fputs("Welcome!\n", stdout);
    fputs("username: ", stdout); fflush(stdout);
    fgets(input_username, USERNAME_LENGTH, stdin);
    input_username[strcspn(input_username, "\n")] = 0x00;
    // if terminal
    //input_password = getpass("Password: "); fflush(stdout);
    fputs("password: ", stdout); fflush(stdout);
    fgets(input_password, PASSWORD_LENGTH, stdin);
    input_password[strcspn(input_password, "\n")] = 0x00;

    printf("searching for user ...\n");
    if((user = get_user_by_name(input_username)) == NULL)
    {
        fprintf(stdout, "no such user\n");
        return;
    }

    printf("checking password ...\n");
    if(check_password(user, input_password) == 1)
    {
        fprintf(stdout, "You are authorized.\n");
        session.logged_in_user = user;
        session.start_time = time(0);
        chdir(user->home);
    }
    else
    {
    	fprintf(stderr, "Authentication failure\n");
    }
}

void
logout()
{
    session.logged_in_user = NULL;
    session.start_time = 0;
}

void
change_name()
{
    char input_username[USERNAME_LENGTH];
        
    fprintf(stdout, "What is the name > ");
    //fgets(input_username, sizeof(input_username), stdin);
    fscanf(stdin, "%s", input_username); // TODO security
    input_username[strcspn(input_username, "\n")] = 0x00; // terminator instead of a newline

    strncpy(session.logged_in_user->name, input_username, strlen(input_username)+1);
    fprintf(stdout, "Name changed.\n");
}

void
change_password()
{
    //char* input_password;
    //input_password = getpass("Password: "); fflush(stdout);

    char input_password[PASSWORD_LENGTH];
    fprintf(stdout, "Password: ");
    fgets(input_password, sizeof(input_password), stdin);
    input_password[strcspn(input_password, "\n")] = 0x00; // terminator instead of a newline

    // strncpy(session.logged_in_user->password_hash, 
    //         str2md5(input_password, strlen(input_password)), 
	//     32);

    // Ernst: Mem-leak free variant
    char *md5 = str2md5(input_password, strlen(input_password));
    strncpy(session.logged_in_user->password_hash, md5, 32);
    free(md5);
    
    fprintf(stdout, "Password changed.\n");
}

void
whoami()
{
    if(session.logged_in_user != NULL)
    {
         print_user(session.logged_in_user);
    }
    else
    {
	 puts("not logged in.");
    }
}

void
not_implemented()
{
    puts("not implemented");
}

