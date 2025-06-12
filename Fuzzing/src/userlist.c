
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "userlist.h"
#include "user.h"

t_user_list user_list;

void
init_userlist()
{
    user_list.number_of_elements = 0;
    user_list.head = NULL;
}

t_user*
get_user_by_name(char* username)
{
     t_user_list_element* element;
     element = user_list.head;
     while (element != NULL)
     {
          if(strcmp(element->user->name, username) == 0)
          {
               return element->user;
          } else {
               element = element->next;
          }
     }
     return NULL;
}

void
walk_list(void (*func)())
{
     int i = 1;
     t_user_list_element* element;
     element = user_list.head;
     while (element != NULL)
     {
          func(i, element);
          element = element->next;
          i++;
     }
}

void
print_list_element(int row_nr, t_user_list_element* element)
{
     printf("%d ", row_nr);
     print_user(element->user);
}

void
print_debug(int i, t_user_list_element* element)
{
     printf("%d user(name='%s' t_user_list_element=[%p] t_user=[%p] element->next=[%p])\n", i, element->user->name, element, element->user, element->next);
     // show data bytes
     /*
     for(int x=0; x<40; x++)
     {
	     cout << (element + x);
	     if(x % 8) printf("\n");
     }
     printf("\n");
     */
}

// returns 1 if success, 0 if not found
int
delete_user_by_id(int id)
{
     int i = 1;
     t_user_list_element* element;
     t_user_list_element* prev_element = NULL;
     element = user_list.head;
     while (element != NULL)
     {
          if(i == id) {
               if(prev_element != NULL) // one element more more
               {
                    prev_element->next = element->next;
               } else { // first element, reset list head
                    user_list.head = element->next;
               }
               free(element->user);
               free(element);
               user_list.number_of_elements--; // one element less
               return 1;
          } 
          prev_element = element;
          element = element->next;
          i++;
     }
     return 0;
}

t_user_list_element*
add_user_to_list(t_user* new_user)
{
     // prepare the new list item
     t_user_list_element* new_element = (t_user_list_element*) malloc(sizeof(t_user_list_element));
     new_element->user = new_user;
     new_element->next = NULL; // it is the new last element in the list = NULL
     
     // append the populated element to the list
     t_user_list_element* last_element;
     if(user_list.head == NULL || user_list.number_of_elements == 0) // empty list
     {
          user_list.head = new_element;
          user_list.number_of_elements = 1;
     } else {  // appended the new element to the list
          // fast forward to last element 
          last_element = user_list.head;
          while(last_element->next != NULL) last_element = last_element->next;
          last_element->next = new_element;
          user_list.number_of_elements++;
     }

     return new_element;
}

void
read_list(char* path)
{
     FILE* fp;
     char * line = NULL;
     size_t len = 0;
     ssize_t read;
     t_user* new_user;

     fp = fopen(path, "r");
     if(!fp)
     {
          fprintf(stderr, "can't open file %s", path);
          exit(EXIT_FAILURE);
     }
     printf("reading file %s\n", path);
     while ((read = getline(&line, &len, fp)) != -1) {
          line[strcspn(line, "\n")] = 0;
          new_user = parse_userlist_list(line);
	  //new_user->id = id; // automatically assign numbers
	  add_user_to_list(new_user);
	  //id++;
     }
     fclose(fp);
     if (line)
          free(line);
}

void
write_list(char* path)
{
     FILE* fp;
     t_user_list_element* element;

     fp = fopen(path, "w");
     if(!fp)
     {
          fprintf(stderr, "can't open file %s", path);
          exit(EXIT_FAILURE);
     }

     element = user_list.head;
     while (element != NULL)
     {
          fprintf(fp, "%s:%.32s:%d:%s:%s\n", // name:hash:id:home:shell
               element->user->name, 
               element->user->password_hash, 
               element->user->id,
               element->user->home,
               element->user->shell);
          
          element = element->next;
     }

     fclose(fp);
}

void
purge_list()
{
     t_user_list_element* element;
     t_user_list_element* next;
     element = user_list.head;
     while (element != NULL)
     {
          next = element->next;
          free(element->user);
          free(element);
          element = next;
     }
     user_list.head = NULL; // TODO?
}

t_user_list_element*
get_last_element()
{
     t_user_list_element* element;
     element = user_list.head;
     if(element == NULL) 
     {
          return NULL;
     }
     while (element->next != NULL) 
     {
          element = element->next; // fast forward to last element
     }

     return element; 
}

int
next_free_id() // returns a free id. does not account for gaps
{
     t_user_list_element* element;
     int max_id = 10000; // default first id

     // bug fix ernst: Handle empty list
     if (user_list.head == NULL)
     {
          return max_id;
     }

     element = user_list.head; // start iterating through the list
     while (element->next != NULL) 
     {
          if(max_id <= element->user->id)
          {
               max_id = element->user->id + 1;
          }
          element = element->next;
     }
     return max_id;
}

t_user*
parse_userlist_list(char* line)
{
    char* token;
    int column = 0;
    t_user* parsed_user = (t_user *)malloc(sizeof(t_user));
    
    token = strtok(line, ":");
    while(token != NULL)
    {
        switch(column)
        {
       	    case 0: // name
                strcpy(parsed_user->name, token);
		break;
       	    case 1: // hash
       		strncpy(parsed_user->password_hash, token, 32);
       		break;
       	    case 2: // id
       		parsed_user->id = atoi(token);
       		parsed_user->gid = atoi(token);
       	        break;
       	    // TODO gid
       	    case 3: // home
       		strcpy(parsed_user->home, token);
       		break;
       	    case 4: // shell
       		strcpy(parsed_user->shell, token);
       		break;
       	    default:
       		free(parsed_user);
       		return NULL;
       }
       token = strtok(NULL, ":");
       column++;
    }
    return parsed_user;
}
