#ifndef JSON_H
#define JSON_H

#define MAX_NESTED_BLOCKS 50

typedef void (*print_function_t)(void *call_arg, const char *output);

struct js_scope
{
    int attribute_count;
    int in_array;
};
typedef struct js_scope js_scope_t;

struct js_serialiser
{
    int level;    

    print_function_t print; 
    void *call_arg;
    int pretty_print;
    
    js_scope_t scopes[MAX_NESTED_BLOCKS];
};
typedef struct js_serialiser js_serialiser_t;


void js_document(js_serialiser_t *s);
void js_document4(js_serialiser_t *s, 
                  print_function_t print_function, 
                  void *call_arg,
                  int pretty_print); 
void js_document_end(js_serialiser_t *s);

void js_object(js_serialiser_t *s, char *name);
void js_object_end(js_serialiser_t *s);

void js_array(js_serialiser_t *s, char *name);
void js_array_end(js_serialiser_t *s);

void js_number(struct js_serialiser *s, char *name, double value);
void js_int_number(struct js_serialiser *s, char *name, long value);
void js_string(js_serialiser_t *s, char *name, char *value);
void js_boolean(js_serialiser_t *s, char *name, int boolean);

#endif

