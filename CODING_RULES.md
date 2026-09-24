# Recommended C style and coding rules

This document describes the C code style used by Tilen MAJERLE in his projects and libraries. It is the recommended guideline for all contributions.

## The single most important rule

Let's start with a quote from a GNOME developer.

> The single most important rule when writing code is this: *check the surrounding code and try to imitate it*.
>
> As a maintainer it is dismaying to receive a patch that is obviously in a different coding style to the surrounding code. This is disrespectful, like someone tromping into a spotlessly-clean house with muddy shoes.
>
> So, whatever this document recommends, if there is already existing code and you are patching it, keep its current style consistent even if it is not your favorite style.

## Integration with VSCode

VSCode can use the `clang-format` tool (part of the LLVM package) to automatically format code during development, but `clang-format` is not limited to VSCode. It is a standalone formatting tool that can be used from any editor or from the command line.

When a file is saved, VSCode can invoke `clang-format` and format the file. The formatting rules are provided by a `.clang-format` file. If `clang-format` cannot find this file in the current directory, it searches upward until it finds one. If no `.clang-format` file is found, clang-format uses its default rules.

## Conventions used

The keywords *MUST*, *MUST NOT*, *REQUIRED*, *SHALL*, *SHALL NOT*, *SHOULD*, *SHOULD NOT*, *RECOMMENDED*, *NOT RECOMMENDED*, *MAY*, and *OPTIONAL* in this document are interpreted as described in BCP 14 [RFC2119] [RFC8174].

## General rules

These are the most obvious and important general rules. Please review them carefully before continuing.

- `clang-format` SHOULD be used with the `.clang-format` file included in this repository (version `20.x` or later is required)
- Use the `C11` standard
- Do not use tabs; use spaces instead
- Use `4` spaces per indent level
- Use `1` space between a keyword and its opening parenthesis
```c
/* OK */
if (condition)
while (condition)
for (init; condition; step)
do {} while (condition)

/* Wrong */
if(condition)
while(condition)
for(init;condition;step)
do {} while(condition)
```

- Do not use space between function name and opening bracket
```c
int32_t sum_result = sum(4, 3);              /* OK */
int32_t sum_result = sum (4, 3);             /* Wrong */
```

- Never use `__` or `_` prefix for variables/functions/macros/types. This is reserved for C language itself
    - Prefer `prv_` name prefix for strictly module-private (static) functions
    - Prefer `libname_int_` or `libnamei_` prefix for library internal functions, that should not be used by the user application while they MUST be used across different library internal modules
- Use only lowercase characters for variables/functions/types with optional underscore `_` char
- Variable names SHOULD be at least `3` characters long
- Opening curly bracket is always at the same line as keyword (`for`, `while`, `do`, `switch`, `if`, ...)
```c
size_t idx;
for (idx = 0; idx < 5; ++idx) {           /* OK */
}
for (idx = 0; idx < 5; ++idx){            /* Wrong */
}
for (idx = 0; idx < 5; ++idx)             /* Wrong */
{
}
```

- Use single space before and after comparison and assignment operators
```c
int32_t var_value;
var_value = 3 + 4;              /* OK */
for (var_value = 0; var_value < 5; ++var_value) /* OK */
var_value=3+4;                  /* Wrong */
var_value = 3+4;                /* Wrong */
for (var_value=0;var_value<5;++var_value)       /* Wrong */
```

- Use single space after every comma
```c
func_name(5, 4);        /* OK */
func_name(4,3);         /* Wrong */
```

- Avoid initializing `global` variables with default values (including `NULL`) when possible; use a dedicated `init` function when initialization is required, to ensure correct values, especially when embedded systems startup process doesn't do it for you.
```c
static int32_t global_var_a;       /* OK */
static int32_t global_var_b = 4;   /* Avoid if initialization can be done later */
static int32_t global_var_a = 0;   /* Avoid if initialization can be delayed */
```
> In embedded systems, RAM regions are often placed in custom memory sections.
> If startup code or linker scripts do not properly initialize those sections, compiler-level initial values may have no effect.
> To avoid this problem, create an init function for each module and set default values there:

```c
static int32_t global_var_a;       /* OK */
static int32_t global_var_b = 4;   /* Avoid if startup and linker scripts may not initialize it properly */

void
my_module_init(void) {
    global_var_a = 0;
    global_var_b = 4;
}
```

- Declare all local variables of the same type in the same line
```c
void
my_func(void) {
    /* 1 */
    char var_char;             /* OK */
    
    /* 2 */
    char var_char1, var_char2;          /* OK */
    
    /* 3 */
    char var_char3;
    char var_char4;             /* Wrong, variable with char type already exists */
}
```

- Declare local variables in order
    1. Custom structures and enumerations
    2. Integer types, wider unsigned type first
    3. Single/Double floating point
```c
int
my_func(void) {
    /* 1 */
    my_struct_t my_struct;     /* First custom structures */
    my_struct_ptr_t* my_struct_ptr; /* Pointers too */

    /* 2 */
    uint32_t var_u32;
    int32_t var_i32;
    uint16_t var_u16;
    int16_t var_i16;
    char var_char;
    /* ... */

    /* 3 */
    double var_dbl;
    float var_flt;
}
```

- Always declare local variables at the beginning of the block, before first executable statement
- Always add trailing comma in the last element of structure (or its children) initialization (this helps clang-format to properly format structures). Unless structure is very simple and short
```c
typedef struct {
    int val_a, val_b;
} str_t;

str_t item = {
    .val_a = 1,
    .val_b = 2,   /* Comma here */
};

/* Examples of "complex" structure, with or with missing several trailing commas, after clang-format runs the formatting */
static const my_struct_t my_var_1 = {
    .type = TYPE1,
    .type_data =
        {
            .type1 =
                {
                    .par1 = 0,
                    .par2 = 1, /* Trailing comma here */
                }, /* Trailing comma here */
        },  /* Trailing comma here */
};

static const my_struct_t my_var_2 = {.type = TYPE2,
                                     .type_data = {
                                         .type2 =
                                             {
                                                 .par1 = 0,
                                                 .par2 = 1,
                                             },
                                     }};    /* Missing comma here */
static const my_struct_t my_var_3 = {.type = TYPE3,
                                     .type_data = {.type3 = {
                                                       .par1 = 0,
                                                       .par2 = 1,
                                                   }}}; /* Missing 2 commas here */

/* No trailing commas - good only for small and simple structures */
static const my_struct_t my_var_4 = {.type = TYPE4, .type_data = {.type4 = {.par1 = 0, .par2 = 1}}};
```

- Declare counter variables in `for` loops with a descriptive name
```c
/* OK */
for (size_t idx = 0; idx < 10; ++idx)

/* OK, if you need the counter variable later */
size_t idx;
for (idx = 0; idx < 10; ++idx) {
    if (...) {
        break;
    }
}
if (idx == 10) {

}

/* Wrong */
size_t idx;
for (idx = 0; idx < 10; ++idx) ...
```

- Avoid variable assignment with function call in declaration, except for single variables
```c
void
calculate(void) {
    /* Avoid function calls when declaring variables */
    int32_t var_value, result = sum(1, 2);

    /* Use this */
    int32_t var_value;
    int32_t result;
    result = sum(1, 2);

    /* This is ok */
    uint8_t status = 3, flags = 4;
}
```

- Except for `char`, `float`, or `double`, always prefer types declared in `stdint.h`, e.g. `uint8_t` for `unsigned 8-bit`.
- Avoid using the `stdbool.h` library. Use `1` or `0` for `true` or `false` respectively
```c
/* OK */
uint8_t status_flag;
status_flag = 0;

/* Wrong */
#include <stdbool.h>
bool status = true;
```

- Never compare against `true`, eg. `if (check_func() == 1)`, use `if (check_func()) { ... }`
- Always compare pointers against `NULL` value
```c
void* ptr;

/* ... */

/* OK, compare against NULL */
if (ptr == NULL || ptr != NULL) {

}

/* Wrong */
if (ptr || !ptr) {

}
```

- Always check a pointer against `NULL` before dereferencing it, unless the surrounding code guarantees, by construction, that it cannot be `NULL` at that point
```c
/* OK */
void
process(int32_t* ptr) {
    if (ptr == NULL) {
        return; /* Guard against NULL before use */
    }
    *ptr = 10; /* Safe to dereference */
}

/* Wrong, ptr is dereferenced without a NULL check */
void
process(int32_t* ptr) {
    *ptr = 10;
}
```

- Prefer the use of *pre-increment (and decrement respectively)* instead of *post-increment (and decrement respectively)* whenever possible. Depending on the semantics, *post-increment* is REQUIRED.
```c
int32_t counter_value = 0;
...
counter_value++;            /*  */
++counter_value;            /* Preferred */

for (size_t idx = 0; idx < 10; ++idx) {}  /* OK */
```

- Always use `size_t` for length or size variables
- Always use `const` for pointer when function should not modify memory pointed to by `pointer`
- Always use `const` for function parameters or variables if they should not be modified
```c

/* When the pointer itself can be modified, but the data it points to cannot */
void
my_func(const void* data) {

}

/* When neither the pointer nor the data it points to can be modified */
void
my_func(const void* const data) {

}

/* Not REQUIRED, but advised */
void
my_func(const size_t length) {

}

/* When the pointer cannot be reassigned, but the data it points to can be modified */
void
my_func(void* const data) {

}
```

- When function may accept pointer of any type, always use `void *`, do not use `uint8_t *`
    - Function MUST take care of proper casting in the implementation
```c
/*
 * To send data, function should not modify memory pointed to by `data` variable
 * thus `const` keyword is important
 *
 * To send generic data (or to write them to file)
 * any type may be passed for data,
 * thus use `void *`
 */
/* OK example */
void
send_data(const void* data, size_t len) { /* OK */
    /* Do not cast `void *` or `const void *` */
    const uint8_t* d_ptr = data; /* Function handles proper type for internal usage */
}

void
send_data(const void* data, int len) {    /* Wrong, do not use int */
}
```

- Always use brackets with `sizeof` operator
- Never use *Variable Length Array* (VLA). Use dynamic memory allocation instead with standard C `malloc` and `free` functions or if library/project provides custom memory allocation, use its implementation
    - Take a look at [LwMEM](https://github.com/MaJerle/lwmem), custom memory management library
- After a pointer is passed to `free`, immediately set it to `NULL` to avoid dangling-pointer and double-free bugs
```c
/* OK */
#include <stdlib.h>
void
my_func(size_t size) {
    int32_t* arr;
    arr = malloc(sizeof(*arr) * size); /* OK, Allocate memory */
    arr = malloc(sizeof *arr * size);  /* Wrong, brackets for sizeof operator are missing */
    if (arr == NULL) {
        /* FAIL, no memory */
    }

    free(arr);  /* Free memory after usage */
    arr = NULL; /* OK, avoid dangling pointer after free */
}

/* Wrong */
void
my_func(size_t size) {
    int32_t arr[size];  /* Wrong, do not use VLA */
}
```

- Always compare variable against zero, except if it is treated as `boolean` type
- Never compare `boolean-treated` variables against zero or one. Use NOT (`!`) instead
```c
size_t length = 5;  /* Counter variable */
uint8_t is_ok = 0;  /* Boolean-treated variable */
if (length)         /* Wrong, length is not treated as boolean */
if (length > 0)     /* OK, length is treated as counter variable containing multi values, not only 0 or 1 */
if (length == 0)    /* OK, length is treated as counter variable containing multi values, not only 0 or 1 */

if (is_ok)          /* OK, variable is treated as boolean */
if (!is_ok)         /* OK, -||- */
if (is_ok == 1)     /* Wrong, never compare boolean variable against 1! */
if (is_ok == 0)     /* Wrong, use ! for negative check */
```

- Always use `/* comment */` for comments, even for *single-line* comment
- Every function MUST include *doxygen-enabled* comment, even if function is `static`
- Use English names/text for functions, variables, comments
- Use *lowercase* characters for variables
- Use *underscore* if variable contains multiple names, eg. `force_redraw`. Do not use `forceRedraw`
- Never cast function returning `void *`, eg. `uint8_t* ptr = (uint8_t *)func_returning_void_ptr();` as `void *` is safely promoted to any other pointer type
    - Use `uint8_t* ptr = func_returning_void_ptr();` instead
- Always use `<` and `>` for C Standard Library include files, eg. `#include <stdlib.h>`
- Always use `""` for custom libraries, eg. `#include "my_library.h"`
- When casting to pointer type, always align asterisk to type, eg. `uint8_t* val = (uint8_t*)var_width_diff_type`
- Always respect code style already used in project or library

## Comments

- Comments starting with `//` are not allowed. Always use `/* comment */`, even for single-line comment
```c
//This is comment (wrong)
/* This is comment (ok) */
```

- For multi-line comments use `space+asterisk` for every line
```c
/*
 * This is multi-line comments,
 * written in 2 lines (ok)
 */

/**
 * Wrong, use double-asterisk only for doxygen documentation
 */

/*
* Single line comment without space before asterisk (wrong)
*/

/*
 * Single line comment in multi-line configuration (wrong)
 */

/* Single line comment (ok) */
```

- Use `12` indents (`12 * 4` spaces) offset when commenting. If statement is larger than `12` indents, make comment `4-spaces` aligned (examples below) to next available indent
```c
void
my_func(void) {
    char val_a, val_b;

    val_a = call_func_returning_char_a(val_a);          /* This is comment with 12*4 spaces indent from beginning of line */
    val_b = call_func_returning_char_a_but_func_name_is_very_long(val_a);   /* This is comment, aligned to 4-spaces indent */
}
```

## Functions

- Every function that may be accessed from outside its module MUST include a function prototype (declaration).
- Function declarations and definitions that accept no parameters MUST explicitly use `(void)`, never empty parentheses `()`
```c
/* OK */
int32_t get_status(void);

/* Wrong, in C this declares a function accepting an unspecified number of parameters, not zero parameters */
int32_t get_status();
```
- Function names MUST be lowercase, optionally separated with underscore `_` characters
```c
/* OK */
void my_func(void);
void myfunc(void);

/* Wrong */
void MYFunc(void);
void myFunc(void);
```

- When a function returns a pointer, align the asterisk with the return type
```c
/* OK */
const char* my_func(void);
my_struct_t* my_func(int32_t val_a, int32_t val_b);

/* Wrong */
const char *my_func(void);
my_struct_t * my_func(void);
```
- Align similar function prototypes for better readability
```c
/* OK */
void        set(int32_t val);
my_type_t   get(void);
my_ptr_t*   get_ptr(void);

/* Wrong */
void set(int32_t val);
const char * get(void);
```

- Function implementations MUST place the return type and any storage-class or qualifier keywords on a separate line from the function name
```c
/* OK */
int32_t
foo(void) {
    return 0;
}

/* OK */
static const char*
get_string(void) {
    return "Hello world!\r\n";
}

/* Wrong */
int32_t foo(void) {

    return 0;
}
```

- A function SHOULD have at most `2` `return` points: one early return at the top of the function for parameter/argument validation, and one return at the end of the function. Avoid `return` statements in the middle of the function body; use a return-value variable to accumulate the result instead
```c
/* OK, single early-return for parameter check, single return at the end */
int32_t
my_func(const void* data, size_t len) {
    if (data == NULL || len == 0) {
        return -1; /* Early return, parameter check */
    }

    /* ... function body ... */

    return 0; /* Single return at the end */
}

/* Wrong, additional return in the middle of the function body */
int32_t
my_func(const void* data, size_t len) {
    if (data == NULL || len == 0) {
        return -1;
    }

    /* ... */
    if (some_condition) {
        return -2; /* Wrong, avoid return in the middle of function flow */
    }
    /* ... */

    return 0;
}

/* OK, use a return-value variable instead of an extra return in the middle */
int32_t
my_func(const void* data, size_t len) {
    int32_t retval = 0;

    if (data == NULL || len == 0) {
        return -1;
    }

    /* ... */
    if (some_condition) {
        retval = -2; /* OK, store the result instead of returning here */
    }

    if (retval == 0) {
        /* Do something else */
        retval = some_function(some_parameter);
    }
    if (retval == 0) {
        /* Do something third */
    }
    /* ... */
    return retval;
}
```

## Variables

- Make variable name all lowercase with optional underscore `_` character
```c
/* OK */
int32_t val;
int32_t my_var;
int32_t myvar;

/* Wrong */
int32_t VAL;
int32_t myVar;
int32_t MYVar;
```

- Group local variables together by `type`
```c
void
foo(void) {
    int32_t val_a, val_b;   /* OK */
    char chr_a;
    char chr_b;              /* Wrong, char type already exists */
}
```

- Do not declare variable after first executable statement
```c
void
foo(void) {
    int32_t val_a;
    val_a = bar();
    int32_t val_b;      /* Wrong, there is already executable statement */
}
```

- You may declare new variables inside next indent level
```c
int32_t val_a, val_b;
val_a = foo();
if (val_a) {
    int32_t val_c, val_d;   /* OK, val_c and val_d are in if-statement scope */
    val_c = foo();
    int32_t val_e;      /* Wrong, there was already executable statement inside block */
}
```

- Declare pointer variables with asterisk aligned to type
```c
/* OK */
char* txt;

/* Wrong */
char *txt;
char * txt;
```

- When declaring multiple pointer variables, you may declare them with asterisk aligned to variable name
```c
/* OK */
char *cur, *nxt;
```

## Structures, enumerations, typedefs

- Structure or enumeration name MUST be lowercase with optional underscore `_` character between words
- Structure or enumeration may contain `typedef` keyword
- All structure members MUST be lowercase
- All enumeration members SHOULD be uppercase
- Structure/enumeration MUST follow doxygen documentation syntax

When structure is declared, it may use one of `3` different options:

1. When structure is declared with *name only*, it *MUST not* contain `_t` suffix after its name.
```c
struct struct_name {
    char* txt;
    char val;
};
```
2. When structure is declared with *typedef only*, it *has to* contain `_t` suffix after its name.
```c
typedef struct {
    char* txt;
    char val;
} struct_name_t;
```
3. When structure is declared with *name and typedef*, it *MUST NOT* contain `_t` for basic name and it *MUST* contain `_t` suffix after its name for typedef part.
```c
typedef struct struct_name {    /* No _t */
    char* txt;
    char val_a;
    char val_b;
} struct_name_t;    /* _t */
```

Examples of bad declarations and their suggested corrections
```c
/* val_a and val_b MUST be separated to 2 lines */
/* Name of structure with typedef MUST include _t suffix */
typedef struct {
    int32_t val_a, val_b;
} point;

/* Corrected version */
typedef struct {
    int32_t val_a;
    int32_t val_b;
} point_t;

/* Wrong name, it MUST not include _t suffix */
struct coord_t {
    int32_t val_a;
    int32_t val_b;
};

/* Wrong parameters, MUST be all uppercase */
typedef enum {
    MY_ENUM_TESTA,
    my_enum_testb,
} my_enum_t;
```

- When initializing structure on declaration, use `C99` initialization style
```c
/* OK */
point_t point = {
    .val_a = 4,
    .val_b = 5,
};

/* Wrong */
point_t point = {1, 2};
```

- When new typedef is introduced for function handles, use `_fn` suffix
```c
/* Function accepts 2 parameters and returns uint8_t */
/* Name of typedef has `_fn` suffix */
typedef uint8_t (*my_func_typedef_fn)(uint8_t par_a, const char* par_b);
```

## Compound statements

- Every compound statement MUST include opening and closing curly bracket, even if it includes only `1` nested statement
- Every compound statement MUST include single indent; when nesting statements, include `1` indent size for each nest
```c
/* OK */
if (cnd) {
    do_a();
} else {
    do_b();
}

/* Wrong */
if (cnd)
    do_a();
else
    do_b();

/* Wrong */
if (cnd) do_a();
else do_b();
```

- In case of `if` or `if-else-if` statement, `else` MUST be in the same line as closing bracket of first statement
```c
/* OK */
if (cnd_a) {

} else if (cnd_b) {

} else {

}

/* Wrong */
if (cnd_a) {

}
else {

}

/* Wrong */
if (cnd_a) {

}
else
{

}
```

- In case of `do-while` statement, `while` part MUST be in the same line as closing bracket of `do` part
```c
/* OK */
do {
    int32_t val;
    val = do_a();
    do_b(val);
} while (check());

/* Wrong */
do
{
/* ... */
} while (check());

/* Wrong */
do {
/* ... */
}
while (check());
```

- Indentation is REQUIRED for every opening bracket
```c
if (cnd_a) {
    do_a();
} else {
    do_b();
    if (cnd_b) {
        do_c();
    }
}
```

- Compound statement MUST include curly brackets, even in the case of a single statement. Examples below show bad practices
```c
if (cnd_a) do_b();
else do_c();

if (cnd_a) do_a(); else do_b();
```

- Empty `while`, `do-while` or `for` loops MUST include brackets
```c
/* OK */
while (is_register_bit_set()) {}

/* Wrong */
while (is_register_bit_set());
while (is_register_bit_set()) { }
while (is_register_bit_set()) {
}
```

- If `while` (or `for`, `do-while`, etc) is empty (it can be the case in embedded programming), use empty single-line brackets
```c
/* Wait for bit to be set in embedded hardware unit */
volatile uint32_t* addr = HW_PERIPH_REGISTER_ADDR;

/* Wait bit 13 to be ready */
while (*addr & (1 << 13)) {}        /* OK, empty loop contains no spaces inside curly brackets */
while (*addr & (1 << 13)) { }       /* Wrong */
while (*addr & (1 << 13)) {         /* Wrong */

}
while (*addr & (1 << 13));          /* Wrong, curly brackets are missing. Can lead to compiler warnings or unintentional bugs */
```
- Always prefer using loops in this order: `for`, `do-while`, `while`
- Avoid incrementing variables inside loop block if possible, see examples

```c
/* Not recommended */
int32_t cnt = 0;
while (cnt < 10) {
    .
    ..
    ...
    ++cnt;
}

/* Better */
for (size_t cnt = 0; cnt < 10; ++cnt) {

}

/* Better, if inc may not happen in every cycle */
for (size_t cnt = 0; cnt < 10; ) {
    if (...) {
        ++cnt;
    }
}
```

- Inline `if` statement MAY be used only for assignment or function call operations
```c
/* OK */
int val = condition ? if_yes : if_no; /* Assignment */
func_call(condition ? if_yes : if_no); /* Function call */
switch (condition ? if_yes : if_no) {...}   /* OK */

/* Wrong, this code is not well maintenable */
condition ? call_to_function_a() : call_to_function_b();

/* Rework to have better program flow */
if (condition) {
    call_to_function_a();
} else {
    call_to_function_b();
}
```

### Switch statement

- Add *single indent* for every `case` statement
- Use additional *single indent* for `break` statement in each `case` or `default` statement
```c
/* OK, every case has single indent */
/* OK, every break has additional indent */
switch (check()) {
    case 0:
        do_a();
        break;
    case 1:
        do_b();
        break;
    default:
        break;
}

/* Wrong, case indent missing */
switch (check()) {
case 0:
    do_a();
    break;
case 1:
    do_b();
    break;
default:
    break;
}

/* Wrong */
switch (check()) {
    case 0:
        do_a();
    break;      /* Wrong, break MUST have indent as it is under case */
    case 1:
    do_b();     /* Wrong, indent under case is missing */
    break;
    default:
        break;
}
```

- Always include `default` statement
```c
/* OK */
switch (var) {
    case 0:
        do_job();
        break;
    default:
        break;
}

/* Wrong, default is missing */
switch (var) {
    case 0:
        do_job();
        break;
}
```

- If local variables are REQUIRED, use curly brackets and put `break` statement inside.
    - Put opening curly bracket in the same line as `case` statement
```c
switch (sel) {
    /* OK */
    case 0: {
        int32_t val_a, val_b;
        char chr;
        val_a = 5;
        /* ... */
        break;
    }

    /* Wrong */
    case 1:
    {
        int32_t val;
        break;
    }

    /* Wrong, break shall be inside */
    case 2: {
        int32_t val;
    }
    break;
}
```

## Macros and preprocessor directives

- Always use macros instead of literal constants, especially for numbers
- All macros MUST be fully uppercase, with optional underscore `_` character, except if they are clearly marked as function which may be in the future replaced with regular function syntax
```c
/* OK */
#define SQUARE(val)         ((val) * (val))

/* Wrong */
#define square(val)           ((val) * (val))
```

- Always protect input parameters with parentheses
```c
/* OK */
#define MIN(val_a, val_b)           ((val_a) < (val_b) ? (val_a) : (val_b))

/* Wrong */
#define MIN(val_a, val_b)           val_a < val_b ? val_a : val_b
```

- Always protect final macro evaluation with parenthesis
```c
/* Wrong */
#define MIN(val_a, val_b)           (val_a) < (val_b) ? (val_a) : (val_b)
#define SUM(val_a, val_b)           (val_a) + (val_b)

/* Imagine result of this equation using wrong SUM implementation */
int32_t expected_result = 5 * SUM(3, 4);  /* Expected result is 5 * 7 = 35 */
int32_t actual_result = 5 * (3) + (4);    /* It is evaluated to this, final result = 19 which is not what we expect */

/* Correct implementation */
#define MIN(val_a, val_b)           ((val_a) < (val_b) ? (val_a) : (val_b))
#define SUM(val_a, val_b)           ((val_a) + (val_b))
```

- When macro uses multiple statements, protect these using `do {} while (0)` statement
```c
typedef struct {
    int32_t pos_x, pos_y;
} point_t;
point_t pnt;                  /* Define new point */

/* Wrong implementation */

/* Define macro to set point */
#define SET_POINT(ptr, val_a, val_b)  (ptr)->pos_x = (val_a); (ptr)->pos_y = (val_b)    /* 2 statements. Last one should not implement semicolon */

SET_POINT(&pnt, 3, 4);        /* Set point to position 3, 4. This evaluates to... */
(&pnt)->pos_x = (3); (&pnt)->pos_y = (4); /* ... to this. In this example this is not a problem. */

/* Consider this ugly code, however it is valid by C standard (not recommended) */
if (cnd_a)                      /* If cnd_a is true */
    if (cnd_b)                  /* If cnd_b is true */
        SET_POINT(&pnt, 3, 4);/* Set point to val_a = 3, val_b = 4 */
    else
        SET_POINT(&pnt, 5, 6);/* Set point to val_a = 5, val_b = 6 */

/* Evaluates to code below. Do you see the problem? */
if (cnd_a)
    if (cnd_b)
        (&pnt)->pos_x = (3); (&pnt)->pos_y = (4);
    else
        (&pnt)->pos_x = (5); (&pnt)->pos_y = (6);

/* Or if we rewrite it a little */
if (cnd_a)
    if (cnd_b)
        (&pnt)->pos_x = (3);
        (&pnt)->pos_y = (4);
    else
        (&pnt)->pos_x = (5);
        (&pnt)->pos_y = (6);

/*
 * Ask yourself a question: To which `if` statement does the `else` keyword belong?
 *
 * Based on first part of code, answer is straight-forward. To inner `if` statement when we check `cnd_b` condition
 * Actual answer: Compilation error as `else` belongs nowhere
 */

/* Better and correct implementation of macro */
#define SET_POINT(ptr, val_a, val_b)  do { (ptr)->pos_x = (val_a); (ptr)->pos_y = (val_b); } while (0)    /* 2 statements. No semicolon after while loop */
/* Or even better */
#define SET_POINT(ptr, val_a, val_b)  do {     \   /* Backslash indicates statement continues in new line */
    (ptr)->pos_x = (val_a);                    \
    (ptr)->pos_y = (val_b);                    \
} while (0)                                     /* 2 statements. No semicolon after while loop */

/* Now original code evaluates to */
if (cnd_a)
    if (cnd_b)
        do { (&pnt)->pos_x = (3); (&pnt)->pos_y = (4); } while (0);
    else
        do { (&pnt)->pos_x = (5); (&pnt)->pos_y = (6); } while (0);

/* Every part of `if` or `else` contains only `1` inner statement (do-while), hence this is valid evaluation */

/* To make code perfect, use brackets for every if-ifelse-else statements */
if (cnd_a) {                    /* If cnd_a is true */
    if (cnd_b) {                /* If cnd_b is true */
        SET_POINT(&pnt, 3, 4);/* Set point to val_a = 3, val_b = 4 */
    } else {
        SET_POINT(&pnt, 5, 6);/* Set point to val_a = 5, val_b = 6 */
    }
}
```

- Avoid using `#ifdef` or `#ifndef`. Use `defined()` or `!defined()` instead
```c
#ifdef XYZ
/* do something */
#endif /* XYZ */
```

- Always document `if/elif/else/endif` statements
```c
/* OK */
#if defined(XYZ)
/* Do if XYZ defined */
#else /* defined(XYZ) */
/* Do if XYZ not defined */
#endif /* !defined(XYZ) */

/* Wrong */
#if defined(XYZ)
/* Do if XYZ defined */
#else
/* Do if XYZ not defined */
#endif
```

- Do not indent sub statements inside `#if` statement
```c
/* OK */
#if defined(XYZ)
#if defined(ABC)
/* do when ABC defined */
#endif /* defined(ABC) */
#else /* defined(XYZ) */
/* Do when XYZ not defined */
#endif /* !defined(XYZ) */

/* Wrong */
#if defined(XYZ)
    #if defined(ABC)
        /* do when ABC defined */
    #endif /* defined(ABC) */
#else /* defined(XYZ) */
    /* Do when XYZ not defined */
#endif /* !defined(XYZ) */
```

## Documentation

Documented code allows doxygen to parse and generate html/pdf/latex output, thus it is very important to do it properly at an early stage of the project.

- Use doxygen-enabled documentation style for `variables`, `functions` and `structures/enumerations`
- Always use `\` for doxygen, do not use `@`
- Pad every doxygen tag with spaces so the description text starts at column `22` of the line, matching `template.c`/`template.h`
```c
/**
 * \brief           Holds pointer to first entry in linked list
 *                  This text is aligned to the same column as the \brief description above
 */
static
type_t* list;
```

- Every structure/enumeration member MUST include documentation
- Align start of comments between different structure members to the same column
```c
/**
 * \brief           This is point struct
 * \note            This structure is used to calculate all point
 *                      related stuff
 */
typedef struct {
    int32_t pos_x;                               /*!< Point X coordinate */
    int32_t pos_y;                               /*!< Point Y coordinate */
    int32_t size;                                /*!< Point size.
                                                     Since comment is very big,
                                                     you may go to next line */
} point_t;

/**
 * \brief           Point color enumeration
 */
typedef enum {
    COLOR_RED,                                  /*!< Red color */
    COLOR_GREEN,                                /*!< Green color */
    COLOR_BLUE,                                 /*!< Blue color */
} point_color_t;
```

- Documentation for a function MUST be written at its *definition* (where the function body is implemented, typically the `.c` file), and MUST NOT be duplicated at its *declaration* (the prototype without a body, typically in the header file)
- Function MUST include `brief` and all parameters documentation
- Every parameter MUST be noted if it is `in` or `out` for *input* and *output* respectively
- Function MUST include `return` parameter if it returns something. This does not apply for `void` functions
- Function can include other doxygen keywords, such as `note` or `warning`
- Use colon `:` between parameter name and its description
```c
/**
 * \brief           Sum `2` numbers
 * \param[in]       par_a: First number
 * \param[in]       par_b: Second number
 * \return          Sum of input values
 */
int32_t
sum(int32_t par_a, int32_t par_b) {
    return par_a + par_b;
}

/**
 * \brief           Sum `2` numbers and write it to pointer
 * \note            This function does not return value, it stores it to pointer instead
 * \param[in]       par_a: First number
 * \param[in]       par_b: Second number
 * \param[out]      result: Output variable used to save result
 */
void
void_sum(int32_t par_a, int32_t par_b, int32_t* result) {
    *result = par_a + par_b;
}
```

- If function returns member of enumeration, use `ref` keyword to specify which one
```c
/**
 * \brief           My enumeration
 */
typedef enum {
    MY_ERR,                                     /*!< Error value */
    MY_OK                                       /*!< OK value */
} my_enum_t;

/**
 * \brief           Check some value
 * \return          \ref MY_OK on success, member of \ref my_enum_t otherwise
 */
my_enum_t
check_value(void) {
    return MY_OK;
}
```

- Wrap constants, literal values, and code identifiers referenced in documentation text in backticks, eg. `` `NULL` ``
```c
/**
 * \brief           Get data from input array
 * \param[in]       inp: Input data
 * \return          Pointer to output data on success, `NULL` otherwise
 */
const void *
get_data(const void* inp) {
    return inp;
}
```

- Documentation for macros MUST include `hideinitializer` doxygen command
```c
/**
 * \brief           Get minimal value between `val_a` and `val_b`
 * \param[in]       val_a: First value
 * \param[in]       val_b: Second value
 * \return          Minimal value between `val_a` and `val_b`
 * \hideinitializer
 */
#define MIN(val_a, val_b)       ((val_a) < (val_b) ? (val_a) : (val_b))
```

## Header/source files

- Leave single empty line at the end of file
- Every file MUST include doxygen annotation for `file` and `brief` description followed by empty line (when using doxygen)
```c
/**
 * \file            template.h
 * \brief           Template include file
 */
                    /* Here is empty line */
```

- Header files MUST include header guards using `#ifndef`
- Include standard C headers before application-specific headers
- Header files should include only the headers required to compile correctly; `.c` files should include additional headers if needed
- Header files MUST expose only module public variables, types, and functions
- Use `extern` for global module variables in header files and define them in source files later
```
/* file.h ... */
#ifndef ...

extern int32_t my_variable; /* This is a global variable declaration in a header */

#endif

/* file.c ... */
int32_t my_variable;        /* Actually defined in source */
```
- Never include `.c` files in another `.c` file
- `.c` file should first include corresponding `.h` file, later others, unless otherwise explicitly necessary
- Do not include module private declarations in header file

- Header file example (no license for sake of an example)
```c
/* License comes here */
#ifndef TEMPLATE_HDR_H
#define TEMPLATE_HDR_H

/* Include headers */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* File content here */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* TEMPLATE_HDR_H */
```

## Clang format integration

This repository includes an up-to-date `.clang-format` file for `clang-format`. The tool can be integrated with most modern IDEs, including VSCode, or run directly from the command line.

To format a single file manually:
```sh
clang-format -i path/to/file.c
```

To format multiple files:
```sh
clang-format -i *.c *.h
```

or recursively:
```sh
find . \( -name '*.c' -o -name '*.h' \) -print0 | xargs -0 clang-format -i
```

Recommended installation methods:
- macOS: `brew install llvm` and add `$(brew --prefix llvm)/bin` to `PATH`
- Linux: install the `clang-format` package from your distribution, or install LLVM from the official LLVM repository
- Windows: install LLVM from the official LLVM installer and ensure `clang-format.exe` is on `PATH`

If the tool is not available, the repository formatting rules can still be reviewed manually, but automated formatting will not work until `clang-format` is installed.

> If one uses Visual Studio Code (vscode), the `clang-format` tool ships with the IDE.