#ifndef __FLOAT_H
#define __FLOAT_H

#include <stdint.h>  

#define FLOAT_Q 14           
#define FLOAT_F (1 << FLOAT_Q)    /* Scaling factor */
 
/* f_point type alias for int32_t handles internal fixed-point representation */
typedef int32_t f_point;

/* Maximum and minimum */
#define FLOAT_MAX INT32_MAX
#define FLOAT_MIN INT32_MIN

/* Convert from integer */
#define INT_TO_FLOAT(n) ((f_point)((n) * FLOAT_F))

/* Convert to integer */
#define FLOAT_TO_INT(x) ((x) / FLOAT_F)

/* Convert to Round int */
#define FLOAT_TO_INT_ROUND(x) (((x) >= 0) ? (((x) + FLOAT_F / 2) / FLOAT_F) : (((x) - FLOAT_F / 2) / FLOAT_F))

/* f_point + float */
#define FLOAT_ADD(x, y) ((x) + (y))

/* f_point - float */
#define FLOAT_SUB(x, y) ((x) - (y))

/* Int + float */
#define FLOAT_ADD_INT(x, n) (FLOAT_ADD((x), INT_TO_FLOAT(n)))

/* f_point - int */
#define FLOAT_SUB_INT(x, n) (FLOAT_SUB((x), INT_TO_FLOAT(n)))

/* f_point * float */
#define FLOAT_MUL(x, y) ((f_point)((int64_t)(x) * ((y) / FLOAT_F)))

/* Divide two fixed-point numbers */
#define FLOAT_DIV(x, y) ((f_point)(((int64_t) (x)) * FLOAT_F / (y)))

/* f_point * int */
#define FLOAT_MUL_INT(x, n) (FLOAT_MUL((x), INT_TO_FLOAT(n)))

/* f_point / float */
#define FLOAT_DIV_INT(x, n) (FLOAT_DIV((x), INT_TO_FLOAT(n)))


/* Comparison */
#define FLOAT_LESS(x, y) ((x) < (y))
#define FLOAT_GREATER(x, y) ((x) > (y))
#define FLOAT_EQUAL(x, y) ((x) == (y))
#define FLOAT_NOT_EQUAL(x, y) ((x) != (y))
#define FLOAT_LESS_EQUAL(x, y) ((x) <= (y))
#define FLOAT_GREATER_EQUAL(x, y) ((x) >= (y))

#endif
