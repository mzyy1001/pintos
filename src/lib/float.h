#ifndef __FLOAT_H
#define __FLOAT_H

#include <stdint.h>  

#define FLOAT_Q 14           
#define FLOAT_F (1 << 14)    // Scaling factor

// Float type as an alias for int32_t to handle the internal fixed-point representation
typedef int32_t Float;

//maximum and minmum
#define FLOAT_MAX INT32_MAX
#define FLOAT_MIN INT32_MIN

// Convert from integer
#define INT_TO_FLOAT(n) ((Float)((n) * FLOAT_F))

// convert to integer
#define FLOAT_TO_INT(x) ((int)((x) / FLOAT_F))

// conver to Round int
#define FLOAT_TO_INT_ROUND(x) (((x) >= 0) ? (((x) + FLOAT_F / 2) / FLOAT_F) : (((x) - FLOAT_F / 2) / FLOAT_F))

// float + float
#define FLOAT_ADD(x, y) ((x) + (y))

// float - float
#define FLOAT_SUB(x, y) ((x) - (y))

// int + float
#define FLOAT_ADD_INT(x, n) ((x) + (n) * FLOAT_F)

// float - int
#define FLOAT_SUB_INT(x, n) ((x) - (n) * FLOAT_F)

// float * int
#define FLOAT_MUL_INT(x, n) ((x) * (n))

// float / float
#define FLOAT_DIV_INT(x, n) ((x) / (n))

// float * float
#define FLOAT_MUL(x, y) ((Float)(((int64_t)(x) * (y)) / FLOAT_F))

// Divide two fixed-point numbers
#define FLOAT_DIV(x, y) ((Float)(((int64_t)(x) * FLOAT_F) / (y)))

//comparision
#define FLOAT_LESS(x, y) ((x) < (y))
#define FLOAT_GREATER(x, y) ((x) > (y))
#define FLOAT_EQUAL(x, y) ((x) == (y))
#define FLOAT_NOT_EQUAL(x, y) ((x) != (y))
#define FLOAT_LESS_EQUAL(x, y) ((x) <= (y))
#define FLOAT_GREATER_EQUAL(x, y) ((x) >= (y))

#endif 