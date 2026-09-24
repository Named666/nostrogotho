#ifndef NHR_MODULE_H_
#define NHR_MODULE_H_

#include "nhr.h"

#define NHR_DECLARE_MODULE_FUNCTION(ret, name, args) \
    ret NHR_CALL nhr_module_##name args;
NHR_MODULE_FUNCTIONS(NHR_DECLARE_MODULE_FUNCTION)
#undef NHR_DECLARE_MODULE_FUNCTION

/* No extra ABI declarations: all module exports are declared by
 * NHR_MODULE_FUNCTIONS above. */

#endif /* NHR_MODULE_H_ */
