import cpp

from FunctionCall fc
where fc.getTarget().getName() = "__libc_use_alloca" 
select fc