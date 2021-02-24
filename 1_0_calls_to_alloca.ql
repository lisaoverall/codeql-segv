import cpp

from FunctionCall fc
where fc.getTarget().getName() = "__builtin_alloca"
select fc