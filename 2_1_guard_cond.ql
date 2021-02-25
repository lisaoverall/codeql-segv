import cpp
import semmle.code.cpp.controlflow.Guards

from FunctionCall fc, GuardCondition gc, FunctionCall fc2
where fc.getTarget().getName() = "__libc_use_alloca" 
and fc2.getTarget().getName() = "__builtin_alloca"
and gc.controls(fc2.getBasicBlock(), _)
and gc.getAChild*() = fc
select gc