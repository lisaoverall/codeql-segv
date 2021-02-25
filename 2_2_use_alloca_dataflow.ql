import cpp
import semmle.code.cpp.controlflow.Guards
import semmle.code.cpp.dataflow.DataFlow

string prettyPrint(Expr f) {
    result = f.getFile().toString() + ":" + f.getLocation().getStartLine()
}

from FunctionCall fc, GuardCondition gc, FunctionCall fc2,
    DataFlow::Node source, DataFlow::Node sink
where fc.getTarget().getName() = "__libc_use_alloca" 
and fc2.getTarget().getName() = "__builtin_alloca"
/* remove line below so we get variables that are the result of fc */
/* and gc.getAChild*() = fc */
and gc.controls(fc2.getBasicBlock(), _)
and DataFlow::localFlow(source, sink)
and source.asExpr() = fc 
and sink.asExpr() = gc
select gc, prettyPrint(gc)