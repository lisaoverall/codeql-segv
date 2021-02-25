import cpp
import semmle.code.cpp.controlflow.Guards
import semmle.code.cpp.dataflow.DataFlow

string prettyPrint(Expr f) {
    result = f.getFile().getShortName() + ":" 
        + f.getLocation().getStartLine() 
        /* + "-" + f.getLocation().getEndLine() */
}

from FunctionCall fc, GuardCondition gc, FunctionCall fc2,
    DataFlow::Node source, DataFlow::Node sink
where fc.getTarget().getName() = "__libc_use_alloca" 
and fc2.getTarget().getName() = "__builtin_alloca"
and gc.controls(fc2.getBasicBlock(), _)
and DataFlow::localFlow(source, sink)
and source.asExpr() = fc 
/* call getAChild* to account for wrappred methods */
and sink.asExpr() = gc.getAChild*()
select gc, prettyPrint(gc)