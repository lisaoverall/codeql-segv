import cpp
import semmle.code.cpp.controlflow.Guards
import semmle.code.cpp.dataflow.DataFlow

string prettyPrint(Expr f) {
    result = f.getFile().getShortName() + ":" 
        + f.getLocation().getStartLine() 
        /* + "-" + f.getLocation().getEndLine() */
}

/* In order to get results containing negation of calls to use_alloca,
must refer to basic block surrounding function call */

from FunctionCall fc1, GuardCondition gc, FunctionCall fc2,
    DataFlow::Node source, DataFlow::Node sink, 
    BasicBlock b1, BasicBlock b2
where fc1.getTarget().getName() = "__libc_use_alloca" 
and fc2.getTarget().getName() = "__builtin_alloca"
and b1.contains(fc1)
and b2.contains(fc2)
and gc.controls(b2, _)
and DataFlow::localFlow(source, sink)
and source.asExpr() = b1.getANode() 
and sink.asExpr() = gc.getAChild*()
select gc, prettyPrint(gc)