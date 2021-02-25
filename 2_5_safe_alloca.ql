import cpp
import semmle.code.cpp.controlflow.Guards
import semmle.code.cpp.dataflow.DataFlow

string prettyPrint(Expr f) {
    result = f.getFile().getShortName() + ":" 
        + f.getLocation().getStartLine() 
        /* + "-" + f.getLocation().getEndLine() */
}

/* Pull previous query into a predicate */
/* Eliminate quantified variable since b2 is allocaCalls' basic block */

predicate isSafeAllocaCall(FunctionCall allocaCall) {
    exists( FunctionCall fc, GuardCondition gc,
    DataFlow::Node source, DataFlow::Node sink, 
    BasicBlock b |
    fc.getTarget().getName() = "__libc_use_alloca" 
    and b.contains(fc)
    and gc.controls(allocaCall.getBasicBlock(), _)
    and DataFlow::localFlow(source, sink)
    and source.asExpr() = b.getANode() 
    and sink.asExpr() = gc.getAChild*()
    )
}

from FunctionCall fc
where fc.getTarget().getName() = "__builtin_alloca"
and isSafeAllocaCall(fc)
select fc, prettyPrint(fc)