import cpp
import semmle.code.cpp.controlflow.Guards
import semmle.code.cpp.dataflow.DataFlow
import semmle.code.cpp.rangeanalysis.SimpleRangeAnalysis

string prettyPrint(Expr f) {
    result = f.getFile().getShortName() + ":" 
        + f.getLocation().getStartLine() 
        /* + "-" + f.getLocation().getEndLine() */
}

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

predicate isOOBAllocaCall(FunctionCall allocaCall) {
    exists(Expr sizearg |
        sizearg = allocaCall.getArgument(0).getFullyConverted()
        and ( upperBound(sizearg) >= 65536
        or lowerBound(sizearg) < 0 )
    )
}

from FunctionCall fc
where fc.getTarget().getName() = "__builtin_alloca"
and isOOBAllocaCall(fc)
and not isSafeAllocaCall(fc)
select fc, prettyPrint(fc)